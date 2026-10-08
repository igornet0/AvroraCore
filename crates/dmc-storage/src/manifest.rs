use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use dmc_model::{ColumnId, RowId, TableId};
use serde::{Deserialize, Serialize};

use crate::codec::TableSchema;
use crate::error::{Error, Result};

pub const STORAGE_MANIFEST_FORMAT_VERSION: u32 = 1;
pub const MANIFEST_FILE: &str = "manifest.json";
pub const MANIFEST_TMP: &str = "manifest.tmp";
/// D4-B: AEAD copy of the table manifest — authoritative whenever storage keys are in use.
pub const SEALED_MANIFEST_FILE: &str = "manifest.sealed";
const SEALED_MANIFEST_TMP: &str = "manifest.sealed.tmp";
pub const SEGMENTS_DIR: &str = "segments";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentManifest {
    pub segment_id: u64,
    pub byte_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageManifest {
    pub format_version: u32,
    pub generation: u64,
    pub table_id: u64,
    pub schema: TableSchema,
    pub segments: Vec<SegmentManifest>,
    pub next_row_id: u64,
}

impl StorageManifest {
    pub fn new(table_id: TableId, schema: TableSchema) -> Self {
        Self {
            format_version: STORAGE_MANIFEST_FORMAT_VERSION,
            generation: 1,
            table_id: table_id.raw(),
            schema,
            segments: Vec::new(),
            next_row_id: 1,
        }
    }

    pub fn table_id(&self) -> TableId {
        TableId::new(self.table_id)
    }

    pub fn next_row_id(&self) -> RowId {
        RowId::new(self.next_row_id)
    }

    pub fn bump_generation(&mut self) {
        self.generation += 1;
    }
}

pub fn table_dir(root: &Path, table_id: TableId) -> PathBuf {
    root.join(format!("table_{}", table_id.raw()))
}

pub fn segments_dir(table_root: &Path) -> PathBuf {
    table_root.join(SEGMENTS_DIR)
}

pub fn manifest_paths(table_root: &Path) -> (PathBuf, PathBuf) {
    (
        table_root.join(MANIFEST_FILE),
        table_root.join(MANIFEST_TMP),
    )
}

pub fn read_manifest(table_root: &Path) -> Result<Option<StorageManifest>> {
    let (manifest_path, _) = manifest_paths(table_root);
    if !manifest_path.is_file() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&manifest_path).map_err(Error::io)?;
    serde_json::from_str(&raw).map_err(|e| Error::Manifest(e.to_string()))
}

/// Sealing context of a table manifest (bound to the table id).
pub fn table_manifest_context(table_id: TableId) -> String {
    format!("table_{}/{MANIFEST_FILE}", table_id.raw())
}

/// Publish the manifest. With storage keys the sealed manifest is written **first** (it is
/// the authoritative one), then the plaintext copy kept for keyless metadata readers; a
/// crash in between leaves a stale plaintext copy, never an unauthenticated store.
pub fn publish_manifest_with(
    table_root: &Path,
    manifest: &StorageManifest,
    cipher: Option<&dmc_vault::StorageCipher>,
) -> Result<()> {
    if let Some(c) = cipher {
        fs::create_dir_all(table_root).map_err(Error::io)?;
        let plain = zeroize::Zeroizing::new(
            serde_json::to_vec(manifest).map_err(|e| Error::Manifest(e.to_string()))?,
        );
        let sealed = c.seal(
            dmc_vault::StoragePurpose::Rows,
            &dmc_vault::storage_cipher::file_context(&table_manifest_context(manifest.table_id())),
            &plain,
        )?;
        write_sync_rename(
            &table_root.join(SEALED_MANIFEST_TMP),
            &table_root.join(SEALED_MANIFEST_FILE),
            &sealed,
        )?;
    }
    publish_manifest(table_root, manifest)
}

/// Read the manifest the store may trust. With storage keys only the sealed manifest
/// counts: missing (while the plaintext copy exists), from another table, tampered or
/// under other keys → error, never a fallback to the unauthenticated copy. Without keys a
/// sealed manifest is refused ("storage keys required").
pub fn read_manifest_with(
    table_root: &Path,
    table_id: TableId,
    cipher: Option<&dmc_vault::StorageCipher>,
) -> Result<Option<StorageManifest>> {
    let sealed_path = table_root.join(SEALED_MANIFEST_FILE);
    let Some(c) = cipher else {
        if sealed_path.is_file() {
            return Err(Error::Corrupt(
                "table manifest is encrypted: storage keys required".into(),
            ));
        }
        return read_manifest(table_root);
    };
    if !sealed_path.is_file() {
        if table_root.join(MANIFEST_FILE).is_file() {
            return Err(Error::Corrupt(
                "table manifest is not authenticated (manifest.sealed missing): plaintext table \
                 on encrypted storage (explicit migration required) or a removed manifest"
                    .into(),
            ));
        }
        return Ok(None);
    }
    let raw = fs::read(&sealed_path).map_err(Error::io)?;
    let plain = c
        .open(
            dmc_vault::StoragePurpose::Rows,
            &dmc_vault::storage_cipher::file_context(&table_manifest_context(table_id)),
            &raw,
        )
        .map(zeroize::Zeroizing::new)
        .map_err(|_| {
            Error::Corrupt(
                "table manifest cannot be decrypted (wrong key, tampered or from another table)"
                    .into(),
            )
        })?;
    let manifest: StorageManifest =
        serde_json::from_slice(&plain).map_err(|e| Error::Manifest(e.to_string()))?;
    if manifest.table_id != table_id.raw() {
        return Err(Error::Corrupt("table manifest is for another table".into()));
    }
    Ok(Some(manifest))
}

pub fn publish_manifest(table_root: &Path, manifest: &StorageManifest) -> Result<()> {
    fs::create_dir_all(table_root).map_err(Error::io)?;
    let (manifest_path, tmp_path) = manifest_paths(table_root);
    let raw = serde_json::to_string_pretty(manifest).map_err(|e| Error::Manifest(e.to_string()))?;
    write_sync_rename(&tmp_path, &manifest_path, raw.as_bytes())?;
    sync_dir(table_root)
}

pub fn write_sync_rename(tmp: &Path, dest: &Path, bytes: &[u8]) -> Result<()> {
    {
        let mut f = File::create(tmp).map_err(Error::io)?;
        f.write_all(bytes).map_err(Error::io)?;
        f.sync_all().map_err(Error::io)?;
    }
    fs::rename(tmp, dest).map_err(Error::io)?;
    Ok(())
}

pub fn sync_dir(dir: &Path) -> Result<()> {
    let f = File::open(dir).map_err(Error::io)?;
    f.sync_all().map_err(Error::io)?;
    Ok(())
}

pub fn schema_from_catalog_columns(
    table_id: TableId,
    columns: &[(ColumnId, dmc_model::SqlDataType, bool)],
) -> TableSchema {
    TableSchema {
        table_id: table_id.raw(),
        columns: columns
            .iter()
            .map(|(id, ty, nullable)| crate::codec::ColumnSchema {
                column_id: id.raw(),
                data_type: ty.clone(),
                nullable: *nullable,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::ColumnSchema;
    use dmc_model::SqlDataType;
    use tempfile::tempdir;

    #[test]
    fn manifest_tmp_not_read() {
        let dir = tempdir().unwrap();
        let table_root = dir.path().join("t");
        fs::create_dir_all(&table_root).unwrap();
        let (_, tmp) = manifest_paths(&table_root);
        fs::write(&tmp, b"{\"format_version\":1}").unwrap();
        assert!(read_manifest(&table_root).unwrap().is_none());
    }

    #[test]
    fn publish_and_read_manifest() {
        let dir = tempdir().unwrap();
        let table_root = dir.path().join("t");
        let schema = TableSchema {
            table_id: 1,
            columns: vec![ColumnSchema {
                column_id: 1,
                data_type: SqlDataType::BigInt,
                nullable: true,
            }],
        };
        let manifest = StorageManifest::new(TableId::new(1), schema);
        publish_manifest(&table_root, &manifest).unwrap();
        let loaded = read_manifest(&table_root).unwrap().unwrap();
        assert_eq!(loaded.table_id, 1);
    }
}
