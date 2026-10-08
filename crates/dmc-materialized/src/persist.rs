use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use dmc_model::{CatalogSnapshotBody, MaterializedWatermark};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const MATERIALIZED_SNAPSHOT_FORMAT_VERSION: u32 = 1;

/// Global materialized-state checkpoint: catalog + row watermark (row data lives in table dirs).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializedStateSnapshot {
    pub format_version: u32,
    pub watermark: MaterializedWatermark,
    pub catalog: CatalogSnapshotBody,
    /// Idempotency aid for replay — ordering remains [`MaterializedWatermark::sequence`].
    pub seen_event_ids: Vec<[u8; 16]>,
    /// D4-B: generation of every table / index store at this checkpoint. A store found
    /// older than recorded on open (with storage keys) is a rollback → refused.
    #[serde(default)]
    pub storage_generations: StorageGenerations,
}

/// Table / index id → store generation (D4-B freshness).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageGenerations {
    pub tables: BTreeMap<u64, u64>,
    pub indexes: BTreeMap<u64, u64>,
}

impl MaterializedStateSnapshot {
    pub fn new(
        watermark: MaterializedWatermark,
        catalog: CatalogSnapshotBody,
        seen_event_ids: Vec<[u8; 16]>,
    ) -> Self {
        Self {
            format_version: MATERIALIZED_SNAPSHOT_FORMAT_VERSION,
            watermark,
            catalog,
            seen_event_ids,
            storage_generations: StorageGenerations::default(),
        }
    }
}

/// Logical name bound into the AAD of an encrypted snapshot (D4-A).
pub const SNAPSHOT_CONTEXT: &str = "materialized_snapshot.json";

pub fn load_materialized_snapshot(path: &Path) -> Result<Option<MaterializedStateSnapshot>> {
    load_materialized_snapshot_with(path, None)
}

/// Load, decrypting with `cipher` (rules: [`crate::sealed_io`]).
pub fn load_materialized_snapshot_with(
    path: &Path,
    cipher: Option<&dmc_vault::StorageCipher>,
) -> Result<Option<MaterializedStateSnapshot>> {
    if !path.is_file() {
        return Ok(None);
    }
    let raw = fs::read(path).map_err(|e| Error::Io(e.to_string()))?;
    let plain = crate::sealed_io::decode_file(
        &raw,
        cipher,
        dmc_vault::StoragePurpose::Snapshot,
        SNAPSHOT_CONTEXT,
        "snapshot",
    )?;
    if plain.is_empty() {
        return Ok(None);
    }
    let snapshot: MaterializedStateSnapshot =
        serde_json::from_slice(&plain).map_err(|e| Error::Corrupt(e.to_string()))?;
    if snapshot.format_version != MATERIALIZED_SNAPSHOT_FORMAT_VERSION {
        return Err(Error::Corrupt(format!(
            "unsupported materialized snapshot version {}",
            snapshot.format_version
        )));
    }
    Ok(Some(snapshot))
}

pub fn save_materialized_snapshot(path: &Path, snapshot: &MaterializedStateSnapshot) -> Result<()> {
    save_materialized_snapshot_with(path, snapshot, None)
}

/// Save, sealing with `cipher` before anything touches the disk (temp file included).
pub fn save_materialized_snapshot_with(
    path: &Path,
    snapshot: &MaterializedStateSnapshot,
    cipher: Option<&dmc_vault::StorageCipher>,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| Error::Io(e.to_string()))?;
    }
    crate::sealed_io::refuse_plaintext_over_sealed(path, cipher, "materialized snapshot")?;
    let plain = zeroize::Zeroizing::new(
        serde_json::to_vec_pretty(snapshot).map_err(|e| Error::Corrupt(e.to_string()))?,
    );
    let raw = crate::sealed_io::encode_file(
        &plain,
        cipher,
        dmc_vault::StoragePurpose::Snapshot,
        SNAPSHOT_CONTEXT,
    )?;
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp).map_err(|e| Error::Io(e.to_string()))?;
        f.write_all(&raw).map_err(|e| Error::Io(e.to_string()))?;
        f.sync_all().map_err(|e| Error::Io(e.to_string()))?;
    }
    fs::rename(&tmp, path).map_err(|e| Error::Io(e.to_string()))?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}
