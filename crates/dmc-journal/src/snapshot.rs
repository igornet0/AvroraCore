//! Crash-safe snapshot publication and manifest recovery (Phase 5.2).
//!
//! Snapshot payload bytes are opaque to this module; an 8-byte little-endian
//! sequence prefix is stored in the file so publication can be validated without
//! parsing materialized state.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::layout::StorageLayout;

pub const MANIFEST_FORMAT_VERSION: u32 = 1;

const SNAPSHOT_TMP: &str = "snapshot.tmp";
const MANIFEST_TMP: &str = "manifest.tmp";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotManifest {
    pub snapshot_id: String,
    pub sequence: u64,
    pub format_version: u32,
    pub snapshot_file: String,
    #[serde(with = "serde_hex32")]
    pub checksum: [u8; 32],
    pub created_at_ms: u64,
}

mod serde_hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let raw = hex::decode(s).map_err(serde::de::Error::custom)?;
        if raw.len() != 32 {
            return Err(serde::de::Error::custom("checksum must be 32 bytes"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        Ok(out)
    }
}

/// Decoded snapshot file: sequence prefix + opaque payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredSnapshot {
    pub manifest: SnapshotManifest,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct SnapshotStore {
    snapshots_dir: PathBuf,
    manifest_path: PathBuf,
}

impl SnapshotStore {
    pub fn new(layout: &StorageLayout) -> Self {
        Self {
            snapshots_dir: layout.snapshots_dir(),
            manifest_path: layout.snapshot_manifest(),
        }
    }

    pub fn snapshots_dir(&self) -> &Path {
        &self.snapshots_dir
    }

    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    /// Read manifest if present. Does not validate snapshot bytes.
    pub fn read_manifest(&self) -> Result<Option<SnapshotManifest>> {
        if !self.manifest_path.is_file() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&self.manifest_path).map_err(Error::io)?;
        let manifest: SnapshotManifest =
            serde_json::from_str(&raw).map_err(|e| Error::SnapshotCorrupt(e.to_string()))?;
        Ok(Some(manifest))
    }

    /// Load manifest, validate checksum/sequence/journal head, return opaque payload.
    pub fn recover(&self, journal_head: u64) -> Result<Option<RecoveredSnapshot>> {
        let Some(manifest) = self.read_manifest()? else {
            return Ok(None);
        };
        validate_manifest_meta(&manifest)?;
        let file_path = self.snapshots_dir.join(&manifest.snapshot_file);
        if !file_path.is_file() {
            return Err(Error::SnapshotCorrupt(format!(
                "snapshot file {} missing",
                manifest.snapshot_file
            )));
        }
        let bytes = fs::read(&file_path).map_err(Error::io)?;
        validate_snapshot_bytes(&manifest, &bytes)?;
        if journal_head < manifest.sequence {
            return Err(Error::SnapshotInconsistent(format!(
                "journal head {journal_head} < snapshot sequence {}",
                manifest.sequence
            )));
        }
        let payload = decode_payload(&bytes)?;
        Ok(Some(RecoveredSnapshot { manifest, payload }))
    }

    /// Atomic publication: snapshot file then manifest. Replaces prior manifest.
    pub fn publish(
        &self,
        sequence: u64,
        payload: &[u8],
        created_at_ms: u64,
    ) -> Result<SnapshotManifest> {
        fs::create_dir_all(&self.snapshots_dir).map_err(Error::io)?;

        let snapshot_id = Uuid::now_v7().to_string();
        let snapshot_file = format!("snapshot-{sequence:012}.bin");
        let file_path = self.snapshots_dir.join(&snapshot_file);
        let encoded = encode_snapshot_blob(sequence, payload);
        let checksum = sha256(&encoded);

        write_sync_rename(
            &self.snapshots_dir.join(SNAPSHOT_TMP),
            &file_path,
            &encoded,
        )?;
        sync_dir(&self.snapshots_dir)?;

        let manifest = SnapshotManifest {
            snapshot_id,
            sequence,
            format_version: MANIFEST_FORMAT_VERSION,
            snapshot_file,
            checksum,
            created_at_ms,
        };
        let manifest_raw =
            serde_json::to_string_pretty(&manifest).map_err(|e| Error::io(e.to_string()))?;
        write_sync_rename(
            &self.snapshots_dir.join(MANIFEST_TMP),
            &self.manifest_path,
            manifest_raw.as_bytes(),
        )?;
        sync_dir(&self.snapshots_dir)?;

        Ok(manifest)
    }
}

pub fn encode_snapshot_blob(sequence: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&sequence.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn decode_payload(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() < 8 {
        return Err(Error::SnapshotCorrupt("snapshot file too short".into()));
    }
    Ok(bytes[8..].to_vec())
}

pub fn snapshot_sequence(bytes: &[u8]) -> Result<u64> {
    if bytes.len() < 8 {
        return Err(Error::SnapshotCorrupt("snapshot file too short".into()));
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    Ok(u64::from_le_bytes(buf))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn validate_manifest_meta(manifest: &SnapshotManifest) -> Result<()> {
    if manifest.format_version != MANIFEST_FORMAT_VERSION {
        return Err(Error::SnapshotCorrupt(format!(
            "unsupported manifest format version {}",
            manifest.format_version
        )));
    }
    if Uuid::parse_str(&manifest.snapshot_id).is_err() {
        return Err(Error::SnapshotCorrupt("invalid snapshot_id".into()));
    }
    if manifest.snapshot_file.ends_with(".tmp") || manifest.snapshot_file.contains('/') {
        return Err(Error::SnapshotCorrupt("invalid snapshot_file name".into()));
    }
    Ok(())
}

fn validate_snapshot_bytes(manifest: &SnapshotManifest, bytes: &[u8]) -> Result<()> {
    let digest = sha256(bytes);
    if digest != manifest.checksum {
        return Err(Error::SnapshotCorrupt("checksum mismatch".into()));
    }
    let embedded = snapshot_sequence(bytes)?;
    if embedded != manifest.sequence {
        return Err(Error::SnapshotCorrupt(format!(
            "embedded sequence {embedded} != manifest sequence {}",
            manifest.sequence
        )));
    }
    Ok(())
}

fn write_sync_rename(tmp: &Path, dest: &Path, bytes: &[u8]) -> Result<()> {
    {
        let mut f = File::create(tmp).map_err(Error::io)?;
        f.write_all(bytes).map_err(Error::io)?;
        f.sync_all().map_err(Error::io)?;
    }
    fs::rename(tmp, dest).map_err(Error::io)?;
    Ok(())
}

fn sync_dir(dir: &Path) -> Result<()> {
    let f = File::open(dir).map_err(Error::io)?;
    f.sync_all().map_err(Error::io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::StorageLayout;

    fn store(dir: &Path) -> SnapshotStore {
        let layout = StorageLayout::from_db_path(dir.join("store.dbs.json"));
        SnapshotStore::new(&layout)
    }

    #[test]
    fn publish_and_recover_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let manifest = store.publish(42, b"payload", 1_000).unwrap();
        assert_eq!(manifest.sequence, 42);
        let recovered = store.recover(42).unwrap().unwrap();
        assert_eq!(recovered.manifest, manifest);
        assert_eq!(recovered.payload, b"payload");
    }

    #[test]
    fn tmp_files_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        store.publish(10, b"a", 1).unwrap();
        fs::write(
            store.snapshots_dir().join(MANIFEST_TMP),
            r#"{"sequence":999}"#,
        )
        .unwrap();
        let recovered = store.recover(10).unwrap().unwrap();
        assert_eq!(recovered.manifest.sequence, 10);
    }

    #[test]
    fn corrupt_snapshot_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        store.publish(5, b"x", 1).unwrap();
        let path = store
            .snapshots_dir()
            .join("snapshot-000000000005.bin");
        let mut bytes = fs::read(&path).unwrap();
        if let Some(b) = bytes.last_mut() {
            *b ^= 0xff;
        }
        fs::write(&path, &bytes).unwrap();
        assert!(store.recover(5).is_err());
    }

    #[test]
    fn journal_head_below_snapshot_is_inconsistent() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        store.publish(100, b"x", 1).unwrap();
        assert!(store.recover(50).is_err());
    }
}
