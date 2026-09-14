use serde::{Deserialize, Serialize};

use dmc_materialized::StateEventRecord;
use dmc_model::CatalogSnapshotBody;

use crate::manifest::{BackupStorageTableEntry, RecoveryMetadata};

pub const JOURNAL_ARTIFACT_FORMAT_VERSION: u32 = 1;
pub const CATALOG_ARTIFACT_FORMAT_VERSION: u32 = 1;
pub const STORAGE_ARTIFACT_FORMAT_VERSION: u32 = 1;
pub const RECOVERY_ARTIFACT_FORMAT_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalSegmentRef {
    pub segment_id: u64,
    pub relative_path: String,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub event_count: u64,
    pub size: u64,
    pub checksum_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JournalArtifact {
    pub format_version: u32,
    pub checkpoint_sequence: u64,
    pub tip_sequence: u64,
    pub segments: Vec<JournalSegmentRef>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JournalSegmentFile {
    pub format_version: u32,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub events: Vec<StateEventRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogArtifact {
    pub format_version: u32,
    pub checkpoint_sequence: u64,
    pub catalog: CatalogSnapshotBody,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageArtifact {
    pub format_version: u32,
    pub checkpoint_sequence: u64,
    pub include_segments: bool,
    pub tables: Vec<BackupStorageTableEntry>,
    pub segments: Vec<StorageSegmentRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageSegmentRef {
    pub table_id: u64,
    pub segment_id: u64,
    pub relative_path: String,
    pub size: u64,
    pub checksum_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryArtifact {
    pub format_version: u32,
    pub checkpoint_sequence: u64,
    pub require_rebuild_rowstore: bool,
    pub require_rebuild_indexstore: bool,
    pub require_rebuild_statistics: bool,
}

impl RecoveryArtifact {
    pub fn from_metadata(meta: &RecoveryMetadata) -> Self {
        Self {
            format_version: RECOVERY_ARTIFACT_FORMAT_VERSION,
            checkpoint_sequence: meta.checkpoint_sequence,
            require_rebuild_rowstore: meta.require_rebuild_rowstore,
            require_rebuild_indexstore: meta.require_rebuild_indexstore,
            require_rebuild_statistics: meta.require_rebuild_statistics,
        }
    }
}
