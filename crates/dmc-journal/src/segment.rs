//! Journal segment metadata and GC result types (Phase 5.3 / 5.7.7).

use crate::lifecycle::SegmentDisposition;
use crate::partition::PartitionId;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SegmentState {
    Active,
    Sealed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalSegmentInfo {
    pub id: u64,
    pub start_sequence: u64,
    pub end_sequence: u64,
    pub state: SegmentState,
    /// First entry timestamp in segment (journal entry time, not filesystem mtime).
    pub first_timestamp_unix_ms: Option<u64>,
    /// Last entry timestamp in segment.
    pub last_timestamp_unix_ms: Option<u64>,
    /// On-disk bytes (header + entries, excluding incomplete tail).
    pub byte_size: u64,
}

/// Partition-local segment eligible for prefix trim / GC (Phase 5.7.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartitionTrimCandidate {
    pub partition_id: PartitionId,
    pub segment_id: u64,
    pub start_sequence: u64,
    pub end_sequence: u64,
    pub disposition: SegmentDisposition,
}

/// Backward-compatible alias (`partition_id = 0` when `partition_count = 1`).
pub type TrimCandidate = PartitionTrimCandidate;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrimResult {
    pub trim_through: u64,
    pub deleted_segments: Vec<u64>,
    pub retained_segments: Vec<u64>,
}
