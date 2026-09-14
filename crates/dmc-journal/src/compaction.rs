//! Compaction policy, candidate selection, artifact/result types (Phase 5.6.1+ / 5.7.8).
//!
//! Candidate selection is independent of retention watermarks — compaction rewrites
//! storage; GC decides when obsolete segments may be deleted.
//!
//! Phase 5.7.8: compaction runs **within one partition** only; global sequence order
//! is preserved by `JournalMergeReader`, not by contiguous segment ranges.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::partition::PartitionId;
use crate::segment::{JournalSegmentInfo, SegmentState};

/// Admin policy for storage-preserving compaction (5.6.1 — no path filters / age / parallelism).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactionPolicy {
    pub enabled: bool,
    pub min_segments: usize,
    pub min_total_bytes: u64,
    pub max_input_bytes: u64,
}

impl Default for CompactionPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            min_segments: 4,
            min_total_bytes: 0,
            max_input_bytes: 256 * 1024 * 1024,
        }
    }
}

impl CompactionPolicy {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }
}

/// A chain of sealed segments eligible for one compaction job within a single partition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactionCandidate {
    pub partition_id: PartitionId,
    pub segment_ids: Vec<u64>,
    pub start_sequence: u64,
    pub end_sequence: u64,
    pub total_bytes: u64,
}

/// Physical compaction output on disk (5.6.2 — orphan until manifest publication in 5.6.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactionArtifact {
    pub partition_id: PartitionId,
    pub segment_id: u64,
    pub source_segment_ids: Vec<u64>,
    pub start_sequence: u64,
    pub end_sequence: u64,
    pub record_count: u64,
    pub byte_size: u64,
    pub path: PathBuf,
}

/// Outcome of a published compaction job (manifest-driven — 5.6.3+).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactionResult {
    pub partition_id: PartitionId,
    pub replacement_segment_id: u64,
    pub source_segment_ids: Vec<u64>,
    pub start_sequence: u64,
    pub end_sequence: u64,
    pub manifest_generation: u64,
}

fn segments_in_partition<'a>(
    segments: &'a [JournalSegmentInfo],
    segment_partitions: &HashMap<u64, PartitionId>,
    partition_id: PartitionId,
) -> Vec<&'a JournalSegmentInfo> {
    let mut sealed: Vec<_> = segments
        .iter()
        .filter(|s| {
            s.state == SegmentState::Sealed
                && s.byte_size > 0
                && segment_partitions
                    .get(&s.id)
                    .copied()
                    .unwrap_or(PartitionId(0))
                    == partition_id
        })
        .collect();
    sealed.sort_by_key(|s| s.id);
    sealed
}

/// Select the longest prefix of oldest sealed segments in **one partition**.
///
/// Does **not** consult retention / consumer / replay pins.
/// Segment ranges may have gaps in global sequence (interleaved partitions).
pub fn select_compaction_candidate_for_partition(
    segments: &[JournalSegmentInfo],
    segment_partitions: &HashMap<u64, PartitionId>,
    partition_id: PartitionId,
    policy: &CompactionPolicy,
) -> Option<CompactionCandidate> {
    if !policy.enabled || policy.min_segments == 0 {
        return None;
    }
    let sealed = segments_in_partition(segments, segment_partitions, partition_id);
    if sealed.len() < policy.min_segments {
        return None;
    }

    let mut best: Option<CompactionCandidate> = None;
    let mut total_bytes = 0u64;
    let mut ids = Vec::new();
    let mut prefix_start = 0u64;
    for seg in sealed {
        if ids.is_empty() {
            prefix_start = seg.start_sequence;
        }
        let next_total = total_bytes.saturating_add(seg.byte_size);
        if next_total > policy.max_input_bytes {
            break;
        }
        total_bytes = next_total;
        ids.push(seg.id);
        if ids.len() >= policy.min_segments && total_bytes >= policy.min_total_bytes {
            best = Some(CompactionCandidate {
                partition_id,
                segment_ids: ids.clone(),
                start_sequence: prefix_start,
                end_sequence: seg.end_sequence,
                total_bytes,
            });
        }
    }
    best
}

/// Select a compaction candidate from the lowest partition id that has one.
pub fn select_compaction_candidate(
    segments: &[JournalSegmentInfo],
    segment_partitions: &HashMap<u64, PartitionId>,
    partition_count: u32,
    policy: &CompactionPolicy,
) -> Option<CompactionCandidate> {
    for pid in 0..partition_count.max(1) {
        if let Some(c) = select_compaction_candidate_for_partition(
            segments,
            segment_partitions,
            PartitionId(pid),
            policy,
        ) {
            return Some(c);
        }
    }
    None
}

#[cfg(test)]
mod unit {
    use super::*;

    fn seg(id: u64, start: u64, end: u64, bytes: u64, state: SegmentState) -> JournalSegmentInfo {
        JournalSegmentInfo {
            id,
            start_sequence: start,
            end_sequence: end,
            state,
            first_timestamp_unix_ms: None,
            last_timestamp_unix_ms: None,
            byte_size: bytes,
        }
    }

    fn policy(min_seg: usize, min_bytes: u64, max_bytes: u64) -> CompactionPolicy {
        CompactionPolicy {
            enabled: true,
            min_segments: min_seg,
            min_total_bytes: min_bytes,
            max_input_bytes: max_bytes,
        }
    }

    fn p0_map(ids: &[u64]) -> HashMap<u64, PartitionId> {
        ids.iter().map(|id| (*id, PartitionId(0))).collect()
    }

    #[test]
    fn disabled_returns_none() {
        let segments = vec![seg(1, 1, 10, 100, SegmentState::Sealed)];
        let map = p0_map(&[1]);
        assert!(select_compaction_candidate(
            &segments,
            &map,
            1,
            &CompactionPolicy::disabled()
        )
        .is_none());
    }

    #[test]
    fn active_never_in_candidate() {
        let segments = vec![
            seg(1, 1, 10, 100, SegmentState::Sealed),
            seg(2, 11, 20, 100, SegmentState::Active),
        ];
        let map = p0_map(&[1, 2]);
        let c = select_compaction_candidate(&segments, &map, 1, &policy(1, 0, 1000)).unwrap();
        assert_eq!(c.partition_id, PartitionId(0));
        assert_eq!(c.segment_ids, vec![1]);
    }

    #[test]
    fn min_segments_and_max_input_bytes() {
        let segments = vec![
            seg(1, 1, 10, 50, SegmentState::Sealed),
            seg(2, 11, 20, 50, SegmentState::Sealed),
            seg(3, 21, 30, 50, SegmentState::Sealed),
            seg(4, 31, 40, 50, SegmentState::Sealed),
        ];
        let map = p0_map(&[1, 2, 3, 4]);
        assert!(select_compaction_candidate(&segments, &map, 1, &policy(4, 0, 150)).is_none());
        let c = select_compaction_candidate(&segments, &map, 1, &policy(4, 0, 200)).unwrap();
        assert_eq!(c.segment_ids, vec![1, 2, 3, 4]);
        assert_eq!(c.total_bytes, 200);
    }

    #[test]
    fn prefers_longest_prefix_under_max_bytes() {
        let segments = vec![
            seg(1, 1, 10, 40, SegmentState::Sealed),
            seg(2, 11, 20, 40, SegmentState::Sealed),
            seg(3, 21, 30, 40, SegmentState::Sealed),
        ];
        let map = p0_map(&[1, 2, 3]);
        let c = select_compaction_candidate(&segments, &map, 1, &policy(2, 0, 120)).unwrap();
        assert_eq!(c.segment_ids, vec![1, 2, 3]);
    }

    #[test]
    fn partitions_never_mix_in_candidate() {
        let segments = vec![
            seg(1, 1, 7, 50, SegmentState::Sealed),
            seg(2, 2, 8, 50, SegmentState::Sealed),
            seg(3, 3, 9, 50, SegmentState::Sealed),
            seg(4, 4, 10, 50, SegmentState::Sealed),
        ];
        let map = HashMap::from([
            (1, PartitionId(0)),
            (2, PartitionId(1)),
            (3, PartitionId(0)),
            (4, PartitionId(1)),
        ]);
        let c = select_compaction_candidate_for_partition(
            &segments,
            &map,
            PartitionId(0),
            &policy(2, 0, 200),
        )
        .unwrap();
        assert_eq!(c.partition_id, PartitionId(0));
        assert_eq!(c.segment_ids, vec![1, 3]);
        assert!(select_compaction_candidate(&segments, &map, 2, &policy(4, 0, 500)).is_none());
    }
}
