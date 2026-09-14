//! Retention pin helpers: age / max-bytes watermarks from segment metadata.
//!
//! Journal GC does not call these — runtime aggregates the result as another `JournalPin`.

use crate::codec::scan_segment;
use crate::segment::{JournalSegmentInfo, SegmentState};
use crate::Result;

/// Last sequence in a contiguous prefix whose entries are strictly before `cutoff_ms`.
/// Stops at the first entry with `timestamp >= cutoff` (prefix trim semantics).
pub fn age_trim_through(
    segments: &[JournalSegmentInfo],
    segment_bytes: impl Fn(u64) -> Result<Vec<u8>>,
    cutoff_ms: u64,
) -> Result<Option<u64>> {
    let mut trim = None;
    let mut ordered: Vec<_> = segments.iter().collect();
    ordered.sort_by_key(|s| s.id);
    'segments: for seg in ordered {
        if seg.end_sequence == 0 {
            continue;
        }
        let bytes = segment_bytes(seg.id)?;
        let (_, entries, _) = scan_segment(&bytes)?;
        for entry in entries {
            if entry.timestamp_unix_ms < cutoff_ms {
                trim = Some(entry.sequence);
            } else {
                break 'segments;
            }
        }
    }
    Ok(trim)
}

/// Whole sealed segments only. Best-effort: after trim, total sealed size may exceed `max_bytes`.
pub fn bytes_trim_through(segments: &[JournalSegmentInfo], max_bytes: u64) -> Option<u64> {
    let mut sealed: Vec<_> = segments
        .iter()
        .filter(|s| s.state == SegmentState::Sealed && s.byte_size > 0)
        .collect();
    sealed.sort_by_key(|s| s.id);
    let total: u64 = sealed.iter().map(|s| s.byte_size).sum();
    if total <= max_bytes {
        return None;
    }
    let mut remaining = total;
    let mut trim = None;
    for seg in sealed {
        if remaining <= max_bytes {
            break;
        }
        remaining = remaining.saturating_sub(seg.byte_size);
        trim = Some(seg.end_sequence);
    }
    trim
}

/// Combine age and bytes limits: more conservative (minimum sequence) wins.
pub fn combine_trim_through(age: Option<u64>, bytes: Option<u64>) -> Option<u64> {
    match (age, bytes) {
        (None, None) => None,
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (Some(a), Some(b)) => Some(a.min(b)),
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    fn seg(id: u64, end: u64, state: SegmentState, bytes: u64) -> JournalSegmentInfo {
        JournalSegmentInfo {
            id,
            start_sequence: if end > 0 { end.saturating_sub(1).max(1) } else { 1 },
            end_sequence: end,
            state,
            first_timestamp_unix_ms: None,
            last_timestamp_unix_ms: None,
            byte_size: bytes,
        }
    }

    #[test]
    fn bytes_deletes_whole_segments_from_oldest() {
        let segments = vec![
            seg(1, 10, SegmentState::Sealed, 100),
            seg(2, 20, SegmentState::Sealed, 100),
            seg(3, 30, SegmentState::Sealed, 100),
        ];
        assert_eq!(bytes_trim_through(&segments, 150), Some(20));
        assert_eq!(bytes_trim_through(&segments, 250), Some(10));
        assert_eq!(bytes_trim_through(&segments, 350), None);
    }

    #[test]
    fn combine_takes_minimum() {
        assert_eq!(combine_trim_through(Some(500), Some(800)), Some(500));
        assert_eq!(combine_trim_through(Some(800), None), Some(800));
        assert_eq!(combine_trim_through(None, None), None);
    }
}
