//! Authoritative segment selection (manifest-driven + legacy bootstrap).

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::codec::{decode_segment_footer, decode_segment_header, scan_segment};
use crate::error::{Error, Result};
use crate::journal_manifest_v2::{read_stored_manifest, validate_stored_manifest};
use crate::layout::{find_segment_path, list_segment_ids};
use crate::types::SEGMENT_HEADER_LEN;

struct SegmentSpan {
    id: u64,
    /// Directory holding the segment (one per partition). Sequence ranges of different
    /// partitions interleave, so overlap only means "compaction orphan" within one directory.
    dir: PathBuf,
    start_sequence: u64,
    end_sequence: u64,
    is_active: bool,
}

fn load_segment_span(
    journal_dir: &Path,
    id: u64,
    active_segments: &[u64],
) -> Result<Option<SegmentSpan>> {
    let path = match find_segment_path(journal_dir, id) {
        Some(p) => p,
        None => return Ok(None),
    };
    let bytes = fs::read(&path).map_err(Error::io)?;
    if bytes.len() < SEGMENT_HEADER_LEN {
        return Ok(None);
    }
    let header = decode_segment_header(&bytes[..SEGMENT_HEADER_LEN])?;
    let footer = decode_segment_footer(&bytes);
    let active_set: HashSet<_> = active_segments.iter().copied().collect();
    let is_active = active_set.contains(&id) && footer.is_none();
    let (_last_good, _entries, last_seq) = scan_segment(&bytes)?;
    let end_sequence = footer.map(|(last, _)| last).unwrap_or(last_seq);
    Ok(Some(SegmentSpan {
        id,
        dir: path.parent().map(Path::to_path_buf).unwrap_or_default(),
        start_sequence: header.first_sequence,
        end_sequence,
        is_active,
    }))
}

fn overlaps(a: &SegmentSpan, b: &SegmentSpan) -> bool {
    a.start_sequence <= b.end_sequence && a.end_sequence >= b.start_sequence
}

fn verify_legacy_topology_unambiguous(spans: &[SegmentSpan]) -> Result<()> {
    for i in 0..spans.len() {
        for j in (i + 1)..spans.len() {
            if spans[i].dir == spans[j].dir && overlaps(&spans[i], &spans[j]) {
                return Err(Error::JournalManifestInconsistent(
                    "legacy journal topology ambiguous: overlapping segment ranges".into(),
                ));
            }
        }
    }
    Ok(())
}

/// Pre-manifest authoritative selection (overlap filter excludes compaction orphans).
pub fn legacy_authoritative_segment_ids(
    journal_dir: &Path,
    active_segments: &[u64],
) -> Result<Vec<u64>> {
    let all_ids = list_segment_ids(journal_dir)?;
    let mut spans = Vec::new();
    for id in all_ids {
        if let Some(span) = load_segment_span(journal_dir, id, active_segments)? {
            spans.push(span);
        }
    }
    spans.sort_by_key(|s| s.id);

    let mut authoritative = Vec::new();
    let mut covered: Vec<(PathBuf, u64, u64)> = Vec::new();
    for span in spans {
        if span.is_active {
            authoritative.push(span.id);
            continue;
        }
        if covered.iter().any(|(dir, start, end)| {
            *dir == span.dir && span.start_sequence <= *end && span.end_sequence >= *start
        }) {
            continue;
        }
        authoritative.push(span.id);
        covered.push((span.dir, span.start_sequence, span.end_sequence));
    }
    Ok(authoritative)
}

/// Segments that constitute the authoritative journal for replay / segment metadata.
///
/// With manifest: **only** manifest-listed segments (validated). Orphans on disk are ignored.
/// Without manifest: legacy non-overlapping topology or `JournalManifestInconsistent`.
pub fn authoritative_segment_ids(
    journal_dir: &Path,
    manifest_path: &Path,
    active_segments: &[u64],
    partition_count: u32,
) -> Result<Vec<u64>> {
    if manifest_path.is_file() {
        let manifest = read_stored_manifest(manifest_path)?
            .ok_or_else(|| Error::JournalManifestInconsistent("empty manifest path".into()))?;
        validate_stored_manifest(&manifest, journal_dir, partition_count)?;
        return Ok(manifest.authoritative_segment_ids());
    }

    legacy_authoritative_segment_ids(journal_dir, active_segments)
}

/// Returns true when on-disk segments have no overlapping ranges (safe for gen-0 bootstrap).
pub fn legacy_topology_unambiguous(journal_dir: &Path, active_segments: &[u64]) -> Result<bool> {
    let all_ids = list_segment_ids(journal_dir)?;
    let mut spans = Vec::new();
    for id in all_ids {
        if let Some(span) = load_segment_span(journal_dir, id, active_segments)? {
            spans.push(span);
        }
    }
    Ok(verify_legacy_topology_unambiguous(&spans).is_ok())
}

#[cfg(test)]
mod unit {
    use super::*;

    fn span(id: u64, dir: &str, start: u64, end: u64) -> SegmentSpan {
        SegmentSpan {
            id,
            dir: PathBuf::from(dir),
            start_sequence: start,
            end_sequence: end,
            is_active: false,
        }
    }

    #[test]
    fn legacy_rejects_overlapping_ranges() {
        let spans = vec![span(1, "j", 1, 100), span(5, "j", 1, 300)];
        assert!(verify_legacy_topology_unambiguous(&spans).is_err());
    }

    #[test]
    fn overlapping_ranges_in_different_partitions_are_unambiguous() {
        // Interleaved partitions: p-0 holds 1,4,7…; p-1 holds 2,5,8… — ranges overlap by design.
        let spans = vec![span(1, "j/p-0", 1, 28), span(2, "j/p-1", 2, 29)];
        assert!(verify_legacy_topology_unambiguous(&spans).is_ok());
    }
}
