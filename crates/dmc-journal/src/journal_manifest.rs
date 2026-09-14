//! Physical journal layout manifest (Phase 5.6 — separate from snapshot manifest).
//!
//! Describes which segment files constitute the authoritative journal topology.
//! Logical event fields (sequence, event_id, path, …) remain in AVJL only.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::codec::{decode_segment_footer, decode_segment_header, validate_sealed_segment};
use crate::compaction::CompactionArtifact;
use crate::crash_injection::{maybe_crash, CrashPoint};
use crate::error::{Error, Result};
use crate::segment::{JournalSegmentInfo, SegmentState};
use crate::types::SEGMENT_HEADER_LEN;

pub const JOURNAL_MANIFEST_FORMAT_VERSION: u32 = 1;
pub const JOURNAL_MANIFEST_FORMAT_VERSION_V2: u32 = 2;
pub const MANIFEST_TMP: &str = "manifest.tmp";

/// Authoritative physical layout after crash-safe publication (5.6.3+).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalManifest {
    pub format_version: u32,
    pub generation: u64,
    pub segments: Vec<SegmentManifestEntry>,
    /// Segments removed from authoritative topology by compaction publication (5.6.5).
    #[serde(default)]
    pub superseded_segment_ids: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentManifestEntry {
    pub segment_id: u64,
    pub start_sequence: u64,
    pub end_sequence: u64,
    #[serde(default)]
    pub start_timestamp_unix_ms: u64,
    #[serde(default)]
    pub end_timestamp_unix_ms: u64,
    pub byte_size: u64,
    pub state: SegmentState,
}

impl JournalManifest {
    pub fn segment_ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.segments.iter().map(|s| s.segment_id)
    }

    pub fn contains_segment(&self, id: u64) -> bool {
        self.segments.iter().any(|s| s.segment_id == id)
    }
}

/// Build a manifest view from on-disk segment scan (pre-publication / diagnostic).
pub fn manifest_from_segment_infos(
    generation: u64,
    infos: &[JournalSegmentInfo],
) -> JournalManifest {
    let mut segments: Vec<_> = infos
        .iter()
        .map(|s| SegmentManifestEntry {
            segment_id: s.id,
            start_sequence: s.start_sequence,
            end_sequence: s.end_sequence,
            start_timestamp_unix_ms: s.first_timestamp_unix_ms.unwrap_or(0),
            end_timestamp_unix_ms: s.last_timestamp_unix_ms.unwrap_or(0),
            byte_size: s.byte_size,
            state: s.state,
        })
        .collect();
    segments.sort_by_key(|s| s.start_sequence);
    JournalManifest {
        format_version: JOURNAL_MANIFEST_FORMAT_VERSION,
        generation,
        segments,
        superseded_segment_ids: Vec::new(),
    }
}

pub fn manifest_paths(runtime_journal_dir: &Path) -> (PathBuf, PathBuf) {
    let manifest = runtime_journal_dir.join("manifest.json");
    let tmp = runtime_journal_dir.join(MANIFEST_TMP);
    (manifest, tmp)
}

/// Read published manifest only — `manifest.tmp` is never authoritative.
///
/// Returns a flattened V1 view (including when the on-disk file is V2).
pub fn read_manifest(manifest_path: &Path) -> Result<Option<JournalManifest>> {
    if !manifest_path.is_file() {
        return Ok(None);
    }
    let raw = fs::read_to_string(manifest_path).map_err(Error::io)?;
    let value: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| Error::JournalManifestInconsistent(e.to_string()))?;
    let version = value
        .get("format_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(1) as u32;
    if version == JOURNAL_MANIFEST_FORMAT_VERSION_V2 {
        let generation = value
            .get("generation")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| Error::JournalManifestInconsistent("missing generation".into()))?;
        let superseded: Vec<u64> = value
            .get("superseded_segment_ids")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let mut segments = Vec::new();
        if let Some(partitions) = value.get("partitions").and_then(|p| p.as_array()) {
            for part in partitions {
                if let Some(segs) = part.get("segments").and_then(|s| s.as_array()) {
                    for seg in segs {
                        let entry: SegmentManifestEntry = serde_json::from_value(seg.clone())
                            .map_err(|e| Error::JournalManifestInconsistent(e.to_string()))?;
                        segments.push(entry);
                    }
                }
            }
        }
        segments.sort_by_key(|s| s.start_sequence);
        return Ok(Some(JournalManifest {
            format_version: JOURNAL_MANIFEST_FORMAT_VERSION,
            generation,
            segments,
            superseded_segment_ids: superseded,
        }));
    }
    let manifest: JournalManifest =
        serde_json::from_str(&raw).map_err(|e| Error::JournalManifestInconsistent(e.to_string()))?;
    Ok(Some(manifest))
}

/// Exactly one ACTIVE segment must be declared in the manifest.
pub fn manifest_active_segment(manifest: &JournalManifest) -> Result<u64> {
    let active: Vec<_> = manifest
        .segments
        .iter()
        .filter(|s| s.state == SegmentState::Active)
        .collect();
    match active.len() {
        0 => Err(Error::JournalManifestInconsistent(
            "manifest has no active segment".into(),
        )),
        1 => Ok(active[0].segment_id),
        _ => Err(Error::JournalManifestInconsistent(
            "manifest has multiple active segments".into(),
        )),
    }
}

/// Validate manifest metadata and on-disk segment correspondence.
/// Empty active segments use `start_sequence` as the next append slot before any record exists.
pub(crate) fn segment_sequence_bounds_valid(
    start_sequence: u64,
    end_sequence: u64,
    state: SegmentState,
) -> bool {
    if start_sequence <= end_sequence {
        return true;
    }
    state == SegmentState::Active && end_sequence + 1 == start_sequence
}

pub fn validate_manifest(manifest: &JournalManifest, journal_dir: &Path) -> Result<()> {
    if manifest.format_version != JOURNAL_MANIFEST_FORMAT_VERSION {
        return Err(Error::JournalManifestInconsistent(format!(
            "unsupported format version {}",
            manifest.format_version
        )));
    }
    if manifest.segments.is_empty() {
        return Err(Error::JournalManifestInconsistent(
            "manifest has no segments".into(),
        ));
    }

    let mut seen_ids = std::collections::HashSet::new();
    let mut prev_end: Option<u64> = None;
    for (idx, entry) in manifest.segments.iter().enumerate() {
        if !seen_ids.insert(entry.segment_id) {
            return Err(Error::JournalManifestInconsistent(format!(
                "duplicate segment_id {}",
                entry.segment_id
            )));
        }
        if !segment_sequence_bounds_valid(
            entry.start_sequence,
            entry.end_sequence,
            entry.state,
        ) {
            return Err(Error::JournalManifestInconsistent(format!(
                "segment {} start > end",
                entry.segment_id
            )));
        }
        if idx > 0 && entry.start_sequence <= manifest.segments[idx - 1].start_sequence {
            return Err(Error::JournalManifestInconsistent(
                "segments must be ordered by start_sequence".into(),
            ));
        }
        if let Some(prev) = prev_end {
            if entry.start_sequence <= prev {
                return Err(Error::JournalManifestInconsistent(format!(
                    "overlapping ranges at segment {}",
                    entry.segment_id
                )));
            }
            if entry.start_sequence != prev.saturating_add(1) {
                return Err(Error::JournalManifestInconsistent(format!(
                    "sequence gap before segment {}",
                    entry.segment_id
                )));
            }
        }
        prev_end = Some(entry.end_sequence);

        let path = crate::layout::resolve_segment_path(journal_dir, entry.segment_id);
        if !path.is_file() {
            return Err(Error::JournalManifestInconsistent(format!(
                "segment file seg-{:012}.jnl missing",
                entry.segment_id
            )));
        }
        let bytes = fs::read(&path).map_err(Error::io)?;
        match entry.state {
            SegmentState::Active => {
                if decode_segment_footer(&bytes).is_some() {
                    return Err(Error::JournalManifestInconsistent(format!(
                        "active segment {} must not have footer",
                        entry.segment_id
                    )));
                }
                decode_segment_header(&bytes[..SEGMENT_HEADER_LEN]).map_err(|e| {
                    Error::JournalSegmentCorrupt(format!("segment {} header: {e}", entry.segment_id))
                })?;
            }
            SegmentState::Sealed => {
                let (_start, end, _count, _) =
                    validate_sealed_segment(&bytes, entry.segment_id).map_err(|e| {
                        Error::JournalSegmentCorrupt(format!("segment {}: {e}", entry.segment_id))
                    })?;
                if end != entry.end_sequence {
                    return Err(Error::JournalManifestInconsistent(format!(
                        "segment {} footer end_sequence mismatch",
                        entry.segment_id
                    )));
                }
            }
        }
    }
    let _active = manifest_active_segment(manifest)?;
    validate_superseded_segment_ids(manifest)?;
    Ok(())
}

fn validate_superseded_segment_ids(manifest: &JournalManifest) -> Result<()> {
    let authoritative: std::collections::HashSet<_> =
        manifest.segments.iter().map(|s| s.segment_id).collect();
    let mut seen = std::collections::HashSet::new();
    for id in &manifest.superseded_segment_ids {
        if !seen.insert(*id) {
            return Err(Error::JournalManifestInconsistent(format!(
                "duplicate superseded segment_id {id}"
            )));
        }
        if authoritative.contains(id) {
            return Err(Error::JournalManifestInconsistent(format!(
                "superseded segment {id} is still authoritative"
            )));
        }
    }
    Ok(())
}

/// Build the next manifest generation for a compaction artifact publication.
pub fn build_compaction_manifest(
    current: &JournalManifest,
    artifact: &CompactionArtifact,
    refreshed: &[JournalSegmentInfo],
) -> Result<JournalManifest> {
    verify_compaction_publishable(current, artifact)?;

    let mut segments: Vec<SegmentManifestEntry> = current
        .segments
        .iter()
        .filter(|s| !artifact.source_segment_ids.contains(&s.segment_id))
        .map(|old| {
            refreshed
                .iter()
                .find(|i| i.id == old.segment_id)
                .map(|i| SegmentManifestEntry {
                    segment_id: i.id,
                    start_sequence: i.start_sequence,
                    end_sequence: i.end_sequence,
                    start_timestamp_unix_ms: i.first_timestamp_unix_ms.unwrap_or(0),
                    end_timestamp_unix_ms: i.last_timestamp_unix_ms.unwrap_or(0),
                    byte_size: i.byte_size,
                    state: i.state,
                })
                .unwrap_or_else(|| old.clone())
        })
        .collect();

    segments.push(SegmentManifestEntry {
        segment_id: artifact.segment_id,
        start_sequence: artifact.start_sequence,
        end_sequence: artifact.end_sequence,
        start_timestamp_unix_ms: 0,
        end_timestamp_unix_ms: 0,
        byte_size: artifact.byte_size,
        state: SegmentState::Sealed,
    });
    segments.sort_by_key(|s| s.start_sequence);

    let mut superseded = current.superseded_segment_ids.clone();
    for id in &artifact.source_segment_ids {
        if !superseded.contains(id) {
            superseded.push(*id);
        }
    }
    superseded.sort_unstable();

    Ok(JournalManifest {
        format_version: JOURNAL_MANIFEST_FORMAT_VERSION,
        generation: current.generation.saturating_add(1),
        segments,
        superseded_segment_ids: superseded,
    })
}

pub fn verify_compaction_publishable(
    current: &JournalManifest,
    artifact: &CompactionArtifact,
) -> Result<()> {
    if artifact.source_segment_ids.is_empty() {
        return Err(Error::format("compaction artifact has no sources"));
    }
    if current.contains_segment(artifact.segment_id) {
        return Err(Error::format("compaction artifact already published"));
    }
    for id in &artifact.source_segment_ids {
        if !current.contains_segment(*id) {
            return Err(Error::CompactionStaleCandidate);
        }
    }

    let mut sources: Vec<_> = current
        .segments
        .iter()
        .filter(|s| artifact.source_segment_ids.contains(&s.segment_id))
        .collect();
    sources.sort_by_key(|s| s.segment_id);

    if sources.len() != artifact.source_segment_ids.len() {
        return Err(Error::CompactionStaleCandidate);
    }
    for (idx, id) in artifact.source_segment_ids.iter().enumerate() {
        if sources[idx].segment_id != *id {
            return Err(Error::CompactionStaleCandidate);
        }
        if sources[idx].state != SegmentState::Sealed {
            return Err(Error::CompactionStaleCandidate);
        }
    }

    let first = sources.first().unwrap();
    let last = sources.last().unwrap();
    if first.start_sequence != artifact.start_sequence {
        return Err(Error::CompactionStaleCandidate);
    }
    if last.end_sequence != artifact.end_sequence {
        return Err(Error::CompactionStaleCandidate);
    }

    for pair in sources.windows(2) {
        if pair[1].start_sequence != pair[0].end_sequence.saturating_add(1) {
            return Err(Error::CompactionStaleCandidate);
        }
    }
    Ok(())
}

/// Atomic manifest publication: tmp → fsync → rename → fsync(dir).
pub fn publish_manifest(
    runtime_journal_dir: &Path,
    manifest: &JournalManifest,
) -> Result<()> {
    fs::create_dir_all(runtime_journal_dir).map_err(Error::io)?;
    let (manifest_path, tmp_path) = manifest_paths(runtime_journal_dir);
    let raw =
        serde_json::to_string_pretty(manifest).map_err(|e| Error::JournalManifestInconsistent(e.to_string()))?;
    write_sync_rename(&tmp_path, &manifest_path, raw.as_bytes())?;
    sync_dir(runtime_journal_dir)?;
    Ok(())
}

pub fn write_sync_rename(tmp: &Path, dest: &Path, bytes: &[u8]) -> Result<()> {
    maybe_crash(CrashPoint::BeforeManifestTmp)?;
    {
        let mut f = File::create(tmp).map_err(Error::io)?;
        f.write_all(bytes).map_err(Error::io)?;
        f.sync_all().map_err(Error::io)?;
    }
    maybe_crash(CrashPoint::AfterManifestTmpFsync)?;
    maybe_crash(CrashPoint::BeforeManifestRename)?;
    fs::rename(tmp, dest).map_err(Error::io)?;
    maybe_crash(CrashPoint::AfterManifestRename)?;
    Ok(())
}

fn sync_dir(dir: &Path) -> Result<()> {
    let f = File::open(dir).map_err(Error::io)?;
    f.sync_all().map_err(Error::io)?;
    Ok(())
}

#[cfg(test)]
mod unit {
    use super::*;
    use crate::partition::PartitionId;

    fn entry(id: u64, start: u64, end: u64) -> SegmentManifestEntry {
        SegmentManifestEntry {
            segment_id: id,
            start_sequence: start,
            end_sequence: end,
            start_timestamp_unix_ms: 0,
            end_timestamp_unix_ms: 0,
            byte_size: 100,
            state: SegmentState::Sealed,
        }
    }

    #[test]
    fn allows_empty_active_segment_bounds() {
        assert!(segment_sequence_bounds_valid(1, 0, SegmentState::Active));
        assert!(!segment_sequence_bounds_valid(2, 0, SegmentState::Active));
        assert!(!segment_sequence_bounds_valid(1, 0, SegmentState::Sealed));
    }

    #[test]
    fn rejects_overlapping_ranges() {
        let manifest = JournalManifest {
            format_version: JOURNAL_MANIFEST_FORMAT_VERSION,
            generation: 1,
            segments: vec![entry(1, 1, 300), entry(2, 250, 400)],
            superseded_segment_ids: Vec::new(),
        };
        let dir = tempfile::tempdir().unwrap();
        let err = validate_manifest(&manifest, dir.path()).unwrap_err();
        assert!(matches!(err, Error::JournalManifestInconsistent(_)));
    }

    #[test]
    fn generation_bump_on_build() {
        let current = JournalManifest {
            format_version: JOURNAL_MANIFEST_FORMAT_VERSION,
            generation: 10,
            segments: vec![
                entry(1, 1, 100),
                entry(2, 101, 200),
                entry(3, 201, 300),
                SegmentManifestEntry {
                    segment_id: 4,
                    start_sequence: 301,
                    end_sequence: 400,
                    start_timestamp_unix_ms: 0,
                    end_timestamp_unix_ms: 0,
                    byte_size: 100,
                    state: SegmentState::Active,
                },
            ],
            superseded_segment_ids: Vec::new(),
        };
        let artifact = CompactionArtifact {
            partition_id: PartitionId(0),
            segment_id: 5,
            source_segment_ids: vec![1, 2, 3],
            start_sequence: 1,
            end_sequence: 300,
            record_count: 300,
            byte_size: 500,
            path: PathBuf::from("seg-005.jnl"),
        };
        let refreshed = vec![
            JournalSegmentInfo {
                id: 4,
                start_sequence: 301,
                end_sequence: 400,
                state: SegmentState::Active,
                first_timestamp_unix_ms: None,
                last_timestamp_unix_ms: None,
                byte_size: 100,
            },
        ];
        let next = build_compaction_manifest(&current, &artifact, &refreshed).unwrap();
        assert_eq!(next.generation, 11);
        assert_eq!(next.segments.len(), 2);
        assert_eq!(next.segments[0].segment_id, 5);
        assert_eq!(next.segments[1].segment_id, 4);
        assert_eq!(next.superseded_segment_ids, vec![1, 2, 3]);
    }
}
