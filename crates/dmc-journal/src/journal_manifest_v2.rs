//! Partition-aware journal manifest (Phase 5.7.4).
//!
//! V2 is the authoritative topology source when `format_version == 2`.
//! V1 manifests remain readable; bootstrap always writes V2.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::codec::{
    decode_segment_footer, decode_segment_header, scan_segment, validate_sealed_segment,
};
use crate::compaction::CompactionArtifact;
use crate::error::{Error, Result};
use crate::journal_manifest::{
    manifest_paths, publish_manifest, segment_sequence_bounds_valid, write_sync_rename,
    JournalManifest, SegmentManifestEntry, JOURNAL_MANIFEST_FORMAT_VERSION,
    JOURNAL_MANIFEST_FORMAT_VERSION_V2,
};
use crate::layout::{
    is_partitioned_layout, list_segment_ids, partition_data_dir, segment_path_for_partition,
};
use crate::partition::PartitionId;
use crate::segment::{JournalSegmentInfo, SegmentState};
use crate::types::SEGMENT_HEADER_LEN;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalManifestV2 {
    pub format_version: u32,
    pub generation: u64,
    pub partition_count: u32,
    pub partitions: Vec<PartitionManifest>,
    #[serde(default)]
    pub superseded_segment_ids: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionManifest {
    pub partition_id: u32,
    pub segments: Vec<SegmentManifestEntry>,
}

/// On-disk manifest (V1 legacy flat or V2 partitioned).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoredJournalManifest {
    V1(JournalManifest),
    V2(JournalManifestV2),
}

impl StoredJournalManifest {
    pub fn format_version(&self) -> u32 {
        match self {
            Self::V1(m) => m.format_version,
            Self::V2(m) => m.format_version,
        }
    }

    pub fn generation(&self) -> u64 {
        match self {
            Self::V1(m) => m.generation,
            Self::V2(m) => m.generation,
        }
    }

    pub fn partition_count(&self) -> u32 {
        match self {
            Self::V1(_) => 1,
            Self::V2(m) => m.partition_count,
        }
    }

    pub fn superseded_segment_ids(&self) -> &[u64] {
        match self {
            Self::V1(m) => &m.superseded_segment_ids,
            Self::V2(m) => &m.superseded_segment_ids,
        }
    }

    pub fn all_segments(&self) -> Vec<(PartitionId, &SegmentManifestEntry)> {
        match self {
            Self::V1(m) => m
                .segments
                .iter()
                .map(|s| (PartitionId(0), s))
                .collect(),
            Self::V2(m) => m
                .partitions
                .iter()
                .flat_map(|p| {
                    p.segments
                        .iter()
                        .map(move |s| (PartitionId(p.partition_id), s))
                })
                .collect(),
        }
    }

    pub fn authoritative_segment_ids(&self) -> Vec<u64> {
        let mut ids: Vec<_> = self.all_segments().into_iter().map(|(_, s)| s.segment_id).collect();
        ids.sort_unstable();
        ids
    }

    pub fn segment_partition(&self, segment_id: u64) -> Option<PartitionId> {
        match self {
            Self::V1(m) => {
                if m.segments.iter().any(|s| s.segment_id == segment_id) {
                    Some(PartitionId(0))
                } else {
                    None
                }
            }
            Self::V2(m) => m.segment_partition(segment_id),
        }
    }

    pub fn as_v1_flat(&self) -> JournalManifest {
        match self {
            Self::V1(m) => m.clone(),
            Self::V2(m) => {
                let mut segments: Vec<_> = m
                    .partitions
                    .iter()
                    .flat_map(|p| p.segments.clone())
                    .collect();
                segments.sort_by_key(|s| s.start_sequence);
                JournalManifest {
                    format_version: JOURNAL_MANIFEST_FORMAT_VERSION,
                    generation: m.generation,
                    segments,
                    superseded_segment_ids: m.superseded_segment_ids.clone(),
                }
            }
        }
    }
}

impl JournalManifestV2 {
    pub fn contains_segment(&self, id: u64) -> bool {
        self.partitions
            .iter()
            .any(|p| p.segments.iter().any(|s| s.segment_id == id))
    }

    pub fn segment_partition(&self, segment_id: u64) -> Option<PartitionId> {
        for p in &self.partitions {
            if p.segments.iter().any(|s| s.segment_id == segment_id) {
                return Some(PartitionId(p.partition_id));
            }
        }
        None
    }
}

/// Read published manifest (V1 or V2). `manifest.tmp` is never authoritative.
pub fn read_stored_manifest(manifest_path: &Path) -> Result<Option<StoredJournalManifest>> {
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
    match version {
        JOURNAL_MANIFEST_FORMAT_VERSION => {
            let m: JournalManifest = serde_json::from_value(value)
                .map_err(|e| Error::JournalManifestInconsistent(e.to_string()))?;
            Ok(Some(StoredJournalManifest::V1(m)))
        }
        JOURNAL_MANIFEST_FORMAT_VERSION_V2 => {
            let m: JournalManifestV2 = serde_json::from_value(value)
                .map_err(|e| Error::JournalManifestInconsistent(e.to_string()))?;
            Ok(Some(StoredJournalManifest::V2(m)))
        }
        other => Err(Error::JournalManifestInconsistent(format!(
            "unsupported format version {other}"
        ))),
    }
}

pub fn segment_manifest_path(
    journal_dir: &Path,
    partition_count: u32,
    partition_id: PartitionId,
    segment_id: u64,
) -> std::path::PathBuf {
    segment_path_for_partition(journal_dir, partition_id, segment_id, partition_count)
}

fn validate_superseded(manifest: &StoredJournalManifest) -> Result<()> {
    let authoritative: HashSet<_> = manifest.authoritative_segment_ids().into_iter().collect();
    let mut seen = HashSet::new();
    for id in manifest.superseded_segment_ids() {
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

fn validate_partition_segments(segments: &[SegmentManifestEntry]) -> Result<()> {
    if segments.is_empty() {
        return Ok(());
    }
    let mut prev_end: Option<u64> = None;
    for (idx, entry) in segments.iter().enumerate() {
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
        if idx > 0 && entry.start_sequence <= segments[idx - 1].start_sequence {
            return Err(Error::JournalManifestInconsistent(
                "partition segments must be ordered by start_sequence".into(),
            ));
        }
        if let Some(prev) = prev_end {
            if entry.start_sequence <= prev {
                return Err(Error::JournalManifestInconsistent(format!(
                    "overlapping ranges in partition at segment {}",
                    entry.segment_id
                )));
            }
        }
        prev_end = Some(entry.end_sequence);
    }
    Ok(())
}

fn validate_segment_on_disk(
    journal_dir: &Path,
    partition_count: u32,
    partition_id: PartitionId,
    entry: &SegmentManifestEntry,
) -> Result<()> {
    let path = segment_manifest_path(journal_dir, partition_count, partition_id, entry.segment_id);
    if !path.is_file() {
        return Err(Error::JournalManifestInconsistent(format!(
            "segment file seg-{:012}.jnl missing for partition {}",
            entry.segment_id,
            partition_id.as_u32()
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
            let (start, end, _, _) =
                validate_sealed_segment(&bytes, entry.segment_id).map_err(|e| {
                    Error::JournalSegmentCorrupt(format!("segment {}: {e}", entry.segment_id))
                })?;
            if start != entry.start_sequence {
                return Err(Error::JournalManifestInconsistent(format!(
                    "segment {} header start_sequence mismatch",
                    entry.segment_id
                )));
            }
            if end != entry.end_sequence {
                return Err(Error::JournalManifestInconsistent(format!(
                    "segment {} footer end_sequence mismatch",
                    entry.segment_id
                )));
            }
        }
    }
    Ok(())
}

pub fn validate_stored_manifest(
    manifest: &StoredJournalManifest,
    journal_dir: &Path,
    expected_partition_count: u32,
) -> Result<()> {
    match manifest {
        StoredJournalManifest::V1(m) => {
            crate::journal_manifest::validate_manifest(m, journal_dir)?;
            if expected_partition_count != 1 {
                return Err(Error::JournalManifestInconsistent(
                    "v1 manifest requires partition_count=1".into(),
                ));
            }
            Ok(())
        }
        StoredJournalManifest::V2(m) => validate_manifest_v2(m, journal_dir, expected_partition_count),
    }
}

pub fn validate_manifest_v2(
    manifest: &JournalManifestV2,
    journal_dir: &Path,
    expected_partition_count: u32,
) -> Result<()> {
    if manifest.format_version != JOURNAL_MANIFEST_FORMAT_VERSION_V2 {
        return Err(Error::JournalManifestInconsistent(format!(
            "unsupported format version {}",
            manifest.format_version
        )));
    }
    if manifest.partition_count == 0 {
        return Err(Error::JournalManifestInconsistent(
            "partition_count must be > 0".into(),
        ));
    }
    if manifest.partition_count != expected_partition_count {
        return Err(Error::JournalManifestInconsistent(format!(
            "manifest partition_count {} != journal config {}",
            manifest.partition_count, expected_partition_count
        )));
    }
    if manifest.partitions.is_empty() {
        return Err(Error::JournalManifestInconsistent(
            "manifest has no partitions".into(),
        ));
    }

    let mut seen_partitions = HashSet::new();
    let mut seen_segments = HashSet::new();
    let mut active_per_partition: HashMap<u32, u64> = HashMap::new();

    for part in &manifest.partitions {
        if part.partition_id >= manifest.partition_count {
            return Err(Error::JournalManifestInconsistent(format!(
                "partition_id {} >= partition_count {}",
                part.partition_id, manifest.partition_count
            )));
        }
        if !seen_partitions.insert(part.partition_id) {
            return Err(Error::JournalManifestInconsistent(format!(
                "duplicate partition_id {}",
                part.partition_id
            )));
        }
        validate_partition_segments(&part.segments)?;
        for entry in &part.segments {
            if !seen_segments.insert(entry.segment_id) {
                return Err(Error::JournalManifestInconsistent(format!(
                    "duplicate segment_id {}",
                    entry.segment_id
                )));
            }
            if entry.state == SegmentState::Active {
                if active_per_partition.insert(part.partition_id, entry.segment_id) != None {
                    return Err(Error::JournalManifestInconsistent(format!(
                        "partition {} has multiple active segments",
                        part.partition_id
                    )));
                }
            }
            validate_segment_on_disk(
                journal_dir,
                manifest.partition_count,
                PartitionId(part.partition_id),
                entry,
            )?;
        }
    }

    validate_superseded(&StoredJournalManifest::V2(manifest.clone()))?;

    let has_any_segment = manifest.partitions.iter().any(|p| !p.segments.is_empty());
    if has_any_segment && active_per_partition.is_empty() {
        return Err(Error::JournalManifestInconsistent(
            "manifest has no active segment".into(),
        ));
    }
    Ok(())
}

/// Active segment id per partition from manifest (only declared Active entries).
pub fn manifest_active_segments(manifest: &StoredJournalManifest) -> Result<Vec<(PartitionId, u64)>> {
    let mut out = Vec::new();
    for (pid, entry) in manifest.all_segments() {
        if entry.state == SegmentState::Active {
            out.push((pid, entry.segment_id));
        }
    }
    if out.is_empty() && !manifest.authoritative_segment_ids().is_empty() {
        return Err(Error::JournalManifestInconsistent(
            "manifest has no active segment".into(),
        ));
    }
    Ok(out)
}

pub fn manifest_active_segment_legacy(manifest: &StoredJournalManifest) -> Result<u64> {
    let actives = manifest_active_segments(manifest)?;
    match actives.len() {
        0 => Err(Error::JournalManifestInconsistent(
            "manifest has no active segment".into(),
        )),
        1 => Ok(actives[0].1),
        _ if manifest.partition_count() == 1 => {
            Err(Error::JournalManifestInconsistent(
                "manifest has multiple active segments".into(),
            ))
        }
        _ => Ok(actives[0].1),
    }
}

pub fn authoritative_journal_head_from_manifest(
    manifest: &StoredJournalManifest,
    journal_dir: &Path,
) -> Result<u64> {
    let mut max_seq = 0u64;
    for (pid, entry) in manifest.all_segments() {
        if entry.state == SegmentState::Sealed {
            max_seq = max_seq.max(entry.end_sequence);
        } else {
            let path = segment_manifest_path(
                journal_dir,
                manifest.partition_count(),
                pid,
                entry.segment_id,
            );
            let bytes = fs::read(&path).map_err(Error::io)?;
            let (_good, _entries, last) = scan_segment(&bytes)?;
            max_seq = max_seq.max(last);
        }
    }
    Ok(max_seq)
}

pub fn discover_segment_partitions(
    journal_dir: &Path,
    partition_count: u32,
) -> Result<HashMap<u64, PartitionId>> {
    let mut map = HashMap::new();
    if !is_partitioned_layout(partition_count) {
        for id in list_segment_ids(journal_dir)? {
            map.insert(id, PartitionId(0));
        }
        return Ok(map);
    }
    for pid in 0..partition_count {
        let dir = partition_data_dir(journal_dir, PartitionId(pid), partition_count);
        if !dir.is_dir() {
            continue;
        }
        let mut ids = HashSet::new();
        crate::layout::collect_segment_ids_in_dir(&dir, &mut ids)?;
        for id in ids {
            map.insert(id, PartitionId(pid));
        }
    }
    Ok(map)
}

pub fn manifest_v2_from_segment_infos(
    generation: u64,
    partition_count: u32,
    segment_partitions: &HashMap<u64, PartitionId>,
    infos: &[JournalSegmentInfo],
) -> JournalManifestV2 {
    let mut by_partition: HashMap<u32, Vec<SegmentManifestEntry>> = HashMap::new();
    for info in infos {
        let pid = segment_partitions
            .get(&info.id)
            .copied()
            .unwrap_or(PartitionId(0))
            .as_u32();
        by_partition
            .entry(pid)
            .or_default()
            .push(segment_manifest_entry(info));
    }
    let mut partitions = Vec::new();
    for pid in 0..partition_count.max(1) {
        let mut segments = by_partition.remove(&pid).unwrap_or_default();
        segments.sort_by_key(|s| s.start_sequence);
        partitions.push(PartitionManifest {
            partition_id: pid,
            segments,
        });
    }
    JournalManifestV2 {
        format_version: JOURNAL_MANIFEST_FORMAT_VERSION_V2,
        generation,
        partition_count: partition_count.max(1),
        partitions,
        superseded_segment_ids: Vec::new(),
    }
}

/// Manifest entry for a segment as observed on disk.
///
/// An active segment without entries yet is recorded with `end_sequence = start_sequence - 1`
/// (the empty-active convention accepted by `segment_sequence_bounds_valid`).
pub fn segment_manifest_entry(info: &JournalSegmentInfo) -> SegmentManifestEntry {
    let end_sequence =
        if info.state == SegmentState::Active && info.end_sequence < info.start_sequence {
            info.start_sequence.saturating_sub(1)
        } else {
            info.end_sequence
        };
    SegmentManifestEntry {
        segment_id: info.id,
        start_sequence: info.start_sequence,
        end_sequence,
        start_timestamp_unix_ms: info.first_timestamp_unix_ms.unwrap_or(0),
        end_timestamp_unix_ms: info.last_timestamp_unix_ms.unwrap_or(0),
        byte_size: info.byte_size,
        state: info.state,
    }
}

/// Next manifest generation after rotating `partition_id`: the manifest's active segment
/// becomes `sealed` and `active` is appended as the partition's new active segment.
///
/// Fails closed unless `current` lists `sealed.segment_id` as the partition's active segment
/// and does not already know `active.segment_id`.
pub fn build_rotation_manifest(
    current: &StoredJournalManifest,
    partition_id: PartitionId,
    sealed: SegmentManifestEntry,
    active: SegmentManifestEntry,
) -> Result<StoredJournalManifest> {
    if sealed.state != SegmentState::Sealed || active.state != SegmentState::Active {
        return Err(Error::JournalManifestInconsistent(
            "rotation requires sealed + active segment entries".into(),
        ));
    }
    let rotate = |segments: &mut Vec<SegmentManifestEntry>| -> Result<()> {
        let idx = segments
            .iter()
            .position(|e| e.segment_id == sealed.segment_id && e.state == SegmentState::Active)
            .ok_or_else(|| {
                Error::JournalManifestInconsistent(format!(
                    "rotation: segment {} is not the manifest active segment",
                    sealed.segment_id
                ))
            })?;
        if segments.iter().any(|e| e.segment_id == active.segment_id) {
            return Err(Error::JournalManifestInconsistent(format!(
                "rotation: segment {} already in manifest",
                active.segment_id
            )));
        }
        segments[idx] = sealed.clone();
        segments.push(active.clone());
        segments.sort_by_key(|e| e.start_sequence);
        Ok(())
    };
    match current {
        StoredJournalManifest::V1(m) => {
            if partition_id.as_u32() != 0 {
                return Err(Error::JournalManifestInconsistent(
                    "v1 manifest has only partition 0".into(),
                ));
            }
            let mut next = m.clone();
            rotate(&mut next.segments)?;
            next.generation = m.generation.saturating_add(1);
            Ok(StoredJournalManifest::V1(next))
        }
        StoredJournalManifest::V2(m) => {
            let mut next = m.clone();
            let part = next
                .partitions
                .iter_mut()
                .find(|p| p.partition_id == partition_id.as_u32())
                .ok_or_else(|| {
                    Error::JournalManifestInconsistent(format!(
                        "rotation: partition {} missing from manifest",
                        partition_id.as_u32()
                    ))
                })?;
            rotate(&mut part.segments)?;
            next.generation = m.generation.saturating_add(1);
            Ok(StoredJournalManifest::V2(next))
        }
    }
}

/// Next manifest generation after creating the first segment of `partition_id`: `active` is
/// added as that partition's active segment.
///
/// Fails closed unless the manifest is V2, the partition exists and has no active segment,
/// and `active.segment_id` is not yet known.
pub fn build_partition_segment_manifest(
    current: &StoredJournalManifest,
    partition_id: PartitionId,
    active: SegmentManifestEntry,
) -> Result<StoredJournalManifest> {
    if active.state != SegmentState::Active {
        return Err(Error::JournalManifestInconsistent(
            "new partition segment must be active".into(),
        ));
    }
    let StoredJournalManifest::V2(m) = current else {
        return Err(Error::JournalManifestInconsistent(
            "partition segment publication requires a v2 manifest".into(),
        ));
    };
    if m.contains_segment(active.segment_id) {
        return Err(Error::JournalManifestInconsistent(format!(
            "segment {} already in manifest",
            active.segment_id
        )));
    }
    let mut next = m.clone();
    let part = next
        .partitions
        .iter_mut()
        .find(|p| p.partition_id == partition_id.as_u32())
        .ok_or_else(|| {
            Error::JournalManifestInconsistent(format!(
                "partition {} missing from manifest",
                partition_id.as_u32()
            ))
        })?;
    if part
        .segments
        .iter()
        .any(|e| e.state == SegmentState::Active)
    {
        return Err(Error::JournalManifestInconsistent(format!(
            "partition {} already has an active segment",
            partition_id.as_u32()
        )));
    }
    part.segments.push(active);
    part.segments.sort_by_key(|e| e.start_sequence);
    next.generation = m.generation.saturating_add(1);
    Ok(StoredJournalManifest::V2(next))
}

/// Next manifest generation for retention GC: `trimmed` sealed segments leave the
/// authoritative topology and are recorded in `superseded_segment_ids`, so a crash before their
/// files are deleted leaves them as obsolete (later GC removes them) instead of authoritative
/// entries pointing at missing files. Superseded ids whose files no longer exist are dropped
/// (`file_exists`), keeping the list bounded.
///
/// Fails closed unless every trimmed id is a sealed segment of `current`.
pub fn build_trim_manifest(
    current: &StoredJournalManifest,
    trimmed: &[u64],
    file_exists: impl Fn(u64) -> bool,
) -> Result<StoredJournalManifest> {
    let trimmed: HashSet<u64> = trimmed.iter().copied().collect();
    for id in &trimmed {
        let sealed = current
            .all_segments()
            .iter()
            .any(|(_, e)| e.segment_id == *id && e.state == SegmentState::Sealed);
        if !sealed {
            return Err(Error::JournalManifestInconsistent(format!(
                "trim: segment {id} is not a sealed manifest segment"
            )));
        }
    }
    let superseded = |old: &[u64]| -> Vec<u64> {
        let mut ids: Vec<u64> = old
            .iter()
            .copied()
            .filter(|id| !trimmed.contains(id) && file_exists(*id))
            .collect();
        ids.extend(trimmed.iter().copied());
        ids.sort_unstable();
        ids.dedup();
        ids
    };
    match current {
        StoredJournalManifest::V1(m) => {
            let mut next = m.clone();
            next.segments.retain(|e| !trimmed.contains(&e.segment_id));
            next.superseded_segment_ids = superseded(&m.superseded_segment_ids);
            next.generation = m.generation.saturating_add(1);
            Ok(StoredJournalManifest::V1(next))
        }
        StoredJournalManifest::V2(m) => {
            let mut next = m.clone();
            for part in &mut next.partitions {
                part.segments.retain(|e| !trimmed.contains(&e.segment_id));
            }
            next.superseded_segment_ids = superseded(&m.superseded_segment_ids);
            next.generation = m.generation.saturating_add(1);
            Ok(StoredJournalManifest::V2(next))
        }
    }
}

/// Verify a compaction artifact can be published into a V2 manifest (5.7.8).
pub fn verify_compaction_publishable_v2(
    current: &JournalManifestV2,
    artifact: &CompactionArtifact,
) -> Result<()> {
    if artifact.source_segment_ids.is_empty() {
        return Err(Error::format("compaction artifact has no sources"));
    }
    if current.contains_segment(artifact.segment_id) {
        return Err(Error::format("compaction artifact already published"));
    }
    let pid = artifact.partition_id.as_u32();
    let partition = current
        .partitions
        .iter()
        .find(|p| p.partition_id == pid)
        .ok_or_else(|| {
            Error::JournalManifestInconsistent(format!("partition {pid} missing from manifest"))
        })?;

    for id in &artifact.source_segment_ids {
        if !current.contains_segment(*id) {
            return Err(Error::CompactionStaleCandidate);
        }
        if current.segment_partition(*id) != Some(artifact.partition_id) {
            return Err(Error::CompactionStaleCandidate);
        }
    }

    let mut sources: Vec<_> = partition
        .segments
        .iter()
        .filter(|s| artifact.source_segment_ids.contains(&s.segment_id))
        .collect();
    sources.sort_by_key(|s| s.start_sequence);

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
    Ok(())
}

/// Build the next V2 manifest generation for partition-local compaction publication.
pub fn build_compaction_manifest_v2(
    current: &JournalManifestV2,
    artifact: &CompactionArtifact,
    refreshed: &[JournalSegmentInfo],
) -> Result<JournalManifestV2> {
    verify_compaction_publishable_v2(current, artifact)?;

    let pid = artifact.partition_id.as_u32();
    let mut partitions = current.partitions.clone();
    let part = partitions
        .iter_mut()
        .find(|p| p.partition_id == pid)
        .ok_or_else(|| {
            Error::JournalManifestInconsistent(format!("partition {pid} missing from manifest"))
        })?;

    part.segments = part
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

    part.segments.push(SegmentManifestEntry {
        segment_id: artifact.segment_id,
        start_sequence: artifact.start_sequence,
        end_sequence: artifact.end_sequence,
        start_timestamp_unix_ms: 0,
        end_timestamp_unix_ms: 0,
        byte_size: artifact.byte_size,
        state: SegmentState::Sealed,
    });
    part.segments.sort_by_key(|s| s.start_sequence);

    let mut superseded = current.superseded_segment_ids.clone();
    for id in &artifact.source_segment_ids {
        if !superseded.contains(id) {
            superseded.push(*id);
        }
    }
    superseded.sort_unstable();

    Ok(JournalManifestV2 {
        format_version: JOURNAL_MANIFEST_FORMAT_VERSION_V2,
        generation: current.generation.saturating_add(1),
        partition_count: current.partition_count,
        partitions,
        superseded_segment_ids: superseded,
    })
}

pub fn publish_stored_manifest(
    runtime_journal_dir: &Path,
    manifest: &StoredJournalManifest,
) -> Result<()> {
    match manifest {
        StoredJournalManifest::V1(m) => publish_manifest(runtime_journal_dir, m),
        StoredJournalManifest::V2(m) => publish_manifest_v2(runtime_journal_dir, m),
    }
}

pub fn publish_manifest_v2(
    runtime_journal_dir: &Path,
    manifest: &JournalManifestV2,
) -> Result<()> {
    fs::create_dir_all(runtime_journal_dir).map_err(Error::io)?;
    let (manifest_path, tmp_path) = manifest_paths(runtime_journal_dir);
    let raw = serde_json::to_string_pretty(manifest)
        .map_err(|e| Error::JournalManifestInconsistent(e.to_string()))?;
    write_sync_rename(&tmp_path, &manifest_path, raw.as_bytes())?;
    sync_dir(runtime_journal_dir)?;
    Ok(())
}

fn sync_dir(dir: &Path) -> Result<()> {
    let f = std::fs::File::open(dir).map_err(Error::io)?;
    f.sync_all().map_err(Error::io)?;
    Ok(())
}

pub fn v1_to_stored(m: JournalManifest) -> StoredJournalManifest {
    StoredJournalManifest::V1(m)
}

pub fn v2_to_stored(m: JournalManifestV2) -> StoredJournalManifest {
    StoredJournalManifest::V2(m)
}
