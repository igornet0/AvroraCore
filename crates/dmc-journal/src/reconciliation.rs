//! Manifest-driven recovery and filesystem reconciliation (Phase 5.6.4–5.6.5, 5.7.4).

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::authoritative::legacy_authoritative_segment_ids;
use crate::error::{Error, Result};
use crate::journal_manifest::{JournalManifest, JOURNAL_MANIFEST_FORMAT_VERSION, MANIFEST_TMP};
use crate::journal_manifest_v2::{read_stored_manifest, validate_stored_manifest};
use crate::layout::list_segment_ids;
use crate::lifecycle::{
    classify_segment_disposition, lifecycle_from_disk, lifecycle_from_manifest_entry,
    JournalSegmentLifecycle, SegmentDisposition,
};

/// Physical journal layout inspection after restart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalReconciliation {
    pub authoritative: Vec<u64>,
    /// Was authoritative, removed by compaction publication, still on disk.
    pub obsolete: Vec<u64>,
    /// On disk but never published in any manifest generation.
    pub orphan: Vec<u64>,
    /// Temporary files that are never authoritative (`*.tmp`).
    pub temporary: Vec<PathBuf>,
    pub lifecycles: Vec<JournalSegmentLifecycle>,
}

/// Result of a safe reconciliation pass (no segment deletion).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalReconciliationResult {
    pub inspection: JournalReconciliation,
    pub temporary_removed: Vec<PathBuf>,
}

/// Classify on-disk journal files against the authoritative manifest.
pub fn inspect_reconciliation(
    journal_dir: &Path,
    manifest_path: &Path,
    runtime_journal_dir: &Path,
    active_segments: &[u64],
    partition_count: u32,
) -> Result<JournalReconciliation> {
    let temporary = list_temporary_files(journal_dir, runtime_journal_dir)?;
    let all_on_disk = list_segment_ids(journal_dir)?;

    let stored = if manifest_path.is_file() {
        read_stored_manifest(manifest_path)?
            .ok_or_else(|| Error::JournalManifestInconsistent("empty manifest path".into()))?
    } else {
        crate::journal_manifest_v2::v1_to_stored(JournalManifest {
            format_version: JOURNAL_MANIFEST_FORMAT_VERSION,
            generation: 0,
            segments: Vec::new(),
            superseded_segment_ids: Vec::new(),
        })
    };

    let authoritative = if manifest_path.is_file() {
        validate_stored_manifest(&stored, journal_dir, partition_count)?;
        stored.authoritative_segment_ids()
    } else {
        legacy_authoritative_segment_ids(journal_dir, active_segments)?
    };

    let auth_set: HashSet<_> = authoritative.iter().copied().collect();
    let superseded_set: HashSet<_> = if manifest_path.is_file() {
        stored.superseded_segment_ids().iter().copied().collect()
    } else {
        HashSet::new()
    };

    let mut obsolete = Vec::new();
    let mut orphan = Vec::new();
    let mut lifecycles = Vec::new();

    for (_pid, entry) in stored.all_segments() {
        if all_on_disk.contains(&entry.segment_id) {
            lifecycles.push(lifecycle_from_manifest_entry(entry));
        }
    }

    for id in all_on_disk {
        if auth_set.contains(&id) {
            continue;
        }
        let disposition = classify_segment_disposition(id, &auth_set, &superseded_set);
        match disposition {
            SegmentDisposition::Obsolete => obsolete.push(id),
            SegmentDisposition::Orphan => orphan.push(id),
            SegmentDisposition::Authoritative | SegmentDisposition::Temporary => {}
        }
        lifecycles.push(lifecycle_from_disk(journal_dir, id, disposition)?);
    }

    for id in &authoritative {
        if lifecycles.iter().any(|l| l.segment_id == *id) {
            continue;
        }
        lifecycles.push(lifecycle_from_disk(
            journal_dir,
            *id,
            SegmentDisposition::Authoritative,
        )?);
    }

    obsolete.sort_unstable();
    orphan.sort_unstable();
    lifecycles.sort_by_key(|l| l.segment_id);

    Ok(JournalReconciliation {
        authoritative,
        obsolete,
        orphan,
        temporary,
        lifecycles,
    })
}

/// Remove temporary files only. Does not delete segment files.
pub fn reconcile_temporary_files(
    journal_dir: &Path,
    runtime_journal_dir: &Path,
) -> Result<Vec<PathBuf>> {
    let temps = list_temporary_files(journal_dir, runtime_journal_dir)?;
    for path in &temps {
        let _ = fs::remove_file(path);
    }
    Ok(temps)
}

pub fn reconcile(
    journal_dir: &Path,
    manifest_path: &Path,
    runtime_journal_dir: &Path,
    active_segments: &[u64],
    partition_count: u32,
) -> Result<JournalReconciliationResult> {
    let inspection = inspect_reconciliation(
        journal_dir,
        manifest_path,
        runtime_journal_dir,
        active_segments,
        partition_count,
    )?;
    let temporary_removed = reconcile_temporary_files(journal_dir, runtime_journal_dir)?;
    Ok(JournalReconciliationResult {
        inspection,
        temporary_removed,
    })
}

/// List non-authoritative temporary artifacts (`manifest.tmp`, `compacted-*.tmp`).
pub fn list_temporary_files(
    journal_dir: &Path,
    runtime_journal_dir: &Path,
) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let manifest_tmp = runtime_journal_dir.join(MANIFEST_TMP);
    if manifest_tmp.is_file() {
        out.push(manifest_tmp);
    }
    if journal_dir.is_dir() {
        for ent in fs::read_dir(journal_dir).map_err(Error::io)? {
            let ent = ent.map_err(Error::io)?;
            let name = ent.file_name().to_string_lossy().into_owned();
            if name.ends_with(".tmp") {
                out.push(ent.path());
            }
        }
        for ent in fs::read_dir(journal_dir).map_err(Error::io)? {
            let ent = ent.map_err(Error::io)?;
            let name = ent.file_name().to_string_lossy().to_string();
            if name.starts_with("p-") && ent.path().is_dir() {
                for sub in fs::read_dir(ent.path()).map_err(Error::io)? {
                    let sub = sub.map_err(Error::io)?;
                    let sub_name = sub.file_name().to_string_lossy().into_owned();
                    if sub_name.ends_with(".tmp") {
                        out.push(sub.path());
                    }
                }
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Journal head from authoritative segments only (ignores orphans and obsolete on disk).
pub fn authoritative_journal_head(
    journal_dir: &Path,
    manifest_path: &Path,
    active_segments: &[u64],
    partition_count: u32,
) -> Result<u64> {
    if let Some(manifest) = read_stored_manifest(manifest_path)? {
        validate_stored_manifest(&manifest, journal_dir, partition_count)?;
        return crate::journal_manifest_v2::authoritative_journal_head_from_manifest(
            &manifest,
            journal_dir,
        );
    }

    let ids = legacy_authoritative_segment_ids(journal_dir, active_segments)?;
    let mut max_seq = 0u64;
    for id in ids {
        let path = crate::layout::resolve_segment_path(journal_dir, id);
        let bytes = fs::read(&path).map_err(Error::io)?;
        if bytes.len() < crate::types::SEGMENT_HEADER_LEN {
            continue;
        }
        let (_last_good, _entries, last) = crate::codec::scan_segment(&bytes)?;
        max_seq = max_seq.max(last);
    }
    Ok(max_seq)
}
