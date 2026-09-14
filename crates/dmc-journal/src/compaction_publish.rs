//! Crash-safe journal manifest publication for compaction (Phase 5.6.3 / 5.7.8).

use std::fs;
use std::path::Path;

use crate::compaction::CompactionArtifact;
use crate::error::{Error, Result};
use crate::journal_manifest::{
    build_compaction_manifest, manifest_from_segment_infos, publish_manifest, validate_manifest,
    JournalManifest,
};
use crate::journal_manifest_v2::{
    build_compaction_manifest_v2, read_stored_manifest, validate_manifest_v2,
    validate_stored_manifest, publish_stored_manifest, StoredJournalManifest, v2_to_stored,
};

pub fn publish_compaction_artifact(
    journal_dir: &Path,
    runtime_journal_dir: &Path,
    manifest_path: &Path,
    artifact: &CompactionArtifact,
    refreshed_segments: &[crate::segment::JournalSegmentInfo],
    partition_count: u32,
) -> Result<JournalManifest> {
    if !artifact.path.is_file() {
        return Err(Error::format(format!(
            "compaction artifact seg-{:012}.jnl missing",
            artifact.segment_id
        )));
    }

    let stored = match read_stored_manifest(manifest_path)? {
        Some(s) => {
            validate_stored_manifest(&s, journal_dir, partition_count)?;
            s
        }
        None => {
            if partition_count > 1 {
                return Err(Error::JournalManifestInconsistent(
                    "multi-partition compaction requires published manifest".into(),
                ));
            }
            v2_to_stored(crate::journal_manifest_v2::manifest_v2_from_segment_infos(
                0,
                1,
                &std::collections::HashMap::new(),
                refreshed_segments,
            ))
        }
    };

    let published = match &stored {
        StoredJournalManifest::V2(current) => {
            let new_v2 = build_compaction_manifest_v2(current, artifact, refreshed_segments)?;
            if new_v2.generation != current.generation.saturating_add(1) {
                return Err(Error::JournalManifestInconsistent(
                    "generation must increment by one".into(),
                ));
            }
            validate_manifest_v2(&new_v2, journal_dir, partition_count)?;
            fs::create_dir_all(runtime_journal_dir).map_err(Error::io)?;
            publish_stored_manifest(
                runtime_journal_dir,
                &StoredJournalManifest::V2(new_v2.clone()),
            )?;
            StoredJournalManifest::V2(new_v2).as_v1_flat()
        }
        StoredJournalManifest::V1(current) => {
            if partition_count > 1 {
                return Err(Error::JournalManifestInconsistent(
                    "v1 manifest incompatible with partition_count > 1".into(),
                ));
            }
            if artifact.partition_id.as_u32() != 0 {
                return Err(Error::CompactionStaleCandidate);
            }
            let current = if current.segments.is_empty() {
                manifest_from_segment_infos(0, refreshed_segments)
            } else {
                current.clone()
            };
            let new_manifest =
                build_compaction_manifest(&current, artifact, refreshed_segments)?;
            validate_manifest(&new_manifest, journal_dir)?;
            if new_manifest.generation != current.generation.saturating_add(1) {
                return Err(Error::JournalManifestInconsistent(
                    "generation must increment by one".into(),
                ));
            }
            fs::create_dir_all(runtime_journal_dir).map_err(Error::io)?;
            publish_manifest(runtime_journal_dir, &new_manifest)?;
            new_manifest
        }
    };

    Ok(published)
}
