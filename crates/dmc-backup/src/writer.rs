use std::fs;
use std::path::{Path, PathBuf};

use dmc_materialized::{StateEventRecord, StateMaterializer};
use dmc_model::{ApplyMode, Catalog, CatalogApplier, StateEvent};
use dmc_storage::{read_manifest, table_dir};

use crate::artifact::{
    CatalogArtifact, JournalArtifact, JournalSegmentFile, JournalSegmentRef, RecoveryArtifact,
    StorageArtifact, StorageSegmentRef, CATALOG_ARTIFACT_FORMAT_VERSION,
    JOURNAL_ARTIFACT_FORMAT_VERSION, STORAGE_ARTIFACT_FORMAT_VERSION,
};
use crate::coordinator::validate_manifest_invariants;
use crate::digest::{copy_dir_all, file_entry, sha256_file, write_json_atomic};
use crate::error::{BackupError, Result};
use crate::manifest::{
    BackupFileRole, BackupManifest, BackupStorageTableEntry, MANIFEST_FILE,
};
use crate::source::BackupSource;
use crate::verify::verify_written_artifact;

/// Result of materializing a frozen [`BackupManifest`] into a staging tree.
#[derive(Clone, Debug)]
pub struct BackupArtifact {
    pub backup_id: String,
    pub checkpoint_sequence: u64,
    pub root: PathBuf,
    pub manifest: BackupManifest,
    pub manifest_digest: String,
}

/// Writes artifact bytes for an already-fixed snapshot contract.
///
/// **Must not** call journal tip / materializer tip / barrier / collect.
pub trait BackupWriter {
    fn write(
        &self,
        manifest: &BackupManifest,
        source: &BackupSource,
        staging: &Path,
    ) -> Result<BackupArtifact>;
}

#[derive(Clone, Debug, Default)]
pub struct DefaultBackupWriter;

impl BackupWriter for DefaultBackupWriter {
    fn write(
        &self,
        manifest: &BackupManifest,
        source: &BackupSource,
        staging: &Path,
    ) -> Result<BackupArtifact> {
        validate_manifest_invariants(manifest)?;
        let n = manifest.checkpoint_sequence;
        let events = source.events_through(n)?;
        if events.iter().any(|e| e.sequence > n) {
            return Err(BackupError::Validation(
                "journal artifact would include sequence > N".into(),
            ));
        }
        if staging.exists() {
            return Err(BackupError::AlreadyExists);
        }

        let backup_id = staging
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.trim_start_matches("backup-").to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unnamed".into());

        fs::create_dir_all(staging).map_err(|e| BackupError::Io(e.to_string()))?;
        for sub in ["journal/segments", "catalog", "storage/tables", "recovery"] {
            fs::create_dir_all(staging.join(sub)).map_err(|e| BackupError::Io(e.to_string()))?;
        }

        let journal_files = write_journal(staging, n, &events)?;
        let catalog = catalog_at(&events, n)?;
        let catalog_files = write_catalog(staging, n, &catalog)?;
        let (storage_files, storage_art) =
            write_storage(staging, n, &catalog, &events, manifest.options.include_rowstore)?;
        let recovery_files = write_recovery(staging, manifest)?;

        let mut out_manifest = manifest.clone();
        out_manifest.files = Vec::new();
        out_manifest.files.extend(journal_files);
        out_manifest.files.extend(catalog_files);
        out_manifest.files.extend(storage_files);
        out_manifest.files.extend(recovery_files);

        // Align catalog/storage counts with rebuilt snapshot @ N (DDL-correct).
        out_manifest.catalog.table_count = catalog.tables().count() as u64;
        out_manifest.catalog.index_count = catalog
            .tables()
            .map(|t| t.indexes.len() as u64)
            .sum();
        out_manifest.catalog.checkpoint_sequence = n;
        out_manifest.journal.tip_sequence = n;
        out_manifest.journal.event_count = events.len() as u64;
        // Index definitions from catalog @ N (CREATE INDEX before N / DROP after N).
        let mut index_definitions = Vec::new();
        for table in catalog.tables() {
            for index in &table.indexes {
                index_definitions.push(crate::manifest::IndexDefinitionRef {
                    index_id: index.id.raw(),
                    table_id: index.table_id.raw(),
                    name: index.name.clone(),
                    unique: index.unique,
                    column_ids: index.columns.iter().map(|c| c.raw()).collect(),
                });
            }
        }
        index_definitions.sort_by_key(|i| i.index_id);
        out_manifest.index_definitions = index_definitions;
        if manifest.options.include_rowstore {
            out_manifest.storage.tables = storage_art.tables.clone();
        }

        let manifest_path = staging.join(MANIFEST_FILE);
        write_json_atomic(&manifest_path, &out_manifest)?;
        let (manifest_size, manifest_digest) = sha256_file(&manifest_path)?;
        out_manifest.files.push(crate::manifest::BackupFileEntry {
            relative_path: MANIFEST_FILE.to_string(),
            role: BackupFileRole::Manifest,
            size: manifest_size,
            checksum_sha256: manifest_digest.clone(),
        });
        // Rewrite with self-entry included (digest of previous write is recorded;
        // final on-disk bytes exclude recursive self-digest churn — keep digest of
        // logical payload without the Manifest self-entry for stability).
        let mut publish_manifest = out_manifest.clone();
        publish_manifest
            .files
            .retain(|f| f.role != BackupFileRole::Manifest);
        write_json_atomic(&manifest_path, &publish_manifest)?;
        let (_, manifest_digest) = sha256_file(&manifest_path)?;

        verify_written_artifact(staging, &publish_manifest)?;

        Ok(BackupArtifact {
            backup_id,
            checkpoint_sequence: n,
            root: staging.to_path_buf(),
            manifest: publish_manifest,
            manifest_digest,
        })
    }
}

fn write_journal(
    staging: &Path,
    n: u64,
    events: &[StateEventRecord],
) -> Result<Vec<crate::manifest::BackupFileEntry>> {
    let segment_rel = "journal/segments/000001.json";
    let segment_path = staging.join(segment_rel);
    let first = events.first().map(|e| e.sequence).unwrap_or(0);
    let last = events.last().map(|e| e.sequence).unwrap_or(0);
    let segment = JournalSegmentFile {
        format_version: JOURNAL_ARTIFACT_FORMAT_VERSION,
        first_sequence: first,
        last_sequence: last,
        events: events.to_vec(),
    };
    write_json_atomic(&segment_path, &segment)?;
    let (size, checksum) = sha256_file(&segment_path)?;
    if last != n {
        return Err(BackupError::Validation(format!(
            "journal segment last_sequence {last} != N {n}"
        )));
    }

    let journal_manifest = JournalArtifact {
        format_version: JOURNAL_ARTIFACT_FORMAT_VERSION,
        checkpoint_sequence: n,
        tip_sequence: n,
        segments: vec![JournalSegmentRef {
            segment_id: 1,
            relative_path: segment_rel.to_string(),
            first_sequence: first,
            last_sequence: last,
            event_count: events.len() as u64,
            size,
            checksum_sha256: checksum,
        }],
    };
    let journal_manifest_path = staging.join("journal/manifest.json");
    write_json_atomic(&journal_manifest_path, &journal_manifest)?;

    Ok(vec![
        file_entry(segment_rel, BackupFileRole::JournalSegment, &segment_path)?,
        file_entry(
            "journal/manifest.json",
            BackupFileRole::Journal,
            &journal_manifest_path,
        )?,
    ])
}

fn catalog_at(events: &[StateEventRecord], n: u64) -> Result<Catalog> {
    let mut catalog = Catalog::new();
    for record in events {
        if record.sequence > n {
            break;
        }
        match &record.event {
            StateEvent::Catalog(event) => {
                catalog
                    .apply(event, ApplyMode::Replay)
                    .map_err(|e| BackupError::Validation(format!("catalog replay: {e}")))?;
            }
            StateEvent::TransactionCommit { events: nested, .. } => {
                for te in nested {
                    if let Some(event) = te.as_catalog() {
                        catalog
                            .apply(event, ApplyMode::Replay)
                            .map_err(|e| BackupError::Validation(format!("catalog replay: {e}")))?;
                    }
                }
            }
            StateEvent::Data(_) => {}
        }
    }
Ok(catalog)
}

fn write_catalog(
    staging: &Path,
    n: u64,
    catalog: &Catalog,
) -> Result<Vec<crate::manifest::BackupFileEntry>> {
    let artifact = CatalogArtifact {
        format_version: CATALOG_ARTIFACT_FORMAT_VERSION,
        checkpoint_sequence: n,
        catalog: catalog.to_snapshot_body(),
    };
    let path = staging.join("catalog/catalog.json");
    write_json_atomic(&path, &artifact)?;
    Ok(vec![file_entry(
        "catalog/catalog.json",
        BackupFileRole::Catalog,
        &path,
    )?])
}

fn write_storage(
    staging: &Path,
    n: u64,
    catalog: &Catalog,
    events: &[StateEventRecord],
    include_segments: bool,
) -> Result<(Vec<crate::manifest::BackupFileEntry>, StorageArtifact)> {
    let mut files = Vec::new();
    let mut tables = Vec::new();
    let mut segment_refs = Vec::new();

    if include_segments {
        let rebuild_root = staging.join(".rebuild_rows");
        fs::create_dir_all(&rebuild_root).map_err(|e| BackupError::Io(e.to_string()))?;
        let mut mat = StateMaterializer::in_memory(&rebuild_root);
        for record in events {
            mat.apply_record(record, ApplyMode::Replay)
                .map_err(|e| BackupError::Validation(format!("storage rebuild: {e}")))?;
        }
        if mat.watermark().sequence != n {
            return Err(BackupError::Validation(format!(
                "rebuilt storage watermark {} != N {n}",
                mat.watermark().sequence
            )));
        }

        for table in catalog.tables() {
            let src = table_dir(&rebuild_root, table.id);
            if !src.is_dir() {
                continue;
            }
            let rel_table = format!("storage/tables/table_{}", table.id.raw());
            let dst = staging.join(&rel_table);
            copy_dir_all(&src, &dst)?;

            let table_manifest = read_manifest(&dst)
                .map_err(|e| BackupError::Validation(format!("storage manifest: {e}")))?
                .ok_or_else(|| BackupError::Corrupt(format!("missing table manifest for {}", table.id.raw())))?;

            tables.push(BackupStorageTableEntry {
                table_id: table_manifest.table_id,
                manifest_generation: table_manifest.generation,
                format_version: table_manifest.format_version,
                next_row_id: table_manifest.next_row_id,
            });

            let table_manifest_rel = format!("{rel_table}/manifest.json");
            files.push(file_entry(
                table_manifest_rel,
                BackupFileRole::Storage,
                &dst.join("manifest.json"),
            )?);

            let segments_dir = dst.join("segments");
            if segments_dir.is_dir() {
                let mut entries: Vec<_> = fs::read_dir(&segments_dir)
                    .map_err(|e| BackupError::Io(e.to_string()))?
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|e| BackupError::Io(e.to_string()))?;
                entries.sort_by_key(|e| e.file_name());
                for entry in entries {
                    if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                        continue;
                    }
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    let segment_id = name
                        .trim_end_matches(".dat")
                        .parse::<u64>()
                        .unwrap_or(0);
                    let rel = format!("{rel_table}/segments/{name}");
                    let (size, checksum) = sha256_file(&entry.path())?;
                    segment_refs.push(StorageSegmentRef {
                        table_id: table.id.raw(),
                        segment_id,
                        relative_path: rel.clone(),
                        size,
                        checksum_sha256: checksum.clone(),
                    });
                    files.push(crate::manifest::BackupFileEntry {
                        relative_path: rel,
                        role: BackupFileRole::StorageSegment,
                        size,
                        checksum_sha256: checksum,
                    });
                }
            }
        }
        let _ = fs::remove_dir_all(&rebuild_root);
    } else {
        // Metadata-only: table ids present in catalog @ N, no RowStore bytes.
        for table in catalog.tables() {
            tables.push(BackupStorageTableEntry {
                table_id: table.id.raw(),
                manifest_generation: 0,
                format_version: dmc_storage::STORAGE_MANIFEST_FORMAT_VERSION,
                next_row_id: table.next_row_id.raw(),
            });
        }
    }
    tables.sort_by_key(|t| t.table_id);

    let artifact = StorageArtifact {
        format_version: STORAGE_ARTIFACT_FORMAT_VERSION,
        checkpoint_sequence: n,
        include_segments,
        tables: tables.clone(),
        segments: segment_refs,
    };
    let path = staging.join("storage/manifest.json");
    write_json_atomic(&path, &artifact)?;
    files.push(file_entry(
        "storage/manifest.json",
        BackupFileRole::Storage,
        &path,
    )?);
    Ok((files, artifact))
}

fn write_recovery(
    staging: &Path,
    manifest: &BackupManifest,
) -> Result<Vec<crate::manifest::BackupFileEntry>> {
    let artifact = RecoveryArtifact::from_metadata(&manifest.recovery_metadata);
    if artifact.checkpoint_sequence != manifest.checkpoint_sequence {
        return Err(BackupError::Validation(
            "recovery checkpoint mismatch".into(),
        ));
    }
    let path = staging.join("recovery/metadata.json");
    write_json_atomic(&path, &artifact)?;
    Ok(vec![file_entry(
        "recovery/metadata.json",
        BackupFileRole::Recovery,
        &path,
    )?])
}
