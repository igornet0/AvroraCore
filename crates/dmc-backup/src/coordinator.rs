use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use dmc_materialized::{
    StateEventLog, StateMaterializer, MATERIALIZED_SNAPSHOT_FORMAT_VERSION,
    STATE_EVENT_LOG_FORMAT_VERSION,
};
use dmc_storage::{read_manifest, table_dir};

use crate::barrier::{require_fully_materialized_tip, ConsistencyPoint};
use crate::error::{BackupError, Result};
use crate::manifest::{
    BackupFileEntry, BackupFileRole, BackupJournalSection, BackupManifest, BackupOptions,
    BackupStorageTableEntry, CatalogSection, IndexDefinitionRef, RecoveryMetadata, StorageSection,
    VaultMetadataSummary, BACKUP_MANIFEST_FORMAT_VERSION,
};
use crate::publish::{publish_staged, PublishedBackup, StagedBackup, STAGE_DIR_PREFIX};
use crate::source::BackupSource;
use crate::vault_meta;
use crate::writer::{BackupWriter, DefaultBackupWriter};

/// Inputs for capturing a backup manifest at the consistency barrier.
#[derive(Clone, Debug)]
pub struct BackupRequest {
    pub database_id: String,
    pub options: BackupOptions,
    pub vault: VaultMetadataSummary,
    /// Override wall-clock; when `None`, a UTC unix-epoch timestamp string is used.
    pub created_at: Option<String>,
}

impl BackupRequest {
    pub fn new(database_id: impl Into<String>) -> Self {
        Self {
            database_id: database_id.into(),
            options: BackupOptions::default(),
            vault: vault_meta::absent(),
            created_at: None,
        }
    }

    pub fn with_vault(mut self, vault: VaultMetadataSummary) -> Self {
        self.vault = vault;
        self
    }

    pub fn with_options(mut self, options: BackupOptions) -> Self {
        self.options = options;
        self
    }

    pub fn with_created_at(mut self, created_at: impl Into<String>) -> Self {
        self.created_at = Some(created_at.into());
        self
    }
}

/// Builds immutable [`BackupManifest`] only after the consistency barrier passes.
pub struct BackupCoordinator;

impl BackupCoordinator {
    /// Determine `N` under V1 rule: journal tip == materialized watermark.
    pub fn determine_checkpoint<L: StateEventLog>(
        mat: &StateMaterializer<L>,
    ) -> Result<ConsistencyPoint> {
        require_fully_materialized_tip(mat)
    }

    /// Capture manifest at barrier — snapshot contract only (no artifact bytes).
    pub fn build_manifest<L: StateEventLog>(
        mat: &StateMaterializer<L>,
        request: &BackupRequest,
    ) -> Result<BackupManifest> {
        let point = Self::determine_checkpoint(mat)?;
        Self::build_manifest_at(mat, request, &point)
    }

    fn build_manifest_at<L: StateEventLog>(
        mat: &StateMaterializer<L>,
        request: &BackupRequest,
        point: &ConsistencyPoint,
    ) -> Result<BackupManifest> {
        let catalog = mat.catalog();
        let n = point.checkpoint_sequence;

        let mut index_definitions = Vec::new();
        for table in catalog.tables() {
            for index in &table.indexes {
                index_definitions.push(IndexDefinitionRef {
                    index_id: index.id.raw(),
                    table_id: index.table_id.raw(),
                    name: index.name.clone(),
                    unique: index.unique,
                    column_ids: index.columns.iter().map(|c| c.raw()).collect(),
                });
            }
        }
        index_definitions.sort_by_key(|i| i.index_id);

        let mut storage_tables = Vec::new();
        for table in catalog.tables() {
            let root = table_dir(mat.storage_root(), table.id);
            if let Some(manifest) = read_manifest(&root).map_err(|e| {
                BackupError::Validation(format!("storage manifest read: {e}"))
            })? {
                storage_tables.push(BackupStorageTableEntry {
                    table_id: manifest.table_id,
                    manifest_generation: manifest.generation,
                    format_version: manifest.format_version,
                    next_row_id: manifest.next_row_id,
                });
            }
        }
        storage_tables.sort_by_key(|t| t.table_id);

        let created_at = request
            .created_at
            .clone()
            .unwrap_or_else(default_created_at);

        let mut manifest = BackupManifest {
            format_version: BACKUP_MANIFEST_FORMAT_VERSION,
            database_id: request.database_id.clone(),
            checkpoint_sequence: n,
            journal: BackupJournalSection {
                tip_sequence: point.journal_tip,
                format_version: STATE_EVENT_LOG_FORMAT_VERSION,
                event_count: point.event_count,
            },
            catalog: CatalogSection {
                checkpoint_sequence: point.catalog_checkpoint,
                snapshot_format_version: MATERIALIZED_SNAPSHOT_FORMAT_VERSION,
                table_count: catalog.tables().count() as u64,
                index_count: index_definitions.len() as u64,
            },
            storage: StorageSection {
                tables: storage_tables,
            },
            index_definitions,
            vault_metadata: request.vault.clone(),
            recovery_metadata: RecoveryMetadata {
                checkpoint_sequence: n,
                require_rebuild_rowstore: !request.options.include_rowstore,
                require_rebuild_indexstore: !request.options.include_index_store,
                require_rebuild_statistics: !request.options.include_statistics,
            },
            options: request.options.clone(),
            created_at,
            files: Vec::new(),
        };

        validate_manifest_invariants(&manifest)?;
        // Placeholders until writer fills digests (7.8.3).
        manifest.files = vec![
            placeholder_file("journal/", BackupFileRole::JournalPlaceholder),
            placeholder_file("catalog/", BackupFileRole::CatalogPlaceholder),
            placeholder_file("storage/", BackupFileRole::StoragePlaceholder),
            placeholder_file("recovery/", BackupFileRole::MetadataPlaceholder),
        ];
        Ok(manifest)
    }

    /// Barrier → frozen source → writer → atomic publish.
    pub fn create_and_publish<L: StateEventLog>(
        mat: &StateMaterializer<L>,
        request: &BackupRequest,
        backups_root: &Path,
        backup_id: &str,
    ) -> Result<PublishedBackup> {
        let staged = Self::stage_artifact(mat, request, backups_root, backup_id)?;
        publish_staged(&staged)
    }

    /// Materialize full artifact under staging (does not publish).
    pub fn stage_artifact<L: StateEventLog>(
        mat: &StateMaterializer<L>,
        request: &BackupRequest,
        backups_root: &Path,
        backup_id: &str,
    ) -> Result<StagedBackup> {
        let manifest = Self::build_manifest(mat, request)?;
        let source = BackupSource::from_log(mat.event_log());
        let staging_dir = backups_root
            .join(".staging")
            .join(format!("{STAGE_DIR_PREFIX}{backup_id}"));
        let publish_dir = backups_root.join(format!("{STAGE_DIR_PREFIX}{backup_id}"));
        if publish_dir.exists() {
            return Err(BackupError::AlreadyExists);
        }
        let artifact = DefaultBackupWriter.write(&manifest, &source, &staging_dir)?;
        Ok(StagedBackup {
            backup_id: backup_id.to_string(),
            staging_dir: artifact.root,
            publish_dir,
            manifest: artifact.manifest,
        })
    }

    /// Manifest-only stage (7.8.2). Prefer [`Self::stage_artifact`] for full backups.
    pub fn stage<L: StateEventLog>(
        mat: &StateMaterializer<L>,
        request: &BackupRequest,
        backups_root: &Path,
        backup_id: &str,
    ) -> Result<StagedBackup> {
        Self::stage_artifact(mat, request, backups_root, backup_id)
    }
}

fn placeholder_file(relative_path: &str, role: BackupFileRole) -> BackupFileEntry {
    BackupFileEntry {
        relative_path: relative_path.to_string(),
        role,
        size: 0,
        checksum_sha256: empty_sha256(),
    }
}

fn empty_sha256() -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest([]))
}

fn default_created_at() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

/// Structural invariants for a captured checkpoint `N`.
pub fn validate_manifest_invariants(manifest: &BackupManifest) -> Result<()> {
    let n = manifest.checkpoint_sequence;
    if manifest.journal.tip_sequence != n {
        return Err(BackupError::Validation(format!(
            "journal tip {} != checkpoint {n}",
            manifest.journal.tip_sequence
        )));
    }
    if manifest.catalog.checkpoint_sequence != n {
        return Err(BackupError::Validation(format!(
            "catalog checkpoint {} != checkpoint {n}",
            manifest.catalog.checkpoint_sequence
        )));
    }
    if manifest.recovery_metadata.checkpoint_sequence != n {
        return Err(BackupError::Validation(format!(
            "recovery checkpoint {} != checkpoint {n}",
            manifest.recovery_metadata.checkpoint_sequence
        )));
    }
    if manifest.format_version != BACKUP_MANIFEST_FORMAT_VERSION {
        return Err(BackupError::Validation(format!(
            "unsupported backup format {}",
            manifest.format_version
        )));
    }
    assert_no_secrets_in_manifest(manifest)?;
    Ok(())
}

/// Reject obvious secret field leakage in serialized manifest JSON.
pub fn assert_no_secrets_in_manifest(manifest: &BackupManifest) -> Result<()> {
    let json = serde_json::to_string(manifest).map_err(|_| BackupError::Internal)?;
    let lowered = json.to_lowercase();
    const FORBIDDEN: &[&str] = &[
        "master_key",
        "masterkey",
        "\"dek\"",
        "\"kek\"",
        "\"password\"",
        "unlock_material",
        "unlockmaterial",
        "unlock_blob",
        "key_material",
        "keypass",
        "private_key",
        "session_token",
        "auth_session",
    ];
    for needle in FORBIDDEN {
        if lowered.contains(needle) {
            return Err(BackupError::Validation(format!(
                "forbidden secret material marker in manifest: {needle}"
            )));
        }
    }
    Ok(())
}
