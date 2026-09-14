//! Phase 7.8 — Backup / restore / recovery.
//!
//! * 7.8.2 — immutable snapshot contract at sequence `N`
//! * 7.8.3 — materialize frozen manifest into a self-contained artifact bound to `N`
//! * 7.8.4 — read-only `verify_backup` over a published artifact (no live DB)
//! * 7.8.5 — restore verified artifact into an empty target (no replay / unlock)
//! * 7.8.6 — recover restored target → READY live DB (rebuild indexes/stats; vault Locked)

mod artifact;
mod barrier;
mod coordinator;
mod digest;
mod error;
mod manifest;
mod list;
mod publish;
mod recovery;
mod restore;
mod source;
mod vault_meta;
mod verify;
mod writer;

pub use artifact::{
    CatalogArtifact, JournalArtifact, JournalSegmentFile, JournalSegmentRef, RecoveryArtifact,
    StorageArtifact, StorageSegmentRef, CATALOG_ARTIFACT_FORMAT_VERSION,
    JOURNAL_ARTIFACT_FORMAT_VERSION, RECOVERY_ARTIFACT_FORMAT_VERSION,
    STORAGE_ARTIFACT_FORMAT_VERSION,
};
pub use barrier::{require_fully_materialized_tip, ConsistencyPoint};
pub use coordinator::{
    assert_no_secrets_in_manifest, validate_manifest_invariants, BackupCoordinator, BackupRequest,
};
pub use error::{BackupError, Result};
pub use manifest::{
    BackupFileEntry, BackupFileRole, BackupJournalSection, BackupManifest, BackupOptions,
    BackupStorageTableEntry, CatalogSection, IndexDefinitionRef, RecoveryMetadata, StorageSection,
    VaultMetadataSummary, BACKUP_MANIFEST_FORMAT_VERSION, MANIFEST_FILE,
};
pub use list::{
    backup_path, list_backups, restore_target_path, BackupInfo,
};
pub use publish::{
    load_published_manifest, publish_staged, stage_manifest, verify_staged, PublishedBackup,
    StagedBackup, STAGE_DIR_PREFIX,
};
pub use recovery::{
    live_paths, recover, RecoveryGate, RecoveryResult, RecoveryState, RecoveryStateFile, LIVE_DIR,
    RECOVERY_STATE_FILE, RECOVER_STAGE_DIR,
};
pub use restore::{
    backup_id_from_path, restore_backup, restored_layout_ok, RestoreResult, RestoreState,
    SessionRestoreState, VaultRestoreState, RESTORE_DIR_PREFIX, RESTORE_STAGE_DIR,
};
pub use source::BackupSource;
pub use vault_meta::{absent as vault_absent, summary_from_optional as vault_summary};
pub use verify::{
    verify_backup, verify_written_artifact, BackupComponent, BackupVerification,
    ComponentVerification,
};
pub use writer::{BackupArtifact, BackupWriter, DefaultBackupWriter};
