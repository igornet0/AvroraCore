//! Avrora vault backup — journal + snapshot layout under `{data_dir}/backups/`.

use std::fs;
use std::path::{Path, PathBuf};

use avrora_proto::BackupListItem;
use dmc_journal::StorageLayout;
use serde::{Deserialize, Serialize};

use crate::control::backup_config::{ALL_SECTIONS, validate_sections};
use crate::runtime::{DbStatus, Runtime};

pub mod archive;
pub mod keys;
pub mod kit;
pub mod remote;

pub const BACKUP_PREFIX: &str = "backup-";
pub const RESTORE_PREFIX: &str = "restore-";
pub const MANIFEST_FILE: &str = "manifest.json";
pub const AVRORA_BACKUP_KIND: &str = "avrora-vault";
pub const AVRORA_BACKUP_FORMAT_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("backup invalid: {0}")]
    Invalid(String),
    #[error("backup not found")]
    NotFound,
    #[error("restore target not empty")]
    TargetNotEmpty,
    #[error("recovery not ready: {0}")]
    RecoveryNotReady(String),
    #[error("vault must be locked")]
    VaultNotLocked,
    #[error("vault must be unlocked")]
    VaultLocked,
    #[error("invalid backup or target id")]
    InvalidId,
    #[error("backup already exists")]
    AlreadyExists,
    #[error("remote backup: {0}")]
    Remote(String),
    #[error("{0}")]
    Io(String),
}

pub type Result<T> = std::result::Result<T, BackupError>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AvroraBackupManifest {
    pub format_version: u32,
    pub kind: String,
    pub database_id: String,
    pub checkpoint_sequence: u64,
    pub created_at: String,
    /// Layout sections captured (`base`, `journal`, `runtime`).
    #[serde(default)]
    pub sections: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestoreStateFile {
    pub state: String,
    pub checkpoint_sequence: u64,
}

pub fn backups_root(data_dir: &Path) -> PathBuf {
    data_dir.join("backups")
}

pub fn restores_root(data_dir: &Path) -> PathBuf {
    data_dir.join("restores")
}

pub fn backup_dir(backups_root: &Path, backup_id: &str) -> PathBuf {
    backups_root.join(format!("{BACKUP_PREFIX}{backup_id}"))
}

pub fn restore_dir(restores_root: &Path, target_id: &str) -> PathBuf {
    restores_root.join(format!("{RESTORE_PREFIX}{target_id}"))
}

pub fn opaque_id_ok(id: &str) -> bool {
    !id.is_empty()
        && !id.contains('/')
        && !id.contains('\\')
        && !id.contains("..")
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

pub(crate) fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    if !src.is_dir() {
        return Err(BackupError::Io(format!("missing dir {}", src.display())));
    }
    fs::create_dir_all(dst).map_err(|e| BackupError::Io(e.to_string()))?;
    for entry in fs::read_dir(src).map_err(|e| BackupError::Io(e.to_string()))? {
        let entry = entry.map_err(|e| BackupError::Io(e.to_string()))?;
        let ty = entry.file_type().map_err(|e| BackupError::Io(e.to_string()))?;
        let dest = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dest)?;
        } else {
            fs::copy(entry.path(), &dest).map_err(|e| BackupError::Io(e.to_string()))?;
        }
    }
    Ok(())
}

pub(crate) fn remove_dir_if_exists(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_dir_all(path).map_err(|e| BackupError::Io(e.to_string()))?;
    }
    Ok(())
}

fn copy_layout_snapshot(layout: &StorageLayout, dest: &Path, sections: &[String]) -> Result<()> {
    for name in sections {
        let src = layout.data_dir.join(name);
        if src.is_dir() {
            copy_dir_all(&src, &dest.join(name))?;
        }
    }
    Ok(())
}

pub(crate) fn load_manifest(path: &Path) -> Result<AvroraBackupManifest> {
    let raw = fs::read(path.join(MANIFEST_FILE)).map_err(|_| BackupError::Invalid("missing manifest".into()))?;
    let manifest: AvroraBackupManifest =
        serde_json::from_slice(&raw).map_err(|e| BackupError::Invalid(e.to_string()))?;
    if manifest.kind != AVRORA_BACKUP_KIND {
        return Err(BackupError::Invalid("unsupported backup kind".into()));
    }
    Ok(manifest)
}

pub async fn create_backup(
    runtime: &Runtime,
    backup_id: &str,
    _include_rowstore: bool,
) -> Result<(String, u64)> {
    let all: Vec<String> = ALL_SECTIONS.iter().map(|s| s.to_string()).collect();
    create_backup_with_sections(runtime, backup_id, &all).await
}

/// Create a local backup containing only the given layout sections.
pub async fn create_backup_with_sections(
    runtime: &Runtime,
    backup_id: &str,
    sections: &[String],
) -> Result<(String, u64)> {
    if !opaque_id_ok(backup_id) {
        return Err(BackupError::InvalidId);
    }
    validate_sections(sections).map_err(BackupError::Invalid)?;
    if runtime.status().await != DbStatus::Unlocked {
        return Err(BackupError::VaultLocked);
    }
    let checkpoint = runtime.force_snapshot().await.map_err(|e| BackupError::Io(e.to_string()))?;
    runtime.persist().await.map_err(|e| BackupError::Io(e.to_string()))?;

    let db_path = runtime.db_path().await;
    let db_id = runtime.db_id().await.unwrap_or_else(|| "main".into());
    let layout = StorageLayout::from_db_path(&db_path);
    let root = backups_root(&layout.data_dir);
    fs::create_dir_all(&root).map_err(|e| BackupError::Io(e.to_string()))?;

    let publish = backup_dir(&root, backup_id);
    if publish.exists() {
        return Err(BackupError::AlreadyExists);
    }

    let staging = root
        .join(".staging")
        .join(format!("{BACKUP_PREFIX}{backup_id}"));
    remove_dir_if_exists(&staging)?;
    fs::create_dir_all(&staging).map_err(|e| BackupError::Io(e.to_string()))?;

    copy_layout_snapshot(&layout, &staging, sections)?;

    let manifest = AvroraBackupManifest {
        format_version: AVRORA_BACKUP_FORMAT_VERSION,
        kind: AVRORA_BACKUP_KIND.into(),
        database_id: db_id,
        checkpoint_sequence: checkpoint,
        created_at: now_rfc3339(),
        sections: sections.to_vec(),
    };
    fs::write(
        staging.join(MANIFEST_FILE),
        serde_json::to_vec_pretty(&manifest).map_err(|e| BackupError::Io(e.to_string()))?,
    )
    .map_err(|e| BackupError::Io(e.to_string()))?;

    fs::rename(&staging, &publish).map_err(|e| BackupError::Io(e.to_string()))?;
    Ok((backup_id.to_string(), checkpoint))
}

pub fn verify_backup(backups_root: &Path, backup_id: &str) -> Result<(u64, bool, Vec<String>)> {
    if !opaque_id_ok(backup_id) {
        return Err(BackupError::InvalidId);
    }
    let path = backup_dir(backups_root, backup_id);
    if !path.is_dir() {
        return Err(BackupError::NotFound);
    }
    let mut errors = Vec::new();
    let manifest = match load_manifest(&path) {
        Ok(m) => m,
        Err(e) => {
            errors.push(e.to_string());
            return Ok((0, false, errors));
        }
    };
    for sub in ["base", "journal"] {
        if !path.join(sub).is_dir() {
            errors.push(format!("missing {sub}"));
        }
    }
    let valid = errors.is_empty();
    Ok((manifest.checkpoint_sequence, valid, errors))
}

pub fn list_backups(backups_root: &Path) -> Result<Vec<BackupListItem>> {
    if !backups_root.is_dir() {
        return Ok(Vec::new());
    }
    let mut items = Vec::new();
    let mut entries: Vec<_> = fs::read_dir(backups_root)
        .map_err(|e| BackupError::Io(e.to_string()))?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with(BACKUP_PREFIX) || name.starts_with('.') || !entry.path().is_dir() {
            continue;
        }
        let backup_id = name.strip_prefix(BACKUP_PREFIX).unwrap_or(&name).to_string();
        match verify_backup(backups_root, &backup_id) {
            Ok((seq, valid, _)) => {
                let created_at = load_manifest(&entry.path())
                    .map(|m| m.created_at)
                    .unwrap_or_default();
                items.push(BackupListItem {
                    backup_id,
                    checkpoint_sequence: seq,
                    created_at,
                    valid,
                    state: if valid { "published".into() } else { "invalid".into() },
                });
            }
            Err(BackupError::NotFound) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(items)
}

pub fn restore_backup(
    backups_root: &Path,
    restores_root: &Path,
    backup_id: &str,
    target_id: &str,
) -> Result<(String, String, u64)> {
    if !opaque_id_ok(backup_id) || !opaque_id_ok(target_id) {
        return Err(BackupError::InvalidId);
    }
    let (seq, valid, _) = verify_backup(backups_root, backup_id)?;
    if !valid {
        return Err(BackupError::Invalid("backup failed verification".into()));
    }
    let src = backup_dir(backups_root, backup_id);
    let dst = restore_dir(restores_root, target_id);
    if dst.exists() {
        return Err(BackupError::TargetNotEmpty);
    }
    fs::create_dir_all(restores_root).map_err(|e| BackupError::Io(e.to_string()))?;
    copy_dir_all(&src, &dst)?;
    let state = RestoreStateFile {
        state: "restored".into(),
        checkpoint_sequence: seq,
    };
    fs::write(
        dst.join("recovery.json"),
        serde_json::to_vec_pretty(&state).map_err(|e| BackupError::Io(e.to_string()))?,
    )
    .map_err(|e| BackupError::Io(e.to_string()))?;
    Ok((backup_id.to_string(), target_id.to_string(), seq))
}

pub async fn recover_backup(
    runtime: &Runtime,
    restores_root: &Path,
    target_id: &str,
) -> Result<(String, u64)> {
    if !opaque_id_ok(target_id) {
        return Err(BackupError::InvalidId);
    }
    if runtime.status().await != DbStatus::Locked {
        return Err(BackupError::VaultNotLocked);
    }
    apply_restored(runtime, restores_root, target_id).await
}

/// Disaster recovery onto a host without a vault (`DbStatus::Empty`): installs
/// a staged restore as the live layout. The process must be restarted and the
/// vault unlocked with the original Master Key afterwards.
pub async fn recover_into_empty(
    runtime: &Runtime,
    restores_root: &Path,
    target_id: &str,
) -> Result<(String, u64)> {
    if !opaque_id_ok(target_id) {
        return Err(BackupError::InvalidId);
    }
    if runtime.status().await != DbStatus::Empty {
        return Err(BackupError::RecoveryNotReady(
            "a vault already exists here; lock it and use regular recover".into(),
        ));
    }
    apply_restored(runtime, restores_root, target_id).await
}

async fn apply_restored(
    runtime: &Runtime,
    restores_root: &Path,
    target_id: &str,
) -> Result<(String, u64)> {
    let src = restore_dir(restores_root, target_id);
    if !src.is_dir() {
        return Err(BackupError::NotFound);
    }
    let state_path = src.join("recovery.json");
    if !state_path.is_file() {
        return Err(BackupError::RecoveryNotReady("missing recovery.json".into()));
    }
    let state: RestoreStateFile = serde_json::from_slice(
        &fs::read(&state_path).map_err(|e| BackupError::Io(e.to_string()))?,
    )
    .map_err(|e| BackupError::Invalid(e.to_string()))?;
    if state.state != "restored" {
        return Err(BackupError::RecoveryNotReady(format!(
            "expected restored, got {}",
            state.state
        )));
    }

    let db_path = runtime.db_path().await;
    let layout = StorageLayout::from_db_path(&db_path);
    for name in ["base", "journal", "runtime"] {
        let live = layout.data_dir.join(name);
        remove_dir_if_exists(&live)?;
        let from = src.join(name);
        if from.is_dir() {
            copy_dir_all(&from, &live)?;
        }
    }

    let ready = RestoreStateFile {
        state: "ready".into(),
        checkpoint_sequence: state.checkpoint_sequence,
    };
    fs::write(
        state_path,
        serde_json::to_vec_pretty(&ready).map_err(|e| BackupError::Io(e.to_string()))?,
    )
    .map_err(|e| BackupError::Io(e.to_string()))?;

    Ok((target_id.to_string(), state.checkpoint_sequence))
}

pub fn backup_status(restores_root: &Path, target_id: &str) -> Result<(String, u64, String)> {
    if !opaque_id_ok(target_id) {
        return Err(BackupError::InvalidId);
    }
    let dst = restore_dir(restores_root, target_id);
    if !dst.is_dir() {
        return Ok(("absent".into(), 0, target_id.to_string()));
    }
    let state_path = dst.join("recovery.json");
    if !state_path.is_file() {
        return Ok(("restored".into(), 0, target_id.to_string()));
    }
    let state: RestoreStateFile = serde_json::from_slice(
        &fs::read(&state_path).map_err(|e| BackupError::Io(e.to_string()))?,
    )
    .map_err(|e| BackupError::Invalid(e.to_string()))?;
    Ok((state.state, state.checkpoint_sequence, target_id.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::Runtime;

    #[test]
    fn manifest_without_sections_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(MANIFEST_FILE),
            br#"{"format_version":1,"kind":"avrora-vault","database_id":"main","checkpoint_sequence":3,"created_at":"t"}"#,
        )
        .unwrap();
        let m = load_manifest(dir.path()).unwrap();
        assert!(m.sections.is_empty());
        assert_eq!(m.checkpoint_sequence, 3);
    }

    #[tokio::test]
    async fn create_list_verify_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.dbs.json");
        let rt = Runtime::at_path(&db_path);
        let (_hex, _id) = rt.create_dev(false).await.unwrap();

        let (id, seq) = create_backup(&rt, "daily", false).await.unwrap();
        assert_eq!(id, "daily");
        assert!(seq >= 0);

        let layout = StorageLayout::from_db_path(&db_path);
        let root = backups_root(&layout.data_dir);
        let items = list_backups(&root).unwrap();
        assert_eq!(items.len(), 1);
        assert!(items[0].valid);

        let (vseq, valid, errs) = verify_backup(&root, "daily").unwrap();
        assert!(valid, "{errs:?}");
        assert_eq!(vseq, seq);
    }
}
