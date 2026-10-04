//! Phase 7.8.5 — Restore verified backup into an empty target (no replay / unlock).

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::artifact::{
    CatalogArtifact, JournalArtifact, RecoveryArtifact, StorageArtifact,
};
use crate::digest::copy_dir_all;
use crate::error::{BackupError, Result};
use crate::manifest::{BackupManifest, MANIFEST_FILE};
use crate::publish::STAGE_DIR_PREFIX;
use crate::verify::verify_backup;

pub const RESTORE_STAGE_DIR: &str = ".restore";
pub const RESTORE_DIR_PREFIX: &str = "restore-";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreState {
    /// Staging completed but not yet published (internal / crash diagnostics).
    Staged,
    /// Atomic publish succeeded — target holds the restored artifact @ N.
    Published,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultRestoreState {
    /// Restore never unlocks; vault remains locked (ADR-022 / ADR-024).
    Locked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionRestoreState {
    /// Sessions are never restored from backup.
    Invalid,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreResult {
    pub backup_id: String,
    pub checkpoint_sequence: u64,
    pub target: PathBuf,
    pub state: RestoreState,
    pub vault: VaultRestoreState,
    pub sessions: SessionRestoreState,
}

/// Restore a **verified** backup artifact into an empty `target` directory.
///
/// Contract:
/// 1. `verify_backup(backup_path)` — reject if invalid (target untouched)
/// 2. `target` must be absent or empty (`RestoreTarget::EmptyDirectory`)
/// 3. Stage under `{parent}/.restore/restore-{id}/`
/// 4. Re-verify staged copy
/// 5. Atomic `rename(staging → target)`
///
/// Does **not** replay journal, unlock vault, or restore sessions.
pub fn restore_backup(backup_path: &Path, target: &Path) -> Result<RestoreResult> {
    // 1. Verify first — never mutate target on invalid backup.
    let verification = verify_backup(backup_path)?;
    if !verification.valid {
        return Err(BackupError::BackupInvalid(if verification.errors.is_empty() {
            "backup verification failed".into()
        } else {
            verification.errors.join("; ")
        }));
    }

    let backup_id = verification.backup_id.clone();
    let checkpoint_sequence = verification.checkpoint_sequence;

    // 2. Empty-target policy.
    ensure_empty_or_absent(target)?;

    let parent = target
        .parent()
        .ok_or_else(|| BackupError::Io("restore target has no parent directory".into()))?;
    fs::create_dir_all(parent).map_err(|e| BackupError::Io(e.to_string()))?;

    let restore_id = make_restore_id(&backup_id);
    let staging_root = parent.join(RESTORE_STAGE_DIR);
    let staging = staging_root.join(format!("{RESTORE_DIR_PREFIX}{restore_id}"));
    if staging.exists() {
        return Err(BackupError::AlreadyExists);
    }

    // 3. Stage copy (isolated from target path).
    let stage_result = (|| -> Result<()> {
        fs::create_dir_all(&staging).map_err(|e| BackupError::Io(e.to_string()))?;
        copy_artifact_tree(backup_path, &staging)?;
        // 4. Validate restored metadata independently of the source path.
        let staged_verify = verify_backup(&staging)?;
        if !staged_verify.valid {
            return Err(BackupError::Corrupt(format!(
                "staged restore failed verification: {}",
                staged_verify.errors.join("; ")
            )));
        }
        if staged_verify.checkpoint_sequence != checkpoint_sequence {
            return Err(BackupError::Corrupt(format!(
                "staged checkpoint {} != backup checkpoint {checkpoint_sequence}",
                staged_verify.checkpoint_sequence
            )));
        }
        assert_no_runtime_secrets(&staging)?;
        Ok(())
    })();

    if let Err(e) = stage_result {
        let _ = fs::remove_dir_all(&staging);
        return Err(e);
    }

    // 5. Atomic publish: staging directory becomes the target.
    // Re-check empty in case of races / leftover.
    ensure_empty_or_absent(target)?;
    if target.exists() {
        // Empty dir — remove so rename can succeed on all platforms.
        fs::remove_dir(target).map_err(|e| BackupError::Io(e.to_string()))?;
    }
    fs::rename(&staging, target).map_err(|e| BackupError::Io(e.to_string()))?;

    // Best-effort cleanup of empty .restore root.
    let _ = fs::remove_dir(&staging_root);

    Ok(RestoreResult {
        backup_id,
        checkpoint_sequence,
        target: target.to_path_buf(),
        state: RestoreState::Published,
        vault: VaultRestoreState::Locked,
        sessions: SessionRestoreState::Invalid,
    })
}

fn make_restore_id(backup_id: &str) -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("{backup_id}-{secs}")
}

/// Target must not exist, or exist as an empty directory (no children).
fn ensure_empty_or_absent(target: &Path) -> Result<()> {
    if !target.exists() {
        return Ok(());
    }
    if !target.is_dir() {
        return Err(BackupError::TargetNotEmpty(
            "restore target exists and is not a directory".into(),
        ));
    }
    let mut rd = fs::read_dir(target).map_err(|e| BackupError::Io(e.to_string()))?;
    if rd.next().is_some() {
        return Err(BackupError::TargetNotEmpty(
            "restore target must be an empty directory (V1)".into(),
        ));
    }
    Ok(())
}

fn copy_artifact_tree(src: &Path, dst: &Path) -> Result<()> {
    // Root manifest
    let manifest_src = src.join(MANIFEST_FILE);
    if !manifest_src.is_file() {
        return Err(BackupError::Corrupt("backup missing manifest.json".into()));
    }
    fs::copy(&manifest_src, dst.join(MANIFEST_FILE)).map_err(|e| BackupError::Io(e.to_string()))?;

    for sub in ["journal", "catalog", "storage", "recovery"] {
        let from = src.join(sub);
        if !from.is_dir() {
            return Err(BackupError::Corrupt(format!(
                "backup missing component directory {sub}"
            )));
        }
        copy_dir_all(&from, &dst.join(sub))?;
    }
    // Optional CLIENT_OWNED key directory component (public / wrapped material only).
    if src.join(crate::ownership::OWNERSHIP_DIR).is_dir() {
        copy_dir_all(
            &src.join(crate::ownership::OWNERSHIP_DIR),
            &dst.join(crate::ownership::OWNERSHIP_DIR),
        )?;
    }

    // Explicitly refuse known secret / session paths if somehow present in artifact.
    for forbidden in [
        "sessions",
        "session",
        "master_key",
        "keypass",
        "unlock_blob",
        "runtime",
        "tauri",
    ] {
        if src.join(forbidden).exists() {
            return Err(BackupError::Validation(format!(
                "refusing to restore forbidden path {forbidden}"
            )));
        }
    }
    Ok(())
}

fn assert_no_runtime_secrets(root: &Path) -> Result<()> {
    for name in [
        "sessions",
        "session.json",
        "master_key",
        "dek",
        "kek",
        "keypass",
        "unlock_blob",
        "unlock_material",
    ] {
        if root.join(name).exists() {
            return Err(BackupError::Validation(format!(
                "restored tree contains forbidden runtime path {name}"
            )));
        }
    }
    // Scan restored root manifest for secret markers (already in verify, belt-and-suspenders).
    let raw = fs::read_to_string(root.join(MANIFEST_FILE)).map_err(|e| BackupError::Io(e.to_string()))?;
    let lowered = raw.to_lowercase();
    for needle in [
        "master_key",
        "password",
        "auth_session",
        "unlock_material",
        "session_token",
    ] {
        if lowered.contains(needle) {
            return Err(BackupError::Validation(format!(
                "secret marker in restored manifest: {needle}"
            )));
        }
    }

    // Load component checkpoints for RestoreResult consumers / tests.
    let _manifest: BackupManifest = serde_json::from_str(&raw)
        .map_err(|e| BackupError::Corrupt(e.to_string()))?;
    let _journal: JournalArtifact = read_json(&root.join("journal/manifest.json"))?;
    let _catalog: CatalogArtifact = read_json(&root.join("catalog/catalog.json"))?;
    let _storage: StorageArtifact = read_json(&root.join("storage/manifest.json"))?;
    let _recovery: RecoveryArtifact = read_json(&root.join("recovery/metadata.json"))?;
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let raw = fs::read(path).map_err(|e| BackupError::Io(e.to_string()))?;
    serde_json::from_slice(&raw).map_err(|e| BackupError::Corrupt(e.to_string()))
}

/// Inspect whether a path looks like a published restore target (layout only).
pub fn restored_layout_ok(target: &Path) -> bool {
    target.join(MANIFEST_FILE).is_file()
        && target.join("journal").is_dir()
        && target.join("catalog").is_dir()
        && target.join("storage").is_dir()
        && target.join("recovery").is_dir()
        && !target.join("sessions").exists()
}

/// Strip `backup-` prefix helper for ids (shared with verify naming).
pub fn backup_id_from_path(path: &Path) -> String {
    path.file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.strip_prefix(STAGE_DIR_PREFIX).unwrap_or(s).to_string())
        .unwrap_or_else(|| "unknown".into())
}
