//! List published backup artifacts under a backups root (opaque ids only).

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{BackupError, Result};
use crate::manifest::{BackupManifest, MANIFEST_FILE};
use crate::publish::STAGE_DIR_PREFIX;
use crate::verify::verify_backup;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupInfo {
    pub backup_id: String,
    pub checkpoint_sequence: u64,
    pub created_at: String,
    pub valid: bool,
    /// High-level lifecycle label for UI (`published` / `invalid`).
    pub state: String,
}

/// Scan `{backups_root}/backup-*` directories and return DTO list (no absolute paths).
pub fn list_backups(backups_root: &Path) -> Result<Vec<BackupInfo>> {
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
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(STAGE_DIR_PREFIX) || !entry.path().is_dir() {
            continue;
        }
        // Skip staging leftovers under `.staging`.
        if name.starts_with('.') {
            continue;
        }
        let backup_id = name
            .strip_prefix(STAGE_DIR_PREFIX)
            .unwrap_or(&name)
            .to_string();
        match backup_info_from_dir(&entry.path(), &backup_id) {
            Ok(info) => items.push(info),
            Err(_) => items.push(BackupInfo {
                backup_id,
                checkpoint_sequence: 0,
                created_at: String::new(),
                valid: false,
                state: "invalid".into(),
            }),
        }
    }
    Ok(items)
}

fn backup_info_from_dir(path: &Path, backup_id: &str) -> Result<BackupInfo> {
    let report = verify_backup(path)?;
    let manifest: BackupManifest = {
        let raw = fs::read(path.join(MANIFEST_FILE)).map_err(|e| BackupError::Io(e.to_string()))?;
        serde_json::from_slice(&raw).map_err(|e| BackupError::Corrupt(e.to_string()))?
    };
    Ok(BackupInfo {
        backup_id: backup_id.to_string(),
        checkpoint_sequence: report.checkpoint_sequence,
        created_at: manifest.created_at,
        valid: report.valid,
        state: if report.valid {
            "published".into()
        } else {
            "invalid".into()
        },
    })
}

pub fn backup_path(backups_root: &Path, backup_id: &str) -> PathBuf {
    backups_root.join(format!("{STAGE_DIR_PREFIX}{backup_id}"))
}

pub fn restore_target_path(restores_root: &Path, target_id: &str) -> PathBuf {
    restores_root.join(target_id)
}
