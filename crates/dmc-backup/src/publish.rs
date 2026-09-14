use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{BackupError, Result};
use crate::manifest::{BackupManifest, MANIFEST_FILE};
use crate::verify::verify_written_artifact;

pub const STAGE_DIR_PREFIX: &str = "backup-";

#[derive(Clone, Debug)]
pub struct StagedBackup {
    pub backup_id: String,
    pub staging_dir: PathBuf,
    pub publish_dir: PathBuf,
    pub manifest: BackupManifest,
}

#[derive(Clone, Debug)]
pub struct PublishedBackup {
    pub backup_id: String,
    pub path: PathBuf,
    pub manifest: BackupManifest,
}

/// Validate staging tree before publish. Corrupt / incomplete stages fail here.
pub fn verify_staged(staged: &StagedBackup) -> Result<()> {
    let manifest_path = staged.staging_dir.join(MANIFEST_FILE);
    if !manifest_path.is_file() {
        return Err(BackupError::Corrupt("missing manifest.json".into()));
    }
    for sub in ["journal", "catalog", "storage", "recovery"] {
        let p = staged.staging_dir.join(sub);
        if !p.is_dir() {
            return Err(BackupError::Corrupt(format!("missing staging dir {sub}")));
        }
    }
    let raw = fs::read(&manifest_path).map_err(|e| BackupError::Io(e.to_string()))?;
    let on_disk: BackupManifest =
        serde_json::from_slice(&raw).map_err(|e| BackupError::Corrupt(e.to_string()))?;
    if !on_disk.logical_eq(&staged.manifest) {
        return Err(BackupError::Corrupt(
            "staged manifest differs from on-disk manifest.json".into(),
        ));
    }
    verify_written_artifact(&staged.staging_dir, &on_disk)?;
    Ok(())
}

/// Atomic publish: rename staging → published. Partial stages never appear as published.
pub fn publish_staged(staged: &StagedBackup) -> Result<PublishedBackup> {
    verify_staged(staged)?;
    if staged.publish_dir.exists() {
        return Err(BackupError::AlreadyExists);
    }
    if let Some(parent) = staged.publish_dir.parent() {
        fs::create_dir_all(parent).map_err(|e| BackupError::Io(e.to_string()))?;
    }
    fs::rename(&staged.staging_dir, &staged.publish_dir)
        .map_err(|e| BackupError::Io(e.to_string()))?;
    Ok(PublishedBackup {
        backup_id: staged.backup_id.clone(),
        path: staged.publish_dir.clone(),
        manifest: staged.manifest.clone(),
    })
}

/// Load a published manifest.
pub fn load_published_manifest(published_dir: &Path) -> Result<BackupManifest> {
    let path = published_dir.join(MANIFEST_FILE);
    if !path.is_file() {
        return Err(BackupError::Corrupt("published manifest missing".into()));
    }
    let raw = fs::read(&path).map_err(|e| BackupError::Io(e.to_string()))?;
    let manifest: BackupManifest =
        serde_json::from_slice(&raw).map_err(|e| BackupError::Corrupt(e.to_string()))?;
    verify_written_artifact(published_dir, &manifest)?;
    Ok(manifest)
}

/// Manifest-only helper retained for unit tests that fabricate staging by hand.
pub fn stage_manifest(
    staging_dir: &Path,
    manifest: &BackupManifest,
    backup_id: &str,
) -> Result<StagedBackup> {
    use crate::digest::write_json_atomic;

    if staging_dir.exists() {
        return Err(BackupError::AlreadyExists);
    }
    let parent = staging_dir
        .parent()
        .ok_or(BackupError::Io("staging parent missing".into()))?;
    let publish_parent = parent
        .parent()
        .ok_or(BackupError::Io("backups root missing".into()))?;
    let publish_dir = publish_parent.join(format!("{STAGE_DIR_PREFIX}{backup_id}"));
    if publish_dir.exists() {
        return Err(BackupError::AlreadyExists);
    }

    // Incomplete layout on purpose for 7.8.2-style tests — verify_staged will fail
    // unless a full writer tree is present. Prefer DefaultBackupWriter for real stages.
    fs::create_dir_all(staging_dir).map_err(|e| BackupError::Io(e.to_string()))?;
    for sub in ["journal", "catalog", "storage", "recovery"] {
        fs::create_dir_all(staging_dir.join(sub)).map_err(|e| BackupError::Io(e.to_string()))?;
    }
    write_json_atomic(&staging_dir.join(MANIFEST_FILE), manifest)?;
    Ok(StagedBackup {
        backup_id: backup_id.to_string(),
        staging_dir: staging_dir.to_path_buf(),
        publish_dir,
        manifest: manifest.clone(),
    })
}
