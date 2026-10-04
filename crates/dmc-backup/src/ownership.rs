//! Optional `ownership/` backup component for CLIENT_OWNED data.
//!
//! Carries the key directory (`client/client-directory.json`: public keys, HPKE
//! envelopes, grants) and the sealed-column rules. All of it is public or wrapped: a
//! backup operator gains nothing that opens CLIENT_OWNED data. Files are listed in the
//! manifest with SHA-256 digests, so `verify_backup` detects tampering or loss.

use std::fs;
use std::path::Path;

use dmc_materialized::protect::{SEALED_COLUMNS_FILE, SealedColumnRule, save_sealed_columns};

use crate::digest::{copy_dir_all, sha256_file, write_json_atomic};
use crate::error::{BackupError, Result};
use crate::manifest::{BackupFileEntry, BackupFileRole, BackupManifest, MANIFEST_FILE};

pub const OWNERSHIP_DIR: &str = "ownership";

fn io(e: impl std::fmt::Display) -> BackupError {
    BackupError::Io(e.to_string())
}

fn list_files(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(dir).map_err(io)? {
        let path = entry.map_err(io)?.path();
        if path.is_dir() {
            list_files(root, &path, out)?;
        } else {
            let rel = path.strip_prefix(root).map_err(io)?;
            out.push(
                rel.components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/"),
            );
        }
    }
    Ok(())
}

/// Copy the ownership component into a staged backup and extend the manifest.
pub(crate) fn attach(
    staging: &Path,
    mut manifest: BackupManifest,
    ownership_dir: Option<&Path>,
    sealed_columns: &[SealedColumnRule],
) -> Result<BackupManifest> {
    let has_dir = ownership_dir.is_some_and(Path::is_dir);
    if !has_dir && sealed_columns.is_empty() {
        return Ok(manifest);
    }
    let dst = staging.join(OWNERSHIP_DIR);
    fs::create_dir_all(&dst).map_err(io)?;
    if let Some(src) = ownership_dir.filter(|p| p.is_dir()) {
        copy_dir_all(src, &dst)?;
    }
    if !sealed_columns.is_empty() {
        save_sealed_columns(&dst, sealed_columns).map_err(|e| BackupError::Io(e.to_string()))?;
    }
    let mut rels = Vec::new();
    list_files(staging, &dst, &mut rels)?;
    rels.sort();
    for rel in rels {
        let (size, checksum_sha256) = sha256_file(&staging.join(&rel))?;
        manifest.files.push(BackupFileEntry {
            relative_path: rel,
            role: BackupFileRole::Ownership,
            size,
            checksum_sha256,
        });
    }
    write_json_atomic(&staging.join(MANIFEST_FILE), &manifest)?;
    Ok(manifest)
}

/// After recovery: rules next to the rows (enforced again), key directory beside them.
pub(crate) fn install_into_live(target: &Path, live_stage: &Path) -> Result<()> {
    let src = target.join(OWNERSHIP_DIR);
    if !src.is_dir() {
        return Ok(());
    }
    let rules = src.join(SEALED_COLUMNS_FILE);
    if rules.is_file() {
        let rows = live_stage.join("rows");
        fs::create_dir_all(&rows).map_err(io)?;
        fs::copy(&rules, rows.join(SEALED_COLUMNS_FILE)).map_err(io)?;
    }
    copy_dir_all(&src, &live_stage.join(OWNERSHIP_DIR))
}
