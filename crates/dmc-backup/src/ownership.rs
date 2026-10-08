//! Optional `ownership/` backup component for CLIENT_OWNED data.
//!
//! Carries the key directory (`client/client-directory.json`: public keys, HPKE
//! envelopes, grants) and the sealed-column rules. All of it is public or wrapped: a
//! backup operator gains nothing that opens CLIENT_OWNED data. Files are listed in the
//! manifest with SHA-256 digests, so `verify_backup` detects tampering or loss.
//!
//! D4-A: in an encrypted backup `identities.json` (password verifiers, grants) is sealed
//! and only unsealed, with the storage keys, when it is installed into a recovered tree.

use std::fs;
use std::path::Path;

use dmc_materialized::protect::{SEALED_COLUMNS_FILE, SealedColumnRule, save_sealed_columns};
use dmc_vault::StorageCipher;

use crate::digest::{copy_dir_all, sha256_file, write_bytes_atomic, write_json_atomic};
use crate::error::{BackupError, Result};
use crate::manifest::{BackupFileEntry, BackupFileRole, BackupManifest, MANIFEST_FILE};
use crate::sealed::{
    decode_component, write_component, write_sealed_manifest, BackupKeys, SEALED_OWNERSHIP_FILES,
};

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
    cipher: Option<&StorageCipher>,
) -> Result<BackupManifest> {
    if manifest.encrypted != cipher.is_some() {
        return Err(BackupError::Validation(
            "ownership component: storage keys do not match the artifact".into(),
        ));
    }
    let has_dir = ownership_dir.is_some_and(Path::is_dir);
    if !has_dir && sealed_columns.is_empty() {
        return Ok(manifest);
    }
    let dst = staging.join(OWNERSHIP_DIR);
    fs::create_dir_all(&dst).map_err(io)?;
    let (database_id, backup_id, n) = (
        manifest.database_id.clone(),
        manifest.backup_id.clone(),
        manifest.checkpoint_sequence,
    );
    let keys = cipher.map(|c| BackupKeys::new(c, &database_id, &backup_id, n));
    if let Some(src) = ownership_dir.filter(|p| p.is_dir()) {
        // Sealed files are never copied in clear: read from the source, written sealed.
        let skip: Vec<_> = match &keys {
            Some(_) => SEALED_OWNERSHIP_FILES.iter().map(|r| staging.join(r)).collect(),
            None => Vec::new(),
        };
        copy_dir_except(src, &dst, &skip)?;
        if let Some(k) = &keys {
            for rel in SEALED_OWNERSHIP_FILES {
                let from = src.join(rel.strip_prefix("ownership/").unwrap_or(rel));
                if from.is_file() {
                    let plain = zeroize::Zeroizing::new(fs::read(&from).map_err(io)?);
                    write_component(staging, rel, &plain, Some(k))?;
                }
            }
        }
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
    if let Some(k) = &keys {
        write_sealed_manifest(staging, &manifest, k)?;
    }
    Ok(manifest)
}

fn copy_dir_except(src: &Path, dst: &Path, skip: &[std::path::PathBuf]) -> Result<()> {
    fs::create_dir_all(dst).map_err(io)?;
    for entry in fs::read_dir(src).map_err(io)? {
        let entry = entry.map_err(io)?;
        let to = dst.join(entry.file_name());
        if skip.contains(&to) {
            continue;
        }
        let ty = entry.file_type().map_err(io)?;
        if ty.is_dir() {
            copy_dir_except(&entry.path(), &to, skip)?;
        } else if ty.is_file() {
            fs::copy(entry.path(), &to).map_err(io)?;
        }
    }
    Ok(())
}

/// After recovery: rules next to the rows (enforced again), key directory beside them.
/// Sealed ownership files are unsealed with the backup keys (as the live server keeps them).
pub(crate) fn install_into_live(
    target: &Path,
    live_stage: &Path,
    manifest: &BackupManifest,
    keys: Option<&BackupKeys<'_>>,
) -> Result<()> {
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
    copy_dir_all(&src, &live_stage.join(OWNERSHIP_DIR))?;
    if manifest.encrypted {
        for rel in SEALED_OWNERSHIP_FILES {
            let path = target.join(rel);
            if !path.is_file() {
                continue;
            }
            let raw = fs::read(&path).map_err(io)?;
            let plain = decode_component(&raw, rel, true, keys)?.ok_or_else(|| {
                BackupError::Corrupt(format!("{rel} is encrypted: storage keys required"))
            })?;
            write_bytes_atomic(&live_stage.join(rel), &plain)?;
        }
    }
    Ok(())
}
