//! D4-E — the installation's key store travels with an encrypted backup.
//!
//! `keystore/keytree.json` is a byte-for-byte copy of the live `vault/keytree.json`: salt,
//! unlock proof and DEKs **wrapped** under KEKs derived from the client-held Master Key.
//! It holds nothing that opens data without that Master Key — the same material already
//! lies next to the data in the live data root, so carrying it adds no trust assumption.
//!
//! It is listed in the manifest (role `key_store`, SHA-256), so `manifest.sealed`
//! authenticates it with the storage keys. Installing it into a restored data root needs
//! no keys (digest against the plaintext listing); a substituted copy is refused at unlock
//! (a foreign key store does not open with the client's Master Key) or at recovery (its
//! digest is not the authenticated one).

use std::fs;
use std::path::Path;

use dmc_vault::StorageCipher;

use crate::digest::{sha256_file, write_json_atomic};
use crate::error::{BackupError, Result};
use crate::manifest::{BackupFileEntry, BackupFileRole, BackupManifest, MANIFEST_FILE};
use crate::sealed::{BackupKeys, write_sealed_manifest};

/// Directory of the key-store component inside a backup / restored target.
pub const KEY_STORE_DIR: &str = "keystore";
/// The carried key store (wrapped key tree; no Master Key, KEK or plaintext DEK).
pub const KEY_STORE_FILE: &str = "keystore/keytree.json";

fn io(e: impl std::fmt::Display) -> BackupError {
    BackupError::Io(e.to_string())
}

/// Copy the key store into a staged **encrypted** backup and extend the manifest (and its
/// authenticated copy). A plaintext backup carries no key store (there are no keys).
pub(crate) fn attach(
    staging: &Path,
    mut manifest: BackupManifest,
    key_store: Option<&Path>,
    cipher: Option<&StorageCipher>,
) -> Result<BackupManifest> {
    let (Some(src), Some(cipher)) = (key_store, cipher) else {
        return Ok(manifest);
    };
    if !manifest.encrypted {
        return Err(BackupError::Validation(
            "key store component: storage keys do not match the artifact".into(),
        ));
    }
    let raw = fs::read(src)
        .map_err(|_| BackupError::Validation("key store of the installation is missing".into()))?;
    dmc_vault::parse_locked_key_tree(&raw).map_err(|_| {
        BackupError::Validation("key store of the installation is unreadable".into())
    })?;
    let dst = staging.join(KEY_STORE_FILE);
    fs::create_dir_all(staging.join(KEY_STORE_DIR)).map_err(io)?;
    dmc_vault::secure_fs::write_secret_file(&dst, &raw).map_err(io)?;
    let (size, checksum_sha256) = sha256_file(&dst)?;
    manifest.files.push(BackupFileEntry {
        relative_path: KEY_STORE_FILE.to_string(),
        role: BackupFileRole::KeyStore,
        size,
        checksum_sha256,
    });
    write_json_atomic(&staging.join(MANIFEST_FILE), &manifest)?;
    let keys = BackupKeys::for_manifest(cipher, &manifest);
    write_sealed_manifest(staging, &manifest, &keys)?;
    Ok(manifest)
}

/// The manifest's key-store entry, if any. Only an encrypted backup may carry one, at
/// exactly [`KEY_STORE_FILE`], once.
pub(crate) fn entry(manifest: &BackupManifest) -> Result<Option<&BackupFileEntry>> {
    let mut found = None;
    for e in manifest
        .files
        .iter()
        .filter(|f| f.role == BackupFileRole::KeyStore)
    {
        if e.relative_path != KEY_STORE_FILE || found.is_some() || !manifest.encrypted {
            return Err(BackupError::Corrupt("invalid key store entry".into()));
        }
        found = Some(e);
    }
    Ok(found)
}

/// Structural checks (no keys): the listed key store is a well-formed locked key tree, and
/// nothing unlisted sits in the key-store directory. Its digest is checked with the other
/// files, and authenticated with them when the keys are present.
pub(crate) fn verify(root: &Path, manifest: &BackupManifest, errors: &mut Vec<String>) {
    let listed = match entry(manifest) {
        Ok(e) => e,
        Err(e) => {
            errors.push(e.to_string());
            return;
        }
    };
    let dir = root.join(KEY_STORE_DIR);
    if dir.exists() {
        let unlisted = fs::read_dir(&dir).map_or(true, |it| {
            it.flatten()
                .any(|e| listed.is_none() || e.file_name() != "keytree.json")
        });
        if unlisted {
            errors.push("unlisted key store content".into());
        }
    }
    if listed.is_some() {
        let ok = fs::read(root.join(KEY_STORE_FILE))
            .ok()
            .is_some_and(|raw| dmc_vault::parse_locked_key_tree(&raw).is_ok());
        if !ok {
            errors.push("key store component is not a key store".into());
        }
    }
}

/// D4-E: install the key store carried by a restored target (`restored_root`, the data
/// root) at `dest` (its vault key store). Needs no keys: the copy must match the size and
/// digest the plaintext manifest lists and parse as a locked key tree; authenticity is
/// established at unlock (Master Key) and recovery (authenticated digest). Returns
/// `false` when the target carries no key store. Never replaces an existing key store.
pub fn install_key_store(restored_root: &Path, dest: &Path) -> Result<bool> {
    let manifest_path = restored_root.join(MANIFEST_FILE);
    if !manifest_path.is_file() {
        return Ok(false);
    }
    let raw = fs::read(&manifest_path).map_err(io)?;
    let manifest: BackupManifest =
        serde_json::from_slice(&raw).map_err(|e| BackupError::Corrupt(e.to_string()))?;
    let Some(listed) = entry(&manifest)? else {
        return Ok(false);
    };
    if dest.exists() {
        return Err(BackupError::Validation(
            "a key store is already installed".into(),
        ));
    }
    let src = restored_root.join(KEY_STORE_FILE);
    let (size, digest) = sha256_file(&src)?;
    if size != listed.size || digest != listed.checksum_sha256 {
        return Err(BackupError::Corrupt(
            "key store does not match the manifest".into(),
        ));
    }
    let key_store = fs::read(&src).map_err(io)?;
    dmc_vault::parse_locked_key_tree(&key_store)
        .map_err(|_| BackupError::Corrupt("key store component is not a key store".into()))?;
    if let Some(dir) = dest.parent() {
        fs::create_dir_all(dir).map_err(io)?;
    }
    dmc_vault::secure_fs::write_secret_file(dest, &key_store).map_err(io)?;
    Ok(true)
}

/// D4-E: after an authenticated recovery, the key store that unlocked the vault must be
/// byte-identical to the one the backup carries (whose digest recovery authenticated).
/// A target without a carried key store has nothing to compare.
pub fn ensure_key_store_matches(restored_root: &Path, key_store: &Path) -> Result<()> {
    let carried = restored_root.join(KEY_STORE_FILE);
    if !carried.is_file() {
        return Ok(());
    }
    let (a, b) = (
        fs::read(&carried).map_err(io)?,
        fs::read(key_store).map_err(io)?,
    );
    if a != b {
        return Err(BackupError::BackupInvalid(
            "installed key store is not the one the backup carries".into(),
        ));
    }
    Ok(())
}
