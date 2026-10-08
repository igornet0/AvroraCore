//! D4-A stage 4.5 — encrypted backup artifacts.
//!
//! An encrypted backup (`manifest.encrypted`) holds only ciphertext for everything that
//! carries values or credentials, sealed with the installation's storage keys:
//!
//! | file | purpose | bound to |
//! |---|---|---|
//! | `journal/segments/*.json` | `Events` | database ‖ backup id ‖ N ‖ path |
//! | `catalog/catalog.json` | `Snapshot` | database ‖ backup id ‖ N ‖ path |
//! | `ownership/identities.json` | `Snapshot` | database ‖ backup id ‖ N ‖ path |
//! | `manifest.sealed` (copy of `manifest.json`) | `Snapshot` | database ‖ backup id ‖ N |
//! | `storage/tables/*/segments/*.dat` | `Rows` (live format, per record) | table ‖ segment ‖ offset |
//!
//! `manifest.sealed` authenticates the plaintext `manifest.json`, and with it every file
//! digest it lists: with keys, a changed, swapped, missing or foreign file is detected
//! even when the plaintext digests were recomputed. Without keys only structure and
//! digests are checked; content checks need the keys (and never write plaintext).
//!
//! Read rules (same as the live D4-A files): sealed + keys → decrypt; sealed + no keys →
//! content deferred (verification) or "storage keys required" (recovery); plaintext +
//! keys → "explicit migration required"; plaintext + no keys → plaintext (dev/test).

use std::path::Path;

use dmc_vault::storage_cipher::{file_context, looks_sealed};
use dmc_vault::{StorageCipher, StoragePurpose};
use zeroize::Zeroizing;

use crate::digest::write_bytes_atomic;
use crate::error::{BackupError, Result};
use crate::manifest::BackupManifest;

/// Authenticated copy of `manifest.json` in an encrypted backup.
pub const SEALED_MANIFEST_FILE: &str = "manifest.sealed";
/// Ownership file holding credential verifiers — sealed in encrypted backups.
pub const SEALED_OWNERSHIP_FILES: &[&str] = &["ownership/identities.json"];

const MANIFEST_CONTEXT: &str = "manifest.json";

/// Sealing context of a backup file.
pub fn backup_context(database_id: &str, backup_id: &str, n: u64, relative_path: &str) -> String {
    format!("backup/{database_id}/{backup_id}/{n}/{relative_path}")
}

/// Storage keys bound to one backup identity.
#[derive(Clone, Copy)]
pub(crate) struct BackupKeys<'a> {
    cipher: &'a StorageCipher,
    database_id: &'a str,
    backup_id: &'a str,
    n: u64,
}

impl<'a> BackupKeys<'a> {
    pub(crate) fn new(
        cipher: &'a StorageCipher,
        database_id: &'a str,
        backup_id: &'a str,
        n: u64,
    ) -> Self {
        Self {
            cipher,
            database_id,
            backup_id,
            n,
        }
    }

    pub(crate) fn for_manifest(cipher: &'a StorageCipher, manifest: &'a BackupManifest) -> Self {
        Self::new(
            cipher,
            &manifest.database_id,
            &manifest.backup_id,
            manifest.checkpoint_sequence,
        )
    }

    fn context(&self, relative_path: &str) -> Vec<u8> {
        file_context(&backup_context(
            self.database_id,
            self.backup_id,
            self.n,
            relative_path,
        ))
    }

    pub(crate) fn seal(
        &self,
        purpose: StoragePurpose,
        relative_path: &str,
        plain: &[u8],
    ) -> Result<Vec<u8>> {
        self.cipher
            .seal(purpose, &self.context(relative_path), plain)
            .map_err(|e| BackupError::Io(format!("seal {relative_path}: {e}")))
    }

    fn open(
        &self,
        purpose: StoragePurpose,
        relative_path: &str,
        raw: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.cipher
            .open(purpose, &self.context(relative_path), raw)
            .map(Zeroizing::new)
            .map_err(|_| {
                BackupError::Corrupt(format!(
                    "backup component {relative_path} cannot be decrypted \
                     (wrong key, tampered, or from another backup)"
                ))
            })
    }
}

/// Purpose a backup file is sealed with.
pub(crate) fn purpose_for(relative_path: &str) -> StoragePurpose {
    if relative_path.starts_with("journal/segments/") {
        StoragePurpose::Events
    } else {
        StoragePurpose::Snapshot
    }
}

/// Write `plain` at `relative_path` under `root`: sealed with `keys`, else as is.
/// The temporary file holds the same bytes as the final one (never plaintext when sealed).
pub(crate) fn write_component(
    root: &Path,
    relative_path: &str,
    plain: &[u8],
    keys: Option<&BackupKeys<'_>>,
) -> Result<()> {
    let path = root.join(relative_path);
    match keys {
        Some(k) => write_bytes_atomic(
            &path,
            &k.seal(purpose_for(relative_path), relative_path, plain)?,
        ),
        None => write_bytes_atomic(&path, plain),
    }
}

/// Decode a component per the read rules. `Ok(None)`: sealed and no keys (content check
/// deferred). `encrypted` is the manifest's declaration; a file that contradicts it fails.
pub(crate) fn decode_component(
    raw: &[u8],
    relative_path: &str,
    encrypted: bool,
    keys: Option<&BackupKeys<'_>>,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let sealed = looks_sealed(raw);
    if sealed != encrypted {
        return Err(BackupError::Corrupt(if encrypted {
            format!("encrypted backup holds plaintext component {relative_path}")
        } else {
            format!("plaintext backup holds sealed component {relative_path}")
        }));
    }
    match (sealed, keys) {
        (true, Some(k)) => k
            .open(purpose_for(relative_path), relative_path, raw)
            .map(Some),
        (true, None) => Ok(None),
        (false, Some(_)) => Err(BackupError::Corrupt(format!(
            "plaintext backup component {relative_path} on encrypted storage: \
             explicit migration required"
        ))),
        (false, None) => Ok(Some(Zeroizing::new(raw.to_vec()))),
    }
}

/// Read and parse a JSON component (see [`decode_component`]).
pub(crate) fn read_component<T: serde::de::DeserializeOwned>(
    root: &Path,
    relative_path: &str,
    encrypted: bool,
    keys: Option<&BackupKeys<'_>>,
) -> Result<Option<T>> {
    let path = root.join(relative_path);
    if !path.is_file() {
        return Err(BackupError::Corrupt(format!("missing {relative_path}")));
    }
    let raw = std::fs::read(&path).map_err(|e| BackupError::Io(e.to_string()))?;
    match decode_component(&raw, relative_path, encrypted, keys)? {
        Some(plain) => serde_json::from_slice(&plain)
            .map(Some)
            .map_err(|e| BackupError::Corrupt(format!("{relative_path}: {e}"))),
        None => Ok(None),
    }
}

/// Write (or rewrite) `manifest.sealed` for `manifest`.
pub(crate) fn write_sealed_manifest(
    root: &Path,
    manifest: &BackupManifest,
    keys: &BackupKeys<'_>,
) -> Result<()> {
    let plain = Zeroizing::new(
        serde_json::to_vec(manifest).map_err(|e| BackupError::Validation(e.to_string()))?,
    );
    let sealed = keys.seal(StoragePurpose::Snapshot, MANIFEST_CONTEXT, &plain)?;
    write_bytes_atomic(&root.join(SEALED_MANIFEST_FILE), &sealed)
}

/// Keyless check: an encrypted backup has a sealed `manifest.sealed`; a plaintext one has none.
pub(crate) fn check_sealed_manifest_presence(root: &Path, manifest: &BackupManifest) -> Result<()> {
    let path = root.join(SEALED_MANIFEST_FILE);
    match (manifest.encrypted, path.is_file()) {
        (true, false) => Err(BackupError::Corrupt(format!(
            "encrypted backup missing {SEALED_MANIFEST_FILE}"
        ))),
        (false, true) => Err(BackupError::Corrupt(format!(
            "plaintext backup holds {SEALED_MANIFEST_FILE}"
        ))),
        (true, true) => {
            let raw = std::fs::read(&path).map_err(|e| BackupError::Io(e.to_string()))?;
            if looks_sealed(&raw) {
                Ok(())
            } else {
                Err(BackupError::Corrupt(format!(
                    "{SEALED_MANIFEST_FILE} is not sealed"
                )))
            }
        }
        (false, false) => Ok(()),
    }
}

/// With keys: `manifest.json` must equal its authenticated copy, field for field (file
/// digests included). Binds the plaintext manifest to this backup identity.
pub(crate) fn authenticate_manifest(
    root: &Path,
    manifest: &BackupManifest,
    keys: &BackupKeys<'_>,
) -> Result<()> {
    let raw = std::fs::read(root.join(SEALED_MANIFEST_FILE))
        .map_err(|_| BackupError::Corrupt(format!("missing {SEALED_MANIFEST_FILE}")))?;
    let plain = keys.open(StoragePurpose::Snapshot, MANIFEST_CONTEXT, &raw)?;
    let authentic: serde_json::Value =
        serde_json::from_slice(&plain).map_err(|e| BackupError::Corrupt(e.to_string()))?;
    let on_disk =
        serde_json::to_value(manifest).map_err(|e| BackupError::Corrupt(e.to_string()))?;
    if authentic != on_disk {
        return Err(BackupError::Corrupt(
            "manifest.json does not match its authenticated copy".into(),
        ));
    }
    Ok(())
}
