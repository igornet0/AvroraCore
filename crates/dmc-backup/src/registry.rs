//! D4-C — authoritative backup registry in the **encrypted live storage**.
//!
//! Every backup created by an installation with storage keys is recorded here:
//! `backup_id → { generation, sha256(manifest.sealed), N }`. The registry lives in the
//! live store (`<storage_root>/backup_registry.sealed`, sealed with the storage keys
//! through `sealed_io`) — never next to the backups, so whoever can rewrite `backups/`
//! cannot rewrite the registry with it.
//!
//! The registry generation is also written **inside** the backup's authenticated manifest
//! (`registry_generation`), so the backup and its registry entry name each other.
//!
//! Order of a backup: data → authenticated manifest → publish → registry entry. A backup
//! that never got its entry (crash, kill) is never accepted.
//!
//! Restore (registered) = keyed verification + registry match, then a sealed **restore
//! attestation** is written into the staged target before it becomes visible; recovery
//! (registered) requires that attestation and, where the live registry is reachable, the
//! registry entry as well. Any mismatch → refused (fail closed).
//!
//! Not covered here (D4-D): replacing the registry **and** the backup together with an
//! older consistent pair — that is a rollback of live storage as a whole.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use dmc_materialized::sealed_io::{decode_file, encode_file};
use dmc_vault::{StorageCipher, StoragePurpose};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::digest::{sha256_file, write_bytes_atomic};
use crate::error::{BackupError, Result};
use crate::manifest::BackupManifest;
use crate::sealed::SEALED_MANIFEST_FILE;

/// Registry file under the live storage root.
pub const REGISTRY_FILE: &str = "backup_registry.sealed";
const REGISTRY_CONTEXT: &str = "backup_registry";
/// Sealed restore attestation inside a restore target.
pub const ATTESTATION_FILE: &str = "recovery/registry-attestation.sealed";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub generation: u64,
    pub manifest_sealed_sha256: String,
    pub checkpoint_sequence: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupRegistry {
    /// Highest generation ever handed out (monotonic within this registry).
    pub generation: u64,
    pub entries: BTreeMap<String, RegistryEntry>,
}

fn corrupt(what: &str, e: impl std::fmt::Display) -> BackupError {
    BackupError::Corrupt(format!("{what}: {e}"))
}

/// SHA-256 of a backup's (or restore target's) `manifest.sealed`.
pub fn manifest_sealed_hash(dir: &Path) -> Result<String> {
    let path = dir.join(SEALED_MANIFEST_FILE);
    if !path.is_file() {
        return Err(BackupError::BackupInvalid(format!(
            "{SEALED_MANIFEST_FILE} missing"
        )));
    }
    Ok(sha256_file(&path)?.1)
}

impl BackupRegistry {
    pub fn path(storage_root: &Path) -> PathBuf {
        storage_root.join(REGISTRY_FILE)
    }

    /// Load (missing file → empty registry: nothing is registered, nothing is accepted).
    /// Tampered, truncated, plaintext or foreign-key registries are errors.
    pub fn load(storage_root: &Path, cipher: &StorageCipher) -> Result<Self> {
        let path = Self::path(storage_root);
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read(&path).map_err(|e| BackupError::Io(e.to_string()))?;
        let plain = decode_file(
            &raw,
            Some(cipher),
            StoragePurpose::Snapshot,
            REGISTRY_CONTEXT,
            "backup registry",
        )
        .map_err(|e| corrupt("backup registry", e))?;
        serde_json::from_slice(&plain).map_err(|e| corrupt("backup registry", e))
    }

    /// Atomic sealed write (temp file holds ciphertext only).
    pub fn save(&self, storage_root: &Path, cipher: &StorageCipher) -> Result<()> {
        let plain = Zeroizing::new(
            serde_json::to_vec(self).map_err(|e| BackupError::Validation(e.to_string()))?,
        );
        let sealed = encode_file(
            &plain,
            Some(cipher),
            StoragePurpose::Snapshot,
            REGISTRY_CONTEXT,
        )
        .map_err(|e| corrupt("backup registry", e))?;
        write_bytes_atomic(&Self::path(storage_root), &sealed)
    }

    pub fn next_generation(&self) -> u64 {
        self.generation + 1
    }

    pub fn register(&mut self, backup_id: &str, entry: RegistryEntry) {
        self.generation = self.generation.max(entry.generation);
        self.entries.insert(backup_id.to_string(), entry);
    }

    /// The backup in `dir` (described by its authenticated `manifest`) is exactly the one
    /// this installation registered under `manifest.backup_id`.
    pub fn confirm(&self, dir: &Path, manifest: &BackupManifest) -> Result<RegistryEntry> {
        let entry = self.entries.get(&manifest.backup_id).ok_or_else(|| {
            BackupError::BackupInvalid("backup is not in this installation's registry".into())
        })?;
        if entry.generation != manifest.registry_generation
            || entry.checkpoint_sequence != manifest.checkpoint_sequence
        {
            return Err(BackupError::BackupInvalid(
                "backup version does not match the registry".into(),
            ));
        }
        if manifest_sealed_hash(dir)? != entry.manifest_sealed_sha256 {
            return Err(BackupError::BackupInvalid(
                "backup manifest does not match the registry (replaced or tampered)".into(),
            ));
        }
        Ok(entry.clone())
    }
}

/// What a registered restore vouches for (sealed into the restore target).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct RestoreAttestation {
    backup_id: String,
    generation: u64,
    manifest_sealed_sha256: String,
}

fn attestation_context(backup_id: &str) -> String {
    format!("restore-attestation/{backup_id}")
}

pub(crate) fn write_attestation(
    target: &Path,
    backup_id: &str,
    entry: &RegistryEntry,
    cipher: &StorageCipher,
) -> Result<()> {
    let att = RestoreAttestation {
        backup_id: backup_id.to_string(),
        generation: entry.generation,
        manifest_sealed_sha256: entry.manifest_sealed_sha256.clone(),
    };
    let plain = serde_json::to_vec(&att).map_err(|e| BackupError::Validation(e.to_string()))?;
    let sealed = encode_file(
        &plain,
        Some(cipher),
        StoragePurpose::Snapshot,
        &attestation_context(backup_id),
    )
    .map_err(|e| corrupt("restore attestation", e))?;
    write_bytes_atomic(&target.join(ATTESTATION_FILE), &sealed)
}

/// The restore target carries a valid attestation for exactly its `manifest.sealed`.
pub(crate) fn check_attestation(
    target: &Path,
    manifest: &BackupManifest,
    cipher: &StorageCipher,
) -> Result<()> {
    let path = target.join(ATTESTATION_FILE);
    let raw = std::fs::read(&path).map_err(|_| {
        BackupError::BackupInvalid("restore target is not attested by the backup registry".into())
    })?;
    let plain = decode_file(
        &raw,
        Some(cipher),
        StoragePurpose::Snapshot,
        &attestation_context(&manifest.backup_id),
        "restore attestation",
    )
    .map_err(|_| {
        BackupError::BackupInvalid("restore attestation invalid (tampered or foreign)".into())
    })?;
    let att: RestoreAttestation =
        serde_json::from_slice(&plain).map_err(|e| corrupt("restore attestation", e))?;
    if att.backup_id != manifest.backup_id
        || att.generation != manifest.registry_generation
        || att.manifest_sealed_sha256 != manifest_sealed_hash(target)?
    {
        return Err(BackupError::BackupInvalid(
            "restore target does not match its attestation".into(),
        ));
    }
    Ok(())
}

/// D4-E (variant B) — emergency restore on a host without the source installation's
/// registry. Accepted **only** for the artifact the client authorized: `authorized` is the
/// SHA-256 of `manifest.sealed` the client stored when the backup was created and sent
/// inside the AEAD of its unlock blob. Checked here, with the storage keys of the carried
/// key store: exact `manifest.sealed` hash, encrypted artifact carrying its key store, full
/// authenticated verification (manifest, every file digest, key store), authenticated
/// checkpoint not below the client's anchor `min_generation`. Then the target
/// receives the same sealed attestation a registered restore writes (or an existing one
/// must be valid), so recovery proceeds exactly as for a registered restore. Another
/// backup of the same installation — same Master Key, other hash — is refused.
pub fn authorize_emergency_restore(
    target: &Path,
    cipher: &StorageCipher,
    authorized: &[u8; 32],
    min_generation: u64,
) -> Result<()> {
    let raw = std::fs::read(target.join(crate::manifest::MANIFEST_FILE))
        .map_err(|e| BackupError::Io(e.to_string()))?;
    let manifest: BackupManifest =
        serde_json::from_slice(&raw).map_err(|e| corrupt("backup manifest", e))?;
    if !manifest.encrypted {
        return Err(BackupError::BackupInvalid(
            "unencrypted backup: explicit migration required".into(),
        ));
    }
    let actual = manifest_sealed_hash(target)?;
    if actual != hex::encode(authorized) {
        return Err(BackupError::BackupInvalid(
            "restore target is not the backup this client authorized".into(),
        ));
    }
    if crate::keystore::entry(&manifest)?.is_none() {
        return Err(BackupError::BackupInvalid(
            "emergency restore requires the backup's carried key store".into(),
        ));
    }
    crate::verify::verify_backup_with(target, Some(cipher))?
        .ensure_valid()
        .map_err(|e| BackupError::BackupInvalid(e.to_string()))?;
    // D4-D on this path, before anything is written: the authenticated checkpoint is what
    // the restored store will be.
    if manifest.checkpoint_sequence < min_generation {
        return Err(BackupError::OlderThanAnchor {
            checkpoint: manifest.checkpoint_sequence,
            min_generation,
        });
    }
    if target.join(ATTESTATION_FILE).exists() {
        return check_attestation(target, &manifest, cipher);
    }
    let entry = RegistryEntry {
        generation: manifest.registry_generation,
        manifest_sealed_sha256: actual,
        checkpoint_sequence: manifest.checkpoint_sequence,
    };
    write_attestation(target, &manifest.backup_id, &entry, cipher)
}
