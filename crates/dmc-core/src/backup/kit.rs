//! Disaster-recovery kit for remote (BackupSAS) backups.
//!
//! Everything needed to reach and decrypt remote backups from a fresh host,
//! **except the Master Key**, which stays with the existing Master Key
//! mechanism (KeyPass / USB). Contents:
//!
//! * vault salt (public; needed with the Master Key to derive data keys),
//! * the Avrora BackupSAS client identity — public key in clear, secret key
//!   sealed with AES-256-GCM under a Master-Key-derived wrapping key,
//! * BackupSAS targets (signed public descriptors), backup catalog and policy.
//!
//! No enrollment secrets, no Master Key and no data keys are written.

use std::fs;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use backupsas_core::{Identity, ParticipantId, PublicKey, SecretKey};
use dmc_vault::KeyMaterial;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::keys::{KeySource, backup_key_from_master, vault_salt};
use super::{BackupError, Result};
use crate::control::backup_catalog::{self, BackupCatalog};
use crate::control::backup_config::{self, BackupConfig};
use crate::control::backup_targets::{self, BackupTargets};

pub const KIT_FORMAT: &str = "avrora-backup-kit/v1";
/// Key label for sealing the identity secret (same HKDF chain as data keys).
pub const KIT_WRAP_KEY_ID: &str = "avrora:kit-wrap-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSecret {
    pub alg: String,
    pub key_id: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KitIdentity {
    pub id: String,
    pub public_key: PublicKey,
    pub secret_key: SealedSecret,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RecoveryKit {
    pub format: String,
    pub created_at: String,
    /// Vault key-tree salt (hex). Not secret; useless without the Master Key.
    pub vault_salt: String,
    pub key_derivation: String,
    /// Key labels used by catalogued backups plus the current one.
    pub backup_key_ids: Vec<String>,
    pub identity: KitIdentity,
    pub targets: BackupTargets,
    pub catalog: BackupCatalog,
    pub backup_config: BackupConfig,
}

fn aad(id: &str, salt_hex: &str) -> Vec<u8> {
    format!("{KIT_FORMAT}\0{id}\0{salt_hex}").into_bytes()
}

fn identity_key_path(control_dir: &Path) -> PathBuf {
    backup_targets::identity_dir(control_dir).join("identity.key")
}

/// Build a kit. `keys` must be able to derive Master-Key-based keys (unlocked
/// vault or Master Key supplied offline).
pub async fn export_kit(
    keys: &KeySource<'_>,
    control_dir: &Path,
    db_path: &Path,
) -> Result<RecoveryKit> {
    let salt = vault_salt(db_path)?;
    let salt_hex = hex::encode(salt);
    if let KeySource::Offline { salt: given, .. } = keys
        && *given != salt
    {
        return Err(BackupError::Invalid(
            "master key source uses a different vault salt".into(),
        ));
    }
    let identity = backup_targets::load_or_create_identity(control_dir).map_err(BackupError::Io)?;
    let secret_hex = Zeroizing::new(
        fs::read_to_string(identity_key_path(control_dir))
            .map_err(|e| BackupError::Io(e.to_string()))?,
    );
    let secret = Zeroizing::new(
        hex::decode(secret_hex.trim())
            .map_err(|_| BackupError::Invalid("identity.key is not hex".into()))?,
    );

    let wrap = keys.derive(KIT_WRAP_KEY_ID).await?;
    let cipher =
        Aes256Gcm::new_from_slice(wrap.as_slice()).map_err(|e| BackupError::Io(e.to_string()))?;
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let id = identity.id.to_string();
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: secret.as_slice(),
                aad: &aad(&id, &salt_hex),
            },
        )
        .map_err(|_| BackupError::Io("kit sealing failed".into()))?;

    let mut targets = backup_targets::load_or_init(control_dir).map_err(BackupError::Io)?;
    targets.vault_salt = Some(salt_hex.clone());
    let catalog = backup_catalog::load(control_dir).map_err(BackupError::Io)?;
    let backup_config = backup_config::load(control_dir).map_err(BackupError::Io)?;
    let mut key_ids: Vec<String> = catalog
        .entries
        .iter()
        .flat_map(|e| e.locations.iter().filter_map(|l| l.key_id.clone()))
        .chain(std::iter::once(super::remote::current_key_id(control_dir)))
        .collect();
    key_ids.sort();
    key_ids.dedup();

    Ok(RecoveryKit {
        format: KIT_FORMAT.into(),
        created_at: backup_targets::now_rfc3339(),
        vault_salt: salt_hex,
        key_derivation: "HKDF-SHA256(metadata_kek(master, salt), salt, \"backup/\" + key_id)"
            .into(),
        backup_key_ids: key_ids,
        identity: KitIdentity {
            id,
            public_key: identity.public_key,
            secret_key: SealedSecret {
                alg: "aes-256-gcm".into(),
                key_id: KIT_WRAP_KEY_ID.into(),
                nonce: hex::encode(nonce),
                ciphertext: hex::encode(ciphertext),
            },
        },
        targets,
        catalog,
        backup_config,
    })
}

/// Write the kit with owner-only permissions.
pub fn write_kit(path: &Path, kit: &RecoveryKit) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let json = serde_json::to_vec_pretty(kit).map_err(|e| BackupError::Io(e.to_string()))?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, json).map_err(|e| BackupError::Io(e.to_string()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
        .map_err(|e| BackupError::Io(e.to_string()))?;
    fs::rename(&tmp, path).map_err(|e| BackupError::Io(e.to_string()))
}

pub fn read_kit(path: &Path) -> Result<RecoveryKit> {
    let raw = fs::read(path).map_err(|e| BackupError::Io(format!("{}: {e}", path.display())))?;
    let kit: RecoveryKit =
        serde_json::from_slice(&raw).map_err(|e| BackupError::Invalid(format!("kit: {e}")))?;
    if kit.format != KIT_FORMAT {
        return Err(BackupError::Invalid(format!(
            "unsupported kit format `{}`",
            kit.format
        )));
    }
    Ok(kit)
}

#[derive(Clone, Debug, Serialize)]
pub struct ImportReport {
    pub identity: String,
    pub targets: Vec<String>,
    pub catalog_entries: usize,
    pub wrote_backup_config: bool,
}

/// Restore identity, targets, catalog and (if absent) policy from a kit.
/// The Master Key proves possession by unsealing the identity.
pub fn import_kit(
    control_dir: &Path,
    kit: &RecoveryKit,
    master: &KeyMaterial,
    force: bool,
) -> Result<ImportReport> {
    let salt_vec =
        hex::decode(&kit.vault_salt).map_err(|_| BackupError::Invalid("kit vault_salt".into()))?;
    let salt: [u8; 32] = salt_vec
        .try_into()
        .map_err(|_| BackupError::Invalid("kit vault_salt must be 32 bytes".into()))?;
    let sealed = &kit.identity.secret_key;
    if sealed.alg != "aes-256-gcm" {
        return Err(BackupError::Invalid(format!(
            "unsupported kit seal `{}`",
            sealed.alg
        )));
    }
    let wrap = backup_key_from_master(master, &salt, &sealed.key_id);
    let cipher =
        Aes256Gcm::new_from_slice(wrap.as_slice()).map_err(|e| BackupError::Io(e.to_string()))?;
    let nonce = hex::decode(&sealed.nonce).map_err(|_| BackupError::Invalid("kit nonce".into()))?;
    if nonce.len() != 12 {
        return Err(BackupError::Invalid("kit nonce".into()));
    }
    let ct = hex::decode(&sealed.ciphertext)
        .map_err(|_| BackupError::Invalid("kit ciphertext".into()))?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ct,
                    aad: &aad(&kit.identity.id, &kit.vault_salt),
                },
            )
            .map_err(|_| BackupError::Invalid("wrong master key or corrupted kit".into()))?,
    );
    let bytes: [u8; 32] = plain
        .as_slice()
        .try_into()
        .map_err(|_| BackupError::Invalid("kit identity key length".into()))?;
    let secret = SecretKey::from_bytes(bytes);
    if secret.public_key() != kit.identity.public_key {
        return Err(BackupError::Invalid(
            "kit identity key does not match public key".into(),
        ));
    }
    let id: ParticipantId = kit
        .identity
        .id
        .parse()
        .map_err(|_| BackupError::Invalid("kit identity id".into()))?;
    if !matches!(id, ParticipantId::Client(_)) {
        return Err(BackupError::Invalid(
            "kit identity must be a client identity".into(),
        ));
    }
    for t in &kit.targets.targets {
        if let backup_targets::TargetKind::Backupsas { descriptor, .. } = &t.kind {
            descriptor
                .verify()
                .map_err(|e| BackupError::Invalid(format!("target `{}`: {e}", t.id)))?;
        }
    }

    let id_dir = backup_targets::identity_dir(control_dir);
    if id_dir.join("identity.key").is_file() {
        let existing = Identity::load(&id_dir).map_err(|e| BackupError::Io(e.to_string()))?;
        if existing.public_key != kit.identity.public_key && !force {
            return Err(BackupError::Invalid(
                "a different BackupSAS identity already exists (use --force to replace)".into(),
            ));
        }
    }
    Identity::from_parts(id, secret)
        .save(&id_dir)
        .map_err(|e| BackupError::Io(e.to_string()))?;

    let existing = backup_targets::load(control_dir).map_err(BackupError::Io)?;
    if backup_targets::targets_path(control_dir).is_file()
        && !existing.targets.is_empty()
        && existing.targets != kit.targets.targets
        && !force
    {
        return Err(BackupError::Invalid(
            "backup targets already configured (use --force to replace)".into(),
        ));
    }
    let mut targets = kit.targets.clone();
    targets.vault_salt = Some(kit.vault_salt.clone());
    backup_targets::save(control_dir, &targets).map_err(BackupError::Io)?;

    let mut catalog = backup_catalog::load(control_dir).map_err(BackupError::Io)?;
    for entry in kit.catalog.entries.iter().cloned() {
        catalog.upsert(entry);
    }
    backup_catalog::save(control_dir, &catalog).map_err(BackupError::Io)?;

    let wrote_backup_config = !backup_config::config_path(control_dir).is_file();
    if wrote_backup_config {
        // Keep the policy but do not start scheduling on the recovery host.
        let mut cfg = kit.backup_config.clone();
        cfg.schedule.enabled = false;
        backup_config::save(control_dir, &cfg).map_err(BackupError::Io)?;
    }

    Ok(ImportReport {
        identity: kit.identity.id.clone(),
        targets: targets.targets.iter().map(|t| t.id.clone()).collect(),
        catalog_entries: catalog.entries.len(),
        wrote_backup_config,
    })
}

/// Vault salt recorded by a kit import (for offline restores on a new host).
pub fn imported_salt(control_dir: &Path) -> Result<Option<[u8; 32]>> {
    let targets = backup_targets::load(control_dir).map_err(BackupError::Io)?;
    let Some(hex_salt) = targets.vault_salt else {
        return Ok(None);
    };
    let bytes = hex::decode(hex_salt).map_err(|_| BackupError::Invalid("vault_salt".into()))?;
    Ok(Some(bytes.try_into().map_err(|_| {
        BackupError::Invalid("vault_salt must be 32 bytes".into())
    })?))
}
