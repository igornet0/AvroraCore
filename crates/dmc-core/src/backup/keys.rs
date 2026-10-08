//! Backup data-key derivation shared by the running vault and offline
//! disaster recovery, so both always produce the same key.
//!
//! `key = HKDF-SHA256(ikm = metadata_kek(master, salt), salt, "…/backup/" + key_id)`
//!
//! Keys are returned as [`BackupKey`] (wiped on drop, redacted `Debug`) and
//! never persisted.
//!
//! Invariants:
//! * the backup data key is **not** a vault DEK: rotating key-tree DEKs
//!   (`rotate_node`) does not change it;
//! * it depends on the Master Key (via the metadata KEK) and the vault salt.
//!   A future Master Key rotation must therefore either keep old Master Keys
//!   available for old backups or re-encrypt/migrate them, and re-export the
//!   recovery kit. Rotating `encryption.key_id` alone only changes the label
//!   for new backups.

use std::path::Path;

use dmc_journal::StorageLayout;
use dmc_vault::KeyMaterial;
use dmc_vault::crypto::{derive_child_key, derive_metadata_kek};
use dmc_vault::persist::DbSnapshot;
use zeroize::Zeroizing;

use super::{BackupError, Result};
use crate::runtime::Runtime;

/// 256-bit backup data key. Wiped on drop; `Debug` never shows the bytes.
pub struct BackupKey(Zeroizing<[u8; 32]>);

impl std::ops::Deref for BackupKey {
    type Target = [u8; 32];

    fn deref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for BackupKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BackupKey([redacted])")
    }
}

/// Derive from the metadata KEK held by an unlocked vault.
pub fn backup_key_from_kek(kek: &KeyMaterial, salt: &[u8], key_id: &str) -> BackupKey {
    let key = derive_child_key(kek, salt, &format!("backup/{key_id}"));
    BackupKey(Zeroizing::new(*key.as_bytes()))
}

/// Derive from the Master Key directly (vault not available, e.g. on a new host).
pub fn backup_key_from_master(master: &KeyMaterial, salt: &[u8], key_id: &str) -> BackupKey {
    backup_key_from_kek(&derive_metadata_kek(master, salt), salt, key_id)
}

/// Key-tree salt of the vault at `db_path` (readable while locked).
pub fn vault_salt(db_path: &Path) -> Result<[u8; 32]> {
    let layout = StorageLayout::from_db_path(db_path);
    let snapshot = [layout.base_snapshot(), layout.legacy_snapshot()]
        .into_iter()
        .find(|p| p.is_file())
        .ok_or_else(|| BackupError::Invalid("vault snapshot not found".into()))?;
    DbSnapshot::load(&snapshot)
        .and_then(|s| s.salt())
        .map_err(|e| BackupError::Invalid(format!("vault snapshot: {e}")))
}

/// Where the data key comes from.
pub enum KeySource<'a> {
    /// The running, unlocked vault.
    Runtime(&'a Runtime),
    /// Master Key + vault salt supplied by the operator (disaster recovery).
    Offline { master: KeyMaterial, salt: [u8; 32] },
}

impl KeySource<'_> {
    pub async fn derive(&self, key_id: &str) -> Result<BackupKey> {
        match self {
            Self::Runtime(rt) => rt
                .derive_backup_key(key_id)
                .await
                .map_err(|_| BackupError::VaultLocked),
            Self::Offline { master, salt } => Ok(backup_key_from_master(master, salt, key_id)),
        }
    }
}

impl std::fmt::Debug for KeySource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Runtime(_) => f.write_str("KeySource::Runtime"),
            Self::Offline { .. } => f.write_str("KeySource::Offline([redacted])"),
        }
    }
}

/// Parse a Master Key given as hex (file contents or stdin), trimming whitespace.
pub fn parse_master_hex(text: &str) -> Result<KeyMaterial> {
    let mut trimmed = Zeroizing::new(text.trim().to_string());
    let parsed = KeyMaterial::from_hex(&trimmed)
        .map_err(|_| BackupError::Invalid("master key must be 64 hex characters".into()));
    zeroize::Zeroize::zeroize(&mut *trimmed);
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn offline_derivation_matches_unlocked_vault() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("k.dbs.json");
        let rt = Runtime::at_path(&db_path);
        let (master_hex, _) = rt.create_dev(false).await.unwrap();
        let salt = vault_salt(&db_path).unwrap();
        let master = parse_master_hex(&master_hex).unwrap();

        let online = KeySource::Runtime(&rt).derive("k1").await.unwrap();
        let offline = KeySource::Offline { master, salt }
            .derive("k1")
            .await
            .unwrap();
        assert_eq!(*online, *offline);
        let other = KeySource::Runtime(&rt).derive("k2").await.unwrap();
        assert_ne!(*online, *other, "key ids are domain separated");
        assert_eq!(format!("{online:?}"), "BackupKey([redacted])");

        let wrong = KeySource::Offline {
            master: KeyMaterial::from_bytes([1u8; 32]),
            salt,
        };
        assert_ne!(*wrong.derive("k1").await.unwrap(), *online);
        assert_eq!(
            format!(
                "{:?}",
                KeySource::Offline {
                    master: KeyMaterial::from_bytes([9; 32]),
                    salt
                }
            ),
            "KeySource::Offline([redacted])"
        );
    }

    #[tokio::test]
    async fn locked_vault_cannot_derive() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("k.dbs.json");
        let rt = Runtime::at_path(&db_path);
        rt.create_dev(false).await.unwrap();
        rt.lock().await.unwrap();
        assert!(matches!(
            KeySource::Runtime(&rt).derive("k1").await,
            Err(BackupError::VaultLocked)
        ));
    }
}
