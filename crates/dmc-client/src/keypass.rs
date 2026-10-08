//! Opaque client-side KeyPass handle. Never crosses the Tauri/UI boundary as Master Key.

use std::path::{Path, PathBuf};

use crate::control::ControlClient;
use crate::error::{ClientError, Result};
use crate::types::{BackupCreateResult, VaultState};
use crate::{
    KeyPassError, KeyPassProvider, MockKeyPassProvider, PasswordKeyPassProvider, UnlockMaterial,
};
use dmc_server::{load_keypass_bundle, KeyPassBundle};

/// D4-D: the client's anti-rollback anchor, kept next to its KeyPass: the highest storage
/// generation this client has seen for the installation (one decimal number).
pub const ANCHOR_FILE: &str = "anchor";

/// D4-E (variant B): the client's backup anchor, kept next to its KeyPass — exactly **one**
/// backup this client authorizes for an emergency restore: `<backup_id> <N> <sha256 hex of
/// manifest.sealed>`. Written only from a `BackupCreate` this client made.
pub const BACKUP_ANCHOR_FILE: &str = "backup-anchor";

/// The one backup artifact a client authorizes for an emergency restore.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupAnchor {
    pub backup_id: String,
    pub checkpoint_sequence: u64,
    pub manifest_sealed_sha256: [u8; 32],
}

impl BackupAnchor {
    fn parse(raw: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(raw).ok()?;
        let mut parts = text.split_whitespace();
        let (id, n, hash) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() || id.is_empty() {
            return None;
        }
        Some(Self {
            backup_id: id.to_string(),
            checkpoint_sequence: n.parse().ok()?,
            manifest_sealed_sha256: hex::decode(hash).ok()?.try_into().ok()?,
        })
    }

    fn render(&self) -> String {
        format!(
            "{} {} {}\n",
            self.backup_id,
            self.checkpoint_sequence,
            hex::encode(self.manifest_sealed_sha256)
        )
    }
}

/// Rust-side KeyPass material for `vault_unlock`. UI only supplies a password string.
pub struct KeyPassHandle {
    kind: KeyPassKind,
    /// KeyPass directory (holds the D4-D anchor); `None`: no anchor is kept.
    dir: Option<PathBuf>,
}

enum KeyPassKind {
    Password(KeyPassBundle),
    Mock(UnlockMaterial),
}

impl KeyPassHandle {
    /// Wrap Master Key into a password KeyPass bundle (client-only).
    pub fn password_wrap(
        master: &UnlockMaterial,
        password: &str,
        db_id: &str,
    ) -> std::result::Result<Self, KeyPassError> {
        let provider = PasswordKeyPassProvider::wrap_master(master, password, db_id)?;
        Ok(Self::from_password_bundle(provider.into_bundle()))
    }

    /// Install an existing password KeyPass bundle (loaded from disk later).
    pub fn from_password_bundle(bundle: KeyPassBundle) -> Self {
        Self {
            kind: KeyPassKind::Password(bundle),
            dir: None,
        }
    }

    /// Load sealed KeyPass directory (no Master Key until unlock password is supplied).
    /// The directory also keeps this client's D4-D anti-rollback anchor.
    pub fn load_from_dir(dir: impl AsRef<Path>) -> std::result::Result<Self, KeyPassError> {
        let bundle = load_keypass_bundle(dir.as_ref())?;
        let mut handle = Self::from_password_bundle(bundle);
        handle.dir = Some(dir.as_ref().to_path_buf());
        Ok(handle)
    }

    /// Test / lab only — never expose UnlockMaterial to TypeScript.
    pub fn mock_for_tests(material: UnlockMaterial) -> Self {
        Self {
            kind: KeyPassKind::Mock(material),
            dir: None,
        }
    }

    /// Keep the D4-D anchor in `dir` (tests / handles not loaded from a directory).
    pub fn with_anchor_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.dir = Some(dir.into());
        self
    }

    /// The anchor: highest storage generation seen (0 without one). A corrupt anchor file
    /// is an error, never silently 0 (that would disable the rollback check).
    pub fn anchor(&self) -> Result<u64> {
        let Some(dir) = &self.dir else { return Ok(0) };
        match std::fs::read(dir.join(ANCHOR_FILE)) {
            Ok(raw) => std::str::from_utf8(&raw)
                .ok()
                .and_then(|t| t.trim().parse::<u64>().ok())
                .ok_or_else(|| ClientError::Message("anti-rollback anchor file is corrupt".into())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(ClientError::Message(format!("anchor: {e}"))),
        }
    }

    fn store_anchor(&self, generation: u64) -> Result<()> {
        let Some(dir) = &self.dir else { return Ok(()) };
        let bytes = format!("{generation}\n");
        let path = dir.join(ANCHOR_FILE);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, bytes)
            .and_then(|_| std::fs::rename(&tmp, &path))
            .map_err(|e| ClientError::Message(format!("anchor: {e}")))
    }

    /// Raise the anchor to `generation` (never lowers it), e.g. after `VaultStatus`.
    pub fn record_generation(&self, generation: u64) -> Result<()> {
        if generation > self.anchor()? {
            self.store_anchor(generation)?;
        }
        Ok(())
    }

    /// D4-E: the backup this client authorizes for an emergency restore (`None`: none
    /// recorded, or no directory). A corrupt file is an error.
    pub fn backup_anchor(&self) -> Result<Option<BackupAnchor>> {
        let Some(dir) = &self.dir else { return Ok(None) };
        match std::fs::read(dir.join(BACKUP_ANCHOR_FILE)) {
            Ok(raw) => BackupAnchor::parse(&raw)
                .map(Some)
                .ok_or_else(|| ClientError::Message("backup anchor file is corrupt".into())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ClientError::Message(format!("backup anchor: {e}"))),
        }
    }

    /// D4-E: record a backup this client just created as its (single) backup anchor. An
    /// unencrypted backup (no authenticated manifest) cannot be authorized; an older backup
    /// never replaces a newer one. Returns whether the anchor now names `created`.
    pub fn record_backup(&self, created: &BackupCreateResult) -> Result<bool> {
        let Some(dir) = &self.dir else { return Ok(false) };
        let hash: [u8; 32] = hex::decode(&created.manifest_sealed_sha256)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| {
                ClientError::Message(
                    "backup has no authenticated manifest: cannot be authorized".into(),
                )
            })?;
        if self
            .backup_anchor()?
            .is_some_and(|a| a.checkpoint_sequence > created.checkpoint_sequence)
        {
            return Ok(false);
        }
        let anchor = BackupAnchor {
            backup_id: created.backup_id.clone(),
            checkpoint_sequence: created.checkpoint_sequence,
            manifest_sealed_sha256: hash,
        };
        let path = dir.join(BACKUP_ANCHOR_FILE);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, anchor.render())
            .and_then(|_| std::fs::rename(&tmp, &path))
            .map_err(|e| ClientError::Message(format!("backup anchor: {e}")))?;
        Ok(true)
    }

    /// D4-E: `BackupCreate`, then record the backup as this client's backup anchor.
    pub fn backup_create(
        &self,
        control: &mut ControlClient<'_>,
        backup_id: &str,
        include_rowstore: bool,
    ) -> Result<BackupCreateResult> {
        let created = control.backup_create(backup_id, include_rowstore)?;
        self.record_backup(&created)?;
        Ok(created)
    }

    /// D4-E (variant B): emergency restore — unlock authorizing exactly the backup in this
    /// client's backup anchor (its `manifest.sealed` hash travels inside the AEAD). The
    /// server opens nothing else. Restoring that backup is an explicit rollback to its
    /// checkpoint, so the generation anchor is reset to the opened generation.
    pub fn vault_unlock_restoring_backup(
        &self,
        control: &mut ControlClient<'_>,
        password: &str,
    ) -> Result<(VaultState, u64)> {
        let anchor = self.backup_anchor()?.ok_or_else(|| {
            ClientError::Message("no backup authorized by this client (backup anchor)".into())
        })?;
        let provider = self.provider(password);
        let (state, generation) = control.vault_unlock_restore(
            provider.as_ref(),
            anchor.checkpoint_sequence,
            &anchor.manifest_sealed_sha256,
        )?;
        self.store_anchor(generation)?;
        Ok((state, generation))
    }

    fn provider(&self, password: &str) -> Box<dyn KeyPassProvider> {
        match &self.kind {
            KeyPassKind::Password(bundle) => {
                Box::new(PasswordKeyPassProvider::new(bundle.clone(), password))
            }
            KeyPassKind::Mock(material) => {
                Box::new(MockKeyPassProvider::with_material(material.clone()))
            }
        }
    }

    /// D4-A stage 5: explicit storage migration with the KeyPass (see
    /// [`ControlClient::storage_migrate_encrypt`]). Returns (events, tables, purged).
    /// Carries the D4-D anchor like an unlock.
    pub fn storage_migrate_encrypt(
        &self,
        control: &mut ControlClient<'_>,
        password: &str,
        purge_plaintext_backups: bool,
    ) -> Result<(u64, u64, u64)> {
        let provider = self.provider(password);
        control.storage_migrate_encrypt_anchored(
            provider.as_ref(),
            purge_plaintext_backups,
            self.anchor()?,
        )
    }

    /// Unlock via KeyPass → UnlockBlob carrying this client's anchor (D4-D): storage older
    /// than what this client has already seen is refused (`StorageRollbackDetected`). On
    /// success the anchor is raised to the opened generation. `password` is required for
    /// password bundles; ignored for mock handles.
    pub fn vault_unlock(
        &self,
        control: &mut ControlClient<'_>,
        password: &str,
    ) -> Result<VaultState> {
        let provider = self.provider(password);
        let (state, generation) =
            control.vault_unlock_anchored(provider.as_ref(), self.anchor()?)?;
        self.record_generation(generation)?;
        Ok(state)
    }

    /// Explicit, operator-acknowledged acceptance of older storage (e.g. a restored older
    /// backup): unlock without the anchor, then reset the anchor to the opened generation.
    pub fn vault_unlock_accepting_rollback(
        &self,
        control: &mut ControlClient<'_>,
        password: &str,
    ) -> Result<(VaultState, u64)> {
        let provider = self.provider(password);
        let (state, generation) = control.vault_unlock_anchored(provider.as_ref(), 0)?;
        self.store_anchor(generation)?;
        Ok((state, generation))
    }
}
