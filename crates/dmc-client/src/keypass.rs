//! Opaque client-side KeyPass handle. Never crosses the Tauri/UI boundary as Master Key.

use std::path::Path;

use crate::control::ControlClient;
use crate::error::Result;
use crate::types::VaultState;
use crate::{
    KeyPassError, KeyPassProvider, MockKeyPassProvider, PasswordKeyPassProvider, UnlockMaterial,
};
use dmc_server::{load_keypass_bundle, KeyPassBundle};

/// Rust-side KeyPass material for `vault_unlock`. UI only supplies a password string.
pub struct KeyPassHandle {
    kind: KeyPassKind,
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
        }
    }

    /// Load sealed KeyPass directory (no Master Key until unlock password is supplied).
    pub fn load_from_dir(dir: impl AsRef<Path>) -> std::result::Result<Self, KeyPassError> {
        let bundle = load_keypass_bundle(dir.as_ref())?;
        Ok(Self::from_password_bundle(bundle))
    }

    /// Test / lab only — never expose UnlockMaterial to TypeScript.
    pub fn mock_for_tests(material: UnlockMaterial) -> Self {
        Self {
            kind: KeyPassKind::Mock(material),
        }
    }

    /// Unlock via KeyPass → UnlockBlob. `password` is required for password bundles;
    /// ignored for mock handles.
    pub fn vault_unlock(
        &self,
        control: &mut ControlClient<'_>,
        password: &str,
    ) -> Result<VaultState> {
        match &self.kind {
            KeyPassKind::Password(bundle) => {
                let provider = PasswordKeyPassProvider::new(bundle.clone(), password);
                control.vault_unlock(&provider as &dyn KeyPassProvider)
            }
            KeyPassKind::Mock(material) => {
                let provider = MockKeyPassProvider::with_material(material.clone());
                let _ = password;
                control.vault_unlock(&provider as &dyn KeyPassProvider)
            }
        }
    }
}
