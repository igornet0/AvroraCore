//! Phase 7.6 — UnlockGate mirrors vault runtime (no secret material stored here).

use dmc_protocol::{ProtocolError, ProtocolErrorCode};

use crate::unlock_blob::UnlockMaterial;
use crate::vault_runtime::VaultRuntime;

/// Runtime vault encryption gate — independent of AuthSession.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultState {
    Locked,
    Unlocked,
}

/// Two-axis security snapshot (auth ≠ vault unlock). Holds no keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityState {
    pub authenticated: bool,
    pub vault_unlocked: bool,
}

impl SecurityState {
    pub fn sql_allowed_axes(&self) -> bool {
        self.authenticated && self.vault_unlocked
    }
}

/// Gates encrypted-data operations. Secret material lives in [`VaultRuntime`] / KeyTree only.
pub struct UnlockGate {
    vault: VaultRuntime,
}

impl std::fmt::Debug for UnlockGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockGate")
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl UnlockGate {
    /// New vault, locked, with one-time master for KeyPass wrap.
    pub fn create_locked() -> Result<(Self, UnlockMaterial), ProtocolError> {
        let (vault, master) = VaultRuntime::create_locked()?;
        Ok((Self { vault }, master))
    }

    pub fn state(&self) -> VaultState {
        if self.vault.is_unlocked() {
            VaultState::Unlocked
        } else {
            VaultState::Locked
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.vault.is_unlocked()
    }

    pub fn is_locked(&self) -> bool {
        self.vault.is_locked()
    }

    /// Apply UnlockMaterial (Master Key bytes) into dmc-vault KeyTree.
    pub fn apply_unlock(&mut self, material: &UnlockMaterial) -> Result<(), ProtocolError> {
        self.vault.unlock(material)
    }

    /// Wipe runtime vault secrets. Does **not** revoke AuthSession.
    pub fn lock(&mut self) {
        self.vault.lock();
    }

    pub fn require_unlocked(&self) -> Result<(), ProtocolError> {
        if self.is_unlocked() {
            Ok(())
        } else {
            Err(ProtocolError::wire(
                ProtocolErrorCode::VaultLocked,
                "vault is locked",
            ))
        }
    }

    pub fn root_dek_present(&self) -> bool {
        self.vault.root_dek_present()
    }
}
