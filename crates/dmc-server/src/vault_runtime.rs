//! Canonical vault runtime for Core — wraps existing `dmc-vault::KeyTree`.
//!
//! SecurityState / UnlockGate ask "unlocked?" — secrets live only in KeyTree RAM.

use dmc_protocol::{ProtocolError, ProtocolErrorCode};
use dmc_vault::{KeyMaterial, KeyPath, KeyTree};

use crate::unlock_blob::UnlockMaterial;

/// In-process vault: public KeyTree metadata always present; KEK/DEK only when unlocked.
pub struct VaultRuntime {
    tree: KeyTree,
}

impl std::fmt::Debug for VaultRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultRuntime")
            .field("unlocked", &self.is_unlocked())
            .finish_non_exhaustive()
    }
}

impl VaultRuntime {
    /// Create a new vault and wipe secrets → Locked startup invariant.
    /// Returns one-time master for client KeyPass wrap (never stored in SecurityState).
    pub fn create_locked() -> Result<(Self, UnlockMaterial), ProtocolError> {
        let (mut tree, master) =
            KeyTree::create_new().map_err(|_| vault_internal("vault create failed"))?;
        tree.wipe_secrets();
        let material = UnlockMaterial(*master.as_bytes());
        // `master` drops here → ZeroizeOnDrop
        Ok((Self { tree }, material))
    }

    pub fn is_unlocked(&self) -> bool {
        self.tree.has_runtime_secrets()
    }

    pub fn is_locked(&self) -> bool {
        !self.is_unlocked()
    }

    /// Apply Master Key from UnlockBlob. Idempotent if already unlocked.
    pub fn unlock(&mut self, material: &UnlockMaterial) -> Result<(), ProtocolError> {
        if self.is_unlocked() {
            return Ok(());
        }
        let master = KeyMaterial::from_bytes(material.0);
        let salt = *self.tree.salt();
        let proof = self.tree.unlock_proof().clone();
        let metas = self.tree.export_meta();
        match KeyTree::unlock(&master, salt, proof, metas) {
            Ok(tree) => {
                self.tree = tree;
                Ok(())
            }
            Err(dmc_vault::Error::WrongMasterKey) => Err(ProtocolError::wire(
                ProtocolErrorCode::UnlockFailed,
                "unlock failed",
            )),
            Err(_) => Err(vault_internal("vault unlock failed")),
        }
        // `master` ZeroizeOnDrop on scope exit
    }

    /// Wipe KEK/DEK from RAM. AuthSession is unaffected.
    pub fn lock(&mut self) {
        self.tree.wipe_secrets();
    }

    /// Test/debug: root DEK present only while unlocked.
    pub fn root_dek_present(&self) -> bool {
        self.tree.peek_dek(&KeyPath::root()).is_ok()
    }
}

fn vault_internal(msg: &str) -> ProtocolError {
    ProtocolError::wire(ProtocolErrorCode::InternalError, msg)
}
