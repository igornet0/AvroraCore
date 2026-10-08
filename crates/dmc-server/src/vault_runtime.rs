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

/// Key-tree nodes whose DEKs encrypt SQL-plane storage at rest (D4-A). Created together
/// with the key store, so its persisted metadata never changes afterwards.
pub const STORAGE_KEY_PATHS: [&str; 5] = [
    dmc_vault::StoragePurpose::ALL[0].key_path(),
    dmc_vault::StoragePurpose::ALL[1].key_path(),
    dmc_vault::StoragePurpose::ALL[2].key_path(),
    dmc_vault::StoragePurpose::ALL[3].key_path(),
    dmc_vault::StoragePurpose::ALL[4].key_path(),
];

/// Key store file inside the layout's vault directory.
pub const KEY_TREE_FILE: &str = "keytree.json";

impl VaultRuntime {
    /// Persistent vault (D4-A stage 1): load the key store at `path` (locked), or — only
    /// if it does not exist — create it once with the storage key nodes and return the
    /// Master Key **once**. An unreadable key store is an error, never a new vault.
    pub fn open_or_create(path: &std::path::Path) -> Result<(Self, Option<UnlockMaterial>), ProtocolError> {
        if path.exists() {
            let tree = dmc_vault::load_locked_key_tree(path).map_err(|_| vault_internal("vault key store unreadable"))?;
            return Ok((Self { tree }, None));
        }
        let (mut tree, master) = KeyTree::create_new().map_err(|_| vault_internal("vault create failed"))?;
        for p in STORAGE_KEY_PATHS {
            let kp = KeyPath::parse(p).map_err(|_| vault_internal("vault create failed"))?;
            tree.ensure_node(&kp).map_err(|_| vault_internal("vault create failed"))?;
        }
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|_| vault_internal("vault create failed"))?;
        }
        dmc_vault::save_key_tree(&tree, path).map_err(|_| vault_internal("vault key store write failed"))?;
        tree.wipe_secrets();
        let material = UnlockMaterial(*master.as_bytes());
        Ok((Self { tree }, Some(material)))
    }

    /// DEK of a storage key node; only while unlocked.
    pub fn storage_dek(&mut self, path: &str) -> Result<KeyMaterial, ProtocolError> {
        if self.is_locked() {
            return Err(ProtocolError::wire(ProtocolErrorCode::VaultLocked, "vault is locked"));
        }
        let kp = KeyPath::parse(path).map_err(|_| vault_internal("bad storage key path"))?;
        self.tree
            .dek(&kp)
            .map(|k| k.clone())
            .map_err(|_| vault_internal("storage key unavailable"))
    }

    /// Storage cipher with every purpose's DEK; only while unlocked.
    pub fn storage_cipher(&mut self) -> Result<dmc_vault::StorageCipher, ProtocolError> {
        if self.is_locked() {
            return Err(ProtocolError::wire(ProtocolErrorCode::VaultLocked, "vault is locked"));
        }
        dmc_vault::StorageCipher::from_unlocked_tree(&mut self.tree)
            .map_err(|_| vault_internal("storage keys unavailable"))
    }

    /// Ephemeral vault (tests / tooling): new tree per call, nothing persisted.
    /// Returns one-time master for client KeyPass wrap (never stored in SecurityState).
    /// D4-F: carries the storage key nodes too, so a dev / test store is encrypted with
    /// them exactly like a persistent one.
    pub fn create_locked() -> Result<(Self, UnlockMaterial), ProtocolError> {
        let (mut tree, master) =
            KeyTree::create_new().map_err(|_| vault_internal("vault create failed"))?;
        for p in STORAGE_KEY_PATHS {
            let kp = KeyPath::parse(p).map_err(|_| vault_internal("vault create failed"))?;
            tree.ensure_node(&kp).map_err(|_| vault_internal("vault create failed"))?;
        }
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
