use std::collections::HashMap;

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::crypto::{AeadBlob, decrypt, derive_child_key, encrypt, unwrap_key, wrap_key};
use crate::error::{Error, Result};
use crate::key::{KeyId, KeyMaterial, KeyPath};

pub const ROOT_KEK_INFO: &str = "root-kek";
/// Domain-separated journal KEK. Payload still uses path DEKs.
pub const JOURNAL_KEK_INFO: &str = "journal/v1";
pub const AUDIT_KEK_INFO: &str = "audit/v1";
pub const METADATA_KEK_INFO: &str = "metadata/v1";
const UNLOCK_AAD: &[u8] = b"dbs-unlock-v1";
const UNLOCK_MSG: &[u8] = b"UNLOCK-OK";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum NodeState {
    Active,
    Revoked,
}

/// Public metadata for a key-tree node (no secret material in clear).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyNodeMeta {
    pub path: String,
    pub id_hex: String,
    pub generation: u64,
    pub state: NodeState,
    /// DEK wrapped under the node KEK (including root).
    pub wrapped_dek: AeadBlob,
}

impl KeyNodeMeta {
    pub fn key_path(&self) -> Result<KeyPath> {
        if self.path.is_empty() || self.path == "/" {
            Ok(KeyPath::root())
        } else {
            KeyPath::parse(self.path.trim_start_matches('/'))
        }
    }
}

/// In-memory key tree.
///
/// Master secret → HKDF → root KEK → unwrap root DEK; child KEKs derived down the path.
/// Master is never stored on disk — only salt, wrapped DEKs, and ciphertext.
#[derive(Clone)]
pub struct KeyTree {
    salt: [u8; 32],
    unlock_proof: AeadBlob,
    nodes: HashMap<String, RuntimeNode>,
    keks: HashMap<String, KeyMaterial>,
    deks: HashMap<String, KeyMaterial>,
}

#[derive(Clone)]
struct RuntimeNode {
    path: KeyPath,
    id: KeyId,
    generation: u64,
    state: NodeState,
    wrapped_dek: AeadBlob,
}

impl KeyTree {
    /// Create a new DB: returns (tree, master_secret). Master must be shown once and never stored.
    pub fn create_new() -> Result<(Self, KeyMaterial)> {
        let master = KeyMaterial::random();
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        let root_kek = derive_child_key(&master, &salt, ROOT_KEK_INFO);
        let root_dek = KeyMaterial::random();
        let wrapped = wrap_key(&root_kek, &root_dek)?;
        let unlock_proof = encrypt(&root_kek, UNLOCK_MSG, UNLOCK_AAD)?;

        let path = KeyPath::root();
        let generation = 1;
        let id = KeyId::from_path(path.as_str(), generation);

        let mut tree = Self {
            salt,
            unlock_proof,
            nodes: HashMap::new(),
            keks: HashMap::new(),
            deks: HashMap::new(),
        };
        tree.nodes.insert(
            path.as_str().to_string(),
            RuntimeNode {
                path: path.clone(),
                id,
                generation,
                state: NodeState::Active,
                wrapped_dek: wrapped,
            },
        );
        tree.keks.insert(path.as_str().to_string(), root_kek);
        tree.deks.insert(path.as_str().to_string(), root_dek);
        Ok((tree, master))
    }

    /// Compatibility helper used by unit tests / CLI demo.
    pub fn new_with_root() -> Self {
        Self::create_new().expect("create_new").0
    }

    /// Unlock a persisted tree with the master secret. Wrong key → WrongMasterKey.
    pub fn unlock(
        master: &KeyMaterial,
        salt: [u8; 32],
        unlock_proof: AeadBlob,
        metas: Vec<KeyNodeMeta>,
    ) -> Result<Self> {
        let root_kek = derive_child_key(master, &salt, ROOT_KEK_INFO);
        let proof =
            decrypt(&root_kek, &unlock_proof, UNLOCK_AAD).map_err(|_| Error::WrongMasterKey)?;
        if proof != UNLOCK_MSG {
            return Err(Error::WrongMasterKey);
        }

        let mut tree = Self {
            salt,
            unlock_proof,
            nodes: HashMap::new(),
            keks: HashMap::new(),
            deks: HashMap::new(),
        };
        tree.keks
            .insert(KeyPath::root().as_str().to_string(), root_kek);

        for meta in metas {
            let path = meta.key_path()?;
            let mut id_bytes = [0u8; 32];
            let decoded =
                hex::decode(&meta.id_hex).map_err(|_| Error::Persist("bad key id".into()))?;
            if decoded.len() != 32 {
                return Err(Error::Persist("bad key id length".into()));
            }
            id_bytes.copy_from_slice(&decoded);
            tree.nodes.insert(
                path.as_str().to_string(),
                RuntimeNode {
                    path: path.clone(),
                    id: KeyId(id_bytes),
                    generation: meta.generation,
                    state: meta.state,
                    wrapped_dek: meta.wrapped_dek,
                },
            );
        }

        if !tree.nodes.contains_key("") {
            return Err(Error::Persist("missing root node".into()));
        }

        // Unwrap root DEK immediately as unlock confirmation.
        let root_path = KeyPath::root();
        tree.dek(&root_path).map_err(|_| Error::WrongMasterKey)?;
        Ok(tree)
    }

    pub fn salt(&self) -> &[u8; 32] {
        &self.salt
    }

    pub fn unlock_proof(&self) -> &AeadBlob {
        &self.unlock_proof
    }

    pub fn export_meta(&self) -> Vec<KeyNodeMeta> {
        let mut nodes: Vec<_> = self
            .nodes
            .values()
            .map(|n| KeyNodeMeta {
                path: if n.path.is_root() {
                    "/".to_string()
                } else {
                    n.path.to_string()
                },
                id_hex: n.id.to_hex(),
                generation: n.generation,
                state: n.state,
                wrapped_dek: n.wrapped_dek.clone(),
            })
            .collect();
        nodes.sort_by(|a, b| a.path.cmp(&b.path));
        nodes
    }

    pub fn meta(&self, path: &KeyPath) -> Option<KeyNodeMeta> {
        self.nodes.get(path.as_str()).map(|n| KeyNodeMeta {
            path: if n.path.is_root() {
                "/".to_string()
            } else {
                n.path.to_string()
            },
            id_hex: n.id.to_hex(),
            generation: n.generation,
            state: n.state,
            wrapped_dek: n.wrapped_dek.clone(),
        })
    }

    /// True when this path or any ancestor is marked [`NodeState::Revoked`].
    pub fn is_revoked(&self, path: &KeyPath) -> bool {
        let mut current = Some(path.clone());
        while let Some(p) = current {
            if self
                .nodes
                .get(p.as_str())
                .is_some_and(|n| n.state == NodeState::Revoked)
            {
                return true;
            }
            current = p.parent();
        }
        false
    }

    pub fn list_nodes(&self) -> Vec<KeyNodeMeta> {
        self.export_meta()
    }

    pub fn ensure_node(&mut self, path: &KeyPath) -> Result<KeyNodeMeta> {
        if let Some(existing) = self.nodes.get(path.as_str()) {
            if existing.state == NodeState::Revoked {
                return Err(Error::Revoked(path.to_string()));
            }
            return Ok(self.meta(path).unwrap());
        }

        let parent = path
            .parent()
            .ok_or_else(|| Error::InvalidPath("cannot ensure root via ensure_node".into()))?;
        self.ensure_node(&parent)?;
        self.derive_kek(path)?;
        let kek = self
            .keks
            .get(path.as_str())
            .ok_or_else(|| Error::UnknownNode(path.to_string()))?
            .clone();
        let dek = KeyMaterial::random();
        let wrapped = wrap_key(&kek, &dek)?;
        let generation = 1;
        let id = KeyId::from_path(path.as_str(), generation);
        self.deks.insert(path.as_str().to_string(), dek);
        self.nodes.insert(
            path.as_str().to_string(),
            RuntimeNode {
                path: path.clone(),
                id,
                generation,
                state: NodeState::Active,
                wrapped_dek: wrapped,
            },
        );
        Ok(self.meta(path).unwrap())
    }

    pub fn derive_kek(&mut self, path: &KeyPath) -> Result<&KeyMaterial> {
        if let Some(meta) = self.nodes.get(path.as_str()) {
            if meta.state == NodeState::Revoked {
                return Err(Error::Revoked(path.to_string()));
            }
        }
        if self.keks.contains_key(path.as_str()) {
            return Ok(self.keks.get(path.as_str()).unwrap());
        }

        let mut climb = path.clone();
        let mut missing = Vec::new();
        loop {
            if self.keks.contains_key(climb.as_str()) {
                break;
            }
            missing.push(climb.clone());
            climb = climb
                .parent()
                .ok_or_else(|| Error::MissingParent(path.to_string()))?;
        }

        for child in missing.into_iter().rev() {
            let parent = child
                .parent()
                .ok_or_else(|| Error::MissingParent(child.to_string()))?;
            if let Some(meta) = self.nodes.get(child.as_str()) {
                if meta.state == NodeState::Revoked {
                    return Err(Error::Revoked(child.to_string()));
                }
            }
            let parent_kek = self
                .keks
                .get(parent.as_str())
                .ok_or_else(|| Error::MissingParent(child.to_string()))?;
            let derived = derive_child_key(parent_kek, &self.salt, &child.info_label());
            self.keks.insert(child.as_str().to_string(), derived);
        }

        Ok(self.keks.get(path.as_str()).unwrap())
    }

    pub fn dek(&mut self, path: &KeyPath) -> Result<&KeyMaterial> {
        let meta = self
            .nodes
            .get(path.as_str())
            .ok_or_else(|| Error::UnknownNode(path.to_string()))?;
        if meta.state == NodeState::Revoked {
            return Err(Error::Revoked(path.to_string()));
        }
        if self.deks.contains_key(path.as_str()) {
            return Ok(self.deks.get(path.as_str()).unwrap());
        }

        let wrapped = meta.wrapped_dek.clone();
        self.derive_kek(path)?;
        let kek = self
            .keks
            .get(path.as_str())
            .ok_or_else(|| Error::UnknownNode(path.to_string()))?;
        let dek = unwrap_key(kek, &wrapped).map_err(|_| Error::UnwrapFailed)?;
        self.deks.insert(path.as_str().to_string(), dek);
        Ok(self.deks.get(path.as_str()).unwrap())
    }

    /// Build the next-generation wrapped DEK without installing it.
    pub fn plan_rotate_meta(&mut self, path: &KeyPath) -> Result<KeyNodeMeta> {
        {
            let meta = self
                .nodes
                .get(path.as_str())
                .ok_or_else(|| Error::UnknownNode(path.to_string()))?;
            if meta.state == NodeState::Revoked {
                return Err(Error::Revoked(path.to_string()));
            }
        }
        self.derive_kek(path)?;
        let kek = self
            .keks
            .get(path.as_str())
            .ok_or_else(|| Error::UnknownNode(path.to_string()))?
            .clone();
        let new_dek = KeyMaterial::random();
        let wrapped = wrap_key(&kek, &new_dek)?;
        let generation = self.nodes.get(path.as_str()).unwrap().generation + 1;
        let id = KeyId::from_path(path.as_str(), generation);
        Ok(KeyNodeMeta {
            path: if path.is_root() {
                "/".to_string()
            } else {
                path.to_string()
            },
            id_hex: id.to_hex(),
            generation,
            state: NodeState::Active,
            wrapped_dek: wrapped,
        })
    }

    pub fn rotate_dek(&mut self, path: &KeyPath) -> Result<KeyNodeMeta> {
        {
            let meta = self
                .nodes
                .get(path.as_str())
                .ok_or_else(|| Error::UnknownNode(path.to_string()))?;
            if meta.state == NodeState::Revoked {
                return Err(Error::Revoked(path.to_string()));
            }
        }
        self.derive_kek(path)?;
        let kek = self
            .keks
            .get(path.as_str())
            .ok_or_else(|| Error::UnknownNode(path.to_string()))?
            .clone();
        let new_dek = KeyMaterial::random();
        let wrapped = wrap_key(&kek, &new_dek)?;
        let generation = self.nodes.get(path.as_str()).unwrap().generation + 1;
        let id = KeyId::from_path(path.as_str(), generation);
        self.deks.insert(path.as_str().to_string(), new_dek);
        let meta = self.nodes.get_mut(path.as_str()).unwrap();
        meta.generation = generation;
        meta.id = id;
        meta.wrapped_dek = wrapped;
        Ok(self.meta(path).unwrap())
    }

    pub fn revoke(&mut self, path: &KeyPath) -> Result<()> {
        if path.is_root() {
            return Err(Error::InvalidPath("cannot revoke root".into()));
        }
        if !self.nodes.contains_key(path.as_str()) {
            return Err(Error::UnknownNode(path.to_string()));
        }
        let victims: Vec<String> = self
            .nodes
            .values()
            .filter(|m| path.is_prefix_of(&m.path))
            .map(|m| m.path.as_str().to_string())
            .collect();
        for key in victims {
            if let Some(meta) = self.nodes.get_mut(&key) {
                meta.state = NodeState::Revoked;
            }
            self.keks.remove(&key);
            self.deks.remove(&key);
        }
        Ok(())
    }

    /// Remove a subtree from the key tree so the path can be reused (DDL DROP).
    /// Distinct from [`revoke`], which keeps nodes as cryptographically dead.
    pub fn purge_subtree(&mut self, path: &KeyPath) -> Result<()> {
        if path.is_root() {
            return Err(Error::InvalidPath("cannot purge root".into()));
        }
        let victims: Vec<String> = self
            .nodes
            .values()
            .filter(|m| path.is_prefix_of(&m.path))
            .map(|m| m.path.as_str().to_string())
            .collect();
        if victims.is_empty() {
            return Err(Error::UnknownNode(path.to_string()));
        }
        for key in victims {
            self.nodes.remove(&key);
            self.keks.remove(&key);
            self.deks.remove(&key);
        }
        Ok(())
    }

    pub fn has_node(&self, path: &KeyPath) -> bool {
        self.nodes.contains_key(path.as_str())
    }
    pub fn wipe_secrets(&mut self) {
        // Drop KeyMaterial values so ZeroizeOnDrop runs; clear maps.
        self.keks.clear();
        self.deks.clear();
    }

    /// True when KEK/DEK material is present in RAM (unlocked).
    pub fn has_runtime_secrets(&self) -> bool {
        !self.keks.is_empty() || !self.deks.is_empty()
    }

    pub fn install_kek(&mut self, path: &KeyPath, kek: KeyMaterial) {
        self.keks.insert(path.as_str().to_string(), kek);
    }

    pub fn export_kek(&self, path: &KeyPath) -> Result<&KeyMaterial> {
        self.keks
            .get(path.as_str())
            .ok_or_else(|| Error::UnknownNode(path.to_string()))
    }

    pub fn peek_dek(&self, path: &KeyPath) -> Result<&KeyMaterial> {
        self.deks
            .get(path.as_str())
            .ok_or_else(|| Error::UnknownNode(path.to_string()))
    }

    /// Install persisted node metadata (replay / journal node bundle).
    pub fn install_meta(&mut self, meta: KeyNodeMeta) -> Result<()> {
        let path = meta.key_path()?;
        self.nodes.insert(
            path.as_str().to_string(),
            RuntimeNode {
                path,
                id: {
                    let decoded = hex::decode(&meta.id_hex)
                        .map_err(|_| Error::Persist("bad key id".into()))?;
                    if decoded.len() != 32 {
                        return Err(Error::Persist("bad key id length".into()));
                    }
                    let mut id_bytes = [0u8; 32];
                    id_bytes.copy_from_slice(&decoded);
                    KeyId(id_bytes)
                },
                generation: meta.generation,
                state: meta.state,
                wrapped_dek: meta.wrapped_dek,
            },
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_down_from_parent() {
        let mut tree = KeyTree::new_with_root();
        let finance = KeyPath::parse("company/finance").unwrap();
        tree.ensure_node(&finance).unwrap();
        let dek1 = tree.dek(&finance).unwrap().as_bytes().to_owned();
        tree.deks.remove(finance.as_str());
        let dek2 = tree.dek(&finance).unwrap().as_bytes().to_owned();
        assert_eq!(dek1, dek2);
    }

    #[test]
    fn revoke_blocks_access() {
        let mut tree = KeyTree::new_with_root();
        let finance = KeyPath::parse("company/finance").unwrap();
        tree.ensure_node(&finance).unwrap();
        tree.revoke(&finance).unwrap();
        assert!(matches!(tree.dek(&finance), Err(Error::Revoked(_))));
    }

    #[test]
    fn rotate_changes_dek() {
        let mut tree = KeyTree::new_with_root();
        let path = KeyPath::parse("company/hr").unwrap();
        tree.ensure_node(&path).unwrap();
        let before = tree.dek(&path).unwrap().as_bytes().to_owned();
        tree.rotate_dek(&path).unwrap();
        let after = tree.dek(&path).unwrap().as_bytes().to_owned();
        assert_ne!(before, after);
    }

    #[test]
    fn wrong_master_rejected() {
        let (tree, master) = KeyTree::create_new().unwrap();
        let salt = *tree.salt();
        let proof = tree.unlock_proof().clone();
        let metas = tree.export_meta();
        let bad = KeyMaterial::random();
        assert!(matches!(
            KeyTree::unlock(&bad, salt, proof.clone(), metas.clone()),
            Err(Error::WrongMasterKey)
        ));
        assert!(KeyTree::unlock(&master, salt, proof, metas).is_ok());
    }
}
