use std::collections::HashMap;

use crate::access::{Capability, Permission};
use crate::crypto::{AeadBlob, decrypt, encrypt};
use crate::error::{Error, Result};
use crate::key::{KeyPath, KeyTree, NodeState};

/// Encrypted KV: values sealed under path DEKs from the key tree.
#[derive(Clone)]
pub struct EncryptedKv {
    tree: KeyTree,
    entries: HashMap<String, StoredValue>,
}

#[derive(Clone)]
pub struct StoredValue {
    pub blob: AeadBlob,
    pub key_generation: u64,
}

impl EncryptedKv {
    pub fn new(tree: KeyTree) -> Self {
        Self {
            tree,
            entries: HashMap::new(),
        }
    }

    pub fn from_parts(tree: KeyTree, entries: HashMap<String, StoredValue>) -> Self {
        Self { tree, entries }
    }

    pub fn tree_mut(&mut self) -> &mut KeyTree {
        &mut self.tree
    }

    pub fn tree(&self) -> &KeyTree {
        &self.tree
    }

    pub fn entries(&self) -> &HashMap<String, StoredValue> {
        &self.entries
    }

    pub fn put(&mut self, path: &str, value: &[u8], cap: &Capability) -> Result<()> {
        let key_path = KeyPath::parse(path)?;
        cap.authorize(&key_path, Permission::Write)?;
        self.tree.ensure_node(&key_path)?;
        let generation = self
            .tree
            .meta(&key_path)
            .ok_or_else(|| Error::UnknownNode(key_path.to_string()))?
            .generation;
        let dek = self.tree.dek(&key_path)?.clone();
        let aad = key_path.to_string();
        let blob = encrypt(&dek, value, aad.as_bytes())?;
        self.entries.insert(
            key_path.as_str().to_string(),
            StoredValue {
                blob,
                key_generation: generation,
            },
        );
        Ok(())
    }

    pub fn get(&mut self, path: &str, cap: &Capability) -> Result<Vec<u8>> {
        let key_path = KeyPath::parse(path)?;
        cap.authorize(&key_path, Permission::Read)?;
        let stored = self
            .entries
            .get(key_path.as_str())
            .ok_or_else(|| Error::NotFound(key_path.to_string()))?
            .clone();
        let meta = self
            .tree
            .meta(&key_path)
            .ok_or_else(|| Error::UnknownNode(key_path.to_string()))?;
        if meta.state == NodeState::Revoked {
            return Err(Error::Revoked(key_path.to_string()));
        }
        if stored.key_generation != meta.generation {
            return Err(Error::AeadFailed);
        }
        let dek = self.tree.dek(&key_path)?.clone();
        let aad = key_path.to_string();
        decrypt(&dek, &stored.blob, aad.as_bytes())
    }

    pub fn delete(&mut self, path: &str, cap: &Capability) -> Result<()> {
        let key_path = KeyPath::parse(path)?;
        cap.authorize(&key_path, Permission::Delete)?;
        if self.entries.remove(key_path.as_str()).is_none() {
            return Err(Error::NotFound(key_path.to_string()));
        }
        Ok(())
    }

    pub fn list_keys(&self, prefix: &str, cap: &Capability) -> Result<Vec<String>> {
        let prefix_path = if prefix.trim().is_empty() || prefix.trim() == "/" {
            KeyPath::root()
        } else {
            KeyPath::parse(prefix)?
        };
        if !cap.scope.is_prefix_of(&prefix_path) && !prefix_path.is_prefix_of(&cap.scope) {
            if !prefix_path.is_root() && !cap.scope.is_prefix_of(&prefix_path) {
                return Err(Error::AccessDenied(
                    Permission::Read.to_string(),
                    prefix_path.to_string(),
                ));
            }
        }
        if !cap.permissions.contains(Permission::Read) {
            return Err(Error::AccessDenied(
                Permission::Read.to_string(),
                prefix_path.to_string(),
            ));
        }

        let mut keys: Vec<String> = self
            .entries
            .keys()
            .filter_map(|k| {
                let kp = KeyPath::parse(k).ok()?;
                if !cap.scope.is_prefix_of(&kp) {
                    return None;
                }
                if self.tree.is_revoked(&kp) {
                    return None;
                }
                if prefix_path.is_root() || prefix_path.is_prefix_of(&kp) || prefix_path == kp {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();
        keys.sort();
        Ok(keys)
    }

    /// Delete every stored value whose path sits under `prefix` (inclusive).
    pub fn delete_prefix(&mut self, prefix: &str, cap: &Capability) -> Result<usize> {
        let keys = self.list_keys(prefix, cap)?;
        let n = keys.len();
        for key in keys {
            self.entries.remove(&key);
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::PermissionSet;
    use crate::key::KeyTree;

    #[test]
    fn put_get_with_scoped_capability() {
        let tree = KeyTree::new_with_root();
        let mut db = EncryptedKv::new(tree);
        let admin = Capability::root_admin();
        let finance_cap = admin
            .delegate(
                KeyPath::parse("company/finance").unwrap(),
                PermissionSet::read_write(),
            )
            .unwrap();

        db.put("company/finance/invoice/1", b"secret-invoice", &finance_cap)
            .unwrap();
        let got = db.get("company/finance/invoice/1", &finance_cap).unwrap();
        assert_eq!(got, b"secret-invoice");

        let hr_cap = Capability::new(
            KeyPath::parse("company/hr").unwrap(),
            PermissionSet::read_write(),
        );
        assert!(db.get("company/finance/invoice/1", &hr_cap).is_err());
    }

    #[test]
    fn list_keys_hides_revoked_paths() {
        let tree = KeyTree::new_with_root();
        let mut db = EncryptedKv::new(tree);
        let admin = Capability::root_admin();
        db.put("company/finance/invoices/001", b"one", &admin)
            .unwrap();
        db.put("company/finance/invoices/002", b"two", &admin)
            .unwrap();
        db.put("company/hr/employees/001", b"bob", &admin).unwrap();

        db.tree_mut()
            .revoke(&KeyPath::parse("company/finance/invoices/001").unwrap())
            .unwrap();

        let keys = db.list_keys("company", &admin).unwrap();
        assert!(!keys.iter().any(|k| k.contains("invoices/001")));
        assert!(keys.iter().any(|k| k.contains("invoices/002")));
        assert!(keys.iter().any(|k| k.contains("hr/employees/001")));
    }
}
