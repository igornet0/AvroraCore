//! On-disk snapshot: salt + wrapped key tree + ciphertext.
//! The master secret is never written to disk.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::access::{PermissionSet, RoleRegistry};
use crate::crypto::{AeadBlob, decrypt, encrypt};
use crate::error::{Error, Result};
use crate::key::{KeyMaterial, KeyNodeMeta, KeyPath, KeyTree};
use crate::store::{EncryptedKv, StoredValue};

const ROLES_AAD: &[u8] = b"dbs-roles-v1";
const OVERLAY_AAD: &[u8] = b"avrora/overlay/v1";
const USERS_AAD: &[u8] = b"avrora/users/v1";
const CAPABILITIES_AAD: &[u8] = b"avrora/capabilities/v1";

#[derive(Clone, Serialize, Deserialize)]
pub struct DbSnapshot {
    pub version: u32,
    pub salt_hex: String,
    pub unlock_proof: AeadBlob,
    pub nodes: Vec<KeyNodeMeta>,
    pub entries: Vec<EntryRecord>,
    pub sealed_roles: Option<AeadBlob>,
    #[serde(default)]
    pub last_applied_sequence: u64,
    #[serde(default)]
    pub journal_format: u16,
    #[serde(default)]
    pub sealed_overlay: Option<AeadBlob>,
    #[serde(default)]
    pub sealed_users: Option<AeadBlob>,
    #[serde(default)]
    pub sealed_capabilities: Option<AeadBlob>,
}

/// Materialized overlay layer sealed inside the snapshot (checkpoint).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OverlayRecord {
    pub path: String,
    pub deleted: bool,
    #[serde(with = "serde_hex_payload")]
    pub payload: Vec<u8>,
    pub source: String,
    pub seq: u64,
}

mod serde_hex_payload {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EntryRecord {
    pub path: String,
    pub key_generation: u64,
    pub blob: AeadBlob,
}

#[derive(Serialize, Deserialize)]
struct RoleRecord {
    id: String,
    name: String,
    scope: String,
    permissions: Vec<String>,
}

impl DbSnapshot {
    pub fn from_kv(kv: &EncryptedKv, roles: &RoleRegistry) -> Result<Self> {
        Self::from_kv_checkpoint(kv, roles, 0, None)
    }

    pub fn from_kv_checkpoint(
        kv: &EncryptedKv,
        roles: &RoleRegistry,
        last_applied_sequence: u64,
        overlay: Option<&[OverlayRecord]>,
    ) -> Result<Self> {
        let tree = kv.tree();
        let sealed_roles = kv.seal_roles_blob(roles)?;
        let entries = kv
            .entries()
            .iter()
            .map(|(path, v)| EntryRecord {
                path: path.clone(),
                key_generation: v.key_generation,
                blob: v.blob.clone(),
            })
            .collect();
        let sealed_overlay = match overlay {
            Some(records) if !records.is_empty() => Some(kv.seal_overlay_blob(records)?),
            _ => None,
        };

        Ok(Self {
            version: 2,
            salt_hex: hex::encode(tree.salt()),
            unlock_proof: tree.unlock_proof().clone(),
            nodes: tree.export_meta(),
            entries,
            sealed_roles: Some(sealed_roles),
            last_applied_sequence,
            journal_format: 1,
            sealed_overlay,
            sealed_users: None,
            sealed_capabilities: None,
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path).map_err(|e| Error::Io(e.to_string()))?;
        serde_json::from_str(&raw).map_err(|e| Error::Persist(e.to_string()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::Io(e.to_string()))?;
        }
        let tmp = path.with_extension("tmp");
        let raw = serde_json::to_string_pretty(self).map_err(|e| Error::Persist(e.to_string()))?;
        fs::write(&tmp, raw).map_err(|e| Error::Io(e.to_string()))?;
        fs::rename(&tmp, path).map_err(|e| Error::Io(e.to_string()))?;
        Ok(())
    }

    pub fn salt(&self) -> Result<[u8; 32]> {
        let bytes = hex::decode(&self.salt_hex).map_err(|_| Error::Persist("bad salt".into()))?;
        if bytes.len() != 32 {
            return Err(Error::Persist("salt length".into()));
        }
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&bytes);
        Ok(salt)
    }

    pub fn unlock(&self, master: &KeyMaterial) -> Result<(EncryptedKv, RoleRegistry)> {
        let salt = self.salt()?;
        let tree = KeyTree::unlock(master, salt, self.unlock_proof.clone(), self.nodes.clone())?;
        let mut entries = HashMap::new();
        for e in &self.entries {
            entries.insert(
                e.path.clone(),
                StoredValue {
                    blob: e.blob.clone(),
                    key_generation: e.key_generation,
                },
            );
        }
        let mut kv = EncryptedKv::from_parts(tree, entries);
        let roles = match &self.sealed_roles {
            Some(blob) => kv.unseal_roles_blob(blob)?,
            None => RoleRegistry::with_root(),
        };
        Ok((kv, roles))
    }

    pub fn unseal_overlay(&self, kv: &mut EncryptedKv) -> Result<Vec<OverlayRecord>> {
        match &self.sealed_overlay {
            Some(blob) => kv.unseal_overlay_blob(blob),
            None => Ok(Vec::new()),
        }
    }

    pub fn unseal_users(&self, kv: &mut EncryptedKv) -> Result<Option<Vec<u8>>> {
        match &self.sealed_users {
            Some(blob) => Ok(Some(kv.unseal_users_blob(blob)?)),
            None => Ok(None),
        }
    }

    pub fn unseal_capabilities(&self, kv: &mut EncryptedKv) -> Result<Option<Vec<u8>>> {
        match &self.sealed_capabilities {
            Some(blob) => Ok(Some(kv.unseal_capabilities_blob(blob)?)),
            None => Ok(None),
        }
    }
}

impl EncryptedKv {
    pub fn seal_roles_blob(&self, roles: &RoleRegistry) -> Result<AeadBlob> {
        let root_dek = self.tree().peek_dek(&KeyPath::root())?;
        let records: Vec<RoleRecord> = roles
            .list()
            .into_iter()
            .map(|r| RoleRecord {
                id: r.id,
                name: r.name,
                scope: r.scope.to_string(),
                permissions: r
                    .permissions
                    .to_names()
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            })
            .collect();
        let json = serde_json::to_vec(&records).map_err(|e| Error::Persist(e.to_string()))?;
        encrypt(root_dek, &json, ROLES_AAD)
    }

    pub fn unseal_roles_blob(&mut self, blob: &AeadBlob) -> Result<RoleRegistry> {
        let dek = self.tree_mut().dek(&KeyPath::root())?.clone();
        let json = decrypt(&dek, blob, ROLES_AAD).map_err(|_| Error::WrongMasterKey)?;
        let records: Vec<RoleRecord> =
            serde_json::from_slice(&json).map_err(|e| Error::Persist(e.to_string()))?;
        let mut registry = RoleRegistry::with_root();
        for r in records {
            if r.id == "root" {
                continue;
            }
            let scope = if r.scope.is_empty() || r.scope == "/" {
                KeyPath::root()
            } else {
                KeyPath::parse(r.scope.trim_start_matches('/'))?
            };
            let perms = PermissionSet::from_names(&r.permissions)?;
            registry.seed_role(&r.id, &r.name, scope, perms);
        }
        Ok(registry)
    }

    pub fn seal_overlay_blob(&self, records: &[OverlayRecord]) -> Result<AeadBlob> {
        let root_dek = self.tree().peek_dek(&KeyPath::root())?;
        let json = serde_json::to_vec(records).map_err(|e| Error::Persist(e.to_string()))?;
        encrypt(root_dek, &json, OVERLAY_AAD)
    }

    pub fn unseal_overlay_blob(&mut self, blob: &AeadBlob) -> Result<Vec<OverlayRecord>> {
        let dek = self.tree_mut().dek(&KeyPath::root())?.clone();
        let json = decrypt(&dek, blob, OVERLAY_AAD).map_err(|_| Error::WrongMasterKey)?;
        serde_json::from_slice(&json).map_err(|e| Error::Persist(e.to_string()))
    }

    pub fn seal_users_blob(&self, json: &[u8]) -> Result<AeadBlob> {
        let root_dek = self.tree().peek_dek(&KeyPath::root())?;
        encrypt(root_dek, json, USERS_AAD)
    }

    pub fn unseal_users_blob(&mut self, blob: &AeadBlob) -> Result<Vec<u8>> {
        let dek = self.tree_mut().dek(&KeyPath::root())?.clone();
        decrypt(&dek, blob, USERS_AAD).map_err(|_| Error::WrongMasterKey)
    }

    pub fn seal_capabilities_blob(&self, json: &[u8]) -> Result<AeadBlob> {
        let root_dek = self.tree().peek_dek(&KeyPath::root())?;
        encrypt(root_dek, json, CAPABILITIES_AAD)
    }

    pub fn unseal_capabilities_blob(&mut self, blob: &AeadBlob) -> Result<Vec<u8>> {
        let dek = self.tree_mut().dek(&KeyPath::root())?.clone();
        decrypt(&dek, blob, CAPABILITIES_AAD).map_err(|_| Error::WrongMasterKey)
    }
}

pub fn default_db_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("store.dbs.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{Capability, PermissionSet};

    #[test]
    fn roundtrip_persist_and_wrong_key() {
        let dir = std::env::temp_dir().join(format!("dbs-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.dbs.json");

        let (tree, master) = KeyTree::create_new().unwrap();
        let mut kv = EncryptedKv::new(tree);
        let mut roles = RoleRegistry::with_root();
        roles.seed_role(
            "finance",
            "Finance",
            KeyPath::parse("company/finance").unwrap(),
            PermissionSet::read_write(),
        );
        let root = Capability::root_admin();
        kv.put("company/finance/a", b"secret", &root).unwrap();

        let snap = DbSnapshot::from_kv(&kv, &roles).unwrap();
        snap.save(&path).unwrap();

        let loaded = DbSnapshot::load(&path).unwrap();
        let bad = KeyMaterial::random();
        assert!(matches!(loaded.unlock(&bad), Err(Error::WrongMasterKey)));

        let (mut kv2, roles2) = loaded.unlock(&master).unwrap();
        assert!(roles2.get("finance").is_some());
        let got = kv2.get("company/finance/a", &root).unwrap();
        assert_eq!(got, b"secret");

        let _ = fs::remove_dir_all(&dir);
    }
}
