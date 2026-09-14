use std::path::{Path, PathBuf};

use dmc_vault::access::{Capability, RoleRegistry};
use dmc_vault::key::{KeyPath, KeyTree};
use dmc_vault::persist::DbSnapshot;
use dmc_vault::store::EncryptedKv;
use dmc_vault::{KeyMaterial, KeyNodeMeta};

use crate::error::{Error, Result};
use crate::paths::{column_key_path, row_key_path, table_key_path, TableId};

/// Encrypted row store with BEGIN/COMMIT as an in-memory snapshot + atomic file rewrite.
pub struct StorageEngine {
    db_path: PathBuf,
    kv: EncryptedKv,
    roles: RoleRegistry,
    cap: Capability,
    checkpoint: Option<(EncryptedKv, RoleRegistry)>,
}

impl StorageEngine {
    pub fn create(path: impl AsRef<Path>) -> Result<(Self, String)> {
        let (tree, master) = KeyTree::create_new()?;
        let mut engine = Self {
            db_path: path.as_ref().to_path_buf(),
            kv: EncryptedKv::new(tree),
            roles: RoleRegistry::with_root(),
            cap: Capability::root_admin(),
            checkpoint: None,
        };
        engine.persist()?;
        Ok((engine, master.to_hex()))
    }

    pub fn open(path: impl AsRef<Path>, master_hex: &str) -> Result<Self> {
        let snap = DbSnapshot::load(path.as_ref())?;
        let master = KeyMaterial::from_hex(master_hex)?;
        let (kv, roles) = snap.unlock(&master)?;
        Ok(Self {
            db_path: path.as_ref().to_path_buf(),
            kv,
            roles,
            cap: Capability::root_admin(),
            checkpoint: None,
        })
    }

    pub fn persist(&mut self) -> Result<()> {
        let snap = DbSnapshot::from_kv(&self.kv, &self.roles)?;
        snap.save(&self.db_path)?;
        Ok(())
    }

    pub fn in_txn(&self) -> bool {
        self.checkpoint.is_some()
    }

    pub fn begin(&mut self) -> Result<()> {
        if self.checkpoint.is_some() {
            return Err(Error::AlreadyInTransaction);
        }
        self.checkpoint = Some((self.kv.clone(), self.roles.clone()));
        Ok(())
    }

    pub fn commit(&mut self) -> Result<()> {
        if self.checkpoint.is_none() {
            return Err(Error::NotInTransaction);
        }
        self.checkpoint = None;
        self.persist()
    }

    pub fn rollback(&mut self) -> Result<()> {
        let Some((kv, roles)) = self.checkpoint.take() else {
            return Err(Error::NotInTransaction);
        };
        self.kv = kv;
        self.roles = roles;
        Ok(())
    }

    pub fn ensure_path(&mut self, path: &str) -> Result<KeyNodeMeta> {
        let kp = KeyPath::parse(path)?;
        Ok(self.kv.tree_mut().ensure_node(&kp)?)
    }

    pub fn purge_path(&mut self, path: &str) -> Result<()> {
        let kp = KeyPath::parse(path)?;
        match self.kv.tree_mut().purge_subtree(&kp) {
            Ok(()) => Ok(()),
            Err(dmc_vault::Error::UnknownNode(_)) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn revoke_path(&mut self, path: &str) -> Result<()> {
        let kp = KeyPath::parse(path)?;
        Ok(self.kv.tree_mut().revoke(&kp)?)
    }

    pub fn has_node(&self, path: &str) -> bool {
        KeyPath::parse(path)
            .ok()
            .map(|p| self.kv.tree().has_node(&p))
            .unwrap_or(false)
    }

    pub fn node_revoked(&self, path: &str) -> bool {
        let Ok(p) = KeyPath::parse(path) else {
            return false;
        };
        self.kv.tree().is_revoked(&p)
    }

    pub fn put_bytes(&mut self, path: &str, value: &[u8]) -> Result<()> {
        self.kv.put(path, value, &self.cap)?;
        Ok(())
    }

    pub fn get_bytes(&mut self, path: &str) -> Result<Option<Vec<u8>>> {
        match self.kv.get(path, &self.cap) {
            Ok(v) => Ok(Some(v)),
            Err(dmc_vault::Error::NotFound(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn delete_bytes(&mut self, path: &str) -> Result<bool> {
        match self.kv.delete(path, &self.cap) {
            Ok(()) => Ok(true),
            Err(dmc_vault::Error::NotFound(_)) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    pub fn delete_prefix(&mut self, prefix: &str) -> Result<usize> {
        Ok(self.kv.delete_prefix(prefix, &self.cap)?)
    }

    pub fn list_prefix(&mut self, prefix: &str) -> Result<Vec<String>> {
        Ok(self.kv.list_keys(prefix, &self.cap)?)
    }

    pub fn put_row(&mut self, table: &TableId, row_id: &str, payload: &[u8]) -> Result<()> {
        let path = row_key_path(table, row_id);
        self.put_bytes(&path, payload)
    }

    pub fn get_row(&mut self, table: &TableId, row_id: &str) -> Result<Option<Vec<u8>>> {
        self.get_bytes(&row_key_path(table, row_id))
    }

    pub fn delete_row(&mut self, table: &TableId, row_id: &str) -> Result<bool> {
        self.delete_bytes(&row_key_path(table, row_id))
    }

    pub fn scan_rows(&mut self, table: &TableId) -> Result<Vec<(String, Vec<u8>)>> {
        let prefix = format!("{}/row", table_key_path(table));
        let keys = self.list_prefix(&prefix)?;
        let mut out = Vec::new();
        for key in keys {
            if let Some(payload) = self.get_bytes(&key)? {
                let row_id = key.rsplit('/').next().unwrap_or(&key).to_string();
                out.push((row_id, payload));
            }
        }
        Ok(out)
    }

    pub fn drop_table_storage(&mut self, table: &TableId) -> Result<()> {
        let path = table_key_path(table);
        self.delete_prefix(&path)?;
        self.purge_path(&path)
    }

    pub fn ensure_table_keys(&mut self, table: &TableId, columns: &[String]) -> Result<()> {
        self.ensure_path(&table_key_path(table))?;
        for col in columns {
            self.ensure_path(&column_key_path(table, col))?;
        }
        Ok(())
    }

    pub fn key_tree(&self) -> &KeyTree {
        self.kv.tree()
    }

    pub fn capability(&self) -> &Capability {
        &self.cap
    }

    /// Bind a session capability from `dmc-core` before storage ops.
    pub fn set_capability(&mut self, cap: Capability) {
        self.cap = cap;
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::column_key_path;

    fn tmp_db() -> (std::path::PathBuf, StorageEngine, String) {
        let dir = std::env::temp_dir().join(format!(
            "dmc-storage-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.dbs.json");
        let (engine, master) = StorageEngine::create(&path).unwrap();
        (path, engine, master)
    }

    #[test]
    fn row_roundtrip_and_txn_rollback() {
        let (path, mut engine, master) = tmp_db();
        let table = TableId::user("public", "users");
        engine
            .ensure_table_keys(&table, &["id".into(), "name".into()])
            .unwrap();
        engine.put_row(&table, "1", b"alice").unwrap();
        engine.persist().unwrap();

        engine.begin().unwrap();
        engine.put_row(&table, "1", b"bob").unwrap();
        engine.rollback().unwrap();
        assert_eq!(engine.get_row(&table, "1").unwrap().unwrap(), b"alice");

        let mut reopened = StorageEngine::open(&path, &master).unwrap();
        assert_eq!(reopened.get_row(&table, "1").unwrap().unwrap(), b"alice");
        assert!(reopened.has_node(&column_key_path(&table, "name")));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn commit_persists_across_reopen() {
        let (path, mut engine, master) = tmp_db();
        let table = TableId::user("public", "users");
        engine.ensure_table_keys(&table, &["id".into()]).unwrap();
        engine.begin().unwrap();
        engine.put_row(&table, "1", b"alice").unwrap();
        engine.commit().unwrap();

        let mut reopened = StorageEngine::open(&path, &master).unwrap();
        assert_eq!(reopened.get_row(&table, "1").unwrap().unwrap(), b"alice");
        let _ = std::fs::remove_file(&path);
    }
}
