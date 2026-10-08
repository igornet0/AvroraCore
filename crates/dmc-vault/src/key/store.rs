//! Persistence of a [`KeyTree`]'s **public** state: salt, unlock proof and the node
//! metadata whose DEKs are already wrapped. The master secret, KEKs and unwrapped DEKs are
//! never written. The file is owner-only (0600) from creation and replaced atomically.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::crypto::AeadBlob;
use crate::error::{Error, Result};
use crate::key::{KeyNodeMeta, KeyTree};

pub const KEY_TREE_FILE_FORMAT: u32 = 1;

#[derive(Serialize, Deserialize)]
struct KeyTreeFile {
    format_version: u32,
    salt_hex: String,
    unlock_proof: AeadBlob,
    nodes: Vec<KeyNodeMeta>,
}

/// Write the public state of `tree` to `path`.
pub fn save_key_tree(tree: &KeyTree, path: &Path) -> Result<()> {
    let mut nodes = tree.export_meta();
    nodes.sort_by(|a, b| a.path.cmp(&b.path));
    let file = KeyTreeFile {
        format_version: KEY_TREE_FILE_FORMAT,
        salt_hex: hex::encode(tree.salt()),
        unlock_proof: tree.unlock_proof().clone(),
        nodes,
    };
    let raw = serde_json::to_vec_pretty(&file).map_err(|e| Error::Persist(e.to_string()))?;
    crate::secure_fs::write_secret_file(path, &raw).map_err(|e| Error::Persist(e.to_string()))
}

/// Load a **locked** tree (no secrets in memory). Any malformed content is an error —
/// the caller must never fall back to creating a new tree.
pub fn load_locked_key_tree(path: &Path) -> Result<KeyTree> {
    let raw = std::fs::read(path).map_err(|e| Error::Persist(format!("key tree: {e}")))?;
    parse_locked_key_tree(&raw)
}

/// [`load_locked_key_tree`] over the file's bytes (e.g. the copy carried by a backup).
pub fn parse_locked_key_tree(raw: &[u8]) -> Result<KeyTree> {
    let file: KeyTreeFile =
        serde_json::from_slice(raw).map_err(|e| Error::Persist(format!("key tree: {e}")))?;
    if file.format_version != KEY_TREE_FILE_FORMAT {
        return Err(Error::Persist("unsupported key tree format".into()));
    }
    let salt: [u8; 32] = hex::decode(&file.salt_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| Error::Persist("bad key tree salt".into()))?;
    KeyTree::locked_from_persisted(salt, file.unlock_proof, file.nodes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KeyPath;

    #[test]
    fn save_load_unlock_and_wrong_master() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keytree.json");
        let (mut tree, master) = KeyTree::create_new().unwrap();
        let storage = KeyPath::parse("storage/rows").unwrap();
        tree.ensure_node(&storage).unwrap();
        let dek = tree.dek(&storage).unwrap().clone();
        save_key_tree(&tree, &path).unwrap();
        // nothing secret on disk
        let raw = std::fs::read(&path).unwrap();
        for secret in [master.as_bytes().to_vec(), dek.as_bytes().to_vec()] {
            assert!(!raw.windows(32).any(|w| w == secret.as_slice()));
            assert!(!String::from_utf8_lossy(&raw).contains(&hex::encode(&secret)));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let locked = load_locked_key_tree(&path).unwrap();
        assert!(!locked.has_runtime_secrets());
        // the same master unlocks and yields the same storage DEK
        let mut open = KeyTree::unlock(
            &master,
            *locked.salt(),
            locked.unlock_proof().clone(),
            locked.export_meta(),
        )
        .unwrap();
        assert_eq!(open.dek(&storage).unwrap().as_bytes(), dek.as_bytes());
        // a different master is refused
        let other = crate::KeyMaterial::random();
        assert!(
            KeyTree::unlock(
                &other,
                *locked.salt(),
                locked.unlock_proof().clone(),
                locked.export_meta()
            )
            .is_err()
        );
        // corrupt file → error (never a fresh tree)
        std::fs::write(&path, b"{\"format_version\":1}").unwrap();
        assert!(load_locked_key_tree(&path).is_err());
    }
}
