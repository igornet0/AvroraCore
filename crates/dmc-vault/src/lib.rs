//! Encrypted KV and hierarchical key tree (storage crypto layer).
//!
//! Formal model:
//! - hierarchical path keys derived via HKDF from a master secret
//! - envelope-wrapped DEKs for rotation / revocation
//! - capabilities (READ / WRITE / GRANT) separate from encryption material
//! - master secret lives only in RAM; wrong key → data inaccessible

pub mod access;
pub mod crypto;
pub mod error;
pub mod key;
pub mod keypass;
pub mod ownership;
pub mod persist;
pub mod secure_fs;
pub mod seed;
pub mod storage_cipher;
pub mod store;

pub use access::{Capability, Permission, PermissionSet, Role, RoleRegistry, authorize_tree_write};
pub use error::{Error, Result};
pub use key::{
    KEY_TREE_FILE_FORMAT, KeyId, KeyMaterial, KeyNodeMeta, KeyPath, KeyTree, NodeState, load_locked_key_tree,
    parse_locked_key_tree, save_key_tree,
};
pub use keypass::{KeyPassBundle, KeyPassMeta};
pub use persist::{DbSnapshot, OverlayRecord, default_db_path};
pub use key::{AUDIT_KEK_INFO, JOURNAL_KEK_INFO, METADATA_KEK_INFO, ROOT_KEK_INFO};
pub use seed::{seed_auth_service, seed_demo};
pub use storage_cipher::{StorageCipher, StoragePurpose};
pub use store::EncryptedKv;
