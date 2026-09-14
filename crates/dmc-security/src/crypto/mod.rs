//! Hashing helpers used by UI credentials. Vault AEAD/key-tree stays in `dmc-vault`.

use sha2::{Digest, Sha256};

pub(crate) fn hash_access_key(salt: &[u8], access_key: &str) -> String {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(access_key.as_bytes());
    hex::encode(h.finalize())
}
