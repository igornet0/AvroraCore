use std::fmt;

use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Opaque 32-byte key identifier (hash of path + generation).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId(pub [u8; 32]);

impl KeyId {
    pub fn from_path(path: &str, generation: u64) -> Self {
        let mut h = Sha256::new();
        h.update(b"key-id/v1/");
        h.update(path.as_bytes());
        h.update(generation.to_le_bytes());
        let digest = h.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&digest);
        Self(id)
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({:02x}{:02x}…)", self.0[0], self.0[1])
    }
}

/// Secret key material. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyMaterial([u8; 32]);

impl KeyMaterial {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> crate::error::Result<Self> {
        let raw = hex::decode(s.trim()).map_err(|_| crate::error::Error::InvalidMasterKey)?;
        if raw.len() != 32 {
            return Err(crate::error::Error::InvalidMasterKey);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&raw);
        Ok(Self(bytes))
    }
}

impl fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyMaterial([REDACTED])")
    }
}
