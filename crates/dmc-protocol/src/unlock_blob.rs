use crate::error::ProtocolErrorCode;
use crate::{ProtocolError, Result};

pub const UNLOCK_BLOB_VERSION: u16 = 1;
/// D4-D: v2 seals `material ‖ min_generation (u64 BE)` — the client's anti-rollback anchor
/// travels inside the AEAD (the version is in the AAD, so it can be neither altered nor
/// downgraded unnoticed).
pub const UNLOCK_BLOB_VERSION_ANCHORED: u16 = 2;
/// D4-E (variant B): v3 seals `material ‖ min_generation (u64 BE) ‖ SHA-256 of the
/// client-authorized backup's manifest.sealed` — the emergency-restore authorization for
/// exactly one backup artifact, bound by the AEAD (version in the AAD).
pub const UNLOCK_BLOB_VERSION_RESTORE: u16 = 3;
/// Length of the backup authorization (SHA-256) in a v3 blob.
pub const UNLOCK_RESTORE_AUTHORIZATION_LEN: usize = 32;
pub const UNLOCK_BLOB_NONCE_LEN: usize = 12;
pub const UNLOCK_MATERIAL_LEN: usize = 32;

/// Session-bound AEAD unlock envelope. Plaintext unlock material never appears in JSON.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UnlockBlob {
    pub version: u16,
    pub session_id: String,
    #[serde(with = "serde_nonce")]
    pub nonce: [u8; UNLOCK_BLOB_NONCE_LEN],
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

impl std::fmt::Debug for UnlockBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockBlob")
            .field("version", &self.version)
            .field("session_id", &self.session_id)
            .field("nonce_len", &self.nonce.len())
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

mod serde_nonce {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(nonce: &[u8; 12], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(nonce)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 12], D::Error> {
        let bytes = <Vec<u8>>::deserialize(d)?;
        if bytes.len() != 12 {
            return Err(serde::de::Error::custom("unlock blob nonce must be 12 bytes"));
        }
        let mut out = [0u8; 12];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

mod serde_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        <Vec<u8>>::deserialize(d)
    }
}

pub fn validate_unlock_blob(blob: &UnlockBlob, max_size: u32) -> Result<()> {
    if ![
        UNLOCK_BLOB_VERSION,
        UNLOCK_BLOB_VERSION_ANCHORED,
        UNLOCK_BLOB_VERSION_RESTORE,
    ]
    .contains(&blob.version)
    {
        return Err(ProtocolError::wire(
            ProtocolErrorCode::UnlockBlobInvalid,
            "unsupported unlock blob version",
        ));
    }
    if blob.session_id.is_empty() {
        return Err(ProtocolError::wire(
            ProtocolErrorCode::UnlockBlobInvalid,
            "missing session id",
        ));
    }
    let encoded_len = blob.ciphertext.len() as u32 + blob.session_id.len() as u32 + 32;
    if encoded_len > max_size {
        return Err(ProtocolError::wire(
            ProtocolErrorCode::InvalidRequest,
            "unlock blob too large",
        ));
    }
    if blob.ciphertext.is_empty() {
        return Err(ProtocolError::wire(
            ProtocolErrorCode::UnlockBlobInvalid,
            "empty unlock blob ciphertext",
        ));
    }
    Ok(())
}

pub fn unlock_blob_aad(version: u16, session_id: &str) -> Vec<u8> {
    format!("avrora-unlock-blob-v{version}/{session_id}").into_bytes()
}
