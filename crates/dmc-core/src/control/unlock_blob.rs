//! AEAD open for session-bound UnlockBlob (Phase 7.6.2 / ADR-022).

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use dmc_protocol::{
    unlock_blob_aad, ProtocolError, ProtocolErrorCode, UnlockBlob, UNLOCK_BLOB_NONCE_LEN,
    UNLOCK_BLOB_VERSION, UNLOCK_MATERIAL_LEN,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

const BINDING_KEY_LEN: usize = 32;

/// Master Key bytes decrypted from UnlockBlob. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct UnlockMaterial(pub [u8; UNLOCK_MATERIAL_LEN]);

impl std::fmt::Debug for UnlockMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UnlockMaterial([REDACTED])")
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct BindingKey([u8; BINDING_KEY_LEN]);

impl BindingKey {
    fn from_slice(key: &[u8; BINDING_KEY_LEN]) -> Self {
        Self(*key)
    }
}

pub fn open_unlock_blob(
    blob: &UnlockBlob,
    binding_key: &[u8; BINDING_KEY_LEN],
) -> Result<UnlockMaterial, ProtocolError> {
    if blob.session_id.is_empty() {
        return Err(ProtocolError::wire(
            ProtocolErrorCode::UnlockBlobInvalid,
            "missing session id",
        ));
    }
    let key = BindingKey::from_slice(binding_key);
    let cipher = Aes256Gcm::new_from_slice(key.0.as_slice())
        .map_err(|_| ProtocolError::wire(ProtocolErrorCode::InternalError, "unlock cipher"))?;
    let aad = unlock_blob_aad(blob.version, &blob.session_id);
    let mut plaintext = cipher
        .decrypt(
            Nonce::from_slice(&blob.nonce),
            Payload {
                msg: &blob.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| {
            ProtocolError::wire(ProtocolErrorCode::UnlockBlobInvalid, "unlock blob decrypt failed")
        })?;
    if plaintext.len() != UNLOCK_MATERIAL_LEN {
        plaintext.zeroize();
        return Err(ProtocolError::wire(
            ProtocolErrorCode::UnlockBlobInvalid,
            "invalid unlock material length",
        ));
    }
    let mut material = [0u8; UNLOCK_MATERIAL_LEN];
    material.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(UnlockMaterial(material))
}

pub fn validate_blob(blob: &UnlockBlob) -> Result<(), ProtocolError> {
    if blob.version != UNLOCK_BLOB_VERSION {
        return Err(ProtocolError::wire(
            ProtocolErrorCode::UnlockBlobInvalid,
            "unsupported unlock blob version",
        ));
    }
    if blob.nonce.len() != UNLOCK_BLOB_NONCE_LEN {
        return Err(ProtocolError::wire(
            ProtocolErrorCode::UnlockBlobInvalid,
            "invalid unlock blob nonce",
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
