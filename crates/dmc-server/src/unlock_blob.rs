//! AEAD seal/open for session-bound UnlockBlob (Phase 7.6.2 / 7.6.6).

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use dmc_protocol::{
    unlock_blob_aad, ProtocolError, ProtocolErrorCode, Result, UnlockBlob, UNLOCK_BLOB_NONCE_LEN,
    UNLOCK_BLOB_VERSION, UNLOCK_MATERIAL_LEN,
};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

const BINDING_KEY_LEN: usize = 32;

/// Client/server unlock material (Master Key bytes). Zeroized on drop. Never Debug-printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct UnlockMaterial(pub [u8; UNLOCK_MATERIAL_LEN]);

impl std::fmt::Debug for UnlockMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UnlockMaterial([REDACTED])")
    }
}

impl UnlockMaterial {
    pub fn random() -> Self {
        let mut material = [0u8; UNLOCK_MATERIAL_LEN];
        rand::thread_rng().fill_bytes(&mut material);
        Self(material)
    }

    /// Explicit wipe (also runs on Drop via ZeroizeOnDrop).
    pub fn wipe(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct BindingKey([u8; BINDING_KEY_LEN]);

impl std::fmt::Debug for BindingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BindingKey([REDACTED])")
    }
}

impl BindingKey {
    fn from_slice(key: &[u8; BINDING_KEY_LEN]) -> Self {
        Self(*key)
    }
}

pub fn seal_unlock_blob(
    session_id: &str,
    binding_key: &[u8; BINDING_KEY_LEN],
    material: &UnlockMaterial,
) -> Result<UnlockBlob> {
    let key = BindingKey::from_slice(binding_key);
    let cipher = Aes256Gcm::new_from_slice(key.0.as_slice())
        .map_err(|_| ProtocolError::wire(ProtocolErrorCode::InternalError, "unlock cipher"))?;
    let mut nonce = [0u8; UNLOCK_BLOB_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let aad = unlock_blob_aad(UNLOCK_BLOB_VERSION, session_id);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &material.0,
                aad: &aad,
            },
        )
        .map_err(|_| {
            ProtocolError::wire(ProtocolErrorCode::UnlockFailed, "unlock blob seal failed")
        })?;
    Ok(UnlockBlob {
        version: UNLOCK_BLOB_VERSION,
        session_id: session_id.into(),
        nonce,
        ciphertext,
    })
}

pub fn open_unlock_blob(
    blob: &UnlockBlob,
    binding_key: &[u8; BINDING_KEY_LEN],
) -> Result<UnlockMaterial> {
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
