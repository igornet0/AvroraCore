//! AEAD seal/open for session-bound UnlockBlob (Phase 7.6.2 / 7.6.6).

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use dmc_protocol::{
    unlock_blob_aad, ProtocolError, ProtocolErrorCode, Result, UnlockBlob, UNLOCK_BLOB_NONCE_LEN,
    UNLOCK_BLOB_VERSION, UNLOCK_BLOB_VERSION_ANCHORED, UNLOCK_BLOB_VERSION_RESTORE,
    UNLOCK_MATERIAL_LEN, UNLOCK_RESTORE_AUTHORIZATION_LEN,
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
    seal_versioned(session_id, binding_key, UNLOCK_BLOB_VERSION, &material.0)
}

/// D4-D: v2 blob carrying the client's anti-rollback anchor (`min_generation`) inside the
/// AEAD together with the unlock material.
pub fn seal_unlock_blob_anchored(
    session_id: &str,
    binding_key: &[u8; BINDING_KEY_LEN],
    material: &UnlockMaterial,
    min_generation: u64,
) -> Result<UnlockBlob> {
    let mut plain = zeroize::Zeroizing::new(material.0.to_vec());
    plain.extend_from_slice(&min_generation.to_be_bytes());
    seal_versioned(session_id, binding_key, UNLOCK_BLOB_VERSION_ANCHORED, &plain)
}

/// D4-E (variant B): v3 blob — additionally carries the client's emergency-restore
/// authorization: SHA-256 of exactly one backup's `manifest.sealed`.
pub fn seal_unlock_blob_restore(
    session_id: &str,
    binding_key: &[u8; BINDING_KEY_LEN],
    material: &UnlockMaterial,
    min_generation: u64,
    authorized_manifest_sealed: &[u8; UNLOCK_RESTORE_AUTHORIZATION_LEN],
) -> Result<UnlockBlob> {
    let mut plain = zeroize::Zeroizing::new(material.0.to_vec());
    plain.extend_from_slice(&min_generation.to_be_bytes());
    plain.extend_from_slice(authorized_manifest_sealed);
    seal_versioned(session_id, binding_key, UNLOCK_BLOB_VERSION_RESTORE, &plain)
}

fn seal_versioned(
    session_id: &str,
    binding_key: &[u8; BINDING_KEY_LEN],
    version: u16,
    plain: &[u8],
) -> Result<UnlockBlob> {
    let key = BindingKey::from_slice(binding_key);
    let cipher = Aes256Gcm::new_from_slice(key.0.as_slice())
        .map_err(|_| ProtocolError::wire(ProtocolErrorCode::InternalError, "unlock cipher"))?;
    let mut nonce = [0u8; UNLOCK_BLOB_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let aad = unlock_blob_aad(version, session_id);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plain,
                aad: &aad,
            },
        )
        .map_err(|_| {
            ProtocolError::wire(ProtocolErrorCode::UnlockFailed, "unlock blob seal failed")
        })?;
    Ok(UnlockBlob {
        version,
        session_id: session_id.into(),
        nonce,
        ciphertext,
    })
}

pub fn open_unlock_blob(
    blob: &UnlockBlob,
    binding_key: &[u8; BINDING_KEY_LEN],
) -> Result<UnlockMaterial> {
    open_unlock_blob_anchored(blob, binding_key).map(|(m, _)| m)
}

/// Open a v1 (`min_generation` = 0: no anchor) or v2 blob → (material, min_generation).
/// A v3 blob (emergency-restore authorization) is refused here: only `VaultUnlock` may
/// act on it ([`open_unlock_blob_full`]), never silently drop the authorization.
pub fn open_unlock_blob_anchored(
    blob: &UnlockBlob,
    binding_key: &[u8; BINDING_KEY_LEN],
) -> Result<(UnlockMaterial, u64)> {
    let opened = open_unlock_blob_full(blob, binding_key)?;
    if opened.restore_authorization.is_some() {
        return Err(ProtocolError::wire(
            ProtocolErrorCode::UnlockBlobInvalid,
            "restore authorization is not accepted by this operation",
        ));
    }
    Ok((opened.material, opened.min_generation))
}

/// Contents of an opened unlock blob.
pub struct OpenedUnlock {
    pub material: UnlockMaterial,
    /// D4-D anti-rollback anchor (0: none).
    pub min_generation: u64,
    /// D4-E (variant B): SHA-256 of the one backup `manifest.sealed` the client authorizes
    /// for an emergency restore (v3 only).
    pub restore_authorization: Option<[u8; UNLOCK_RESTORE_AUTHORIZATION_LEN]>,
}

/// Open a v1, v2 or v3 blob.
pub fn open_unlock_blob_full(
    blob: &UnlockBlob,
    binding_key: &[u8; BINDING_KEY_LEN],
) -> Result<OpenedUnlock> {
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
    let expected = match blob.version {
        UNLOCK_BLOB_VERSION => UNLOCK_MATERIAL_LEN,
        UNLOCK_BLOB_VERSION_ANCHORED => UNLOCK_MATERIAL_LEN + 8,
        UNLOCK_BLOB_VERSION_RESTORE => UNLOCK_MATERIAL_LEN + 8 + UNLOCK_RESTORE_AUTHORIZATION_LEN,
        _ => 0,
    };
    if plaintext.len() != expected {
        plaintext.zeroize();
        return Err(ProtocolError::wire(
            ProtocolErrorCode::UnlockBlobInvalid,
            "invalid unlock material length",
        ));
    }
    let mut material = [0u8; UNLOCK_MATERIAL_LEN];
    material.copy_from_slice(&plaintext[..UNLOCK_MATERIAL_LEN]);
    let min_generation = if blob.version == UNLOCK_BLOB_VERSION {
        0
    } else {
        let at = UNLOCK_MATERIAL_LEN;
        u64::from_be_bytes(plaintext[at..at + 8].try_into().expect("8 bytes"))
    };
    let restore_authorization = (blob.version == UNLOCK_BLOB_VERSION_RESTORE).then(|| {
        let mut h = [0u8; UNLOCK_RESTORE_AUTHORIZATION_LEN];
        h.copy_from_slice(&plaintext[UNLOCK_MATERIAL_LEN + 8..]);
        h
    });
    plaintext.zeroize();
    Ok(OpenedUnlock {
        material: UnlockMaterial(material),
        min_generation,
        restore_authorization,
    })
}
