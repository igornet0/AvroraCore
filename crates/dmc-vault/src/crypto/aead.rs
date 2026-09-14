use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::key::KeyMaterial;

const NONCE_LEN: usize = 12;

/// AEAD ciphertext package stored on disk / in the KV layer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AeadBlob {
    #[serde(with = "serde_nonce")]
    pub nonce: [u8; NONCE_LEN],
    #[serde(with = "serde_hex_vec")]
    pub ciphertext: Vec<u8>,
}

mod serde_nonce {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(nonce: &[u8; 12], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(nonce))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 12], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 12 {
            return Err(serde::de::Error::custom("nonce must be 12 bytes"));
        }
        let mut out = [0u8; 12];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

mod serde_hex_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

pub fn encrypt(key: &KeyMaterial, plaintext: &[u8], aad: &[u8]) -> Result<AeadBlob> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| Error::AeadFailed)?;
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::AeadFailed)?;
    Ok(AeadBlob { nonce, ciphertext })
}

pub fn decrypt(key: &KeyMaterial, blob: &AeadBlob, aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| Error::AeadFailed)?;
    cipher
        .decrypt(
            Nonce::from_slice(&blob.nonce),
            Payload {
                msg: &blob.ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::AeadFailed)
}

/// Wrap a DEK under a KEK (envelope encryption).
pub fn wrap_key(kek: &KeyMaterial, dek: &KeyMaterial) -> Result<AeadBlob> {
    encrypt(kek, dek.as_bytes(), b"key-wrap")
}

/// Unwrap a DEK under a KEK.
pub fn unwrap_key(kek: &KeyMaterial, wrapped: &AeadBlob) -> Result<KeyMaterial> {
    let bytes = decrypt(kek, wrapped, b"key-wrap")?;
    if bytes.len() != 32 {
        return Err(Error::UnwrapFailed);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(KeyMaterial::from_bytes(arr))
}
