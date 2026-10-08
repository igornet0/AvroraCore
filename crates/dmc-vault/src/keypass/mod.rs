//! Wrapped Master Key container (KeyPass).
//!
//! Master Key never touches disk in plaintext. Argon2id(Master Password) yields a KEK
//! that AEAD-wraps the 32-byte vault master. The same bundle is written locally and
//! onto USB (`avrora/keypass.json` + `encrypted-master-key.bin`).

use std::fs;
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::crypto::{AeadBlob, decrypt, encrypt};
use crate::error::{Error, Result};
use crate::key::KeyMaterial;

pub const USB_DIR_NAME: &str = "avrora";
pub const META_FILE: &str = "keypass.json";
pub const CIPHER_FILE: &str = "encrypted-master-key.bin";

pub const MIN_PASSWORD_LEN: usize = 8;
pub const KDF_ALG: &str = "argon2id";
pub const WRAP_ALG: &str = "aes-256-gcm";
pub const M_COST: u32 = 19_456;
pub const T_COST: u32 = 2;
pub const P_COST: u32 = 1;
const SALT_LEN: usize = 16;
const VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KdfParams {
    pub alg: String,
    pub salt_b64: String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrapParams {
    pub alg: String,
    pub nonce_b64: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyPassMeta {
    pub version: u32,
    pub device_id: String,
    pub db_id: String,
    pub kdf: KdfParams,
    pub wrap: WrapParams,
    pub created_at: String,
}

#[derive(Clone, Debug)]
pub struct KeyPassBundle {
    pub meta: KeyPassMeta,
    pub ciphertext: Vec<u8>,
}

impl KeyPassBundle {
    pub fn device_id(&self) -> &str {
        &self.meta.device_id
    }

    pub fn db_id(&self) -> &str {
        &self.meta.db_id
    }
}

/// Sibling directory next to the vault file: `{stem}.keypass/`.
pub fn local_dir(db_path: &Path) -> PathBuf {
    let stem = db_path.file_stem().unwrap_or_default().to_string_lossy();
    db_path.with_file_name(format!("{stem}.keypass"))
}

/// `{mount}/avrora/`
pub fn usb_dir(mount: &Path) -> PathBuf {
    mount.join(USB_DIR_NAME)
}

pub fn exists(dir: &Path) -> bool {
    dir.join(META_FILE).is_file() && dir.join(CIPHER_FILE).is_file()
}

pub fn db_id_from_salt(salt: &[u8; 32]) -> String {
    hex::encode(salt)
}

pub fn wrap(master: &KeyMaterial, password: &str, db_id: &str) -> Result<KeyPassBundle> {
    let password = password.trim();
    if password.len() < MIN_PASSWORD_LEN {
        return Err(Error::InvalidMasterPassword(MIN_PASSWORD_LEN));
    }
    if db_id.is_empty() {
        return Err(Error::Persist("empty db_id".into()));
    }

    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let kek = derive_kek(password, &salt, M_COST, T_COST, P_COST)?;
    let aad = wrap_aad(db_id);
    let blob = encrypt(&kek, master.as_bytes(), &aad)?;

    Ok(KeyPassBundle {
        meta: KeyPassMeta {
            version: VERSION,
            device_id: uuid::Uuid::new_v4().to_string(),
            db_id: db_id.to_string(),
            kdf: KdfParams {
                alg: KDF_ALG.into(),
                salt_b64: B64.encode(salt),
                m_cost: M_COST,
                t_cost: T_COST,
                p_cost: P_COST,
            },
            wrap: WrapParams {
                alg: WRAP_ALG.into(),
                nonce_b64: B64.encode(blob.nonce),
            },
            created_at: chrono::Utc::now().to_rfc3339(),
        },
        ciphertext: blob.ciphertext,
    })
}

pub fn unwrap(bundle: &KeyPassBundle, password: &str) -> Result<KeyMaterial> {
    unwrap_for_db(bundle, password, None)
}

pub fn unwrap_for_db(
    bundle: &KeyPassBundle,
    password: &str,
    expected_db_id: Option<&str>,
) -> Result<KeyMaterial> {
    if let Some(expected) = expected_db_id {
        if bundle.meta.db_id != expected {
            return Err(Error::KeyPassDbMismatch);
        }
    }
    if bundle.meta.version != VERSION {
        return Err(Error::Persist(format!(
            "unsupported keypass version {}",
            bundle.meta.version
        )));
    }
    if bundle.meta.kdf.alg != KDF_ALG {
        return Err(Error::Persist(format!(
            "unsupported kdf {}",
            bundle.meta.kdf.alg
        )));
    }
    if bundle.meta.wrap.alg != WRAP_ALG {
        return Err(Error::Persist(format!(
            "unsupported wrap {}",
            bundle.meta.wrap.alg
        )));
    }

    let salt = decode_b64(&bundle.meta.kdf.salt_b64)?;
    let nonce = decode_b64(&bundle.meta.wrap.nonce_b64)?;
    if nonce.len() != 12 {
        return Err(Error::Persist("keypass nonce must be 12 bytes".into()));
    }
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce);

    let kek = derive_kek(
        password.trim(),
        &salt,
        bundle.meta.kdf.m_cost,
        bundle.meta.kdf.t_cost,
        bundle.meta.kdf.p_cost,
    )?;
    let blob = AeadBlob {
        nonce: nonce_arr,
        ciphertext: bundle.ciphertext.clone(),
    };
    let aad = wrap_aad(&bundle.meta.db_id);
    let bytes = decrypt(&kek, &blob, &aad).map_err(|_| Error::WrongMasterPassword)?;
    if bytes.len() != 32 {
        return Err(Error::WrongMasterPassword);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(KeyMaterial::from_bytes(arr))
}

pub fn save(dir: &Path, bundle: &KeyPassBundle) -> Result<()> {
    fs::create_dir_all(dir).map_err(|e| Error::Io(e.to_string()))?;
    let meta_raw =
        serde_json::to_vec_pretty(&bundle.meta).map_err(|e| Error::Persist(e.to_string()))?;
    // Wrapped master + KDF params: owner-only (limits offline guessing to the owner account).
    crate::secure_fs::write_secret_file(&dir.join(CIPHER_FILE), &bundle.ciphertext)
        .map_err(|e| Error::Io(e.to_string()))?;
    crate::secure_fs::write_secret_file(&dir.join(META_FILE), &meta_raw)
        .map_err(|e| Error::Io(e.to_string()))?;
    Ok(())
}

pub fn load(dir: &Path) -> Result<KeyPassBundle> {
    let meta_path = dir.join(META_FILE);
    let cipher_path = dir.join(CIPHER_FILE);
    if !meta_path.is_file() || !cipher_path.is_file() {
        return Err(Error::KeyPassNotFound);
    }
    let raw = fs::read_to_string(&meta_path).map_err(|e| Error::Io(e.to_string()))?;
    let meta: KeyPassMeta =
        serde_json::from_str(&raw).map_err(|e| Error::Persist(e.to_string()))?;
    let ciphertext = fs::read(&cipher_path).map_err(|e| Error::Io(e.to_string()))?;
    Ok(KeyPassBundle { meta, ciphertext })
}

pub fn matches_device(dir: &Path, device_id: &str) -> bool {
    match load(dir) {
        Ok(bundle) => bundle.meta.device_id == device_id,
        Err(_) => false,
    }
}

fn wrap_aad(db_id: &str) -> Vec<u8> {
    format!("avrora-keypass-v1/{db_id}").into_bytes()
}

fn derive_kek(
    password: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<KeyMaterial> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(32)).map_err(|_| Error::KdfFailed)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut kek = [0u8; 32];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut kek)
        .map_err(|_| Error::KdfFailed)?;
    Ok(KeyMaterial::from_bytes(kek))
}

fn decode_b64(s: &str) -> Result<Vec<u8>> {
    B64.decode(s.trim())
        .map_err(|e| Error::Persist(format!("invalid base64: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "avrora-keypass-{}-{}-{}",
            name,
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let master = KeyMaterial::random();
        let bundle = wrap(&master, "correct-horse", "db-aaa").unwrap();
        let got = unwrap(&bundle, "correct-horse").unwrap();
        assert_eq!(got.to_hex(), master.to_hex());
    }

    #[test]
    fn wrong_password_fails() {
        let master = KeyMaterial::random();
        let bundle = wrap(&master, "correct-horse", "db-aaa").unwrap();
        let err = unwrap(&bundle, "wrong-password").unwrap_err();
        assert!(matches!(err, Error::WrongMasterPassword));
    }

    #[test]
    fn wrong_db_id_rejected() {
        let master = KeyMaterial::random();
        let bundle = wrap(&master, "correct-horse", "db-aaa").unwrap();
        let err = unwrap_for_db(&bundle, "correct-horse", Some("db-bbb")).unwrap_err();
        assert!(matches!(err, Error::KeyPassDbMismatch));
    }

    #[test]
    fn short_password_rejected() {
        let master = KeyMaterial::random();
        let err = wrap(&master, "short", "db-aaa").unwrap_err();
        assert!(matches!(err, Error::InvalidMasterPassword(_)));
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = temp_dir("save");
        let master = KeyMaterial::random();
        let bundle = wrap(&master, "correct-horse", "db-aaa").unwrap();
        save(&dir, &bundle).unwrap();
        assert!(exists(&dir));
        let loaded = load(&dir).unwrap();
        assert_eq!(loaded.meta.device_id, bundle.meta.device_id);
        assert_eq!(loaded.meta.db_id, "db-aaa");
        let got = unwrap(&loaded, "correct-horse").unwrap();
        assert_eq!(got.to_hex(), master.to_hex());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn local_dir_uses_stem() {
        let path = Path::new("/data/store.dbs.json");
        assert_eq!(local_dir(path), PathBuf::from("/data/store.dbs.keypass"));
        assert_eq!(
            usb_dir(Path::new("/Volumes/KEY")),
            PathBuf::from("/Volumes/KEY/avrora")
        );
    }
}
