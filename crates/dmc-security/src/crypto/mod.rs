//! UI access-key verification. Vault AEAD/key-tree stays in `dmc-vault`.
//!
//! New records use the shared Argon2id credential KDF (`dmc_vault::ownership::credential`);
//! there is no second password-hashing implementation. The legacy SHA-256 check exists
//! only to verify v1 files once before they are upgraded.

use dmc_vault::ownership::{PasswordKdfParams, Verifier, derive_credential_secrets, random_salt};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::credentials::{AUTH_FILE_V1_SHA256, AUTH_FILE_V2_ARGON2ID, AuthFile};

/// Salt + Argon2id verifier for a new access key.
pub(crate) struct AccessKeyRecord {
    pub salt: [u8; 16],
    pub kdf: PasswordKdfParams,
    pub verifier: Verifier,
}

pub(crate) fn new_access_key_record(access_key: &str) -> Option<AccessKeyRecord> {
    let salt = random_salt();
    let kdf = PasswordKdfParams::default();
    let secrets = derive_credential_secrets(access_key, &salt, &kdf).ok()?;
    Some(AccessKeyRecord {
        salt,
        kdf,
        verifier: secrets.verifier,
    })
}

/// Constant-time verification for v1 (legacy SHA-256) and v2 (Argon2id) files.
pub(crate) fn verify_access_key(file: &AuthFile, access_key: &str) -> bool {
    let Ok(salt) = hex::decode(&file.salt_hex) else {
        return false;
    };
    match file.version {
        AUTH_FILE_V2_ARGON2ID => match (&file.kdf, &file.verifier) {
            (Some(kdf), Some(expected)) => derive_credential_secrets(access_key, &salt, kdf)
                .map(|s| expected.matches(&s.verifier))
                .unwrap_or(false),
            _ => false,
        },
        AUTH_FILE_V1_SHA256 => match &file.access_key_hash {
            Some(expected_hex) => {
                let mut h = Sha256::new();
                h.update(&salt);
                h.update(access_key.as_bytes());
                let actual = h.finalize();
                match hex::decode(expected_hex) {
                    Ok(expected) if expected.len() == actual.len() => {
                        actual.as_slice().ct_eq(&expected).into()
                    }
                    _ => false,
                }
            }
            None => false,
        },
        _ => false,
    }
}

pub(crate) fn auth_file_v2(record: AccessKeyRecord, totp_secret_b32: String) -> AuthFile {
    AuthFile {
        version: AUTH_FILE_V2_ARGON2ID,
        salt_hex: hex::encode(record.salt),
        access_key_hash: None,
        kdf: Some(record.kdf),
        verifier: Some(record.verifier),
        totp_secret_b32,
    }
}
