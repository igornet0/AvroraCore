//! Password → (authentication verifier, KEK wrapping key).
//!
//! One Argon2id evaluation produces a 32-byte root that HKDF-SHA256 splits into two
//! domain-separated outputs:
//!
//! * `verifier` — stored by the authentication layer and compared in constant time;
//! * `wrap_key` — never stored; it only opens the subject KEK envelope.
//!
//! HKDF is one-way, so a stolen verifier does not yield the wrapping key (an attacker
//! still has to brute-force the password through Argon2id). The password is never
//! used directly as a data key.

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use super::error::{Error, Result};
use crate::key::KeyMaterial;

pub const KDF_ARGON2ID: &str = "argon2id-v19";
pub const SALT_LEN: usize = 16;
/// Minimum password length for credentials that wrap cryptographic keys.
pub const MIN_KEY_CREDENTIAL_LEN: usize = 8;

const HKDF_SALT: &[u8] = b"avrora/credential/v1";
const INFO_VERIFIER: &[u8] = b"auth-verifier";
const INFO_WRAP: &[u8] = b"kek-wrap";

/// Argon2id cost parameters (persisted next to each verifier so they can be raised later).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordKdfParams {
    pub alg: KdfAlg,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KdfAlg {
    #[serde(rename = "argon2id-v19")]
    Argon2idV19,
}

impl Default for PasswordKdfParams {
    /// OWASP-recommended Argon2id baseline (19 MiB, t=2, p=1) — same as KeyPass.
    fn default() -> Self {
        Self {
            alg: KdfAlg::Argon2idV19,
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
        }
    }
}

/// Random per-credential salt.
pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Authentication verifier (not secret enough to unlock keys, but still not logged).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verifier(#[serde(with = "hex32")] [u8; 32]);

impl Verifier {
    /// Constant-time comparison.
    pub fn matches(&self, other: &Verifier) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Verifier([REDACTED])")
    }
}

/// Output of one credential derivation. `wrap_key` is zeroized on drop.
pub struct CredentialSecrets {
    pub verifier: Verifier,
    pub wrap_key: KeyMaterial,
}

impl fmt::Debug for CredentialSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialSecrets([REDACTED])")
    }
}

pub fn derive_credential_secrets(
    password: &str,
    salt: &[u8],
    params: &PasswordKdfParams,
) -> Result<CredentialSecrets> {
    let KdfAlg::Argon2idV19 = params.alg;
    let argon_params = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(32))
        .map_err(|_| Error::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut root = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), salt, root.as_mut())
        .map_err(|_| Error::Kdf)?;

    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), root.as_ref());
    let mut verifier = [0u8; 32];
    hk.expand(INFO_VERIFIER, &mut verifier).map_err(|_| Error::Kdf)?;
    let mut wrap = [0u8; 32];
    hk.expand(INFO_WRAP, &mut wrap).map_err(|_| Error::Kdf)?;
    let wrap_key = KeyMaterial::from_bytes(wrap);
    wrap.zeroize();
    Ok(CredentialSecrets {
        verifier: Verifier(verifier),
        wrap_key,
    })
}

/// Policy for passwords that protect cryptographic keys.
pub fn check_key_credential_policy(password: &str) -> Result<()> {
    if password.chars().count() < MIN_KEY_CREDENTIAL_LEN {
        return Err(Error::WeakCredential(format!(
            "at least {MIN_KEY_CREDENTIAL_LEN} characters required"
        )));
    }
    Ok(())
}

/// Credential-derived KEK wrapping key handed from authentication to key access.
///
/// Not `Clone`, redacted `Debug`, wiped on drop. Holding one proves the password was
/// presented in this process; it does not by itself authorize access to any key.
pub struct CredentialUnlock {
    credential_id: String,
    wrap_key: KeyMaterial,
}

impl CredentialUnlock {
    pub fn new(credential_id: impl Into<String>, wrap_key: KeyMaterial) -> Self {
        Self {
            credential_id: credential_id.into(),
            wrap_key,
        }
    }

    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    pub(crate) fn wrap_key(&self) -> &KeyMaterial {
        &self.wrap_key
    }
}

impl fmt::Debug for CredentialUnlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialUnlock")
            .field("credential_id", &self.credential_id)
            .field("wrap_key", &"[REDACTED]")
            .finish()
    }
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let raw = hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)?;
        raw.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

#[cfg(test)]
pub(crate) fn test_params() -> PasswordKdfParams {
    PasswordKdfParams {
        alg: KdfAlg::Argon2idV19,
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_and_wrap_key_are_domain_separated() {
        let salt = random_salt();
        let s = derive_credential_secrets("correct horse", &salt, &test_params()).unwrap();
        assert_ne!(&s.verifier.0, s.wrap_key.as_bytes());
        let again = derive_credential_secrets("correct horse", &salt, &test_params()).unwrap();
        assert!(s.verifier.matches(&again.verifier));
        assert_eq!(s.wrap_key.as_bytes(), again.wrap_key.as_bytes());
        let wrong = derive_credential_secrets("wrong horse", &salt, &test_params()).unwrap();
        assert!(!s.verifier.matches(&wrong.verifier));
    }

    #[test]
    fn salts_make_outputs_unique() {
        let a = derive_credential_secrets("pw-pw-pw-pw", &random_salt(), &test_params()).unwrap();
        let b = derive_credential_secrets("pw-pw-pw-pw", &random_salt(), &test_params()).unwrap();
        assert!(!a.verifier.matches(&b.verifier));
    }

    #[test]
    fn debug_is_redacted() {
        let s = derive_credential_secrets("pw-pw-pw-pw", &random_salt(), &test_params()).unwrap();
        let unlock = CredentialUnlock::new("password", s.wrap_key);
        let shown = format!("{unlock:?} {:?}", s.verifier);
        assert!(shown.contains("REDACTED"));
        assert!(!shown.contains(&hex::encode(&s.verifier.0)));
    }

    #[test]
    fn policy_rejects_short_passwords() {
        assert!(check_key_credential_policy("short").is_err());
        assert!(check_key_credential_policy("long-enough").is_ok());
    }
}
