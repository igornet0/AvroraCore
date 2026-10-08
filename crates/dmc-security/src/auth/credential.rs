use std::collections::HashMap;
use std::fmt;

use dmc_vault::ownership::{
    CredentialUnlock, PasswordKdfParams, Verifier, derive_credential_secrets, random_salt,
};
use serde::{Deserialize, Serialize};

use crate::auth::identity::IdentityId;
use crate::{Error, Result};

/// Presentation secret for authentication. Not stored in Session. `Debug` is redacted.
#[derive(Clone, PartialEq, Eq)]
pub enum Credential {
    Password {
        identity_name: String,
        password: String,
    },
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password { identity_name, .. } => f
                .debug_struct("Password")
                .field("identity_name", identity_name)
                .field("password", &"[REDACTED]")
                .finish(),
        }
    }
}

/// The presented password is wiped when the credential is dropped.
impl Drop for Credential {
    fn drop(&mut self) {
        match self {
            Self::Password { password, .. } => zeroize::Zeroize::zeroize(password),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedIdentity {
    pub identity_id: IdentityId,
}

pub trait CredentialVerifier {
    fn verify(&self, credential: &Credential) -> Result<AuthenticatedIdentity>;
}

/// Stored password verifier: Argon2id(password, salt) → HKDF "auth-verifier".
///
/// The password and the KEK-wrapping key are never stored. `credential_id` changes on
/// every password change so key envelopes bound to an old password can be pruned.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordRecord {
    pub credential_id: String,
    #[serde(with = "hex16")]
    pub salt: [u8; 16],
    pub params: PasswordKdfParams,
    pub verifier: Verifier,
}

impl fmt::Debug for PasswordRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordRecord")
            .field("credential_id", &self.credential_id)
            .field("params", &self.params)
            .field("verifier", &"[REDACTED]")
            .finish()
    }
}

impl PasswordRecord {
    fn create(password: &str, params: PasswordKdfParams) -> Result<(Self, CredentialUnlock)> {
        let salt = random_salt();
        let secrets = derive_credential_secrets(password, &salt, &params)
            .map_err(|e| Error::AuthenticationFailed(e.to_string()))?;
        let credential_id = format!("pw-{}", uuid::Uuid::new_v4().simple());
        let unlock = CredentialUnlock::new(credential_id.clone(), secrets.wrap_key);
        Ok((
            Self {
                credential_id,
                salt,
                params,
                verifier: secrets.verifier,
            },
            unlock,
        ))
    }

    /// Constant-time check; on success also yields the KEK-wrapping key.
    fn check(&self, password: &str) -> Option<CredentialUnlock> {
        let secrets = derive_credential_secrets(password, &self.salt, &self.params).ok()?;
        if self.verifier.matches(&secrets.verifier) {
            Some(CredentialUnlock::new(self.credential_id.clone(), secrets.wrap_key))
        } else {
            None
        }
    }
}

/// Password verifier store. Holds only Argon2id-derived verifiers (never passwords).
#[derive(Clone, Default)]
pub struct PasswordCredentialVerifier {
    pub(crate) records: HashMap<String, PasswordRecord>,
    pub(crate) params: PasswordKdfParams,
}

impl fmt::Debug for PasswordCredentialVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordCredentialVerifier")
            .field("identities", &self.records.len())
            .finish()
    }
}

/// Same message for unknown identity and wrong password (no account enumeration).
pub(crate) const INVALID_CREDENTIALS: &str = "invalid credentials";

impl PasswordCredentialVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Override Argon2id cost for new records (existing records keep their own params).
    pub fn with_params(params: PasswordKdfParams) -> Self {
        Self {
            records: HashMap::new(),
            params,
        }
    }

    pub fn set_password(&mut self, identity_name: impl Into<String>, password: impl Into<String>) {
        let _ = self.set_password_with_unlock(identity_name, password);
    }

    /// Replace the verifier and return the key-unlock for the new credential.
    pub fn set_password_with_unlock(
        &mut self,
        identity_name: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<CredentialUnlock> {
        let password = password.into();
        let (record, unlock) = PasswordRecord::create(&password, self.params)?;
        self.records.insert(identity_name.into(), record);
        Ok(unlock)
    }

    /// Verify a password. Unknown identities still pay the KDF cost (timing parity).
    pub(crate) fn check(&self, identity_name: &str, password: &str) -> Result<CredentialUnlock> {
        match self.records.get(identity_name) {
            Some(record) => record
                .check(password)
                .ok_or_else(|| Error::AuthenticationFailed(INVALID_CREDENTIALS.into())),
            None => {
                let _ = derive_credential_secrets(password, &[0u8; 16], &self.params);
                Err(Error::AuthenticationFailed(INVALID_CREDENTIALS.into()))
            }
        }
    }

    pub(crate) fn credential_id(&self, identity_name: &str) -> Option<&str> {
        self.records
            .get(identity_name)
            .map(|r| r.credential_id.as_str())
    }

    pub(crate) fn records(&self) -> &HashMap<String, PasswordRecord> {
        &self.records
    }

    pub(crate) fn replace_records(&mut self, records: HashMap<String, PasswordRecord>) {
        self.records = records;
    }
}

impl CredentialVerifier for PasswordCredentialVerifier {
    fn verify(&self, credential: &Credential) -> Result<AuthenticatedIdentity> {
        let Credential::Password {
            identity_name,
            password,
        } = credential;
        self.check(identity_name, password)?;
        Ok(AuthenticatedIdentity {
            identity_id: IdentityId::new("pending-name-lookup"),
        })
    }
}

mod hex16 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let raw = hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)?;
        raw.try_into()
            .map_err(|_| serde::de::Error::custom("expected 16 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_never_holds_password_and_debug_is_redacted() {
        let mut v = PasswordCredentialVerifier::new();
        v.set_password("alice", "hunter2-hunter2");
        let shown = format!("{v:?} {:?}", v.records["alice"]);
        assert!(!shown.contains("hunter2"));
        let json = serde_json::to_string(&v.records["alice"]).unwrap();
        assert!(!json.contains("hunter2"));
        let cred = Credential::Password {
            identity_name: "alice".into(),
            password: "hunter2-hunter2".into(),
        };
        assert!(!format!("{cred:?}").contains("hunter2"));
    }

    #[test]
    fn check_same_error_for_unknown_and_wrong() {
        let mut v = PasswordCredentialVerifier::new();
        v.set_password("alice", "right-password");
        assert!(v.check("alice", "right-password").is_ok());
        let wrong = v.check("alice", "wrong-password").unwrap_err().to_string();
        let ghost = v.check("ghost", "wrong-password").unwrap_err().to_string();
        assert_eq!(wrong, ghost);
    }
}
