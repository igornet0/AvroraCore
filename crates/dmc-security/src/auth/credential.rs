use crate::auth::identity::IdentityId;
use crate::{Error, Result};

/// Presentation secret for authentication. Not stored in Session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Credential {
    Password {
        identity_name: String,
        password: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedIdentity {
    pub identity_id: IdentityId,
}

pub trait CredentialVerifier {
    fn verify(&self, credential: &Credential) -> Result<AuthenticatedIdentity>;
}

/// In-memory password verifier for tests and local bootstrap.
#[derive(Clone, Debug, Default)]
pub struct PasswordCredentialVerifier {
    pub(crate) passwords: std::collections::HashMap<String, String>,
}

impl PasswordCredentialVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_password(&mut self, identity_name: impl Into<String>, password: impl Into<String>) {
        self.passwords
            .insert(identity_name.into(), password.into());
    }
}

impl CredentialVerifier for PasswordCredentialVerifier {
    fn verify(&self, credential: &Credential) -> Result<AuthenticatedIdentity> {
        let Credential::Password {
            identity_name,
            password,
        } = credential;
        match self.passwords.get(identity_name) {
            Some(expected) if expected == password => Ok(AuthenticatedIdentity {
                identity_id: IdentityId::new("pending-name-lookup"),
            }),
            Some(_) => Err(Error::AuthenticationFailed(format!(
                "invalid credential for identity '{identity_name}'"
            ))),
            None => Err(Error::AuthenticationFailed(format!(
                "unknown credential for identity '{identity_name}'"
            ))),
        }
    }
}
