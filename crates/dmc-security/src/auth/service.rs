use crate::auth::credential::AuthenticatedIdentity;
use crate::auth::identity::{Identity, IdentityDirectory, IdentityId, IdentityStatus};
use crate::auth::principal::AuthPrincipal;
use crate::auth::session::{AuthSession, InMemorySessionStore, SessionManager};
use crate::auth::{Authenticator, CatalogAuthorizer, Credential, CredentialVerifier, GrantStore, PasswordCredentialVerifier};
use crate::identity::SessionId;
use crate::{Error, Result};

/// Phase 7.2 security facade: identity + credential + runtime sessions + grants.
#[derive(Clone, Debug)]
pub struct AuthService {
    identities: IdentityDirectory,
    credentials: PasswordCredentialVerifier,
    sessions: InMemorySessionStore,
    grants: GrantStore,
}

impl Default for AuthService {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthService {
    pub fn new() -> Self {
        Self {
            identities: IdentityDirectory::new(),
            credentials: PasswordCredentialVerifier::new(),
            sessions: InMemorySessionStore::new(),
            grants: GrantStore::new(),
        }
    }

    pub fn identities(&self) -> &IdentityDirectory {
        &self.identities
    }

    pub fn identities_mut(&mut self) -> &mut IdentityDirectory {
        &mut self.identities
    }

    pub fn grants(&self) -> &GrantStore {
        &self.grants
    }

    pub fn grants_mut(&mut self) -> &mut GrantStore {
        &mut self.grants
    }

    pub fn sessions(&self) -> &InMemorySessionStore {
        &self.sessions
    }

    pub fn sessions_mut(&mut self) -> &mut InMemorySessionStore {
        &mut self.sessions
    }

    pub fn set_clock_ms(&mut self, now: Option<u64>) {
        self.sessions.set_clock_ms(now);
    }

    pub fn authorizer(&self) -> CatalogAuthorizer<'_> {
        CatalogAuthorizer::new(&self.grants)
    }

    pub fn create_identity(
        &mut self,
        name: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<IdentityId> {
        let name = name.into();
        let id = IdentityId::new(uuid::Uuid::new_v4().to_string());
        self.identities.insert(Identity {
            id: id.clone(),
            name: name.clone(),
            status: IdentityStatus::Active,
        })?;
        self.credentials.set_password(name, password);
        Ok(id)
    }

    pub fn create_identity_with_id(
        &mut self,
        id: impl Into<String>,
        name: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<IdentityId> {
        let id = IdentityId::new(id);
        let name = name.into();
        self.identities.insert(Identity {
            id: id.clone(),
            name: name.clone(),
            status: IdentityStatus::Active,
        })?;
        self.credentials.set_password(name, password);
        Ok(id)
    }

    pub fn configure_credential(
        &mut self,
        identity_name: impl Into<String>,
        password: impl Into<String>,
    ) {
        self.credentials.set_password(identity_name, password);
    }

    pub fn disable_identity(&mut self, id: &IdentityId) -> Result<()> {
        self.identities.disable(id)
    }

    pub fn login(&mut self, identity_name: &str, password: &str) -> Result<(AuthSession, AuthPrincipal)> {
        let authenticated = self.authenticate(&Credential::Password {
            identity_name: identity_name.into(),
            password: password.into(),
        })?;
        let session = self.create_session(authenticated.identity_id.clone())?;
        let principal = AuthPrincipal::new(authenticated.identity_id, session.id.clone());
        Ok((session, principal))
    }

    /// Revoke AuthSession only — does **not** lock the vault.
    pub fn logout(&mut self, session_id: &SessionId) -> Result<()> {
        self.revoke_session(session_id)
    }

    pub fn restart(&mut self) {
        self.sessions.clear_sessions();
    }
}

impl Authenticator for AuthService {
    fn authenticate(&self, credential: &Credential) -> Result<AuthenticatedIdentity> {
        let Credential::Password {
            identity_name,
            password,
        } = credential;
        match self.credentials.passwords.get(identity_name) {
            Some(expected) if expected == password => {}
            Some(_) => {
                return Err(Error::AuthenticationFailed(format!(
                    "invalid credential for identity '{identity_name}'"
                )));
            }
            None => {
                return Err(Error::AuthenticationFailed(format!(
                    "unknown credential for identity '{identity_name}'"
                )));
            }
        }
        let identity = self
            .identities
            .get_by_name(identity_name)
            .ok_or_else(|| Error::UnknownIdentity(identity_name.clone()))?;
        if !identity.is_active() {
            return Err(Error::IdentityDisabled(identity.id.as_str().to_string()));
        }
        Ok(AuthenticatedIdentity {
            identity_id: identity.id.clone(),
        })
    }
}

impl SessionManager for AuthService {
    fn create_session(&mut self, identity_id: IdentityId) -> Result<AuthSession> {
        self.identities
            .get(&identity_id)
            .ok_or_else(|| Error::UnknownIdentity(identity_id.as_str().to_string()))?;
        self.sessions.create_session(identity_id)
    }

    fn validate_session(&self, session_id: &SessionId) -> Result<AuthSession> {
        self.sessions.validate_session(session_id)
    }

    fn revoke_session(&mut self, session_id: &SessionId) -> Result<()> {
        self.sessions.revoke_session(session_id)
    }

    fn expire_sessions(&mut self, now_ms: u64) -> usize {
        self.sessions.expire_sessions(now_ms)
    }

    fn clear_sessions(&mut self) {
        self.sessions.clear_sessions();
    }

    fn principal_for(&self, session_id: &SessionId) -> Result<AuthPrincipal> {
        self.sessions.principal_for(session_id)
    }

    fn unlock_binding_key(&self, session_id: &SessionId) -> Result<[u8; 32]> {
        self.sessions.unlock_binding_key(session_id)
    }
}

impl CredentialVerifier for AuthService {
    fn verify(&self, credential: &Credential) -> Result<AuthenticatedIdentity> {
        Authenticator::authenticate(self, credential)
    }
}
