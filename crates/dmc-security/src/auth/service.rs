use std::path::Path;

use dmc_vault::ownership::{
    CredentialUnlock, PasswordKdfParams, SubjectId, TenantId, check_key_credential_policy,
};
use serde::{Deserialize, Serialize};

use crate::auth::credential::{AuthenticatedIdentity, PasswordRecord, INVALID_CREDENTIALS};
use crate::auth::identity::{Identity, IdentityDirectory, IdentityId, IdentityStatus, KeyCustody};
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
    /// Channel (connection / HTTP signing channel) of the network request being handled.
    /// Set by the transport for the duration of one request (D5); `None` in-process.
    request_channel: Option<String>,
    /// Pending Ed25519 authentication challenges (single use, short TTL).
    pub(crate) challenges: crate::auth::client_auth::ChallengeStore,
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
            request_channel: None,
            challenges: crate::auth::client_auth::ChallengeStore::new(),
        }
    }

    /// Bind the current network request to `channel` (D5). Every session check during
    /// the request requires the session to belong to this channel, and sessions created
    /// during it are bound to it. Transports must call [`Self::end_request`] afterwards.
    pub fn begin_request(&mut self, channel: &str) {
        self.request_channel = Some(channel.to_string());
    }

    pub fn end_request(&mut self) {
        self.request_channel = None;
    }

    pub fn request_channel(&self) -> Option<&str> {
        self.request_channel.as_deref()
    }

    /// The transport channel closed: its sessions end (no rebind protocol).
    pub fn close_channel(&mut self, channel: &str) -> usize {
        self.sessions.revoke_channel_sessions(channel)
    }

    /// Create a session for a CLIENT_OWNED subject proven by Ed25519 authentication,
    /// bound to the current request channel.
    pub(crate) fn create_client_session(
        &mut self,
        identity_id: IdentityId,
        subject: SubjectId,
        key_version: u32,
    ) -> Result<AuthSession> {
        let channel = self
            .request_channel
            .clone()
            .ok_or_else(|| Error::AuthenticationFailed("client authentication needs a transport channel".into()))?;
        Ok(self
            .sessions
            .insert_bound(identity_id, Some(channel), Some(subject), Some(key_version)))
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
            subject_id: None,
            tenant: None,
            custody: KeyCustody::Server,
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
            subject_id: None,
            tenant: None,
            custody: KeyCustody::Server,
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

    /// Disable an identity and revoke its live sessions. Sessions are also re-checked
    /// against identity status on every use (see [`SessionManager`] impl), so a disabled
    /// identity cannot keep operating through a session issued before it was disabled.
    pub fn disable_identity(&mut self, id: &IdentityId) -> Result<()> {
        self.identities.disable(id)?;
        self.sessions.revoke_identity_sessions(id);
        Ok(())
    }

    pub(crate) fn require_live_identity(&self, session: &AuthSession) -> Result<()> {
        let identity = self
            .identities
            .get(&session.identity_id)
            .ok_or_else(|| Error::UnknownIdentity(session.identity_id.as_str().to_string()))?;
        if !identity.is_active() {
            return Err(Error::IdentityDisabled(identity.id.as_str().to_string()));
        }
        Ok(())
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

    /// Argon2id cost for passwords set from now on (tests may lower it).
    pub fn set_password_kdf_params(&mut self, params: PasswordKdfParams) {
        self.credentials.params = params;
    }

    // ── authentication that also yields key access material ───────────────────

    /// Authenticate and return the credential-derived KEK-wrapping key.
    ///
    /// The returned [`CredentialUnlock`] proves the password was presented; it grants no
    /// data access by itself — key access still goes through authorization in
    /// [`crate::ownership::KeyManager`]. Disabled identities are rejected after the
    /// password check, with the same error kind as before.
    pub fn authenticate_with_key_unlock(
        &self,
        credential: &Credential,
    ) -> Result<(AuthenticatedIdentity, CredentialUnlock)> {
        let Credential::Password {
            identity_name,
            password,
        } = credential;
        let unlock = self.credentials.check(identity_name, password)?;
        let identity = self
            .identities
            .get_by_name(identity_name)
            .ok_or_else(|| Error::AuthenticationFailed(INVALID_CREDENTIALS.into()))?;
        // CLIENT_OWNED identities authenticate only by Ed25519 proof of possession
        // (AUTH-BINDING); a password must never yield a session for them.
        if identity.custody == KeyCustody::Client {
            return Err(Error::AuthenticationFailed(INVALID_CREDENTIALS.into()));
        }
        if !identity.is_active() {
            return Err(Error::IdentityDisabled(identity.id.as_str().to_string()));
        }
        Ok((
            AuthenticatedIdentity {
                identity_id: identity.id.clone(),
            },
            unlock,
        ))
    }

    /// Create an identity enrolled for data ownership: random opaque [`SubjectId`],
    /// tenant binding, password policy for key-protecting credentials.
    ///
    /// Returns the [`CredentialUnlock`] needed to create the subject keyring.
    pub fn enroll_owner(
        &mut self,
        name: impl Into<String>,
        password: &str,
        tenant: TenantId,
    ) -> Result<(IdentityId, SubjectId, CredentialUnlock)> {
        check_key_credential_policy(password)
            .map_err(|e| Error::AuthenticationFailed(e.to_string()))?;
        let name = name.into();
        let id = IdentityId::new(uuid::Uuid::new_v4().to_string());
        let subject = SubjectId::random();
        self.identities.insert(Identity {
            id: id.clone(),
            name: name.clone(),
            status: IdentityStatus::Active,
            subject_id: Some(subject),
            tenant: Some(tenant),
            custody: KeyCustody::Server,
        })?;
        let unlock = self.credentials.set_password_with_unlock(name, password)?;
        Ok((id, subject, unlock))
    }

    /// Create a CLIENT_OWNED identity **without a password** for an already assigned
    /// subject. It can authenticate only with the Ed25519 key registered for `subject`
    /// (enrollment, `crate::ownership::enrollment`). No server keyring exists for it.
    pub fn create_client_identity(
        &mut self,
        name: impl Into<String>,
        tenant: TenantId,
        subject: SubjectId,
    ) -> Result<IdentityId> {
        let id = IdentityId::new(uuid::Uuid::new_v4().to_string());
        self.identities.insert(Identity {
            id: id.clone(),
            name: name.into(),
            status: IdentityStatus::Active,
            subject_id: Some(subject),
            tenant: Some(tenant),
            custody: KeyCustody::Client,
        })?;
        Ok(id)
    }

    /// Verify the old password, install the new one, and return both unlocks so the
    /// caller can rewrap the subject KEK (no data re-encryption).
    pub fn change_password(
        &mut self,
        identity_name: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<(CredentialUnlock, CredentialUnlock)> {
        let (_, old_unlock) = self.authenticate_with_key_unlock(&Credential::Password {
            identity_name: identity_name.into(),
            password: old_password.into(),
        })?;
        let identity = self
            .identities
            .get_by_name(identity_name)
            .ok_or_else(|| Error::AuthenticationFailed(INVALID_CREDENTIALS.into()))?;
        if identity.subject_id.is_some() {
            check_key_credential_policy(new_password)
                .map_err(|e| Error::AuthenticationFailed(e.to_string()))?;
        }
        let new_unlock = self
            .credentials
            .set_password_with_unlock(identity_name, new_password)?;
        Ok((old_unlock, new_unlock))
    }

    /// Current credential id of an identity (used to prune stale KEK envelopes).
    pub fn current_credential_id(&self, identity_id: &IdentityId) -> Option<String> {
        let identity = self.identities.get(identity_id)?;
        self.credentials
            .credential_id(&identity.name)
            .map(str::to_string)
    }

    // ── persistence (identities + verifiers only; never passwords or keys) ────

    pub fn save_identities(&self, path: &Path) -> Result<()> {
        let mut identities: Vec<Identity> = self.identities.list().into_iter().cloned().collect();
        identities.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
        let mut credentials: Vec<(String, PasswordRecord)> = self
            .credentials
            .records()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        credentials.sort_by(|a, b| a.0.cmp(&b.0));
        let file = IdentityFile {
            format_version: IDENTITY_FILE_FORMAT,
            identities,
            credentials,
        };
        let raw = serde_json::to_vec_pretty(&file)
            .map_err(|e| Error::Conflict(format!("identity file encode: {e}")))?;
        write_atomic(path, &raw)
    }

    /// Load identities + verifiers (sessions and grants are not persisted here).
    pub fn load_identities(&mut self, path: &Path) -> Result<()> {
        let raw = std::fs::read(path).map_err(|e| Error::Conflict(format!("identity file: {e}")))?;
        let file: IdentityFile = serde_json::from_slice(&raw)
            .map_err(|e| Error::Conflict(format!("identity file decode: {e}")))?;
        if file.format_version != IDENTITY_FILE_FORMAT {
            return Err(Error::Conflict(format!(
                "unsupported identity file format {}",
                file.format_version
            )));
        }
        let mut dir = IdentityDirectory::new();
        for identity in file.identities {
            dir.insert(identity)?;
        }
        self.identities = dir;
        self.credentials
            .replace_records(file.credentials.into_iter().collect());
        Ok(())
    }
}

const IDENTITY_FILE_FORMAT: u32 = 1;

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    format_version: u32,
    identities: Vec<Identity>,
    credentials: Vec<(String, PasswordRecord)>,
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let io = |e: std::io::Error| Error::Conflict(format!("identity file write: {e}"));
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir).map_err(io)?;
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp).map_err(io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).map_err(io)?;
        }
        f.write_all(bytes).map_err(io)?;
        f.sync_all().map_err(io)?;
    }
    std::fs::rename(&tmp, path).map_err(io)?;
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(io)
}

impl Authenticator for AuthService {
    fn authenticate(&self, credential: &Credential) -> Result<AuthenticatedIdentity> {
        self.authenticate_with_key_unlock(credential)
            .map(|(identity, _unlock)| identity)
    }
}

impl SessionManager for AuthService {
    fn create_session(&mut self, identity_id: IdentityId) -> Result<AuthSession> {
        self.identities
            .get(&identity_id)
            .ok_or_else(|| Error::UnknownIdentity(identity_id.as_str().to_string()))?;
        Ok(self
            .sessions
            .insert_bound(identity_id, self.request_channel.clone(), None, None))
    }

    fn validate_session(&self, session_id: &SessionId) -> Result<AuthSession> {
        let session = self.sessions.validate_session(session_id)?;
        self.require_live_identity(&session)?;
        // D5: inside a network request the session must belong to that request's channel.
        if let Some(channel) = &self.request_channel {
            if session.channel.as_deref() != Some(channel.as_str()) {
                return Err(Error::UnknownSession(session_id.as_str().to_string()));
            }
        }
        Ok(session)
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
        let session = self.validate_session(session_id)?;
        Ok(AuthPrincipal::new(session.identity_id.clone(), session.id.clone()))
    }

    fn unlock_binding_key(&self, session_id: &SessionId) -> Result<[u8; 32]> {
        let session = self.validate_session(session_id)?;
        Ok(session.unlock_binding_key)
    }
}

impl CredentialVerifier for AuthService {
    fn verify(&self, credential: &Credential) -> Result<AuthenticatedIdentity> {
        Authenticator::authenticate(self, credential)
    }
}
