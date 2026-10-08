use std::collections::HashMap;

use dmc_vault::ownership::SubjectId;

use crate::auth::identity::IdentityId;
use crate::auth::principal::AuthPrincipal;
use crate::identity::{now_unix_ms, SessionId, DEFAULT_SESSION_TTL_MS};
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    Created,
    Authenticated,
    Active,
    Expired,
    Revoked,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AuthSession {
    pub id: SessionId,
    pub identity_id: IdentityId,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub state: SessionState,
    /// Per-session AEAD key for UnlockBlob (never Master Key).
    pub unlock_binding_key: [u8; 32],
    /// Transport channel the session is bound to (D5): a DMC/control connection id or an
    /// HTTP signing channel. `None` only for sessions created outside any request
    /// (in-process); such sessions are refused inside network requests.
    pub channel: Option<String>,
    /// CLIENT_OWNED subject proven by Ed25519 authentication (None for password sessions).
    pub subject: Option<SubjectId>,
    /// Auth key version used to authenticate (CLIENT_OWNED sessions).
    pub auth_key_version: Option<u32>,
}

/// Session binding key is wiped when the session record is dropped.
impl Drop for AuthSession {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.unlock_binding_key);
    }
}

impl std::fmt::Debug for AuthSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthSession")
            .field("id", &self.id)
            .field("identity_id", &self.identity_id)
            .field("created_at_ms", &self.created_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("state", &self.state)
            .field("channel", &self.channel)
            .field("subject", &self.subject)
            .field("unlock_binding_key", &"[REDACTED]")
            .finish()
    }
}

impl AuthSession {
    pub fn is_active(&self, now_ms: u64) -> bool {
        matches!(self.state, SessionState::Active | SessionState::Authenticated)
            && now_ms < self.expires_at_ms
    }
}

pub trait SessionManager {
    fn create_session(&mut self, identity_id: IdentityId) -> Result<AuthSession>;
    fn validate_session(&self, session_id: &SessionId) -> Result<AuthSession>;
    fn revoke_session(&mut self, session_id: &SessionId) -> Result<()>;
    fn expire_sessions(&mut self, now_ms: u64) -> usize;
    fn clear_sessions(&mut self);
    fn principal_for(&self, session_id: &SessionId) -> Result<AuthPrincipal>;
    fn unlock_binding_key(&self, session_id: &SessionId) -> Result<[u8; 32]>;
}

#[derive(Clone, Debug, Default)]
pub struct InMemorySessionStore {
    sessions: HashMap<String, AuthSession>,
    session_ttl_ms: u64,
    clock_ms: Option<u64>,
}

impl InMemorySessionStore {
    /// Revoke every session bound to `channel` (the connection closed; there is no rebind).
    pub fn revoke_channel_sessions(&mut self, channel: &str) -> usize {
        let mut revoked = 0usize;
        for session in self.sessions.values_mut() {
            if session.channel.as_deref() == Some(channel) && !matches!(session.state, SessionState::Revoked) {
                session.state = SessionState::Revoked;
                revoked += 1;
            }
        }
        revoked
    }

    /// Revoke every live session of `identity_id` (used when the identity is disabled).
    pub fn revoke_identity_sessions(&mut self, identity_id: &IdentityId) -> usize {
        let mut revoked = 0usize;
        for session in self.sessions.values_mut() {
            if &session.identity_id == identity_id && !matches!(session.state, SessionState::Revoked) {
                session.state = SessionState::Revoked;
                revoked += 1;
            }
        }
        revoked
    }

    pub fn new() -> Self {
        Self {
            session_ttl_ms: DEFAULT_SESSION_TTL_MS,
            ..Self::default()
        }
    }

    pub fn with_ttl_ms(session_ttl_ms: u64) -> Self {
        Self {
            session_ttl_ms,
            ..Self::default()
        }
    }

    pub fn set_clock_ms(&mut self, now: Option<u64>) {
        self.clock_ms = now;
    }

    fn now(&self) -> u64 {
        self.clock_ms.unwrap_or_else(now_unix_ms)
    }

    pub fn now_ms(&self) -> u64 {
        self.now()
    }

    pub fn insert(&mut self, identity_id: IdentityId) -> AuthSession {
        self.insert_bound(identity_id, None, None, None)
    }

    /// Create a session bound to `channel` (and, for CLIENT_OWNED, to the proven subject).
    pub fn insert_bound(
        &mut self,
        identity_id: IdentityId,
        channel: Option<String>,
        subject: Option<SubjectId>,
        auth_key_version: Option<u32>,
    ) -> AuthSession {
        let now = self.now();
        let mut unlock_binding_key = [0u8; 32];
        rand::fill(&mut unlock_binding_key);
        let session = AuthSession {
            id: SessionId::new(),
            identity_id,
            created_at_ms: now,
            expires_at_ms: now.saturating_add(self.session_ttl_ms),
            state: SessionState::Active,
            unlock_binding_key,
            channel,
            subject,
            auth_key_version,
        };
        self.sessions
            .insert(session.id.as_str().to_string(), session.clone());
        session
    }

    pub fn get(&self, session_id: &SessionId) -> Option<&AuthSession> {
        self.sessions.get(session_id.as_str())
    }

    pub fn get_mut(&mut self, session_id: &SessionId) -> Option<&mut AuthSession> {
        self.sessions.get_mut(session_id.as_str())
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }
}

impl SessionManager for InMemorySessionStore {
    fn create_session(&mut self, identity_id: IdentityId) -> Result<AuthSession> {
        Ok(self.insert(identity_id))
    }

    fn validate_session(&self, session_id: &SessionId) -> Result<AuthSession> {
        let now = self.now();
        let session = self
            .sessions
            .get(session_id.as_str())
            .cloned()
            .ok_or_else(|| Error::UnknownSession(session_id.as_str().to_string()))?;
        if matches!(session.state, SessionState::Revoked) {
            return Err(Error::UnknownSession(session_id.as_str().to_string()));
        }
        if !session.is_active(now) {
            return Err(Error::SessionExpired(session_id.as_str().to_string()));
        }
        Ok(session)
    }

    fn revoke_session(&mut self, session_id: &SessionId) -> Result<()> {
        let session = self
            .sessions
            .get_mut(session_id.as_str())
            .ok_or_else(|| Error::UnknownSession(session_id.as_str().to_string()))?;
        session.state = SessionState::Revoked;
        Ok(())
    }

    fn expire_sessions(&mut self, now_ms: u64) -> usize {
        let mut expired = 0usize;
        for session in self.sessions.values_mut() {
            if matches!(
                session.state,
                SessionState::Active | SessionState::Authenticated
            ) && now_ms >= session.expires_at_ms
            {
                session.state = SessionState::Expired;
                expired += 1;
            }
        }
        expired
    }

    fn clear_sessions(&mut self) {
        self.sessions.clear();
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
