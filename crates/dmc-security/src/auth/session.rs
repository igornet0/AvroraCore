use std::collections::HashMap;

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthSession {
    pub id: SessionId,
    pub identity_id: IdentityId,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub state: SessionState,
    /// Per-session AEAD key for UnlockBlob (never Master Key).
    pub unlock_binding_key: [u8; 32],
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

    pub fn insert(&mut self, identity_id: IdentityId) -> AuthSession {
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
        Ok(AuthPrincipal::new(session.identity_id, session.id))
    }

    fn unlock_binding_key(&self, session_id: &SessionId) -> Result<[u8; 32]> {
        let session = self.validate_session(session_id)?;
        Ok(session.unlock_binding_key)
    }
}
