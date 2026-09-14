use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::types::VaultState;

/// Connection lifecycle phase (transport + auth). Vault is a separate axis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionPhase {
    Disconnected,
    Connecting,
    Connected,
    Authenticated,
}

/// Read-only snapshot for UI. Never includes Master Key / binding key / DEK.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionSnapshot {
    pub phase: ConnectionPhase,
    pub session_id: Option<String>,
    pub identity_id: Option<String>,
    /// Last observed vault state from `vault_status` / unlock / lock.
    /// `None` until queried after authenticate. Not authoritative across reconnect.
    pub vault: Option<VaultState>,
}

#[derive(Default)]
pub(crate) struct SessionState {
    pub phase: ConnectionPhase,
    pub session_id: Option<String>,
    pub identity_id: Option<String>,
    /// Per-session AEAD key for UnlockBlob — client-only, never UI-exposed.
    pub unlock_binding_key: Option<UnlockBindingKey>,
    pub vault: Option<VaultState>,
}

impl SessionState {
    pub fn disconnected() -> Self {
        Self {
            phase: ConnectionPhase::Disconnected,
            ..Default::default()
        }
    }

    pub fn clear_auth(&mut self) {
        // Keep session_id so a following SQL round-trip can observe server
        // SessionInvalid (E2E). Wipe binding key — unlock requires re-auth.
        if let Some(mut key) = self.unlock_binding_key.take() {
            key.zeroize();
        }
        self.identity_id = None;
        self.vault = None;
        if self.phase == ConnectionPhase::Authenticated {
            self.phase = ConnectionPhase::Connected;
        }
    }

    pub fn clear_all(&mut self) {
        self.session_id = None;
        self.clear_auth();
        self.phase = ConnectionPhase::Disconnected;
    }

    pub fn snapshot(&self) -> SessionSnapshot {
        SessionSnapshot {
            phase: self.phase,
            session_id: self.session_id.clone(),
            identity_id: self.identity_id.clone(),
            vault: self.vault,
        }
    }

    pub fn require_session(&self) -> crate::Result<&str> {
        self.session_id
            .as_deref()
            .ok_or(crate::ClientError::NotAuthenticated)
    }

    pub fn require_binding(&self) -> crate::Result<&[u8; 32]> {
        self.unlock_binding_key
            .as_ref()
            .map(|k| &k.0)
            .ok_or(crate::ClientError::NotAuthenticated)
    }
}

impl Default for ConnectionPhase {
    fn default() -> Self {
        Self::Disconnected
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct UnlockBindingKey(pub [u8; 32]);

impl std::fmt::Debug for UnlockBindingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UnlockBindingKey([REDACTED])")
    }
}
