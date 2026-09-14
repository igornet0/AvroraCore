use crate::auth::identity::IdentityId;
use crate::identity::SessionId;

/// Authorization subject — identity bound to an authenticated session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthPrincipal {
    pub identity_id: IdentityId,
    pub session_id: SessionId,
}

impl AuthPrincipal {
    pub fn new(identity_id: IdentityId, session_id: SessionId) -> Self {
        Self {
            identity_id,
            session_id,
        }
    }
}
