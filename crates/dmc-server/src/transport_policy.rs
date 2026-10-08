//! Which requests the CLIENT_OWNED transport adapters (HTTP, control-plane tunnel) may
//! forward to the shared dispatcher. One definition for every adapter, so transports
//! cannot drift apart (cross-transport consistency, P10).
//!
//! Not reachable through these adapters: password authentication, vault, backup,
//! restore, runtime and catalog administration, invite creation — those stay on DMC IPC
//! and the operator planes.

use dmc_protocol::ControlRequest;

/// Requests that need a CLIENT_OWNED session.
pub fn client_owned_session_request(req: &ControlRequest) -> bool {
    matches!(
        req,
        ControlRequest::ClientKeyRegister { .. }
            | ControlRequest::ClientKeyGet { .. }
            | ControlRequest::ClientKeyRotate { .. }
            | ControlRequest::KeyEnvelopePut { .. }
            | ControlRequest::KeyEnvelopeGet { .. }
            | ControlRequest::GrantCreate { .. }
            | ControlRequest::GrantList { .. }
            | ControlRequest::GrantRevoke { .. }
            | ControlRequest::SealedColumnDeclare { .. }
            | ControlRequest::Logout { .. }
    )
}

/// Pre-session requests: Ed25519 authentication and invite enrollment.
pub fn client_owned_preauth_request(req: &ControlRequest) -> bool {
    matches!(
        req,
        ControlRequest::ClientAuthBegin { .. }
            | ControlRequest::ClientAuthFinish { .. }
            | ControlRequest::IdentityEnroll { .. }
    )
}
