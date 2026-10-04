//! In-process security domain for Avrora.
//!
//! `dmc-core` (the `avrora` process) must call this crate's public contract
//! rather than authentication internals. Phase 1 keeps a single process;
//! later phases split `avrora-auth` while sharing this library.
//!
//! # Contract
//!
//! | Operation | Trait / type |
//! |-----------|----------------|
//! | `enroll` / `authenticate` | [`IdentityService`] (`AuthManager`) |
//! | `validate_session` / `revoke_session` | [`IdentityService`] (UI Bearer) |
//! | `create_session` / `revoke_session` | [`AuthorizationService`] (role session) |
//! | `authorize` | [`AuthorizationService`] |
//! | `resolve_capabilities` | [`AuthorizationService`] |
//! | `apply_policy` | [`policy::apply_policy`] (stub) |
//!
//! Authorization is local: SQL and vault paths never call Auth over the network.

pub mod audit;
pub mod auth;
pub mod authentication;
pub mod authorization;
pub mod capabilities;
pub mod credentials;
pub mod dev;
mod crypto;
pub mod error;
pub mod identity;
pub mod ownership;
pub mod policy;
pub mod roles;
mod sessions;

pub use audit::{
    AuditEvent, AuditId, AuditOperation, AuditReason, AuditResult, AuditTrail, SecurityEvent,
};
pub use auth::{
    Action, AuthPrincipal, AuthService, AuthSession, AuthenticatedIdentity, Authenticator,
    AuthorizationDecision, Authorizer, CatalogAuthorizer, Credential, CredentialVerifier,
    GrantStore, Identity, IdentityDirectory, IdentityId, IdentityStatus, PasswordCredentialVerifier,
    Resource, SessionManager, SessionState,
};
pub use authentication::{
    dev_enroll_ui_auth, dev_enroll_ui_auth_with_totp, AuthManager, AuthStatus, DevUiCredentials,
    SetupBeginResponse,
};
pub use dev::{DEV_DEFAULT_UI_ACCESS_KEY, UI_ACCESS_KEY, UI_TOTP_SECRET};
pub use authorization::{AccessControl, RotationReport, Session};
pub use capabilities::{
    Capability, CapabilityId, CapabilityRef, CapabilitySet, CapabilityStatus, IssuedCapability,
    KeyPath, Permission, PermissionSet,
};
pub use credentials::ui_auth_path;
pub use error::{AuthError, Error, Result};
pub use identity::user::{User, UserDirectory, UserStatus};
pub use identity::{
    DeviceId, Principal, SessionId, UserId, ISSUER, LOCAL_DEVICE, ROOT_USER, UI_OPERATOR,
};
pub use policy::apply_policy;
pub use roles::{Role, RoleRegistry};

/// UI identity: enroll, login, opaque Bearer session lifecycle.
#[allow(async_fn_in_trait)]
pub trait IdentityService: Send + Sync {
    async fn enroll_begin(&self, access_key: &str) -> std::result::Result<SetupBeginResponse, AuthError>;
    async fn enroll_confirm(
        &self,
        access_key: &str,
        totp_code: &str,
    ) -> std::result::Result<String, AuthError>;
    async fn authenticate(
        &self,
        access_key: &str,
        totp_code: &str,
    ) -> std::result::Result<String, AuthError>;
    async fn validate_session(&self, token: &str) -> bool;
    async fn revoke_session(&self, token: &str);
}

/// Local AuthZ over vault capabilities. No network.
pub trait AuthorizationService {
    fn create_session(&mut self, role_id: &str) -> Result<SessionId>;
    fn authorize(&self, session: &SessionId, resource: &KeyPath, permission: Permission) -> Result<()>;
    fn resolve_capabilities(&self, session: &SessionId) -> Result<Capability>;
    fn revoke_session(&mut self, session: &SessionId);
}
