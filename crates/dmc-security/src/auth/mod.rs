//! Phase 7.2 — catalog authentication & hierarchical authorization.
//!
//! Separate from legacy Event Plane `User` / `AccessControl` (KeyPath ACL).
//! SQL integration uses [`AuthService`] + [`CatalogAuthorizer`] before parse/bind/execute.

mod authorizer;
pub mod bootstrap;
pub mod client_auth;
mod credential;
mod grant;
mod identity;
mod principal;
mod resource;
mod service;
mod session;

pub use authorizer::{AuthorizationDecision, Authorizer, CatalogAuthorizer};
pub use credential::{
    AuthenticatedIdentity, Credential, CredentialVerifier, PasswordCredentialVerifier,
};
pub use grant::GrantStore;
pub use identity::{Identity, IdentityDirectory, IdentityId, IdentityStatus, KeyCustody};
pub use principal::AuthPrincipal;
pub use resource::{Action, Resource};
pub use service::{AuthService, BootstrapRecord};
pub use session::{AuthSession, InMemorySessionStore, SessionManager, SessionState};

/// Authenticate a credential into an identity handle (no session yet).
pub trait Authenticator {
    fn authenticate(&self, credential: &Credential) -> crate::Result<AuthenticatedIdentity>;
}
