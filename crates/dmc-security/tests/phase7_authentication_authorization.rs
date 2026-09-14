//! Phase 7.2 — authentication + hierarchical authorization tests.

use dmc_security::auth::{
    Action, Authenticator, AuthPrincipal, AuthService, Authorizer, Credential, GrantStore,
    IdentityId, Resource, SessionManager,
};
use dmc_security::{Error, Result};

fn alice_service() -> AuthService {
    let mut auth = AuthService::new();
    auth.create_identity_with_id("alice-id", "alice", "secret")
        .unwrap();
    auth
}

#[test]
fn authentication_valid_credential() {
    let auth = alice_service();
    let id = auth
        .authenticate(&Credential::Password {
            identity_name: "alice".into(),
            password: "secret".into(),
        })
        .unwrap();
    assert_eq!(id.identity_id, IdentityId::new("alice-id"));
}

#[test]
fn authentication_invalid_credential() {
    let auth = alice_service();
    let err = auth
        .authenticate(&Credential::Password {
            identity_name: "alice".into(),
            password: "wrong".into(),
        })
        .unwrap_err();
    assert!(matches!(err, Error::AuthenticationFailed(_)));
}

#[test]
fn authentication_unknown_identity() {
    let auth = AuthService::new();
    let err = auth
        .authenticate(&Credential::Password {
            identity_name: "ghost".into(),
            password: "x".into(),
        })
        .unwrap_err();
    assert!(matches!(err, Error::AuthenticationFailed(_)));
}

#[test]
fn authentication_disabled_identity() {
    let mut auth = alice_service();
    auth.disable_identity(&IdentityId::new("alice-id")).unwrap();
    let err = auth
        .authenticate(&Credential::Password {
            identity_name: "alice".into(),
            password: "secret".into(),
        })
        .unwrap_err();
    assert!(matches!(err, Error::IdentityDisabled(_)));
}

#[test]
fn identity_lookup_is_deterministic() {
    let auth = alice_service();
    let a = auth.identities().get_by_name("alice").unwrap();
    let b = auth.identities().get_by_name("alice").unwrap();
    assert_eq!(a.id, b.id);
    assert_eq!(a.name, "alice");
}

#[test]
fn session_create_validate_revoke() {
    let mut auth = alice_service();
    let session = auth
        .create_session(IdentityId::new("alice-id"))
        .unwrap();
    assert!(auth.validate_session(&session.id).is_ok());
    auth.revoke_session(&session.id).unwrap();
    assert!(matches!(
        auth.validate_session(&session.id),
        Err(Error::UnknownSession(_))
    ));
}

#[test]
fn session_expiration() {
    let mut auth = alice_service();
    auth.set_clock_ms(Some(1_000));
    let session = auth
        .create_session(IdentityId::new("alice-id"))
        .unwrap();
    auth.set_clock_ms(Some(session.expires_at_ms + 1));
    assert!(matches!(
        auth.validate_session(&session.id),
        Err(Error::SessionExpired(_))
    ));
}

#[test]
fn session_unknown_rejected() {
    let auth = alice_service();
    assert!(matches!(
        auth.validate_session(&"missing".into()),
        Err(Error::UnknownSession(_))
    ));
}

#[test]
fn restart_invalidates_runtime_sessions() {
    let mut auth = alice_service();
    let session = auth
        .create_session(IdentityId::new("alice-id"))
        .unwrap();
    auth.restart();
    assert_eq!(auth.sessions().len(), 0);
    assert!(matches!(
        auth.validate_session(&session.id),
        Err(Error::UnknownSession(_))
    ));
}

#[test]
fn authorization_database_allow_and_deny() {
    let mut grants = GrantStore::new();
    let id = IdentityId::new("alice-id");
    grants.grant(id.clone(), Resource::database("avrora"), Action::Connect);
    assert!(grants
        .authorize_exact(&id, &Resource::database("avrora"), Action::Connect)
        .is_ok());
    assert!(grants
        .authorize_exact(&id, &Resource::database("other"), Action::Connect)
        .is_err());
}

#[test]
fn authorization_schema_usage() {
    let mut grants = GrantStore::new();
    let id = IdentityId::new("alice-id");
    grants.grant(id.clone(), Resource::database("avrora"), Action::Connect);
    grants.grant(
        id.clone(),
        Resource::schema("avrora", "public"),
        Action::Usage,
    );
    assert!(grants
        .authorize_table_action(&id, "avrora", "public", "users", Action::Select)
        .is_err());
    grants.grant(
        id.clone(),
        Resource::table("avrora", "public", "users"),
        Action::Select,
    );
    assert!(grants
        .authorize_table_action(&id, "avrora", "public", "users", Action::Select)
        .is_ok());
}

#[test]
fn authorization_table_actions() {
    let mut grants = GrantStore::new();
    let id = IdentityId::new("u");
    grants.grant(id.clone(), Resource::database("avrora"), Action::Connect);
    grants.grant(
        id.clone(),
        Resource::schema("avrora", "public"),
        Action::Usage,
    );
    for action in [
        Action::Select,
        Action::Insert,
        Action::Update,
        Action::Delete,
    ] {
        grants.grant(
            id.clone(),
            Resource::table("avrora", "public", "t"),
            action,
        );
        assert!(grants
            .authorize_table_action(&id, "avrora", "public", "t", action)
            .is_ok());
    }
}

#[test]
fn authorization_create_and_drop() {
    let mut grants = GrantStore::new();
    let id = IdentityId::new("admin");
    grants.grant(id.clone(), Resource::System, Action::Create);
    grants.grant(id.clone(), Resource::database("avrora"), Action::Connect);
    grants.grant(id.clone(), Resource::database("avrora"), Action::Create);
    grants.grant(
        id.clone(),
        Resource::schema("avrora", "public"),
        Action::Create,
    );
    assert!(grants.authorize_database_create(&id, "sales").is_ok());
    assert!(grants
        .authorize_create_schema_on_database(&id, "avrora")
        .is_ok());
    assert!(grants
        .authorize_schema_create(&id, "avrora", "public")
        .is_ok());
}

#[test]
fn hierarchy_db_deny_blocks_schema_allow() {
    let mut grants = GrantStore::new();
    let id = IdentityId::new("u");
    grants.grant(
        id.clone(),
        Resource::schema("avrora", "public"),
        Action::Usage,
    );
    grants.grant(
        id.clone(),
        Resource::table("avrora", "public", "users"),
        Action::Select,
    );
    assert!(grants
        .authorize_table_action(&id, "avrora", "public", "users", Action::Select)
        .is_err());
}

#[test]
fn hierarchy_schema_deny_blocks_table_allow() {
    let mut grants = GrantStore::new();
    let id = IdentityId::new("u");
    grants.grant(id.clone(), Resource::database("avrora"), Action::Connect);
    grants.grant(
        id.clone(),
        Resource::table("avrora", "public", "users"),
        Action::Select,
    );
    assert!(grants
        .authorize_table_action(&id, "avrora", "public", "users", Action::Select)
        .is_err());
}

#[test]
fn login_returns_session_and_principal() {
    let mut auth = alice_service();
    let (session, principal) = auth.login("alice", "secret").unwrap();
    assert_eq!(principal.identity_id, IdentityId::new("alice-id"));
    assert_eq!(principal.session_id, session.id);
}

#[test]
fn principal_for_active_session() {
    let mut auth = alice_service();
    let (_, principal) = auth.login("alice", "secret").unwrap();
    let resolved = auth.principal_for(&principal.session_id).unwrap();
    assert_eq!(resolved, principal);
}

#[test]
fn auth_failure_differs_from_authz_failure() {
    let auth_err = Error::AuthenticationFailed("bad password".into());
    let authz_err = Error::PermissionDenied("no select".into());
    assert_ne!(auth_err.to_string(), authz_err.to_string());
}

#[test]
fn authz_failure_differs_from_storage_error() {
    let authz_err = Error::PermissionDenied("denied".into());
    let storage_err = Error::Vault(dmc_vault::Error::Locked);
    assert_ne!(authz_err.to_string(), storage_err.to_string());
}

#[test]
fn catalog_authorizer_wraps_grant_store() {
    let mut auth = alice_service();
    auth.grants_mut().grant(
        IdentityId::new("alice-id"),
        Resource::database("avrora"),
        Action::Connect,
    );
    let authorizer = auth.authorizer();
    let principal = AuthPrincipal::new(IdentityId::new("alice-id"), "s".into());
    assert!(authorizer
        .authorize(&principal, &Resource::database("avrora"), Action::Connect)
        .is_ok());
}

#[test]
fn expire_sessions_marks_expired() {
    let mut auth = alice_service();
    auth.set_clock_ms(Some(1_000));
    let session = auth
        .create_session(IdentityId::new("alice-id"))
        .unwrap();
    let expired = auth.expire_sessions(session.expires_at_ms + 1);
    assert_eq!(expired, 1);
    assert!(matches!(
        auth.validate_session(&session.id),
        Err(Error::SessionExpired(_))
    ));
}

#[test]
fn grant_all_catalog_helper_covers_table_dml() {
    let mut grants = GrantStore::new();
    let id = IdentityId::new("admin");
    grants.grant_all_catalog(id.clone(), "avrora", "public", &["users"]);
    assert!(grants
        .authorize_table_action(&id, "avrora", "public", "users", Action::Select)
        .is_ok());
    assert!(grants
        .authorize_table_action(&id, "avrora", "public", "users", Action::Insert)
        .is_ok());
}

#[test]
fn schema_deny_even_with_db_allow_and_table_allow() {
    let mut grants = GrantStore::new();
    let id = IdentityId::new("u");
    grants.grant(id.clone(), Resource::database("avrora"), Action::Connect);
    // schema USAGE intentionally missing
    grants.grant(
        id.clone(),
        Resource::table("avrora", "public", "users"),
        Action::Select,
    );
    let err = grants
        .authorize_table_action(&id, "avrora", "public", "users", Action::Select)
        .unwrap_err();
    assert!(matches!(err, Error::PermissionDenied(_)));
}

// silence unused Result import in tests
fn _ok() -> Result<()> {
    Ok(())
}
