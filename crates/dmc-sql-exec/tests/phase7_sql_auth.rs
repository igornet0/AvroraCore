//! Phase 7.2 — SQL authorization integration (auth before parse/bind/execute).

use dmc_materialized::StateMaterializer;
use dmc_model::{ApplyMode, Catalog, CatalogApplier, ColumnDef, SqlDataType};
use dmc_security::auth::{Action, AuthService, Resource, SessionManager};
use dmc_sql_bind::bind_sql;
use dmc_sql_exec::{
    authorize_sql, collect_rows, execute_authorized_sql, execute_bound_statement,
    map_security_error, ExecutionContext, ExecutionError, JournalBackend, Value,
};
use std::path::Path;
use tempfile::tempdir;

fn users_columns() -> Vec<ColumnDef> {
    vec![
        ColumnDef {
            name: "id".into(),
            data_type: SqlDataType::BigInt,
            nullable: false,
            default: None,
        },
        ColumnDef {
            name: "name".into(),
            data_type: SqlDataType::Text,
            nullable: true,
            default: None,
        },
    ]
}

fn bootstrap(
    root: &Path,
) -> (
    Catalog,
    ExecutionContext,
    AuthService,
    dmc_security::auth::AuthPrincipal,
) {
    let mut catalog = Catalog::new();
    let mut events = catalog.bootstrap_default().unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let create = catalog
        .create_table_event(schema, "users", users_columns(), Some(vec!["id".into()]))
        .unwrap();
    catalog.apply(&create, ApplyMode::Live).unwrap();
    events.push(create);

    let snapshot = root.join("materialized_snapshot.json");
    let log = root.join("state_events.json");
    let rows = root.join("rows");
    let mut mat = StateMaterializer::open(rows, snapshot, log).unwrap();
    for event in &events {
        mat.mutate_catalog(event.clone()).unwrap();
    }
    let table_id = catalog.table_by_name(schema, "users").unwrap().id;

    let mut ctx = ExecutionContext::new();
    ctx.attach_journal(JournalBackend::File(mat));
    ctx.attach_session_catalog(&catalog);
    ctx.insert_materialized_from_journal(table_id).unwrap();

    let mut auth = AuthService::new();
    let identity = auth.create_identity("analyst", "pw").unwrap();
    auth.grants_mut().grant(
        identity.clone(),
        Resource::database("avrora"),
        Action::Connect,
    );
    auth.grants_mut().grant(
        identity.clone(),
        Resource::schema("avrora", "public"),
        Action::Usage,
    );
    auth.grants_mut().grant(
        identity.clone(),
        Resource::table("avrora", "public", "users"),
        Action::Select,
    );
    let (_, principal) = auth.login("analyst", "pw").unwrap();
    (catalog, ctx, auth, principal)
}

fn grant_insert(auth: &mut AuthService, identity: &dmc_security::auth::IdentityId) {
    auth.grants_mut().grant(
        identity.clone(),
        Resource::table("avrora", "public", "users"),
        Action::Insert,
    );
}

#[test]
fn authorized_select_succeeds() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, auth, principal) = bootstrap(dir.path());
    let rows = collect_rows(
        &execute_authorized_sql(
            "SELECT id FROM users WHERE id = 1",
            &auth,
            &principal,
            &mut ctx,
        )
        .unwrap(),
    );
    assert!(rows.is_empty());
}

#[test]
fn unauthorized_select_denied_before_execution() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, mut auth, principal) = bootstrap(dir.path());
    auth.grants_mut().replace(vec![]);
    auth.grants_mut().grant(
        principal.identity_id.clone(),
        Resource::database("avrora"),
        Action::Connect,
    );
    auth.grants_mut().grant(
        principal.identity_id.clone(),
        Resource::schema("avrora", "public"),
        Action::Usage,
    );
    let err = execute_authorized_sql(
        "SELECT id FROM users",
        &auth,
        &principal,
        &mut ctx,
    )
    .unwrap_err();
    assert!(matches!(err, ExecutionError::AuthorizationDenied(_)));
    assert!(bind_sql(&mut catalog, "SELECT id FROM users").is_ok());
}

#[test]
fn authorized_insert_succeeds() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, mut auth, principal) = bootstrap(dir.path());
    grant_insert(&mut auth, &principal.identity_id);
    execute_authorized_sql(
        "INSERT INTO users (id, name) VALUES (1, 'A')",
        &auth,
        &principal,
        &mut ctx,
    )
    .unwrap();
}

#[test]
fn unauthorized_insert_denied() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, auth, principal) = bootstrap(dir.path());
    let err = execute_authorized_sql(
        "INSERT INTO users (id, name) VALUES (1, 'A')",
        &auth,
        &principal,
        &mut ctx,
    )
    .unwrap_err();
    assert!(matches!(err, ExecutionError::AuthorizationDenied(_)));
}

#[test]
fn authorized_create_table_succeeds() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, mut auth, principal) = bootstrap(dir.path());
    auth.grants_mut().grant(
        principal.identity_id.clone(),
        Resource::database("avrora"),
        Action::Create,
    );
    auth.grants_mut().grant(
        principal.identity_id.clone(),
        Resource::schema("avrora", "public"),
        Action::Create,
    );
    execute_authorized_sql(
        "CREATE TABLE accounts (id BIGINT PRIMARY KEY, name TEXT)",
        &auth,
        &principal,
        &mut ctx,
    )
    .unwrap();
}

#[test]
fn unauthorized_create_table_denied() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, auth, principal) = bootstrap(dir.path());
    let err = execute_authorized_sql(
        "CREATE TABLE accounts (id BIGINT PRIMARY KEY, name TEXT)",
        &auth,
        &principal,
        &mut ctx,
    )
    .unwrap_err();
    assert!(matches!(err, ExecutionError::AuthorizationDenied(_)));
}

#[test]
fn invalid_session_rejected_before_authorization() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, mut auth, principal) = bootstrap(dir.path());
    auth.revoke_session(&principal.session_id).unwrap();
    let err = execute_authorized_sql(
        "SELECT id FROM users",
        &auth,
        &principal,
        &mut ctx,
    )
    .unwrap_err();
    assert!(matches!(err, ExecutionError::SessionInvalid(_)));
    let _ = (catalog, ctx);
}

#[test]
fn auth_failure_separate_from_authz_failure() {
    let dir = tempdir().unwrap();
    let (_catalog, _ctx, mut auth, _) = bootstrap(dir.path());
    let auth_err = auth.login("analyst", "bad").unwrap_err();
    let authz_err = map_security_error(dmc_security::Error::PermissionDenied("nope".into()));
    assert!(matches!(
        map_security_error(auth_err),
        ExecutionError::AuthenticationFailed(_)
    ));
    assert!(matches!(authz_err, ExecutionError::AuthorizationDenied(_)));
}

#[test]
fn authorize_sql_runs_before_execute_bound_statement() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, auth, principal) = bootstrap(dir.path());
    let authorizer = auth.authorizer();
    assert!(authorize_sql(&authorizer, &principal, "SELECT id FROM users").is_ok());
    let bypass = execute_bound_statement(
        bind_sql(&mut catalog, "SELECT id FROM users").unwrap(),
        &mut ctx,
    );
    assert!(bypass.is_ok(), "legacy path still executes without gate");
}

#[test]
fn acceptance_identity_to_sql_gate() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut ctx, mut auth, principal) = bootstrap(dir.path());
    grant_insert(&mut auth, &principal.identity_id);
    execute_authorized_sql(
        "INSERT INTO users (id, name) VALUES (10, 'Z')",
        &auth,
        &principal,
        &mut ctx,
    )
    .unwrap();
    let rows = collect_rows(
        &execute_authorized_sql(
            "SELECT name FROM users WHERE id = 10",
            &auth,
            &principal,
            &mut ctx,
        )
        .unwrap(),
    );
    assert_eq!(rows[0][0], Value::String("Z".into()));
}
