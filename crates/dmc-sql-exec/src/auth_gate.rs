//! Authorize SQL statements before parse/bind/execute (Phase 7.2 boundary).

use dmc_security::auth::{Action, AuthPrincipal, Authorizer, CatalogAuthorizer, Resource};
use dmc_sql_front::{parse_sql, CreateTable, QualifiedName, Statement, TableRef};

use crate::error::{ExecutionError, Result};

pub const DEFAULT_DATABASE: &str = "avrora";
pub const DEFAULT_SCHEMA: &str = "public";

type AuthResult<T> = std::result::Result<T, dmc_security::Error>;

/// Validate session principal and authorize SQL text before execution.
pub fn authorize_sql(
    authorizer: &CatalogAuthorizer<'_>,
    principal: &AuthPrincipal,
    sql: &str,
) -> Result<()> {
    let stmt = parse_sql(sql).map_err(|e| ExecutionError::InvalidPlan(e.to_string()))?;
    authorize_statement(authorizer, principal, &stmt).map_err(map_security_error)
}

pub fn authorize_statement(
    authorizer: &CatalogAuthorizer<'_>,
    principal: &AuthPrincipal,
    stmt: &Statement,
) -> AuthResult<()> {
    match stmt {
        Statement::Select(select) => {
            for table in &select.from {
                authorize_table_ref(authorizer, principal, table, Action::Select)?;
            }
        }
        Statement::Insert(insert) => {
            let (db, schema, table) = resolve_qualified_name(&insert.table);
            authorizer.authorize_table(principal, &db, &schema, &table, Action::Insert)?;
        }
        Statement::Update(update) => {
            let (db, schema, table) = resolve_qualified_name(&update.table);
            authorizer.authorize_table(principal, &db, &schema, &table, Action::Update)?;
        }
        Statement::Delete(delete) => {
            let (db, schema, table) = resolve_qualified_name(&delete.table);
            authorizer.authorize_table(principal, &db, &schema, &table, Action::Delete)?;
        }
        Statement::CreateDatabase(create) => {
            authorizer.authorize_database_create(principal, &create.name.name)?;
        }
        Statement::CreateSchema(create) => {
            authorizer.authorize_create_schema_on_database(principal, DEFAULT_DATABASE)?;
            let _ = create.name.name.as_str();
        }
        Statement::CreateTable(create) => {
            let (db, schema, _) = resolve_create_table_target(create);
            authorizer.authorize_create_schema_on_database(principal, &db)?;
            authorizer.authorize_schema_create(principal, &db, &schema)?;
        }
        Statement::DropTable(drop) => {
            let (db, schema, table) = resolve_qualified_name(&drop.name);
            authorizer.authorize_table(principal, &db, &schema, &table, Action::Drop)?;
        }
        Statement::CreateIndex(create) => {
            let (db, schema, table) = resolve_qualified_name(&create.table);
            authorizer.authorize_table(principal, &db, &schema, &table, Action::Create)?;
        }
        Statement::DropIndex(_drop) => {
            authorizer.authorize(
                principal,
                &Resource::schema(DEFAULT_DATABASE, DEFAULT_SCHEMA),
                Action::Drop,
            )?;
        }
        Statement::Begin | Statement::Commit | Statement::Rollback => {}
    }
    Ok(())
}

fn authorize_table_ref(
    authorizer: &CatalogAuthorizer<'_>,
    principal: &AuthPrincipal,
    table: &TableRef,
    action: Action,
) -> AuthResult<()> {
    let (db, schema, name) = resolve_qualified_name(&table.name);
    authorizer.authorize_table(principal, &db, &schema, &name, action)?;
    if let Some(join) = &table.join {
        let (db, schema, name) = resolve_qualified_name(&join.table);
        authorizer.authorize_table(principal, &db, &schema, &name, action)?;
    }
    Ok(())
}

fn resolve_qualified_name(name: &QualifiedName) -> (String, String, String) {
    match name.parts.len() {
        1 => (
            DEFAULT_DATABASE.into(),
            DEFAULT_SCHEMA.into(),
            name.parts[0].name.clone(),
        ),
        2 => (
            DEFAULT_DATABASE.into(),
            name.parts[0].name.clone(),
            name.parts[1].name.clone(),
        ),
        3 => (
            name.parts[0].name.clone(),
            name.parts[1].name.clone(),
            name.parts[2].name.clone(),
        ),
        _ => (
            DEFAULT_DATABASE.into(),
            DEFAULT_SCHEMA.into(),
            name.parts
                .last()
                .map(|p| p.name.clone())
                .unwrap_or_default(),
        ),
    }
}

fn resolve_create_table_target(create: &CreateTable) -> (String, String, String) {
    let table = create
        .name
        .parts
        .last()
        .map(|p| p.name.clone())
        .unwrap_or_default();
    let (db, schema, _) = resolve_qualified_name(&create.name);
    (db, schema, table)
}

pub fn map_security_error(err: dmc_security::Error) -> ExecutionError {
    match err {
        dmc_security::Error::AuthenticationFailed(msg) => ExecutionError::AuthenticationFailed(msg),
        dmc_security::Error::PermissionDenied(msg) => ExecutionError::AuthorizationDenied(msg),
        dmc_security::Error::UnknownIdentity(msg) => ExecutionError::AuthenticationFailed(msg),
        dmc_security::Error::IdentityDisabled(msg) => ExecutionError::AuthenticationFailed(msg),
        dmc_security::Error::UnknownSession(msg) | dmc_security::Error::SessionExpired(msg) => {
            ExecutionError::SessionInvalid(msg)
        }
        other => ExecutionError::Security(other.to_string()),
    }
}
