use crate::auth::grant::GrantStore;
use crate::auth::identity::IdentityId;
use crate::auth::principal::AuthPrincipal;
use crate::auth::resource::{Action, Resource};
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationDecision {
    Allow,
}

pub trait Authorizer {
    fn authorize(
        &self,
        principal: &AuthPrincipal,
        resource: &Resource,
        action: Action,
    ) -> Result<AuthorizationDecision>;
}

/// Hierarchical catalog authorizer backed by explicit grants.
#[derive(Clone, Debug)]
pub struct CatalogAuthorizer<'a> {
    grants: &'a GrantStore,
}

impl<'a> CatalogAuthorizer<'a> {
    pub fn new(grants: &'a GrantStore) -> Self {
        Self { grants }
    }

    pub fn grants(&self) -> &GrantStore {
        self.grants
    }

    pub fn authorize_table(
        &self,
        principal: &AuthPrincipal,
        database: &str,
        schema: &str,
        table: &str,
        action: Action,
    ) -> Result<AuthorizationDecision> {
        self.grants
            .authorize_table_action(&principal.identity_id, database, schema, table, action)?;
        Ok(AuthorizationDecision::Allow)
    }

    pub fn authorize_schema_usage(
        &self,
        principal: &AuthPrincipal,
        database: &str,
        schema: &str,
    ) -> Result<AuthorizationDecision> {
        self.grants.authorize_exact(
            &principal.identity_id,
            &Resource::database(database),
            Action::Connect,
        )?;
        self.grants.authorize_exact(
            &principal.identity_id,
            &Resource::schema(database, schema),
            Action::Usage,
        )?;
        Ok(AuthorizationDecision::Allow)
    }

    pub fn authorize_schema_create(
        &self,
        principal: &AuthPrincipal,
        database: &str,
        schema: &str,
    ) -> Result<AuthorizationDecision> {
        self.grants
            .authorize_schema_create(&principal.identity_id, database, schema)?;
        Ok(AuthorizationDecision::Allow)
    }

    pub fn authorize_database_create(
        &self,
        principal: &AuthPrincipal,
        database: &str,
    ) -> Result<AuthorizationDecision> {
        self.grants
            .authorize_database_create(&principal.identity_id, database)?;
        Ok(AuthorizationDecision::Allow)
    }

    pub fn authorize_create_schema_on_database(
        &self,
        principal: &AuthPrincipal,
        database: &str,
    ) -> Result<AuthorizationDecision> {
        self.grants
            .authorize_create_schema_on_database(&principal.identity_id, database)?;
        Ok(AuthorizationDecision::Allow)
    }
}

impl Authorizer for CatalogAuthorizer<'_> {
    fn authorize(
        &self,
        principal: &AuthPrincipal,
        resource: &Resource,
        action: Action,
    ) -> Result<AuthorizationDecision> {
        self.grants
            .authorize_exact(&principal.identity_id, resource, action)?;
        Ok(AuthorizationDecision::Allow)
    }
}

impl GrantStore {
    pub fn check_hierarchy_table(
        &self,
        identity_id: &IdentityId,
        database: &str,
        schema: &str,
        table: &str,
        action: Action,
    ) -> Result<()> {
        if !self.has_grant(identity_id, &Resource::database(database), Action::Connect) {
            return Err(Error::PermissionDenied(format!(
                "database '{database}' CONNECT required"
            )));
        }
        if !self.has_grant(identity_id, &Resource::schema(database, schema), Action::Usage) {
            return Err(Error::PermissionDenied(format!(
                "schema '{database}.{schema}' USAGE required"
            )));
        }
        if !self.has_grant(
            identity_id,
            &Resource::table(database, schema, table),
            action,
        ) {
            return Err(Error::PermissionDenied(format!(
                "table '{database}.{schema}.{table}' {action} denied"
            )));
        }
        Ok(())
    }
}
