use std::collections::HashSet;

use crate::auth::identity::IdentityId;
use crate::auth::{Action, Resource};
use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Grant {
    pub identity_id: IdentityId,
    pub resource: Resource,
    pub action: Action,
}

#[derive(Clone, Debug, Default)]
pub struct GrantStore {
    grants: Vec<Grant>,
}

impl GrantStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn grant(
        &mut self,
        identity_id: IdentityId,
        resource: Resource,
        action: Action,
    ) -> &mut Self {
        if !self.has_grant(&identity_id, &resource, action) {
            self.grants.push(Grant {
                identity_id,
                resource,
                action,
            });
        }
        self
    }

    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }

    /// Remove a grant; returns whether it existed.
    pub fn revoke(&mut self, identity_id: &IdentityId, resource: &Resource, action: Action) -> bool {
        let before = self.grants.len();
        self.grants
            .retain(|g| !(g.identity_id == *identity_id && g.resource == *resource && g.action == action));
        before != self.grants.len()
    }

    pub fn for_identity(&self, identity_id: &IdentityId) -> Vec<Grant> {
        self.grants.iter().filter(|g| g.identity_id == *identity_id).cloned().collect()
    }

    pub fn replace(&mut self, grants: Vec<Grant>) {
        self.grants = grants;
    }

    pub fn has_grant(
        &self,
        identity_id: &IdentityId,
        resource: &Resource,
        action: Action,
    ) -> bool {
        self.grants.iter().any(|g| {
            g.identity_id == *identity_id && g.resource == *resource && g.action == action
        })
    }

    pub fn authorize_exact(
        &self,
        identity_id: &IdentityId,
        resource: &Resource,
        action: Action,
    ) -> Result<()> {
        if self.has_grant(identity_id, resource, action) {
            Ok(())
        } else {
            Err(Error::PermissionDenied(format!(
                "identity '{}' denied {action} on {resource}",
                identity_id.as_str()
            )))
        }
    }

    pub fn authorize_table_action(
        &self,
        identity_id: &IdentityId,
        database: &str,
        schema: &str,
        table: &str,
        action: Action,
    ) -> Result<()> {
        self.authorize_exact(
            identity_id,
            &Resource::database(database),
            Action::Connect,
        )?;
        self.authorize_exact(
            identity_id,
            &Resource::schema(database, schema),
            Action::Usage,
        )?;
        self.authorize_exact(
            identity_id,
            &Resource::table(database, schema, table),
            action,
        )
    }

    pub fn authorize_schema_create(
        &self,
        identity_id: &IdentityId,
        database: &str,
        schema: &str,
    ) -> Result<()> {
        self.authorize_exact(
            identity_id,
            &Resource::database(database),
            Action::Connect,
        )?;
        self.authorize_exact(
            identity_id,
            &Resource::schema(database, schema),
            Action::Create,
        )
    }

    pub fn authorize_database_create(
        &self,
        identity_id: &IdentityId,
        database: &str,
    ) -> Result<()> {
        self.authorize_exact(identity_id, &Resource::System, Action::Create)?;
        let _ = database;
        Ok(())
    }

    pub fn authorize_create_schema_on_database(
        &self,
        identity_id: &IdentityId,
        database: &str,
    ) -> Result<()> {
        self.authorize_exact(
            identity_id,
            &Resource::database(database),
            Action::Connect,
        )?;
        self.authorize_exact(
            identity_id,
            &Resource::database(database),
            Action::Create,
        )
    }

    pub fn grant_all_catalog(
        &mut self,
        identity_id: IdentityId,
        database: &str,
        schema: &str,
        tables: &[&str],
    ) {
        let actions = [
            Action::Connect,
            Action::Usage,
            Action::Select,
            Action::Insert,
            Action::Update,
            Action::Delete,
            Action::Create,
            Action::Drop,
        ];
        for action in actions {
            self.grant(identity_id.clone(), Resource::System, action);
            self.grant(
                identity_id.clone(),
                Resource::database(database),
                action,
            );
            self.grant(
                identity_id.clone(),
                Resource::schema(database, schema),
                action,
            );
        }
        for table in tables {
            for action in actions {
                self.grant(
                    identity_id.clone(),
                    Resource::table(database, schema, *table),
                    action,
                );
            }
        }
    }

    pub fn granted_actions(
        &self,
        identity_id: &IdentityId,
        resource: &Resource,
    ) -> HashSet<Action> {
        self.grants
            .iter()
            .filter(|g| g.identity_id == *identity_id && g.resource == *resource)
            .map(|g| g.action)
            .collect()
    }
}
