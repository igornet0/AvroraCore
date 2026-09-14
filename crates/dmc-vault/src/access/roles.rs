use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::key::KeyPath;

use super::{Capability, Permission, PermissionSet};

/// Named capability for the local admin UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Role {
    pub id: String,
    pub name: String,
    pub scope: KeyPath,
    pub permissions: PermissionSet,
}

impl Role {
    pub fn to_capability(&self) -> Capability {
        Capability::new(self.scope.clone(), self.permissions)
    }
}

/// In-memory registry of named roles.
#[derive(Clone)]
pub struct RoleRegistry {
    roles: HashMap<String, Role>,
}

impl RoleRegistry {
    pub fn empty() -> Self {
        Self {
            roles: HashMap::new(),
        }
    }

    pub fn with_root() -> Self {
        let mut roles = HashMap::new();
        roles.insert(
            "root".to_string(),
            Role {
                id: "root".to_string(),
                name: "Root Admin".to_string(),
                scope: KeyPath::root(),
                permissions: PermissionSet::all(),
            },
        );
        Self { roles }
    }

    pub fn ensure_root(&mut self) {
        if !self.roles.contains_key("root") {
            *self = Self::with_root();
        }
    }

    pub fn list(&self) -> Vec<Role> {
        let mut list: Vec<_> = self.roles.values().cloned().collect();
        list.sort_by(|a, b| a.id.cmp(&b.id));
        list
    }

    pub fn get(&self, id: &str) -> Option<&Role> {
        self.roles.get(id)
    }

    pub fn create(
        &mut self,
        id: String,
        name: String,
        scope: KeyPath,
        permissions: PermissionSet,
        actor: &Capability,
    ) -> Result<Role> {
        if self.roles.contains_key(&id) {
            return Err(Error::InvalidPath(format!("role already exists: {id}")));
        }
        if id == "root" {
            return Err(Error::InvalidPath("cannot recreate root".into()));
        }
        // Actor must be able to delegate this capability.
        let _child = actor.delegate(scope.clone(), permissions)?;
        let role = Role {
            id: id.clone(),
            name,
            scope,
            permissions,
        };
        self.roles.insert(id, role.clone());
        Ok(role)
    }

    pub fn update(
        &mut self,
        id: &str,
        name: Option<String>,
        scope: Option<KeyPath>,
        permissions: Option<PermissionSet>,
        actor: &Capability,
    ) -> Result<Role> {
        if id == "root" {
            return Err(Error::InvalidPath("cannot modify root role".into()));
        }
        let existing = self
            .roles
            .get(id)
            .ok_or_else(|| Error::NotFound(format!("role:{id}")))?
            .clone();
        let new_scope = scope.unwrap_or(existing.scope);
        let new_perms = permissions.unwrap_or(existing.permissions);
        let _ = actor.delegate(new_scope.clone(), new_perms)?;
        let role = Role {
            id: id.to_string(),
            name: name.unwrap_or(existing.name),
            scope: new_scope,
            permissions: new_perms,
        };
        self.roles.insert(id.to_string(), role.clone());
        Ok(role)
    }

    pub fn delete(&mut self, id: &str) -> Result<()> {
        if id == "root" {
            return Err(Error::InvalidPath("cannot delete root".into()));
        }
        if self.roles.remove(id).is_none() {
            return Err(Error::NotFound(format!("role:{id}")));
        }
        Ok(())
    }

    /// Seed helper without GRANT checks (startup only).
    pub fn seed_role(&mut self, id: &str, name: &str, scope: KeyPath, permissions: PermissionSet) {
        self.roles.insert(
            id.to_string(),
            Role {
                id: id.to_string(),
                name: name.to_string(),
                scope,
                permissions,
            },
        );
    }
}

/// Tree ops (ensure/revoke/rotate) require WRITE or GRANT under the path.
pub fn authorize_tree_write(cap: &Capability, path: &KeyPath) -> Result<()> {
    if cap.authorize(path, Permission::Grant).is_ok() {
        return Ok(());
    }
    cap.authorize(path, Permission::Write)
}
