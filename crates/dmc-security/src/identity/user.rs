//! Vault user directory (Phase 2.1). Policy lives on roles; users only hold RoleIds.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::identity::{now_unix_ms, UserId, ROOT_USER};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserStatus {
    Active,
    Disabled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub status: UserStatus,
    pub roles: Vec<String>,
    pub created_at: u64,
}

impl User {
    pub fn root() -> Self {
        Self {
            id: UserId::root(),
            status: UserStatus::Active,
            roles: vec![ROOT_USER.to_string()],
            created_at: now_unix_ms(),
        }
    }

    pub fn is_active(&self) -> bool {
        self.status == UserStatus::Active
    }
}

#[derive(Clone, Debug, Default)]
pub struct UserDirectory {
    users: HashMap<String, User>,
}

impl UserDirectory {
    pub fn with_root() -> Self {
        let mut dir = Self::default();
        dir.users.insert(ROOT_USER.to_string(), User::root());
        dir
    }

    pub fn list(&self) -> Vec<User> {
        let mut list: Vec<_> = self.users.values().cloned().collect();
        list.sort_by(|a, b| a.id.0.cmp(&b.id.0));
        list
    }

    pub fn get(&self, id: &str) -> Option<&User> {
        self.users.get(id)
    }

    pub fn create(&mut self, id: String, roles: Vec<String>) -> Result<User> {
        if self.users.contains_key(&id) {
            return Err(Error::Conflict(format!("user already exists: {id}")));
        }
        if id.is_empty() || id.contains('/') {
            return Err(Error::InvalidUser(id));
        }
        let user = User {
            id: UserId::new(id.clone()),
            status: UserStatus::Active,
            roles,
            created_at: now_unix_ms(),
        };
        self.users.insert(id, user.clone());
        Ok(user)
    }

    pub fn assign_roles(&mut self, id: &str, roles: Vec<String>) -> Result<User> {
        let user = self
            .users
            .get_mut(id)
            .ok_or_else(|| Error::UnknownUser(id.to_string()))?;
        if id == ROOT_USER && !roles.iter().any(|r| r == ROOT_USER) {
            return Err(Error::InvalidUser("root must keep the root role".into()));
        }
        user.roles = roles;
        Ok(user.clone())
    }

    pub fn set_status(&mut self, id: &str, status: UserStatus) -> Result<User> {
        if id == ROOT_USER && status == UserStatus::Disabled {
            return Err(Error::InvalidUser("cannot disable root".into()));
        }
        let user = self
            .users
            .get_mut(id)
            .ok_or_else(|| Error::UnknownUser(id.to_string()))?;
        user.status = status;
        Ok(user.clone())
    }

    pub fn replace(&mut self, users: Vec<User>) {
        self.users.clear();
        for u in users {
            self.users.insert(u.id.0.clone(), u);
        }
    }
}
