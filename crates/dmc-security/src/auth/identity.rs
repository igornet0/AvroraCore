use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Stable identity handle — independent of session, catalog ids, or RowId.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentityId(pub String);

impl IdentityId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IdentityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for IdentityId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub id: IdentityId,
    pub name: String,
    pub status: IdentityStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityStatus {
    Active,
    Disabled,
}

impl Identity {
    pub fn is_active(&self) -> bool {
        matches!(self.status, IdentityStatus::Active)
    }
}

#[derive(Clone, Debug, Default)]
pub struct IdentityDirectory {
    by_id: HashMap<String, Identity>,
    by_name: HashMap<String, IdentityId>,
}

impl IdentityDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, identity: Identity) -> Result<()> {
        if self.by_name.contains_key(&identity.name) {
            return Err(Error::Conflict(format!(
                "identity name already exists: {}",
                identity.name
            )));
        }
        let id = identity.id.clone();
        self.by_name.insert(identity.name.clone(), id.clone());
        self.by_id.insert(id.as_str().to_string(), identity);
        Ok(())
    }

    pub fn get(&self, id: &IdentityId) -> Option<&Identity> {
        self.by_id.get(id.as_str())
    }

    pub fn get_by_name(&self, name: &str) -> Option<&Identity> {
        self.by_name
            .get(name)
            .and_then(|id| self.by_id.get(id.as_str()))
    }

    pub fn list(&self) -> Vec<&Identity> {
        self.by_id.values().collect()
    }

    pub fn disable(&mut self, id: &IdentityId) -> Result<()> {
        let identity = self
            .by_id
            .get_mut(id.as_str())
            .ok_or_else(|| Error::UnknownIdentity(id.as_str().to_string()))?;
        identity.status = IdentityStatus::Disabled;
        Ok(())
    }
}
