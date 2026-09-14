//! Issued capabilities: identity, generation, issuer/subject, TTL, revoke.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use dmc_vault::access::{Capability, PermissionSet};
use dmc_vault::key::KeyPath;

use crate::error::{Error, Result};
use crate::identity::{now_unix_ms, UserId};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilityId(pub String);

impl CapabilityId {
    pub fn new() -> Self {
        Self(format!("cap_{}", Uuid::new_v4().simple()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for CapabilityId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for CapabilityId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CapabilityStatus {
    Active,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedCapability {
    pub id: CapabilityId,
    pub generation: u64,
    pub issuer: UserId,
    pub subject: UserId,
    pub scope: String,
    pub permissions: Vec<String>,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub status: CapabilityStatus,
    #[serde(default)]
    pub parent_id: Option<CapabilityId>,
    #[serde(default)]
    pub source_role: Option<String>,
}

impl IssuedCapability {
    pub fn scope_path(&self) -> Result<KeyPath> {
        if self.scope.is_empty() || self.scope == "/" {
            Ok(KeyPath::root())
        } else {
            KeyPath::parse(self.scope.trim_start_matches('/')).map_err(Error::from_vault)
        }
    }

    pub fn permission_set(&self) -> Result<PermissionSet> {
        PermissionSet::from_names(&self.permissions).map_err(Error::from_vault)
    }

    pub fn to_vault(&self) -> Result<Capability> {
        Ok(Capability::new(self.scope_path()?, self.permission_set()?))
    }

    pub fn effective_status(&self, now_ms: u64) -> CapabilityStatus {
        if self.status == CapabilityStatus::Revoked {
            return CapabilityStatus::Revoked;
        }
        if self.expires_at.is_some_and(|t| now_ms >= t) {
            return CapabilityStatus::Expired;
        }
        CapabilityStatus::Active
    }

    pub fn is_live(&self, now_ms: u64) -> bool {
        self.effective_status(now_ms) == CapabilityStatus::Active
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityRef {
    pub capability_id: CapabilityId,
    pub generation: u64,
    pub scope: String,
    pub permissions: Vec<String>,
}

impl CapabilityRef {
    pub fn from_issued(cap: &IssuedCapability) -> Self {
        Self {
            capability_id: cap.id.clone(),
            generation: cap.generation,
            scope: cap.scope.clone(),
            permissions: cap.permissions.clone(),
        }
    }

    pub fn scope_path(&self) -> Result<KeyPath> {
        if self.scope.is_empty() || self.scope == "/" {
            Ok(KeyPath::root())
        } else {
            KeyPath::parse(self.scope.trim_start_matches('/')).map_err(Error::from_vault)
        }
    }

    pub fn permission_set(&self) -> Result<PermissionSet> {
        PermissionSet::from_names(&self.permissions).map_err(Error::from_vault)
    }

    pub fn to_vault(&self) -> Result<Capability> {
        Ok(Capability::new(self.scope_path()?, self.permission_set()?))
    }
}

#[derive(Clone, Debug, Default)]
pub struct CapabilityRegistry {
    caps: HashMap<String, IssuedCapability>,
}

impl CapabilityRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seed_root() -> Self {
        let mut reg = Self::new();
        let now = now_unix_ms();
        let cap = IssuedCapability {
            id: CapabilityId::from("cap_root"),
            generation: 1,
            issuer: UserId::root(),
            subject: UserId::root(),
            scope: "/".into(),
            permissions: PermissionSet::all()
                .to_names()
                .into_iter()
                .map(str::to_string)
                .collect(),
            issued_at: now,
            expires_at: None,
            status: CapabilityStatus::Active,
            parent_id: None,
            source_role: Some("root".into()),
        };
        reg.caps.insert(cap.id.0.clone(), cap);
        reg
    }

    pub fn insert(&mut self, cap: IssuedCapability) -> IssuedCapability {
        self.caps.insert(cap.id.0.clone(), cap.clone());
        cap
    }

    pub fn get(&self, id: &CapabilityId) -> Option<&IssuedCapability> {
        self.caps.get(id.as_str())
    }

    pub fn get_mut(&mut self, id: &CapabilityId) -> Option<&mut IssuedCapability> {
        self.caps.get_mut(id.as_str())
    }

    pub fn list(&self) -> Vec<IssuedCapability> {
        let mut v: Vec<_> = self.caps.values().cloned().collect();
        v.sort_by(|a, b| a.id.0.cmp(&b.id.0));
        v
    }

    pub fn for_subject(&self, subject: &str) -> Vec<IssuedCapability> {
        self.caps
            .values()
            .filter(|c| c.subject.as_str() == subject)
            .cloned()
            .collect()
    }

    pub fn replace(&mut self, caps: Vec<IssuedCapability>) {
        self.caps.clear();
        for c in caps {
            self.caps.insert(c.id.0.clone(), c);
        }
        if !self.caps.contains_key("cap_root") {
            *self = Self::seed_root();
        }
    }

    pub fn revoke(&mut self, id: &CapabilityId) -> Result<IssuedCapability> {
        let cap = self
            .caps
            .get_mut(id.as_str())
            .ok_or_else(|| Error::UnknownCapability(id.to_string()))?;
        cap.status = CapabilityStatus::Revoked;
        cap.generation = cap.generation.saturating_add(1);
        Ok(cap.clone())
    }
}
