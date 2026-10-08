//! Cryptographic authorization: may this principal obtain a key of that subject?
//!
//! Default deny. Database roles, `cap_root`, catalog grants and "admin" status are not
//! inputs to this decision — only subject ownership, tenant and explicit owner-issued
//! delegations are.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use dmc_vault::ownership::{SubjectId, TenantId};
use serde::{Deserialize, Serialize};

use crate::auth::IdentityId;
use crate::identity::SessionId;
use crate::{Error, Result};

/// Operation on a subject's keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyOp {
    /// Decrypt records of the subject.
    Read,
    /// Encrypt new records under the subject's active key.
    Write,
    /// Grant another subject read access.
    Delegate,
    /// Rotate / destroy / rewrap the subject's keys.
    ManageKeys,
}

/// Authenticated subject on whose behalf a key operation runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CryptoPrincipal {
    pub identity_id: IdentityId,
    pub session_id: SessionId,
    pub subject: SubjectId,
    pub tenant: TenantId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllowReason {
    Owner,
    Delegated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    TenantMismatch,
    NotOwner,
    UnknownSubject,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAccessDecision {
    Allow(AllowReason),
    Deny(DenyReason),
}

impl KeyAccessDecision {
    pub fn is_allowed(self) -> bool {
        matches!(self, Self::Allow(_))
    }

    pub fn require(self, op: KeyOp) -> Result<AllowReason> {
        match self {
            Self::Allow(r) => Ok(r),
            Self::Deny(r) => Err(Error::KeyAccessDenied(format!("{op:?}: {r:?}"))),
        }
    }
}

/// Read access granted by `owner` to `grantee` (both in `tenant`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationGrant {
    pub owner: SubjectId,
    pub grantee: SubjectId,
    pub tenant: TenantId,
    pub granted_at_ms: u64,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
}

impl DelegationGrant {
    fn live(&self, now_ms: u64) -> bool {
        self.expires_at_ms.is_none_or(|t| now_ms < t)
    }
}

/// Persisted owner-issued delegations (`delegations.json`).
///
/// Policy metadata only: a forged grant gives nothing without a delegated key
/// envelope, which only the owner's unlocked keys can produce.
#[derive(Clone, Debug)]
pub struct DelegationRegistry {
    path: PathBuf,
    grants: Vec<DelegationGrant>,
}

#[derive(Serialize, Deserialize)]
struct DelegationFile {
    format_version: u32,
    grants: Vec<DelegationGrant>,
}

const DELEGATION_FORMAT: u32 = 1;

impl DelegationRegistry {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let grants = match fs::read(&path) {
            Ok(raw) => {
                let file: DelegationFile = serde_json::from_slice(&raw)
                    .map_err(|e| Error::Conflict(format!("delegations decode: {e}")))?;
                if file.format_version != DELEGATION_FORMAT {
                    return Err(Error::Conflict("unsupported delegations format".into()));
                }
                file.grants
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(Error::Conflict(format!("delegations read: {e}"))),
        };
        Ok(Self { path, grants })
    }

    pub fn grants(&self) -> &[DelegationGrant] {
        &self.grants
    }

    pub fn has_live(&self, owner: SubjectId, grantee: SubjectId, tenant: &TenantId, now_ms: u64) -> bool {
        self.grants.iter().any(|g| {
            g.owner == owner && g.grantee == grantee && &g.tenant == tenant && g.live(now_ms)
        })
    }

    pub fn grant(&mut self, grant: DelegationGrant) -> Result<()> {
        self.grants
            .retain(|g| !(g.owner == grant.owner && g.grantee == grant.grantee));
        self.grants.push(grant);
        self.persist()
    }

    pub fn revoke(&mut self, owner: SubjectId, grantee: SubjectId) -> Result<bool> {
        let before = self.grants.len();
        self.grants
            .retain(|g| !(g.owner == owner && g.grantee == grantee));
        if self.grants.len() == before {
            return Ok(false);
        }
        self.persist()?;
        Ok(true)
    }

    fn persist(&self) -> Result<()> {
        let io = |e: std::io::Error| Error::Conflict(format!("delegations write: {e}"));
        let file = DelegationFile {
            format_version: DELEGATION_FORMAT,
            grants: self.grants.clone(),
        };
        let raw = serde_json::to_vec_pretty(&file)
            .map_err(|e| Error::Conflict(format!("delegations encode: {e}")))?;
        let dir = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(dir).map_err(io)?;
        let tmp = self.path.with_extension("tmp");
        {
            let mut f = fs::File::create(&tmp).map_err(io)?;
            f.write_all(&raw).map_err(io)?;
            f.sync_all().map_err(io)?;
        }
        fs::rename(&tmp, &self.path).map_err(io)?;
        fs::File::open(dir).and_then(|d| d.sync_all()).map_err(io)
    }
}

/// Pure decision function.
///
/// * different tenant → deny;
/// * owner → allow every op;
/// * non-owner → allow `Read` only with a live owner-issued delegation; everything else deny.
pub fn decide(
    principal: &CryptoPrincipal,
    owner: SubjectId,
    owner_tenant: Option<&TenantId>,
    op: KeyOp,
    delegations: &DelegationRegistry,
    now_ms: u64,
) -> KeyAccessDecision {
    let Some(owner_tenant) = owner_tenant else {
        return KeyAccessDecision::Deny(DenyReason::UnknownSubject);
    };
    if owner_tenant != &principal.tenant {
        return KeyAccessDecision::Deny(DenyReason::TenantMismatch);
    }
    if principal.subject == owner {
        return KeyAccessDecision::Allow(AllowReason::Owner);
    }
    if op == KeyOp::Read && delegations.has_live(owner, principal.subject, owner_tenant, now_ms) {
        return KeyAccessDecision::Allow(AllowReason::Delegated);
    }
    KeyAccessDecision::Deny(DenyReason::NotOwner)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(subject: SubjectId, tenant: &str) -> CryptoPrincipal {
        CryptoPrincipal {
            identity_id: IdentityId::new("id"),
            session_id: SessionId::new(),
            subject,
            tenant: TenantId::new(tenant).unwrap(),
        }
    }

    #[test]
    fn decision_matrix() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = DelegationRegistry::open(dir.path().join("d.json")).unwrap();
        let t = TenantId::new("acme").unwrap();
        let (alice, bob) = (SubjectId::random(), SubjectId::random());
        let a = principal(alice, "acme");
        let b = principal(bob, "acme");

        for op in [KeyOp::Read, KeyOp::Write, KeyOp::Delegate, KeyOp::ManageKeys] {
            assert!(decide(&a, alice, Some(&t), op, &reg, 0).is_allowed());
            assert_eq!(
                decide(&b, alice, Some(&t), op, &reg, 0),
                KeyAccessDecision::Deny(DenyReason::NotOwner)
            );
            assert!(!decide(&a, bob, Some(&t), op, &reg, 0).is_allowed());
        }
        assert_eq!(
            decide(&principal(alice, "other"), alice, Some(&t), KeyOp::Read, &reg, 0),
            KeyAccessDecision::Deny(DenyReason::TenantMismatch)
        );
        assert_eq!(
            decide(&a, SubjectId::random(), None, KeyOp::Read, &reg, 0),
            KeyAccessDecision::Deny(DenyReason::UnknownSubject)
        );

        reg.grant(DelegationGrant {
            owner: alice,
            grantee: bob,
            tenant: t.clone(),
            granted_at_ms: 0,
            expires_at_ms: Some(100),
        })
        .unwrap();
        assert_eq!(
            decide(&b, alice, Some(&t), KeyOp::Read, &reg, 50),
            KeyAccessDecision::Allow(AllowReason::Delegated)
        );
        assert!(!decide(&b, alice, Some(&t), KeyOp::Write, &reg, 50).is_allowed());
        assert!(!decide(&b, alice, Some(&t), KeyOp::Read, &reg, 100).is_allowed(), "expired");

        let reloaded = DelegationRegistry::open(dir.path().join("d.json")).unwrap();
        assert_eq!(reloaded.grants().len(), 1);
        reg.revoke(alice, bob).unwrap();
        assert!(!decide(&b, alice, Some(&t), KeyOp::Read, &reg, 50).is_allowed());
    }
}
