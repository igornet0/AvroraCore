//! Session-side capability refs (cached scope/perms + id/generation).

use dmc_vault::access::{Capability, Permission, PermissionSet};
use dmc_vault::key::KeyPath;

use crate::capabilities::issued::CapabilityRef;
use crate::error::{Error, Result};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapabilitySet {
    refs: Vec<CapabilityRef>,
}

impl CapabilitySet {
    pub fn empty() -> Self {
        Self { refs: Vec::new() }
    }

    pub fn from_refs(refs: Vec<CapabilityRef>) -> Self {
        Self { refs }
    }

    pub fn from_capability(cap: Capability) -> Self {
        Self {
            refs: vec![CapabilityRef {
                capability_id: "cap_ephemeral".into(),
                generation: 1,
                scope: cap.scope.to_string(),
                permissions: cap
                    .permissions
                    .to_names()
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            }],
        }
    }

    pub fn refs(&self) -> &[CapabilityRef] {
        &self.refs
    }

    pub fn items(&self) -> Vec<Capability> {
        self.refs.iter().filter_map(|r| r.to_vault().ok()).collect()
    }

    pub fn authorize(&self, target: &KeyPath, need: Permission) -> Result<()> {
        if self.refs.is_empty() {
            return Err(Error::from_vault(dmc_vault::Error::AccessDenied(
                need.to_string(),
                target.to_string(),
            )));
        }
        let mut last = None;
        for r in &self.refs {
            match r.to_vault() {
                Ok(cap) => match cap.authorize(target, need) {
                    Ok(()) => return Ok(()),
                    Err(e) => last = Some(e),
                },
                Err(e) => last = Some(dmc_vault::Error::InvalidPath(e.to_string())),
            }
        }
        Err(Error::from_vault(last.unwrap()))
    }

    pub fn covering(&self, target: &KeyPath, need: Permission) -> Result<Capability> {
        self.authorize(target, need)?;
        for r in &self.refs {
            if let Ok(cap) = r.to_vault() {
                if cap.authorize(target, need).is_ok() {
                    return Ok(cap);
                }
            }
        }
        Err(Error::from_vault(dmc_vault::Error::AccessDenied(
            need.to_string(),
            target.to_string(),
        )))
    }

    pub fn permissions_covering(&self, scope: &KeyPath) -> PermissionSet {
        let mut acc = PermissionSet::empty();
        for r in &self.refs {
            if let (Ok(sp), Ok(perms)) = (r.scope_path(), r.permission_set()) {
                if sp.is_prefix_of(scope) {
                    acc = acc.union(perms);
                }
            }
        }
        acc
    }

    pub fn primary(&self) -> Option<Capability> {
        self.refs.first().and_then(|r| r.to_vault().ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmc_vault::access::Permission;

    #[test]
    fn union_allows_either_scope() {
        let finance = Capability::new(
            KeyPath::parse("company/finance").unwrap(),
            PermissionSet::read_write(),
        );
        let hr = Capability::new(
            KeyPath::parse("company/hr").unwrap(),
            PermissionSet::empty().with(Permission::Read),
        );
        let set = CapabilitySet::from_refs(vec![
            CapabilityRef {
                capability_id: "a".into(),
                generation: 1,
                scope: finance.scope.to_string(),
                permissions: finance
                    .permissions
                    .to_names()
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            },
            CapabilityRef {
                capability_id: "b".into(),
                generation: 1,
                scope: hr.scope.to_string(),
                permissions: hr
                    .permissions
                    .to_names()
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            },
        ]);
        set.authorize(
            &KeyPath::parse("company/finance/invoices/1").unwrap(),
            Permission::Write,
        )
        .unwrap();
        set.authorize(&KeyPath::parse("company/hr/emp/1").unwrap(), Permission::Read)
            .unwrap();
        assert!(set
            .authorize(
                &KeyPath::parse("company/hr/emp/1").unwrap(),
                Permission::Write
            )
            .is_err());
    }
}
