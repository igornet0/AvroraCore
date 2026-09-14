use crate::error::{Error, Result};
use crate::key::KeyPath;

use super::{Permission, PermissionSet};

/// Capability token: logical ACL bound to a key-tree scope.
///
/// Hybrid model:
/// - capability = may the subject *logically* act on this subtree?
/// - key material = can the subject *cryptographically* open the data?
///
/// Both must pass for a successful read/write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capability {
    pub scope: KeyPath,
    pub permissions: PermissionSet,
}

impl Capability {
    pub fn new(scope: KeyPath, permissions: PermissionSet) -> Self {
        Self { scope, permissions }
    }

    pub fn root_admin() -> Self {
        Self::new(KeyPath::root(), PermissionSet::all())
    }

    /// Check that this capability covers `target` with `need`.
    pub fn authorize(&self, target: &KeyPath, need: Permission) -> Result<()> {
        if !self.scope.is_prefix_of(target) {
            return Err(Error::AccessDenied(need.to_string(), target.to_string()));
        }
        if !self.permissions.contains(need) {
            return Err(Error::AccessDenied(need.to_string(), target.to_string()));
        }
        Ok(())
    }

    /// Delegate a narrower capability. Requires GRANT on self, and
    /// `child_scope` must be under (or equal) self.scope. Child perms ⊆ self.
    pub fn delegate(&self, child_scope: KeyPath, child_perms: PermissionSet) -> Result<Capability> {
        if !self.permissions.contains(Permission::Grant) {
            return Err(Error::CannotDelegate(self.scope.to_string()));
        }
        if !self.scope.is_prefix_of(&child_scope) {
            return Err(Error::CannotDelegate(child_scope.to_string()));
        }
        if !child_perms.is_subset_of(self.permissions) {
            return Err(Error::CannotDelegate(child_scope.to_string()));
        }
        // Delegated capabilities never inherit GRANT unless explicitly kept.
        Ok(Capability::new(child_scope, child_perms))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finance_read_cannot_touch_hr() {
        let cap = Capability::new(
            KeyPath::parse("company/finance").unwrap(),
            PermissionSet::empty().with(Permission::Read),
        );
        assert!(
            cap.authorize(
                &KeyPath::parse("company/finance/invoices").unwrap(),
                Permission::Read
            )
            .is_ok()
        );
        assert!(
            cap.authorize(&KeyPath::parse("company/hr").unwrap(), Permission::Read)
                .is_err()
        );
    }

    #[test]
    fn grant_required_to_delegate() {
        let cap = Capability::new(
            KeyPath::parse("company").unwrap(),
            PermissionSet::empty().with(Permission::Read),
        );
        assert!(
            cap.delegate(
                KeyPath::parse("company/finance").unwrap(),
                PermissionSet::empty().with(Permission::Read),
            )
            .is_err()
        );
    }
}
