use crate::access::{Capability, PermissionSet, RoleRegistry};
use crate::key::KeyPath;
use crate::store::EncryptedKv;

/// Populate demo org tree, sample values, and scoped roles.
pub fn seed_demo(kv: &mut EncryptedKv, roles: &mut RoleRegistry) {
    let root = Capability::root_admin();

    let samples = [
        ("company/finance/invoices/001", "Invoice #001 — $12,000"),
        ("company/finance/invoices/002", "Invoice #002 — $3,450"),
        (
            "company/finance/salaries/alice",
            "Alice salary: confidential",
        ),
        ("company/hr/employees/001", "Employee: Bob (HR)"),
        ("company/hr/employees/002", "Employee: Carol (Eng)"),
    ];

    for (path, value) in samples {
        kv.put(path, value.as_bytes(), &root).expect("seed put");
    }

    roles.seed_role(
        "finance",
        "Finance",
        KeyPath::parse("company/finance").unwrap(),
        PermissionSet::read_write().with(crate::access::Permission::Grant),
    );
    roles.seed_role(
        "hr",
        "HR",
        KeyPath::parse("company/hr").unwrap(),
        PermissionSet::read_write(),
    );
    roles.seed_role(
        "finance-readonly",
        "Finance Read-Only",
        KeyPath::parse("company/finance").unwrap(),
        PermissionSet::empty().with(crate::access::Permission::Read),
    );
}

/// Standard auth vault layout for embedding encrypted RBAC in other services.
pub fn seed_auth_service(kv: &mut EncryptedKv, roles: &mut RoleRegistry) {
    let root = Capability::root_admin();
    for path in ["auth/users", "auth/sessions", "auth/grants", "auth/keys"] {
        kv.put(path, b"{}", &root).expect("auth seed put");
    }
    roles.seed_role(
        "auth_admin",
        "Auth Administrator",
        KeyPath::parse("auth").unwrap(),
        PermissionSet::all(),
    );
    roles.seed_role(
        "auth_service",
        "Auth Service (embed)",
        KeyPath::parse("auth").unwrap(),
        PermissionSet::read_write().with(crate::access::Permission::Grant),
    );
    roles.seed_role(
        "auth_readonly",
        "Auth Read-Only",
        KeyPath::parse("auth").unwrap(),
        PermissionSet::empty().with(crate::access::Permission::Read),
    );
}
