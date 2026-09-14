use dmc_vault::access::{Capability, Permission, PermissionSet};
use dmc_vault::key::{KeyPath, KeyTree};
use dmc_vault::store::EncryptedKv;

fn main() {
    // Root holds full crypto + ACL power.
    let tree = KeyTree::new_with_root();
    let mut db = EncryptedKv::new(tree);
    let root = Capability::root_admin();

    // Delegate: finance may READ/WRITE but not GRANT further (unless we add GRANT).
    let finance = root
        .delegate(
            KeyPath::parse("company/finance").unwrap(),
            PermissionSet::read_write().with(Permission::Grant),
        )
        .expect("delegate finance");

    let invoices = finance
        .delegate(
            KeyPath::parse("company/finance/invoices").unwrap(),
            PermissionSet::empty()
                .with(Permission::Read)
                .with(Permission::Write),
        )
        .expect("delegate invoices");

    db.put(
        "company/finance/invoices/001",
        b"Invoice #001 - $12_000",
        &invoices,
    )
    .expect("put invoice");

    let value = db
        .get("company/finance/invoices/001", &invoices)
        .expect("get invoice");
    println!("finance read OK: {}", String::from_utf8_lossy(&value));

    // HR capability cannot read finance branch (ACL).
    let hr = Capability::new(
        KeyPath::parse("company/hr").unwrap(),
        PermissionSet::read_write(),
    );
    match db.get("company/finance/invoices/001", &hr) {
        Err(e) => println!("hr blocked (expected): {e}"),
        Ok(_) => println!("BUG: hr should not read finance"),
    }

    // Parent finance scope can still read child path.
    let value = db
        .get("company/finance/invoices/001", &finance)
        .expect("finance parent get");
    println!(
        "finance parent read OK: {}",
        String::from_utf8_lossy(&value)
    );

    // Revoke the invoices node — crypto gate fails even with a valid capability.
    let path = KeyPath::parse("company/finance/invoices/001").unwrap();
    db.tree_mut().revoke(&path).expect("revoke");
    match db.get("company/finance/invoices/001", &finance) {
        Err(e) => println!("after revoke (expected): {e}"),
        Ok(_) => println!("BUG: revoked path still readable"),
    }
}
