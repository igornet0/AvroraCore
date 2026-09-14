//! Scheduled-style reissue of user capabilities.

use dmc_security::{
    AccessControl, AuditOperation, Permission, PermissionSet, UserId,
};
use dmc_vault::key::KeyPath;

fn seed_finance(ac: &mut AccessControl) {
    ac.roles_mut().seed_role(
        "finance",
        "Finance",
        KeyPath::parse("company/finance").unwrap(),
        PermissionSet::read_write().with(Permission::Grant),
    );
}

#[test]
fn rotate_reissues_role_caps_and_revokes_sessions() {
    let mut ac = AccessControl::empty();
    seed_finance(&mut ac);
    ac.create_user("alice".into(), vec!["finance".into()]).unwrap();
    let alice = ac.open_user_session("alice", Some("dev-a")).unwrap();
    let before = ac
        .list_issued()
        .into_iter()
        .find(|c| c.subject.as_str() == "alice")
        .unwrap();

    let report = ac.rotate_all_user_capabilities().unwrap();
    assert_eq!(report.rotated_users, 1);
    assert!(report.rotated_capabilities >= 1);
    assert!(ac.session(&alice).is_err());

    let after = ac
        .list_issued()
        .into_iter()
        .find(|c| c.subject.as_str() == "alice" && c.is_live(u64::MAX))
        .unwrap();
    assert_ne!(after.id, before.id);
    assert_eq!(after.source_role.as_deref(), Some("finance"));
    assert_eq!(before.status, dmc_security::CapabilityStatus::Active);
    let revoked = ac.issued(&before.id).unwrap();
    assert_eq!(revoked.status, dmc_security::CapabilityStatus::Revoked);
    assert!(revoked.generation > before.generation);

    let root = ac.issued(&dmc_security::CapabilityId::from("cap_root")).unwrap();
    assert_eq!(root.status, dmc_security::CapabilityStatus::Active);

    assert!(ac
        .audit()
        .list()
        .iter()
        .any(|e| e.operation == AuditOperation::CapabilityRotated));
}

#[test]
fn rotate_reissues_direct_grants_with_same_scope() {
    let mut ac = AccessControl::empty();
    seed_finance(&mut ac);
    ac.create_user("alice".into(), vec!["finance".into()]).unwrap();
    ac.create_user("bob".into(), vec![]).unwrap();
    let alice = ac.open_user_session("alice", None).unwrap();
    let granted = ac
        .grant(
            &alice,
            "bob",
            KeyPath::parse("company/finance/invoices").unwrap(),
            PermissionSet::empty().with(Permission::Read),
            Some(60_000),
        )
        .unwrap();
    assert_eq!(granted.issuer, UserId::from("alice"));

    ac.rotate_all_user_capabilities().unwrap();

    let live: Vec<_> = ac
        .list_issued()
        .into_iter()
        .filter(|c| c.subject.as_str() == "bob" && c.status == dmc_security::CapabilityStatus::Active)
        .collect();
    assert_eq!(live.len(), 1);
    assert_ne!(live[0].id, granted.id);
    assert_eq!(live[0].scope, granted.scope);
    assert_eq!(live[0].permissions, granted.permissions);
    assert_eq!(live[0].expires_at, granted.expires_at);
    assert!(ac.issued(&granted.id).unwrap().status == dmc_security::CapabilityStatus::Revoked);
}

#[test]
fn rotate_skips_root_only() {
    let mut ac = AccessControl::empty();
    let report = ac.rotate_all_user_capabilities().unwrap();
    assert_eq!(report.rotated_users, 0);
    assert_eq!(report.rotated_capabilities, 0);
    assert_eq!(
        ac.issued(&dmc_security::CapabilityId::from("cap_root"))
            .unwrap()
            .status,
        dmc_security::CapabilityStatus::Active
    );
}
