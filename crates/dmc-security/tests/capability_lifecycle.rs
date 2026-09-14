//! Phase 2.2 capability lifecycle.

use dmc_security::{
    AccessControl, CapabilityId, Permission, PermissionSet, UserId,
};
use dmc_vault::key::KeyPath;

fn seed_finance_hr(ac: &mut AccessControl) {
    ac.roles_mut().seed_role(
        "finance",
        "Finance",
        KeyPath::parse("company/finance").unwrap(),
        PermissionSet::read_write().with(Permission::Grant),
    );
    ac.roles_mut().seed_role(
        "hr",
        "HR",
        KeyPath::parse("company/hr").unwrap(),
        PermissionSet::empty().with(Permission::Read),
    );
}

#[test]
fn grant_subset_scope_and_permissions() {
    let mut ac = AccessControl::empty();
    seed_finance_hr(&mut ac);
    ac.create_user("alice".into(), vec!["finance".into()]).unwrap();
    ac.create_user("bob".into(), vec![]).unwrap();
    let alice = ac.open_user_session("alice", Some("alice-device")).unwrap();

    let issued = ac
        .grant(
            &alice,
            "bob",
            KeyPath::parse("company/finance/invoices").unwrap(),
            PermissionSet::empty()
                .with(Permission::Read)
                .with(Permission::Write),
            None,
        )
        .unwrap();
    assert_eq!(issued.issuer, UserId::from("alice"));
    assert_eq!(issued.subject, UserId::from("bob"));
    assert!(issued.id.as_str().starts_with("cap_"));
    assert_ne!(issued.id.as_str(), "company/finance/invoices");

    let bob = ac.open_user_session("bob", Some("bob-device")).unwrap();
    ac.authorize(
        &bob,
        &KeyPath::parse("company/finance/invoices/1").unwrap(),
        Permission::Write,
    )
    .unwrap();

    let granted = ac
        .audit()
        .list()
        .iter()
        .find(|e| e.operation == dmc_security::AuditOperation::CapabilityGranted)
        .expect("grant is a security audit event");
    assert!(granted.event_id.is_none());
    assert!(granted.sequence.is_none());
    assert_eq!(granted.capability_id.as_ref(), Some(&issued.id));
}

#[test]
fn invalid_delegation_scope_is_denied() {
    let mut ac = AccessControl::empty();
    seed_finance_hr(&mut ac);
    ac.create_user("alice".into(), vec!["finance".into()]).unwrap();
    ac.create_user("bob".into(), vec![]).unwrap();
    let alice = ac.open_user_session("alice", None).unwrap();
    let err = ac
        .grant(
            &alice,
            "bob",
            KeyPath::parse("company/hr").unwrap(),
            PermissionSet::empty().with(Permission::Read),
            None,
        )
        .unwrap_err();
    assert!(err.to_string().contains("delegation denied"));
}

#[test]
fn permission_escalation_is_denied() {
    let mut ac = AccessControl::empty();
    ac.roles_mut().seed_role(
        "reader",
        "Reader",
        KeyPath::parse("company/finance").unwrap(),
        PermissionSet::empty()
            .with(Permission::Read)
            .with(Permission::Grant),
    );
    ac.create_user("alice".into(), vec!["reader".into()]).unwrap();
    ac.create_user("bob".into(), vec![]).unwrap();
    let alice = ac.open_user_session("alice", None).unwrap();
    let err = ac
        .grant(
            &alice,
            "bob",
            KeyPath::parse("company/finance").unwrap(),
            PermissionSet::empty()
                .with(Permission::Read)
                .with(Permission::Write),
            None,
        )
        .unwrap_err();
    assert!(err.to_string().contains("delegation denied"));
}

#[test]
fn expired_capability_denies_authorize() {
    let mut ac = AccessControl::empty();
    seed_finance_hr(&mut ac);
    ac.set_clock_ms(Some(1_000_000));
    ac.create_user("alice".into(), vec!["finance".into()]).unwrap();
    ac.create_user("bob".into(), vec![]).unwrap();
    let alice = ac.open_user_session("alice", None).unwrap();
    ac.grant(
        &alice,
        "bob",
        KeyPath::parse("company/finance").unwrap(),
        PermissionSet::empty().with(Permission::Read),
        Some(1_000),
    )
    .unwrap();
    let bob = ac.open_user_session("bob", None).unwrap();
    ac.authorize(
        &bob,
        &KeyPath::parse("company/finance/x").unwrap(),
        Permission::Read,
    )
    .unwrap();

    ac.set_clock_ms(Some(1_002_000));
    let err = ac
        .authorize(
            &bob,
            &KeyPath::parse("company/finance/x").unwrap(),
            Permission::Read,
        )
        .unwrap_err();
    assert!(err.to_string().contains("expired"));
    assert!(ac.session(&bob).is_ok(), "session TTL is independent");
}

#[test]
fn revoke_capability_denies_existing_session_without_closing_it() {
    let mut ac = AccessControl::empty();
    seed_finance_hr(&mut ac);
    ac.create_user("alice".into(), vec!["finance".into()]).unwrap();
    let alice = ac.open_user_session("alice", None).unwrap();
    let cap_id = ac
        .session(&alice)
        .unwrap()
        .capabilities
        .refs()
        .first()
        .unwrap()
        .capability_id
        .clone();

    ac.authorize(
        &alice,
        &KeyPath::parse("company/finance/inv/1").unwrap(),
        Permission::Read,
    )
    .unwrap();
    ac.revoke_capability(&cap_id).unwrap();
    assert!(ac.session(&alice).is_ok());
    let err = ac
        .authorize(
            &alice,
            &KeyPath::parse("company/finance/inv/1").unwrap(),
            Permission::Read,
        )
        .unwrap_err();
    assert!(err.to_string().contains("revoked"));
}

#[test]
fn session_isolation_revoke_does_not_affect_other_user() {
    let mut ac = AccessControl::empty();
    seed_finance_hr(&mut ac);
    ac.create_user("alice".into(), vec!["finance".into()]).unwrap();
    ac.create_user("bob".into(), vec!["finance".into()]).unwrap();
    let alice = ac.open_user_session("alice", None).unwrap();
    let bob = ac.open_user_session("bob", None).unwrap();
    let alice_cap = ac
        .session(&alice)
        .unwrap()
        .capabilities
        .refs()
        .first()
        .unwrap()
        .capability_id
        .clone();

    ac.revoke_capability(&alice_cap).unwrap();
    assert!(ac
        .authorize(
            &alice,
            &KeyPath::parse("company/finance/x").unwrap(),
            Permission::Read
        )
        .is_err());
    ac.authorize(
        &bob,
        &KeyPath::parse("company/finance/x").unwrap(),
        Permission::Read,
    )
    .unwrap();
}

#[test]
fn disable_user_still_revokes_sessions() {
    let mut ac = AccessControl::empty();
    seed_finance_hr(&mut ac);
    ac.create_user("bob".into(), vec!["finance".into()]).unwrap();
    let sid = ac.open_user_session("bob", None).unwrap();
    ac.disable_user("bob").unwrap();
    assert!(ac.session(&sid).is_err());
    assert!(ac.open_user_session("bob", None).is_err());
}

#[test]
fn capability_id_is_not_scope_plus_permissions() {
    let mut ac = AccessControl::empty();
    seed_finance_hr(&mut ac);
    ac.create_user("alice".into(), vec!["finance".into()]).unwrap();
    let caps: Vec<CapabilityId> = ac
        .list_issued()
        .into_iter()
        .filter(|c| c.subject.as_str() == "alice")
        .map(|c| c.id)
        .collect();
    assert_eq!(caps.len(), 1);
    assert!(caps[0].as_str().starts_with("cap_"));
    assert!(!caps[0].as_str().contains("finance"));
}
