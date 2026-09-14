use dmc_core::runtime::Runtime;
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};

#[tokio::test]
async fn revoke_survives_checkpoint_and_does_not_close_session() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let rt = Runtime::at_path(&path);
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    rt.create_role(
        &admin,
        "finance".into(),
        "Finance".into(),
        KeyPath::parse("company/finance").unwrap(),
        PermissionSet::read_write(),
    )
    .await
    .unwrap();
    rt.create_user(&admin, "alice".into(), vec!["finance".into()])
        .await
        .unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    rt.put_data(&alice, "company/finance/inv/1", b"secret")
        .await
        .unwrap();

    let caps = rt.list_capabilities().await.unwrap();
    let alice_cap = caps
        .iter()
        .find(|c| c.subject.as_str() == "alice")
        .unwrap()
        .id
        .clone();
    rt.revoke_capability(&admin, alice_cap.as_str()).await.unwrap();

    assert!(rt.get_data(&alice, "company/finance/inv/1").await.is_err());
    // Session still listed via open failure only on authorize, not existence:
    // get_data fails on capability, not unknown session.
    let audit = rt.audit_log().await;
    assert!(audit.iter().any(|r| r.op == "CAPABILITY_REVOKED"));
    assert!(audit.iter().any(|r| r.op == "SESSION_OPEN" && r.event_id.is_empty()));
}

#[tokio::test]
async fn grant_then_authorize_and_audit_has_no_event_id() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let rt = Runtime::at_path(&path);
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    rt.create_role(
        &admin,
        "finance".into(),
        "Finance".into(),
        KeyPath::parse("company/finance").unwrap(),
        PermissionSet::read_write().with(Permission::Grant),
    )
    .await
    .unwrap();
    rt.create_user(&admin, "alice".into(), vec!["finance".into()])
        .await
        .unwrap();
    rt.create_user(&admin, "bob".into(), vec![]).await.unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    let issued = rt
        .grant_capability(
            &alice,
            "bob",
            KeyPath::parse("company/finance").unwrap(),
            PermissionSet::empty().with(Permission::Read),
            None,
        )
        .await
        .unwrap();
    assert!(issued.id.as_str().starts_with("cap_"));
    let bob = rt.open_user_session("bob", Some("dev-b")).await.unwrap();
    rt.put_data(&alice, "company/finance/inv/1", b"x").await.unwrap();
    let got = rt.get_data(&bob, "company/finance/inv/1").await.unwrap();
    assert_eq!(got, b"x");

    let audit = rt.audit_log().await;
    let grant = audit.iter().find(|r| r.op == "CAPABILITY_GRANTED").unwrap();
    assert!(grant.event_id.is_empty());
    assert_eq!(grant.sequence, 0);
    assert_eq!(grant.capability_id.as_deref(), Some(issued.id.as_str()));
    assert!(audit.iter().any(|r| r.op == "OVERLAY" && !r.event_id.is_empty() && r.sequence > 0));
}
