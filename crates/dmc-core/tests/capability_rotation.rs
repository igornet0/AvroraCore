use dmc_core::runtime::Runtime;
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};

#[tokio::test]
async fn runtime_rotate_changes_user_capabilities() {
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
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    rt.put_data(&alice, "company/finance/inv/1", b"secret")
        .await
        .unwrap();

    let before = rt
        .list_capabilities()
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.subject.as_str() == "alice")
        .unwrap();

    let report = rt.rotate_all_user_capabilities().await.unwrap();
    assert_eq!(report.rotated_users, 1);
    assert!(report.rotated_capabilities >= 1);

    let after = rt
        .list_capabilities()
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.subject.as_str() == "alice" && c.status == dmc_core::CapabilityStatus::Active)
        .unwrap();
    assert_ne!(after.id, before.id);

    assert!(rt.get_data(&alice, "company/finance/inv/1").await.is_err());
    let alice2 = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    let got = rt.get_data(&alice2, "company/finance/inv/1").await.unwrap();
    assert_eq!(got, b"secret");

    let audit = rt.audit_log().await;
    assert!(audit.iter().any(|r| r.op == "CAPABILITY_ROTATED"));
}

#[tokio::test]
async fn runtime_rotate_requires_unlocked() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let rt = Runtime::at_path(&path);
    assert!(rt.rotate_all_user_capabilities().await.is_err());
}
