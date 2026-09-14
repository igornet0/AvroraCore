use dmc_core::runtime::Runtime;
use dmc_vault::key::KeyPath;
use dmc_vault::PermissionSet;

#[tokio::test]
async fn user_roles_session_snapshot_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let master = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
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
        rt.create_role(
            &admin,
            "hr".into(),
            "HR".into(),
            KeyPath::parse("company/hr").unwrap(),
            PermissionSet::empty().with(dmc_vault::Permission::Read),
        )
        .await
        .unwrap();
        rt.create_user(&admin, "alice".into(), vec!["finance".into()])
            .await
            .unwrap();
        let alice = rt.open_user_session("alice", Some("device-1")).await.unwrap();
        rt.put_data(&alice, "company/finance/inv/1", b"secret")
            .await
            .unwrap();
        assert!(rt
            .put_data(&alice, "company/hr/e/1", b"nope")
            .await
            .is_err());
        rt.assign_roles(&admin, "alice", vec!["finance".into(), "hr".into()])
            .await
            .unwrap();
        // Snapshot: still no HR write/read on the old session.
        assert!(rt.get_data(&alice, "company/hr/e/1").await.is_err());
        rt.force_snapshot().await.unwrap();
        master
    };

    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let users = rt.list_users().await.unwrap();
    assert!(users.iter().any(|u| u.id.as_str() == "alice"));
    let alice = rt.open_user_session("alice", Some("device-1")).await.unwrap();
    let got = rt.get_data(&alice, "company/finance/inv/1").await.unwrap();
    assert_eq!(got, b"secret");
}
