//! Phase 5.8.2 — consumer group / member lifecycle.

use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{Error, GroupId, GroupState, MemberId, SessionId, StreamId};
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};

async fn setup_finance_stream(rt: &Runtime) -> (dmc_core::SessionId, dmc_core::SessionId, StreamId) {
    let admin = rt.admin_session().await.unwrap();
    rt.create_role(
        &admin,
        "finance".into(),
        "Finance".into(),
        KeyPath::parse("company/finance").unwrap(),
        PermissionSet::empty().with(Permission::Read),
    )
    .await
    .unwrap();
    rt.create_user(&admin, "alice".into(), vec!["finance".into()])
        .await
        .unwrap();
    rt.configure_channel(ChannelSpec::internal("bus"))
        .await
        .unwrap();
    let stream = rt
        .create_stream(StreamSpec {
            id: StreamId::from("finance-read"),
            direction: StreamDirection::Outbound,
            channel_id: "bus".into(),
            path_scope: KeyPath::parse("company/finance").unwrap(),
            required_perms: PermissionSet::empty().with(Permission::Read),
        })
        .await
        .unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    (admin, alice, stream)
}

async fn setup_hr_user(rt: &Runtime, admin: &dmc_core::SessionId) -> dmc_core::SessionId {
    rt.create_role(
        admin,
        "hr".into(),
        "HR".into(),
        KeyPath::parse("company/hr").unwrap(),
        PermissionSet::empty().with(Permission::Read),
    )
    .await
    .unwrap();
    rt.create_user(admin, "bob".into(), vec!["hr".into()])
        .await
        .unwrap();
    rt.open_user_session("bob", Some("dev-b")).await.unwrap()
}

#[tokio::test]
async fn create_group_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_admin, alice, stream) = setup_finance_stream(&rt).await;
    let subs_before = rt.list_subscriptions().await.len();
    let group = rt
        .create_group(&alice, GroupId::from("finance-workers"), &stream)
        .await
        .unwrap();
    assert_eq!(group.group_id.as_str(), "finance-workers");
    assert_eq!(group.stream_id, stream);
    assert_eq!(group.generation, 1);
    assert_eq!(group.state, GroupState::Empty);
    assert!(group.members.is_empty());
    assert_eq!(rt.list_subscriptions().await.len(), subs_before);
}

#[tokio::test]
async fn duplicate_group_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_admin, alice, stream) = setup_finance_stream(&rt).await;
    rt.create_group(&alice, GroupId::from("g1"), &stream)
        .await
        .unwrap();
    let err = rt
        .create_group(&alice, GroupId::from("g1"), &stream)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::GroupExists(_)));
}

#[tokio::test]
async fn join_member_appears_and_bumps_generation() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_admin, alice, stream) = setup_finance_stream(&rt).await;
    rt.create_group(&alice, GroupId::from("g1"), &stream)
        .await
        .unwrap();
    let member = rt
        .join_group(&alice, &GroupId::from("g1"), MemberId::from("A"), Some("dev-a"))
        .await
        .unwrap();
    assert_eq!(member.member_id.as_str(), "A");
    assert_eq!(member.generation_joined, 2);
    let desc = rt.describe_group(&alice, &GroupId::from("g1")).await.unwrap();
    assert_eq!(desc.generation, 2);
    assert_eq!(desc.members.len(), 1);
    assert_eq!(desc.state, GroupState::Stable);
}

#[tokio::test]
async fn duplicate_member_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_admin, alice, stream) = setup_finance_stream(&rt).await;
    rt.create_group(&alice, GroupId::from("g1"), &stream)
        .await
        .unwrap();
    rt.join_group(&alice, &GroupId::from("g1"), MemberId::from("A"), None)
        .await
        .unwrap();
    let err = rt
        .join_group(&alice, &GroupId::from("g1"), MemberId::from("A"), None)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::MemberExists(_)));
}

#[tokio::test]
async fn generation_on_join_and_leave() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_admin, alice, stream) = setup_finance_stream(&rt).await;
    let gid = GroupId::from("g1");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.generation, 3);
    rt.leave_group(&alice, &gid, &MemberId::from("A"))
        .await
        .unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.generation, 4);
    assert_eq!(desc.members.len(), 1);
    assert_eq!(desc.state, GroupState::Stable);
}

#[tokio::test]
async fn leave_last_member_sets_empty_state() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_admin, alice, stream) = setup_finance_stream(&rt).await;
    let gid = GroupId::from("g1");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    rt.leave_group(&alice, &gid, &MemberId::from("A"))
        .await
        .unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.state, GroupState::Empty);
    assert!(desc.members.is_empty());
}

#[tokio::test]
async fn describe_group_returns_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_admin, alice, stream) = setup_finance_stream(&rt).await;
    let gid = GroupId::from("workers");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("m1"), None)
        .await
        .unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.group_id, gid);
    assert_eq!(desc.stream_id, stream);
    assert_eq!(desc.members[0].member_id.as_str(), "m1");
    assert_eq!(desc.members[0].generation_joined, 2);
}

#[tokio::test]
async fn delete_empty_group_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_admin, alice, stream) = setup_finance_stream(&rt).await;
    let gid = GroupId::from("g1");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.delete_group(&alice, &gid).await.unwrap();
    let err = rt.describe_group(&alice, &gid).await.unwrap_err();
    assert!(matches!(err, Error::UnknownGroup(_)));
}

#[tokio::test]
async fn delete_non_empty_group_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_admin, alice, stream) = setup_finance_stream(&rt).await;
    let gid = GroupId::from("g1");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    let err = rt.delete_group(&alice, &gid).await.unwrap_err();
    assert!(matches!(err, Error::GroupNotEmpty(_)));
}

#[tokio::test]
async fn persistence_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (_admin, alice, stream) = setup_finance_stream(&rt).await;
        let gid = GroupId::from("persist-g");
        rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        (master, gid)
    };
    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a2")).await.unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.generation, 2);
    assert_eq!(desc.members.len(), 1);
}

#[tokio::test]
async fn generation_persistence_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, expected_gen) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (_admin, alice, stream) = setup_finance_stream(&rt).await;
        let gid = GroupId::from("gen-g");
        rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        rt.join_group(&alice, &gid, MemberId::from("B"), None)
            .await
            .unwrap();
        let expected_gen = rt.describe_group(&alice, &gid).await.unwrap().generation;
        (master, gid, expected_gen)
    };
    assert_eq!(expected_gen, 3);
    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a3")).await.unwrap();
    assert_eq!(
        rt.describe_group(&alice, &gid).await.unwrap().generation,
        expected_gen
    );
}

#[tokio::test]
async fn disabled_user_denied() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, _alice, stream) = setup_finance_stream(&rt).await;
    rt.disable_user(&admin, "alice").await.unwrap();
    let err = rt
        .open_user_session("alice", Some("dev-x"))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("disabled"),
        "expected disabled user error, got {err}"
    );
    let err = rt
        .create_group(
            &SessionId::from("00000000000000000000000000000000"),
            GroupId::from("g1"),
            &stream,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::UnknownSession(_)),
        "stale session must not operate on groups, got {err}"
    );
}

#[tokio::test]
async fn capability_wrong_scope_denied() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, _alice, stream) = setup_finance_stream(&rt).await;
    let bob = setup_hr_user(&rt, &admin).await;
    let err = rt
        .create_group(&bob, GroupId::from("g1"), &stream)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::AuthorizationDenied(_)));
}

#[tokio::test]
async fn group_does_not_expand_acl() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_stream(&rt).await;
    let _bob = setup_hr_user(&rt, &admin).await;
    rt.create_group(&alice, GroupId::from("finance-workers"), &stream)
        .await
        .unwrap();
    let bob = rt.open_user_session("bob", Some("dev-b2")).await.unwrap();
    let err = rt
        .join_group(&bob, &GroupId::from("finance-workers"), MemberId::from("B"), None)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::AuthorizationDenied(_)));
}

#[tokio::test]
async fn delete_recreate_starts_new_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_admin, alice, stream) = setup_finance_stream(&rt).await;
    let gid = GroupId::from("reuse");
    let first = rt
        .create_group(&alice, gid.clone(), &stream)
        .await
        .unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    rt.leave_group(&alice, &gid, &MemberId::from("A"))
        .await
        .unwrap();
    assert_eq!(rt.describe_group(&alice, &gid).await.unwrap().generation, 3);
    rt.delete_group(&alice, &gid).await.unwrap();
    let second = rt
        .create_group(&alice, gid.clone(), &stream)
        .await
        .unwrap();
    assert_ne!(first.instance_id, second.instance_id);
    assert_eq!(second.generation, 1);
    assert_eq!(second.state, GroupState::Empty);
}

#[tokio::test]
async fn restart_preserves_generation_after_leave() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (_admin, alice, stream) = setup_finance_stream(&rt).await;
        let gid = GroupId::from("leave-persist");
        rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        rt.leave_group(&alice, &gid, &MemberId::from("A"))
            .await
            .unwrap();
        rt.lock().await.unwrap();
        (master, gid)
    };
    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a4")).await.unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.generation, 3);
    assert_eq!(desc.state, GroupState::Empty);
}
