//! Phase 5.8.3 — consumer group member heartbeat + lease.

use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{
    Error, GroupId, GroupMember, GroupState, MemberId, SessionId, StreamId, DEFAULT_MEMBER_LEASE_MS,
};
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};

const BASE_NOW: u64 = 10_000;

async fn setup_finance_stream(rt: &Runtime) -> (SessionId, SessionId, StreamId) {
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

async fn setup_hr_user(rt: &Runtime, admin: &SessionId) -> SessionId {
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

async fn setup_group_with_member(rt: &Runtime) -> (SessionId, GroupId, GroupMember) {
    rt.set_now_ms(Some(BASE_NOW)).await;
    let (_admin, alice, stream) = setup_finance_stream(rt).await;
    let gid = GroupId::from("lease-g");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    let joined = rt
        .join_group(&alice, &gid, MemberId::from("A"), Some("dev-a"))
        .await
        .unwrap();
    (alice, gid, joined)
}

#[tokio::test]
async fn join_initializes_heartbeat_and_lease() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_alice, _gid, member) = setup_group_with_member(&rt).await;
    assert_eq!(member.last_heartbeat_at_ms, BASE_NOW);
    assert_eq!(
        member.lease_expires_at_ms,
        BASE_NOW + DEFAULT_MEMBER_LEASE_MS
    );
}

#[tokio::test]
async fn heartbeat_extends_lease_without_generation_bump() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (alice, gid, member) = setup_group_with_member(&rt).await;
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    let gen_before = rt.describe_group(&alice, &gid).await.unwrap().generation;
    assert_eq!(gen_before, 3);

    let hb_at = BASE_NOW + 15_000;
    rt.set_now_ms(Some(hb_at)).await;
    let updated = rt
        .heartbeat_group_member(&alice, &gid, &member.member_id)
        .await
        .unwrap();
    assert_eq!(updated.last_heartbeat_at_ms, hb_at);
    assert_eq!(
        updated.lease_expires_at_ms,
        hb_at + DEFAULT_MEMBER_LEASE_MS
    );
    assert_eq!(
        rt.describe_group(&alice, &gid).await.unwrap().generation,
        gen_before
    );
}

#[tokio::test]
async fn member_alive_before_lease_expires() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (alice, gid, _mid) = setup_group_with_member(&rt).await;
    let expires = BASE_NOW + DEFAULT_MEMBER_LEASE_MS;
    rt.set_now_ms(Some(expires - 1)).await;
    let result = rt.reconcile_group_leases().await.unwrap();
    assert!(result.expired_members.is_empty());
    assert_eq!(rt.describe_group(&alice, &gid).await.unwrap().members.len(), 1);
}

#[tokio::test]
async fn member_expires_at_lease_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (alice, gid, member) = setup_group_with_member(&rt).await;
    let expires = BASE_NOW + DEFAULT_MEMBER_LEASE_MS;
    rt.set_now_ms(Some(expires)).await;
    let result = rt.reconcile_group_leases().await.unwrap();
    assert_eq!(
        result.expired_members,
        vec![(gid.clone(), member.member_id)]
    );
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert!(desc.members.is_empty());
    assert_eq!(desc.generation, 3);
    assert_eq!(desc.state, GroupState::Empty);
}

#[tokio::test]
async fn expiration_removes_member_and_rebalances() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    rt.set_now_ms(Some(BASE_NOW)).await;
    let (_admin, alice, stream) = setup_finance_stream(&rt).await;
    let gid = GroupId::from("workers");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    let gen_before = rt.describe_group(&alice, &gid).await.unwrap().generation;
    rt.set_now_ms(Some(BASE_NOW + 1_000)).await;
    rt.heartbeat_group_member(&alice, &gid, &MemberId::from("A"))
        .await
        .unwrap();
    rt.set_now_ms(Some(BASE_NOW + DEFAULT_MEMBER_LEASE_MS)).await;
    rt.reconcile_group_leases().await.unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.members.len(), 1);
    assert_eq!(desc.members[0].member_id.as_str(), "A");
    assert_eq!(desc.generation, gen_before + 1);
    assert_eq!(desc.state, GroupState::Stable);
}

#[tokio::test]
async fn multiple_expirations_bump_generation_once() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    rt.set_now_ms(Some(BASE_NOW)).await;
    let (_admin, alice, stream) = setup_finance_stream(&rt).await;
    let gid = GroupId::from("multi-expire");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    rt.join_group(&alice, &gid, MemberId::from("C"), None)
        .await
        .unwrap();
    let gen_before = rt.describe_group(&alice, &gid).await.unwrap().generation;
    rt.set_now_ms(Some(BASE_NOW + 1_000)).await;
    rt.heartbeat_group_member(&alice, &gid, &MemberId::from("C"))
        .await
        .unwrap();
    rt.set_now_ms(Some(BASE_NOW + DEFAULT_MEMBER_LEASE_MS)).await;
    let result = rt.reconcile_group_leases().await.unwrap();
    assert_eq!(result.expired_members.len(), 2);
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.members.len(), 1);
    assert_eq!(desc.members[0].member_id.as_str(), "C");
    assert_eq!(desc.generation, gen_before + 1);
}

#[tokio::test]
async fn heartbeat_and_lease_persist_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, hb_at, lease_expires, generation) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (alice, gid, member) = setup_group_with_member(&rt).await;
        let hb_at = BASE_NOW + 5_000;
        rt.set_now_ms(Some(hb_at)).await;
        let updated = rt
            .heartbeat_group_member(&alice, &gid, &member.member_id)
            .await
            .unwrap();
        let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
        rt.lock().await.unwrap();
        (
            master,
            gid,
            hb_at,
            updated.lease_expires_at_ms,
            generation,
        )
    };
    let rt = Runtime::at_path(&path);
    rt.set_now_ms(Some(hb_at)).await;
    rt.unlock(&master).await.unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a2")).await.unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.generation, generation);
    assert_eq!(desc.members.len(), 1);
    assert_eq!(desc.members[0].lease_expires_at_ms, lease_expires);
}

#[tokio::test]
async fn expired_member_removed_on_unlock_reconcile() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (alice, gid, _mid) = setup_group_with_member(&rt).await;
        assert_eq!(rt.describe_group(&alice, &gid).await.unwrap().members.len(), 1);
        rt.lock().await.unwrap();
        (master, gid)
    };
    let rt = Runtime::at_path(&path);
    rt.set_now_ms(Some(BASE_NOW + DEFAULT_MEMBER_LEASE_MS)).await;
    rt.unlock(&master).await.unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a3")).await.unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert!(desc.members.is_empty());
    assert_eq!(desc.generation, 3);
}

#[tokio::test]
async fn heartbeat_stale_generation_joined_still_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (alice, gid, member) = setup_group_with_member(&rt).await;
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    let member_a = rt
        .describe_group(&alice, &gid)
        .await
        .unwrap()
        .members
        .into_iter()
        .find(|m| m.member_id.as_str() == "A")
        .unwrap();
    assert_eq!(member_a.generation_joined, 2);
    assert_eq!(rt.describe_group(&alice, &gid).await.unwrap().generation, 3);
    rt.set_now_ms(Some(BASE_NOW + 1_000)).await;
    rt.heartbeat_group_member(&alice, &gid, &member.member_id)
        .await
        .unwrap();
}

#[tokio::test]
async fn wrong_user_cannot_heartbeat_member() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_stream(&rt).await;
    let bob = setup_hr_user(&rt, &admin).await;
    let gid = GroupId::from("g1");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    let err = rt
        .heartbeat_group_member(&bob, &gid, &MemberId::from("A"))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::AuthorizationDenied(_)));
}

#[tokio::test]
async fn disabled_user_cannot_heartbeat() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, gid, mid) = {
        let (admin, alice, stream) = setup_finance_stream(&rt).await;
        let gid = GroupId::from("g1");
        rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
        let mid = MemberId::from("A");
        rt.join_group(&alice, &gid, mid.clone(), None)
            .await
            .unwrap();
        (admin, alice, gid, mid)
    };
    rt.disable_user(&admin, "alice").await.unwrap();
    let err = rt
        .heartbeat_group_member(&alice, &gid, &mid)
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::UnknownSession(_)),
        "disabled session must not heartbeat, got {err}"
    );
}

#[tokio::test]
async fn expiration_is_audited() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_alice, gid, _mid) = setup_group_with_member(&rt).await;
    rt.set_now_ms(Some(BASE_NOW + DEFAULT_MEMBER_LEASE_MS))
        .await;
    rt.reconcile_group_leases().await.unwrap();
    let audit = rt.audit_log().await;
    assert!(audit
        .iter()
        .any(|r| r.op == "GROUP_MEMBER_EXPIRED" && r.path.contains(gid.as_str())));
}
