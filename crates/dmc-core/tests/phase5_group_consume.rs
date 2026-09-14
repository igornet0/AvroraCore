//! Phase 5.8.5 — group_consume + durable GroupPendingDelivery (no ACK / no offset advance).

use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{
    Error, GroupId, GroupPolicy, GroupStartPosition, GroupState, MemberId, SessionId, StreamId,
    DEFAULT_MEMBER_LEASE_MS,
};
use dmc_journal::partition::resolve_partition;
use dmc_journal::set_test_partition_count;
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};

struct PartitionGuard;
impl Drop for PartitionGuard {
    fn drop(&mut self) {
        set_test_partition_count(None);
    }
}

fn with_partitions(n: u32) -> PartitionGuard {
    set_test_partition_count(Some(n));
    PartitionGuard
}

fn path_for_partition(prefix: &str, target: u32, parts: u32) -> String {
    for i in 0..20_000 {
        let path = format!("{prefix}/route-{i}");
        let kp = KeyPath::parse(&path).unwrap();
        if resolve_partition(&kp, None, parts).unwrap().as_u32() == target {
            return path;
        }
    }
    panic!("no path for partition {target} under {prefix}");
}

async fn setup_finance(rt: &Runtime) -> (SessionId, SessionId, StreamId) {
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

async fn setup_hr(rt: &Runtime, admin: &SessionId) -> SessionId {
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
async fn basic_group_consume_returns_event() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("g1");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
    rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
        .await
        .unwrap();

    let offsets_before = rt.describe_group(&alice, &gid).await.unwrap().offsets;
    let delivered = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("expected event");
    assert_eq!(delivered.partition_id, 0);
    assert_eq!(delivered.delivery.attempt, 1);
    assert_eq!(delivered.delivery.generation, generation);
    assert_eq!(delivered.delivery.member_id.as_str(), "A");
    let offsets_after = rt.describe_group(&alice, &gid).await.unwrap().offsets;
    assert_eq!(offsets_after, offsets_before, "consume must not advance GroupOffset");
}

#[tokio::test]
async fn pending_redelivers_same_sequence() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    rt.set_now_ms(Some(10_000)).await;
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("g1");
    rt.create_group_with_policy(
        &alice,
        gid.clone(),
        &stream,
        GroupPolicy {
            retry: dmc_core::GroupRetryPolicy {
                max_attempts: 5,
                backoff_ms: vec![0, 0, 0, 0, 0],
            },
            ..Default::default()
        },
    )
    .await
    .unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
    rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
        .await
        .unwrap();

    let d1 = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .unwrap();
    rt.group_retry(
        &alice,
        &gid,
        &MemberId::from("A"),
        generation,
        &d1.delivery.delivery_id,
    )
    .await
    .unwrap();
    let d2 = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(d1.sequence, d2.sequence);
    assert_eq!(d1.event_id, d2.event_id);
    assert_ne!(d1.delivery.delivery_id, d2.delivery.delivery_id);
    assert_eq!(d2.delivery.attempt, 2);
}

#[tokio::test]
async fn crash_restart_redelivers_pending() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation, seq, event_id, attempt) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("persist-pending");
        rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
        rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
            .await
            .unwrap();
        let d1 = rt
            .group_consume(&alice, &gid, &MemberId::from("A"), generation)
            .await
            .unwrap()
            .unwrap();
        rt.lock().await.unwrap();
        (
            master,
            gid,
            generation,
            d1.sequence,
            d1.event_id,
            d1.delivery.attempt,
        )
    };
    let rt = Runtime::at_path(&path);
    set_test_partition_count(Some(1));
    rt.unlock(&master).await.unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a2")).await.unwrap();
    let d2 = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(d2.sequence, seq);
    assert_eq!(d2.event_id, event_id);
    assert_eq!(d2.delivery.attempt, attempt + 1);
}

#[tokio::test]
async fn member_b_does_not_see_partition_owned_by_a() {
    let _g = with_partitions(2);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("workers");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    let generation = desc.generation;
    let a_parts: Vec<_> = desc
        .members
        .iter()
        .find(|m| m.member_id.as_str() == "A")
        .unwrap()
        .partitions
        .clone();
    let b_parts: Vec<_> = desc
        .members
        .iter()
        .find(|m| m.member_id.as_str() == "B")
        .unwrap()
        .partitions
        .clone();
    assert_eq!(a_parts, vec![0]);
    assert_eq!(b_parts, vec![1]);

    let p0 = path_for_partition("company/finance", 0, 2);
    rt.put_data(&admin, &p0, br#"{"p":0}"#).await.unwrap();

    let a_got = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("A owns P0");
    assert_eq!(a_got.partition_id, 0);

    let b_got = rt
        .group_consume(&alice, &gid, &MemberId::from("B"), generation)
        .await
        .unwrap();
    assert!(b_got.is_none(), "B must not see P0 events");
}

#[tokio::test]
async fn lowest_assigned_partition_skipped_when_empty() {
    let _g = with_partitions(2);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("iso");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;

    let p1 = path_for_partition("company/finance", 1, 2);
    rt.put_data(&admin, &p1, br#"{"p":1}"#).await.unwrap();

    let got = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.partition_id, 1);
}

#[tokio::test]
async fn stale_generation_rejected() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("g1");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    let old_generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    let err = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), old_generation)
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::StaleGeneration { .. }),
        "expected StaleGeneration, got {err}"
    );
}

#[tokio::test]
async fn capability_denied_before_history() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let bob = setup_hr(&rt, &admin).await;
    let gid = GroupId::from("finance-workers");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
    let err = rt
        .group_consume(&bob, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::AuthorizationDenied(_)),
        "expected AuthorizationDenied, got {err}"
    );
}

#[tokio::test]
async fn unknown_member_rejected() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("g1");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
    let err = rt
        .group_consume(&alice, &gid, &MemberId::from("Z"), generation)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::UnknownMember(_)));
}

#[tokio::test]
async fn consume_does_not_change_generation_or_offsets() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("g1");
    rt.create_group_with_policy(
        &alice,
        gid.clone(),
        &stream,
        GroupPolicy {
            start_position: GroupStartPosition::Earliest,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    let before = rt.describe_group(&alice, &gid).await.unwrap();
    rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
        .await
        .unwrap();
    let _ = rt
        .group_consume(
            &alice,
            &gid,
            &MemberId::from("A"),
            before.generation,
        )
        .await
        .unwrap();
    let after = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(after.generation, before.generation);
    assert_eq!(after.state, GroupState::Stable);
    let before_seqs: Vec<_> = before.offsets.iter().map(|o| o.sequence).collect();
    let after_seqs: Vec<_> = after.offsets.iter().map(|o| o.sequence).collect();
    assert_eq!(after_seqs, before_seqs);
}
