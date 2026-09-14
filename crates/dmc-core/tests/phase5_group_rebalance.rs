//! Phase 5.8.8 — rebalance + generation fencing (no retry/DLQ).

use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{
    assign_partitions, Error, GroupId, GroupPolicy, GroupStartPosition, GroupState, MemberId,
    SessionId, StreamId, DEFAULT_MEMBER_LEASE_MS,
};
use dmc_journal::partition::resolve_partition;
use dmc_journal::set_test_partition_count;
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};

const BASE_NOW: u64 = 10_000;

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

fn multi_flight_policy() -> GroupPolicy {
    GroupPolicy {
        max_in_flight: 8,
        ..Default::default()
    }
}

fn owners(desc: &dmc_core::GroupDescription) -> Vec<(u32, String)> {
    desc.assignments
        .iter()
        .map(|a| (a.partition_id, a.member_id.as_str().to_string()))
        .collect()
}

async fn offset_of(rt: &Runtime, session: &SessionId, gid: &GroupId, pid: u32) -> u64 {
    rt.describe_group(session, gid)
        .await
        .unwrap()
        .offsets
        .iter()
        .find(|o| o.partition_id == pid)
        .map(|o| o.sequence)
        .unwrap_or(0)
}

#[test]
fn assign_four_partitions_three_members_is_deterministic() {
    let a = assign_partitions(
        &[0, 1, 2, 3],
        &[MemberId::from("A"), MemberId::from("B"), MemberId::from("C")],
    );
    assert_eq!(
        a,
        assign_partitions(
            &[3, 1, 0, 2],
            &[MemberId::from("C"), MemberId::from("A"), MemberId::from("B")],
        )
    );
    assert_eq!(a.get(&0).unwrap().as_str(), "A");
    assert_eq!(a.get(&1).unwrap().as_str(), "B");
    assert_eq!(a.get(&2).unwrap().as_str(), "C");
    assert_eq!(a.get(&3).unwrap().as_str(), "A");
}

#[tokio::test]
async fn join_sequence_rebalances_and_bumps_generation() {
    let _g = with_partitions(4);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("rb-join");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    assert_eq!(
        owners(&rt.describe_group(&alice, &gid).await.unwrap()),
        vec![(0, "A".into()), (1, "A".into()), (2, "A".into()), (3, "A".into())]
    );
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.generation, 3);
    assert_eq!(
        owners(&desc),
        vec![(0, "A".into()), (1, "B".into()), (2, "A".into()), (3, "B".into())]
    );
    rt.join_group(&alice, &gid, MemberId::from("C"), None)
        .await
        .unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.generation, 4);
    assert_eq!(
        owners(&desc),
        vec![
            (0, "A".into()),
            (1, "B".into()),
            (2, "C".into()),
            (3, "A".into())
        ]
    );
}

#[tokio::test]
async fn leave_reassigns_all_partitions_to_survivor() {
    let _g = with_partitions(3);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("rb-leave");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    rt.leave_group(&alice, &gid, &MemberId::from("A"))
        .await
        .unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.generation, 4);
    assert_eq!(
        owners(&desc),
        vec![(0, "B".into()), (1, "B".into()), (2, "B".into())]
    );
}

#[tokio::test]
async fn expiry_bumps_generation_once_and_rebalances() {
    let _g = with_partitions(2);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    rt.set_now_ms(Some(BASE_NOW)).await;
    let (_admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("rb-expire");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    let gen_before = rt.describe_group(&alice, &gid).await.unwrap().generation;
    rt.set_now_ms(Some(BASE_NOW + DEFAULT_MEMBER_LEASE_MS))
        .await;
    let result = rt.reconcile_group_leases().await.unwrap();
    assert_eq!(result.expired_members.len(), 2);
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.generation, gen_before + 1);
    assert_eq!(desc.state, GroupState::Empty);
    assert!(desc.assignments.is_empty());
}

#[tokio::test]
async fn pending_survives_rebalance_and_offset_unchanged() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("rb-pending");
    rt.create_group_with_policy(&alice, gid.clone(), &stream, multi_flight_policy())
        .await
        .unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    let offset_before = offset_of(&rt, &alice, &gid, 0).await;
    rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
        .await
        .unwrap();
    rt.put_data(&admin, "company/finance/tx/2", br#"{"v":2}"#)
        .await
        .unwrap();
    let gen_a = rt.describe_group(&alice, &gid).await.unwrap().generation;
    let _ = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), gen_a)
        .await
        .unwrap();
    let _ = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), gen_a)
        .await
        .unwrap();
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, offset_before);
}

#[tokio::test]
async fn new_owner_redelivers_pending_after_leave() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("rb-handoff");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
        .await
        .unwrap();
    let gen_a = rt.describe_group(&alice, &gid).await.unwrap().generation;
    let d1 = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), gen_a)
        .await
        .unwrap()
        .expect("event");
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    rt.leave_group(&alice, &gid, &MemberId::from("A"))
        .await
        .unwrap();
    let gen_b = rt.describe_group(&alice, &gid).await.unwrap().generation;
    let d2 = rt
        .group_consume(&alice, &gid, &MemberId::from("B"), gen_b)
        .await
        .unwrap()
        .expect("redelivery");
    assert_eq!(d2.sequence, d1.sequence);
    assert_eq!(d2.event_id, d1.event_id);
    assert_ne!(d2.delivery.delivery_id, d1.delivery.delivery_id);
    assert_eq!(d2.delivery.generation, gen_b);
    assert!(d2.delivery.attempt >= 2);
}

#[tokio::test]
async fn expiry_pending_redelivered_by_survivor() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    rt.set_now_ms(Some(BASE_NOW)).await;
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("rb-expire-pending");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
        .await
        .unwrap();
    let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
    let d1 = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("A event on P0");
    assert_eq!(d1.partition_id, 0);
    rt.set_now_ms(Some(BASE_NOW + 1_000)).await;
    rt.heartbeat_group_member(&alice, &gid, &MemberId::from("B"))
        .await
        .unwrap();
    rt.set_now_ms(Some(BASE_NOW + DEFAULT_MEMBER_LEASE_MS))
        .await;
    rt.reconcile_group_leases().await.unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.members.len(), 1);
    assert_eq!(desc.members[0].member_id.as_str(), "B");
    let gen_b = desc.generation;
    let d2 = rt
        .group_consume(&alice, &gid, &MemberId::from("B"), gen_b)
        .await
        .unwrap()
        .expect("B inherits pending");
    assert_eq!(d2.sequence, d1.sequence);
    assert_ne!(d2.delivery.delivery_id, d1.delivery.delivery_id);
    assert_eq!(d2.delivery.generation, gen_b);
}

#[tokio::test]
async fn old_generation_cannot_consume_after_rebalance() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("rb-consume-gen");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    let old_gen = rt.describe_group(&alice, &gid).await.unwrap().generation;
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    let err = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), old_gen)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::StaleGeneration { .. }), "got {err}");
}

#[tokio::test]
async fn old_generation_cannot_ack_after_rebalance() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("rb-ack-gen");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    let old_gen = rt.describe_group(&alice, &gid).await.unwrap().generation;
    rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
        .await
        .unwrap();
    let d = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), old_gen)
        .await
        .unwrap()
        .expect("event");
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    let err = rt
        .group_ack(
            &alice,
            &gid,
            &MemberId::from("A"),
            old_gen,
            &d.delivery.delivery_id,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::StaleGeneration { .. }), "got {err}");
}

#[tokio::test]
async fn fenced_delivery_cannot_ack_after_new_owner_redelivery() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("rb-fenced-ack");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
        .await
        .unwrap();
    let gen_a = rt.describe_group(&alice, &gid).await.unwrap().generation;
    let d1 = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), gen_a)
        .await
        .unwrap()
        .expect("event");
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    rt.leave_group(&alice, &gid, &MemberId::from("A"))
        .await
        .unwrap();
    let gen_b = rt.describe_group(&alice, &gid).await.unwrap().generation;
    let _ = rt
        .group_consume(&alice, &gid, &MemberId::from("B"), gen_b)
        .await
        .unwrap()
        .expect("redelivery");
    let err = rt
        .group_ack(
            &alice,
            &gid,
            &MemberId::from("B"),
            gen_b,
            &d1.delivery.delivery_id,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::StaleDelivery(_)), "got {err}");
}

#[tokio::test]
async fn wrong_member_cannot_ack_foreign_partition() {
    let _g = with_partitions(2);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("rb-not-assigned");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    rt.put_data(
        &admin,
        &path_for_partition("company/finance", 0, 2),
        br#"{"v":1}"#,
    )
        .await
        .unwrap();
    let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
    let d = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("A on P0");
    assert_eq!(d.partition_id, 0);
    let err = rt
        .group_ack(
            &alice,
            &gid,
            &MemberId::from("B"),
            generation,
            &d.delivery.delivery_id,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NotAssigned { .. }), "got {err}");
}

#[tokio::test]
async fn heartbeat_does_not_bump_generation() {
    let _g = with_partitions(2);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    rt.set_now_ms(Some(BASE_NOW)).await;
    let (_admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("rb-heartbeat");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    let gen_before = rt.describe_group(&alice, &gid).await.unwrap().generation;
    let owners_before = owners(&rt.describe_group(&alice, &gid).await.unwrap());
    rt.heartbeat_group_member(&alice, &gid, &MemberId::from("A"))
        .await
        .unwrap();
    rt.set_now_ms(Some(BASE_NOW + 1_000)).await;
    rt.heartbeat_group_member(&alice, &gid, &MemberId::from("A"))
        .await
        .unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.generation, gen_before);
    assert_eq!(owners(&desc), owners_before);
}

#[tokio::test]
async fn former_owner_cannot_consume_after_leave() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("rb-left-consume");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    rt.leave_group(&alice, &gid, &MemberId::from("A"))
        .await
        .unwrap();
    let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
    let err = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::UnknownMember(_)), "got {err}");
}

#[tokio::test]
async fn offset_never_decreases_after_rebalance() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("rb-offset-monotonic");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
        .await
        .unwrap();
    let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
    let d = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("event");
    rt.group_ack(
        &alice,
        &gid,
        &MemberId::from("A"),
        generation,
        &d.delivery.delivery_id,
    )
    .await
    .unwrap();
    let offset_after_ack = offset_of(&rt, &alice, &gid, 0).await;
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    rt.leave_group(&alice, &gid, &MemberId::from("A"))
        .await
        .unwrap();
    assert!(offset_of(&rt, &alice, &gid, 0).await >= offset_after_ack);
}

#[tokio::test]
async fn rebalance_persists_across_restart() {
    let _g = with_partitions(3);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation, expected_owners, offsets) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (_admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("rb-persist");
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
        let desc = rt.describe_group(&alice, &gid).await.unwrap();
        rt.lock().await.unwrap();
        (
            master,
            gid,
            desc.generation,
            owners(&desc),
            desc.offsets.iter().map(|o| (o.partition_id, o.sequence)).collect::<Vec<_>>(),
        )
    };
    set_test_partition_count(Some(3));
    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.generation, generation);
    assert_eq!(owners(&desc), expected_owners);
    assert_eq!(
        desc.offsets.iter().map(|o| (o.partition_id, o.sequence)).collect::<Vec<_>>(),
        offsets
    );
}

#[tokio::test]
async fn ack_after_rebalance_handoff_advances_offset() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("rb-ack-handoff");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
        .await
        .unwrap();
    let gen_a = rt.describe_group(&alice, &gid).await.unwrap().generation;
    let _ = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), gen_a)
        .await
        .unwrap()
        .expect("event");
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    rt.leave_group(&alice, &gid, &MemberId::from("A"))
        .await
        .unwrap();
    let gen_b = rt.describe_group(&alice, &gid).await.unwrap().generation;
    let d = rt
        .group_consume(&alice, &gid, &MemberId::from("B"), gen_b)
        .await
        .unwrap()
        .expect("redelivery");
    let ack = rt
        .group_ack(
            &alice,
            &gid,
            &MemberId::from("B"),
            gen_b,
            &d.delivery.delivery_id,
        )
        .await
        .unwrap();
    assert!(ack.advanced);
    assert_eq!(ack.new_offset, d.sequence);
}
