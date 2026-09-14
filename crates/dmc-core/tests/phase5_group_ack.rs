//! Phase 5.8.6 — group_ack + contiguous GroupOffset (no retry/DLQ).

use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{
    DeliveryId, Error, GroupId, GroupPolicy, GroupStartPosition, MemberId, SessionId, StreamId,
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

fn multi_flight_policy() -> GroupPolicy {
    GroupPolicy {
        max_in_flight: 8,
        ..Default::default()
    }
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

#[tokio::test]
async fn ack_first_delivery_advances_offset() {
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
    let before = offset_of(&rt, &alice, &gid, 0).await;
    rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
        .await
        .unwrap();
    let d = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("event");
    let ack = rt
        .group_ack(
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            &d.delivery.delivery_id,
        )
        .await
        .unwrap();
    assert_eq!(ack.acknowledged_sequence, d.sequence);
    assert_eq!(ack.new_offset, d.sequence);
    assert!(ack.advanced);
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, d.sequence);
    assert!(ack.new_offset > before);
}

#[tokio::test]
async fn ack_gap_does_not_skip_unacked() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("g-gap");
    rt.create_group_with_policy(&alice, gid.clone(), &stream, multi_flight_policy())
        .await
        .unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
    for i in 1..=4 {
        rt.put_data(
            &admin,
            &format!("company/finance/tx/{i}"),
            format!(r#"{{"v":{i}}}"#).as_bytes(),
        )
        .await
        .unwrap();
    }
    let mut deliveries = Vec::new();
    for _ in 0..4 {
        deliveries.push(
            rt.group_consume(&alice, &gid, &MemberId::from("A"), generation)
                .await
                .unwrap()
                .expect("event"),
        );
    }
    assert_eq!(deliveries.len(), 4);
    let base = offset_of(&rt, &alice, &gid, 0).await;
    // pending: base+1 .. base+4
    let ack101 = rt
        .group_ack(
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            &deliveries[0].delivery.delivery_id,
        )
        .await
        .unwrap();
    assert_eq!(ack101.new_offset, base + 1);
    assert!(ack101.advanced);

    let _ = rt
        .group_ack(
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            &deliveries[2].delivery.delivery_id,
        )
        .await
        .unwrap();
    let ack104 = rt
        .group_ack(
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            &deliveries[3].delivery.delivery_id,
        )
        .await
        .unwrap();
    assert_eq!(ack104.new_offset, base + 1);
    assert!(!ack104.advanced);
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, base + 1);
}

#[tokio::test]
async fn ack_gap_closure_advances_to_high_water() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("g-close");
    rt.create_group_with_policy(&alice, gid.clone(), &stream, multi_flight_policy())
        .await
        .unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
    for i in 1..=4 {
        rt.put_data(
            &admin,
            &format!("company/finance/tx/{i}"),
            format!(r#"{{"v":{i}}}"#).as_bytes(),
        )
        .await
        .unwrap();
    }
    let mut deliveries = Vec::new();
    for _ in 0..4 {
        deliveries.push(
            rt.group_consume(&alice, &gid, &MemberId::from("A"), generation)
                .await
                .unwrap()
                .expect("event"),
        );
    }
    let base = offset_of(&rt, &alice, &gid, 0).await;
    for idx in [0usize, 2, 3] {
        rt.group_ack(
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            &deliveries[idx].delivery.delivery_id,
        )
        .await
        .unwrap();
    }
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, base + 1);
    let closed = rt
        .group_ack(
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            &deliveries[1].delivery.delivery_id,
        )
        .await
        .unwrap();
    assert_eq!(closed.new_offset, base + 4);
    assert!(closed.advanced);
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, base + 4);
}

#[tokio::test]
async fn duplicate_ack_is_idempotent() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("g-dup");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
    rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
        .await
        .unwrap();
    let d = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("event");
    let first = rt
        .group_ack(
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            &d.delivery.delivery_id,
        )
        .await
        .unwrap();
    let second = rt
        .group_ack(
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            &d.delivery.delivery_id,
        )
        .await
        .unwrap();
    assert_eq!(second.new_offset, first.new_offset);
    assert!(!second.advanced);
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, first.new_offset);
}

#[tokio::test]
async fn stale_delivery_id_rejected_after_redelivery() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("g-stale");
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
        .expect("event");
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
        .expect("redelivery");
    assert_eq!(d1.sequence, d2.sequence);
    assert_ne!(d1.delivery.delivery_id, d2.delivery.delivery_id);
    assert_eq!(d2.delivery.attempt, 2);
    let err = rt
        .group_ack(
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            &d1.delivery.delivery_id,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::StaleDelivery(_)), "got {err}");
    let ack = rt
        .group_ack(
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            &d2.delivery.delivery_id,
        )
        .await
        .unwrap();
    assert!(ack.advanced);
}

#[tokio::test]
async fn wrong_member_cannot_ack() {
    let _g = with_partitions(2);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("g-member");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
    let p0 = path_for_partition("company/finance", 0, 2);
    rt.put_data(&admin, &p0, br#"{"p":0}"#).await.unwrap();
    let d = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("A event");
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
    assert!(
        matches!(err, Error::NotAssigned { .. } | Error::StaleDelivery(_)),
        "got {err}"
    );
}

#[tokio::test]
async fn stale_generation_cannot_ack() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("g-gen");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    let old_generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
    rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
        .await
        .unwrap();
    let d = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), old_generation)
        .await
        .unwrap()
        .expect("event");
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    let new_generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
    assert!(new_generation > old_generation);
    let err = rt
        .group_ack(
            &alice,
            &gid,
            &MemberId::from("A"),
            old_generation,
            &d.delivery.delivery_id,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::StaleGeneration { .. }),
        "got {err}"
    );
}

#[tokio::test]
async fn wrong_group_ack_denied() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let ga = GroupId::from("ga");
    let gb = GroupId::from("gb");
    rt.create_group(&alice, ga.clone(), &stream).await.unwrap();
    rt.create_group(&alice, gb.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &ga, MemberId::from("A"), None)
        .await
        .unwrap();
    rt.join_group(&alice, &gb, MemberId::from("A"), None)
        .await
        .unwrap();
    let gen_a = rt.describe_group(&alice, &ga).await.unwrap().generation;
    let gen_b = rt.describe_group(&alice, &gb).await.unwrap().generation;
    rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
        .await
        .unwrap();
    let d = rt
        .group_consume(&alice, &ga, &MemberId::from("A"), gen_a)
        .await
        .unwrap()
        .expect("event");
    let err = rt
        .group_ack(
            &alice,
            &gb,
            &MemberId::from("A"),
            gen_b,
            &d.delivery.delivery_id,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::StaleDelivery(_) | Error::NotAssigned { .. }),
        "got {err}"
    );
}

#[tokio::test]
async fn crash_before_ack_redelivers_same_sequence() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation, seq, delivery_id) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("crash-before");
        rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
        rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
            .await
            .unwrap();
        let d = rt
            .group_consume(&alice, &gid, &MemberId::from("A"), generation)
            .await
            .unwrap()
            .expect("event");
        rt.lock().await.unwrap();
        (
            master,
            gid,
            generation,
            d.sequence,
            d.delivery.delivery_id.clone(),
        )
    };
    set_test_partition_count(Some(1));
    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    let d2 = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("redelivery");
    assert_eq!(d2.sequence, seq);
    assert_ne!(d2.delivery.delivery_id, delivery_id);
    assert!(d2.delivery.attempt >= 2);
}

#[tokio::test]
async fn crash_after_ack_consumes_next_sequence() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation, first_seq) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("crash-after");
        rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
        rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
            .await
            .unwrap();
        rt.put_data(&admin, "company/finance/tx/2", br#"{"v":2}"#)
            .await
            .unwrap();
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
        rt.lock().await.unwrap();
        (master, gid, generation, d.sequence)
    };
    set_test_partition_count(Some(1));
    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    let d2 = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("next");
    assert!(d2.sequence > first_seq);
}

#[tokio::test]
async fn ack_persists_across_restart() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation, offset, assignment_len) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("persist-ack");
        rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let desc = rt.describe_group(&alice, &gid).await.unwrap();
        let generation = desc.generation;
        rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
            .await
            .unwrap();
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
        let offset = offset_of(&rt, &alice, &gid, 0).await;
        rt.lock().await.unwrap();
        (master, gid, generation, offset, desc.assignments.len())
    };
    set_test_partition_count(Some(1));
    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.generation, generation);
    assert_eq!(desc.assignments.len(), assignment_len);
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, offset);
}

#[tokio::test]
async fn ack_on_p0_does_not_move_p1() {
    let _g = with_partitions(2);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("g-iso");
    rt.create_group_with_policy(&alice, gid.clone(), &stream, multi_flight_policy())
        .await
        .unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
    let p0 = path_for_partition("company/finance", 0, 2);
    let p1 = path_for_partition("company/finance", 1, 2);
    rt.put_data(&admin, &p0, br#"{"p":0}"#).await.unwrap();
    rt.put_data(&admin, &p1, br#"{"p":1}"#).await.unwrap();
    let p1_before = offset_of(&rt, &alice, &gid, 1).await;
    let d0 = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("p0");
    assert_eq!(d0.partition_id, 0);
    rt.group_ack(
        &alice,
        &gid,
        &MemberId::from("A"),
        generation,
        &d0.delivery.delivery_id,
    )
    .await
    .unwrap();
    assert_eq!(offset_of(&rt, &alice, &gid, 1).await, p1_before);
}

#[tokio::test]
async fn rebalance_does_not_rollback_offset() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("g-rebal");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
    rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
        .await
        .unwrap();
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
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, offset_after_ack);
}

#[tokio::test]
async fn unknown_delivery_is_stale() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("g-unknown");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
    let err = rt
        .group_ack(
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            &DeliveryId::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::StaleDelivery(_)), "got {err}");
}
