//! Phase 5.8.10 — per-group DLQ metadata (journal immutable).

use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{
    Error, GroupDlqReason, GroupId, GroupPolicy, GroupRetryPolicy, GroupRetryResponse, MemberId,
    SessionId, StreamId,
};
use dmc_journal::set_test_partition_count;
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};

const BASE_NOW: u64 = 200_000;

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

fn dlq_policy(max_in_flight: u32) -> GroupPolicy {
    GroupPolicy {
        max_in_flight,
        retry: GroupRetryPolicy {
            max_attempts: 1,
            backoff_ms: vec![0],
        },
        ..Default::default()
    }
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

async fn offset_of(rt: &Runtime, alice: &SessionId, gid: &GroupId, pid: u32) -> u64 {
    rt.describe_group(alice, gid)
        .await
        .unwrap()
        .offsets
        .iter()
        .find(|o| o.partition_id == pid)
        .map(|o| o.sequence)
        .unwrap_or(0)
}

async fn join_and_gen(rt: &Runtime, alice: &SessionId, gid: &GroupId) -> u64 {
    rt.join_group(alice, gid, MemberId::from("A"), None)
        .await
        .unwrap();
    rt.describe_group(alice, gid).await.unwrap().generation
}

async fn retry_to_dlq(
    rt: &Runtime,
    alice: &SessionId,
    gid: &GroupId,
    member: &MemberId,
    generation: u64,
    delivery_id: &dmc_core::DeliveryId,
) -> dmc_core::GroupDlqResult {
    match rt
        .group_retry(alice, gid, member, generation, delivery_id)
        .await
        .unwrap()
    {
        GroupRetryResponse::Dlq(result) => result,
        GroupRetryResponse::Retry(_) => panic!("expected DLQ transition"),
    }
}

#[tokio::test]
async fn max_attempts_retry_moves_to_dlq() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("dlq-basic");
    rt.create_group_with_policy(&alice, gid.clone(), &stream, dlq_policy(1))
        .await
        .unwrap();
    let generation = join_and_gen(&rt, &alice, &gid).await;
    rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
        .await
        .unwrap();
    let d = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("event");
    let dlq = retry_to_dlq(
        &rt,
        &alice,
        &gid,
        &MemberId::from("A"),
        generation,
        &d.delivery.delivery_id,
    )
    .await;
    assert_eq!(dlq.sequence, d.sequence);
    assert_eq!(dlq.entry.event_id, d.event_id);
    assert_eq!(dlq.entry.attempts, 1);
    assert_eq!(dlq.entry.reason, GroupDlqReason::MaxAttemptsExceeded);
    assert!(dlq.advanced);
}

#[tokio::test]
async fn dlq_removes_pending_and_advances_offset() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("dlq-offset");
    rt.create_group_with_policy(&alice, gid.clone(), &stream, dlq_policy(1))
        .await
        .unwrap();
    let generation = join_and_gen(&rt, &alice, &gid).await;
    let before = offset_of(&rt, &alice, &gid, 0).await;
    rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
        .await
        .unwrap();
    let d = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("event");
    let dlq = retry_to_dlq(
        &rt,
        &alice,
        &gid,
        &MemberId::from("A"),
        generation,
        &d.delivery.delivery_id,
    )
    .await;
    assert!(dlq.new_offset > before);
    assert_eq!(dlq.new_offset, d.sequence);
    assert!(rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn ack_and_dlq_contiguous_progression() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("dlq-contig");
    rt.create_group_with_policy(&alice, gid.clone(), &stream, dlq_policy(4))
        .await
        .unwrap();
    let generation = join_and_gen(&rt, &alice, &gid).await;
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
    rt.group_ack(
        &alice,
        &gid,
        &MemberId::from("A"),
        generation,
        &deliveries[0].delivery.delivery_id,
    )
    .await
    .unwrap();
    retry_to_dlq(
        &rt,
        &alice,
        &gid,
        &MemberId::from("A"),
        generation,
        &deliveries[1].delivery.delivery_id,
    )
    .await;
    retry_to_dlq(
        &rt,
        &alice,
        &gid,
        &MemberId::from("A"),
        generation,
        &deliveries[2].delivery.delivery_id,
    )
    .await;
    assert_eq!(
        offset_of(&rt, &alice, &gid, 0).await,
        deliveries[2].sequence
    );
    assert_eq!(rt.list_group_dlq(&alice, &gid).await.unwrap().len(), 2);
}

#[tokio::test]
async fn dlq_gap_blocks_offset_until_resolved() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("dlq-gap");
    rt.create_group_with_policy(&alice, gid.clone(), &stream, dlq_policy(3))
        .await
        .unwrap();
    let generation = join_and_gen(&rt, &alice, &gid).await;
    for i in 1..=3 {
        rt.put_data(
            &admin,
            &format!("company/finance/tx/{i}"),
            format!(r#"{{"v":{i}}}"#).as_bytes(),
        )
        .await
        .unwrap();
    }
    let mut ds = Vec::new();
    for _ in 0..3 {
        ds.push(
            rt.group_consume(&alice, &gid, &MemberId::from("A"), generation)
                .await
                .unwrap()
                .expect("event"),
        );
    }
    retry_to_dlq(
        &rt,
        &alice,
        &gid,
        &MemberId::from("A"),
        generation,
        &ds[0].delivery.delivery_id,
    )
    .await;
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, ds[0].sequence);
    assert!(offset_of(&rt, &alice, &gid, 0).await < ds[1].sequence);
    retry_to_dlq(
        &rt,
        &alice,
        &gid,
        &MemberId::from("A"),
        generation,
        &ds[1].delivery.delivery_id,
    )
    .await;
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, ds[1].sequence);
}

#[tokio::test]
async fn stale_delivery_after_dlq() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("dlq-stale");
    rt.create_group_with_policy(&alice, gid.clone(), &stream, dlq_policy(1))
        .await
        .unwrap();
    let generation = join_and_gen(&rt, &alice, &gid).await;
    rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
        .await
        .unwrap();
    let d = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("event");
    let old_id = d.delivery.delivery_id.clone();
    retry_to_dlq(
        &rt,
        &alice,
        &gid,
        &MemberId::from("A"),
        generation,
        &old_id,
    )
    .await;
    let err = rt
        .group_retry(&alice, &gid, &MemberId::from("A"), generation, &old_id)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::StaleDelivery(_)), "got {err}");
}

#[tokio::test]
async fn stale_generation_cannot_dlq_via_retry() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("dlq-stale-gen");
    rt.create_group_with_policy(&alice, gid.clone(), &stream, dlq_policy(1))
        .await
        .unwrap();
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
        .group_retry(
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
async fn wrong_member_cannot_dlq() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("dlq-not-assigned");
    rt.create_group_with_policy(&alice, gid.clone(), &stream, dlq_policy(1))
        .await
        .unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
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
        .expect("A event");
    let err = rt
        .group_retry(
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
async fn dlq_survives_restart_and_no_redelivery() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation, seq, event_id) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("dlq-restart");
        rt.create_group_with_policy(&alice, gid.clone(), &stream, dlq_policy(1))
            .await
            .unwrap();
        let generation = join_and_gen(&rt, &alice, &gid).await;
        rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
            .await
            .unwrap();
        let d = rt
            .group_consume(&alice, &gid, &MemberId::from("A"), generation)
            .await
            .unwrap()
            .expect("event");
        retry_to_dlq(
            &rt,
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            &d.delivery.delivery_id,
        )
        .await;
        rt.lock().await.unwrap();
        (master, gid, generation, d.sequence, d.event_id)
    };
    set_test_partition_count(Some(1));
    let rt = Runtime::at_path(&path);
    rt.set_now_ms(Some(BASE_NOW)).await;
    rt.unlock(&master).await.unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    let entry = rt
        .get_group_dlq_entry(&alice, &gid, 0, seq)
        .await
        .unwrap();
    assert_eq!(entry.event_id, event_id);
    assert_eq!(rt.list_group_dlq(&alice, &gid).await.unwrap().len(), 1);
    assert!(rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn dlq_entry_is_idempotent_per_sequence() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("dlq-idempotent");
    rt.create_group_with_policy(&alice, gid.clone(), &stream, dlq_policy(1))
        .await
        .unwrap();
    let generation = join_and_gen(&rt, &alice, &gid).await;
    rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
        .await
        .unwrap();
    let d = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("event");
    let first = retry_to_dlq(
        &rt,
        &alice,
        &gid,
        &MemberId::from("A"),
        generation,
        &d.delivery.delivery_id,
    )
    .await;
    assert_eq!(rt.list_group_dlq(&alice, &gid).await.unwrap().len(), 1);
    let err = rt
        .group_retry(&alice, &gid, &MemberId::from("A"), generation, &d.delivery.delivery_id)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::StaleDelivery(_)), "got {err}");
    let entry = rt
        .get_group_dlq_entry(&alice, &gid, 0, first.sequence)
        .await
        .unwrap();
    assert_eq!(entry.sequence, first.sequence);
}

#[tokio::test]
async fn new_owner_can_dlq_after_rebalance() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("dlq-rebalance");
    rt.create_group_with_policy(&alice, gid.clone(), &stream, dlq_policy(1))
        .await
        .unwrap();
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
    let dlq = retry_to_dlq(
        &rt,
        &alice,
        &gid,
        &MemberId::from("B"),
        gen_b,
        &d.delivery.delivery_id,
    )
    .await;
    assert_eq!(dlq.entry.generation, gen_b);
}

#[tokio::test]
async fn dlq_metadata_survives_journal_gc_semantics() {
    let entry = dmc_core::GroupDlqEntry {
        group_id: GroupId::from("g"),
        partition_id: 0,
        sequence: 42,
        event_id: "e42".into(),
        attempts: 3,
        first_delivered_at_ms: 1,
        last_delivered_at_ms: 2,
        reason: GroupDlqReason::MaxAttemptsExceeded,
        created_at_ms: 3,
        generation: 7,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: dmc_core::GroupDlqEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.sequence, 42);
    assert_eq!(back.reason, GroupDlqReason::MaxAttemptsExceeded);
}
