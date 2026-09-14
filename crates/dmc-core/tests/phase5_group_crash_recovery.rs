//! Phase 5.8.11 — consumer group crash / recovery matrix (ADR-015 §5.8.11).

use std::fs;
use std::path::Path;

use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{
    Error, GroupCrashPoint, GroupDeliveredEvent, GroupDlqReason, GroupId, GroupPolicy,
    GroupRetryPolicy, GroupRetryResponse, MemberId, SessionId, StreamId,
    DEFAULT_MEMBER_LEASE_MS, is_simulated_group_crash, set_test_group_crash_point,
};
use dmc_journal::{set_test_partition_count, StorageLayout};
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};

const BASE_NOW: u64 = 500_000;

struct TestGuard;
impl Drop for TestGuard {
    fn drop(&mut self) {
        set_test_partition_count(None);
        set_test_group_crash_point(None);
    }
}

fn with_test_env(n: u32) -> TestGuard {
    set_test_partition_count(Some(n));
    TestGuard
}

fn disarm_group_crash() {
    set_test_group_crash_point(None);
}

async fn reopen(path: &Path, master: &str, now_ms: u64) -> Runtime {
    let rt = Runtime::at_path(path);
    rt.set_now_ms(Some(now_ms)).await;
    rt.unlock(master).await.unwrap();
    rt
}

fn retry_policy(max_attempts: u32, backoff_ms: Vec<u64>) -> GroupPolicy {
    GroupPolicy {
        retry: GroupRetryPolicy {
            max_attempts,
            backoff_ms,
        },
        ..Default::default()
    }
}

fn multi_flight_policy(max_in_flight: u32, max_attempts: u32, backoff_ms: Vec<u64>) -> GroupPolicy {
    GroupPolicy {
        max_in_flight,
        retry: GroupRetryPolicy {
            max_attempts,
            backoff_ms,
        },
        ..Default::default()
    }
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

fn owners(desc: &dmc_core::GroupDescription) -> Vec<(u32, String)> {
    desc.assignments
        .iter()
        .map(|a| (a.partition_id, a.member_id.as_str().to_string()))
        .collect()
}

async fn produce_n(rt: &Runtime, admin: &SessionId, n: u32) {
    for i in 1..=n {
        rt.put_data(
            admin,
            &format!("company/finance/tx/{i}"),
            format!(r#"{{"v":{i}}}"#).as_bytes(),
        )
        .await
        .unwrap();
    }
}

async fn consume_many(
    rt: &Runtime,
    alice: &SessionId,
    gid: &GroupId,
    member: &MemberId,
    generation: u64,
    n: u32,
) -> Vec<GroupDeliveredEvent> {
    let mut out = Vec::new();
    for _ in 0..n {
        out.push(
            rt.group_consume(alice, gid, member, generation)
                .await
                .unwrap()
                .expect("event"),
        );
    }
    out
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

fn group_meta_paths(db_path: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let layout = StorageLayout::from_db_path(db_path);
    let meta = layout.group_meta();
    (meta.clone(), meta.with_extension("tmp"))
}

fn assert_generation_assignment_aligned(desc: &dmc_core::GroupDescription) {
    for owner in &desc.assignments {
        assert_eq!(
            owner.generation, desc.generation,
            "partition {} owner generation split from group generation",
            owner.partition_id
        );
    }
}

async fn assert_no_orphan_offset(
    rt: &Runtime,
    alice: &SessionId,
    gid: &GroupId,
    member: &MemberId,
    generation: u64,
    pid: u32,
) {
    let offset = offset_of(rt, alice, gid, pid).await;
    let dlq_seqs: Vec<u64> = rt
        .list_group_dlq(alice, gid)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.partition_id == pid)
        .map(|e| e.sequence)
        .collect();
    for seq in dlq_seqs {
        assert!(
            offset >= seq,
            "offset {offset} behind resolved DLQ sequence {seq}"
        );
    }
    if let Ok(Some(next)) = rt
        .group_consume(alice, gid, member, generation)
        .await
    {
        assert!(
            next.sequence > offset,
            "orphan offset {offset} with pending redelivery at {}",
            next.sequence
        );
    }
}

// --- ACK (4) ---

#[tokio::test]
async fn ack_crash_before_persist_redelivers_same_sequence() {
    let _g = with_test_env(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation, seq, event_id, offset_before) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        rt.set_now_ms(Some(BASE_NOW)).await;
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("ack-g2");
        rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
        produce_n(&rt, &admin, 1).await;
        let d = rt
            .group_consume(&alice, &gid, &MemberId::from("A"), generation)
            .await
            .unwrap()
            .expect("event");
        let offset_before = offset_of(&rt, &alice, &gid, 0).await;
        set_test_group_crash_point(Some(GroupCrashPoint::G2_AfterStateMutation));
        let err = rt
            .group_ack(
                &alice,
                &gid,
                &MemberId::from("A"),
                generation,
                &d.delivery.delivery_id,
            )
            .await
            .unwrap_err();
        assert!(is_simulated_group_crash(&err));
        disarm_group_crash();
        (
            master,
            gid,
            generation,
            d.sequence,
            d.event_id,
            offset_before,
        )
    };
    set_test_partition_count(Some(1));
    let rt = reopen(&path, &master, BASE_NOW).await;
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, offset_before);
    let redelivered = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("redelivery");
    assert_eq!(redelivered.sequence, seq);
    assert_eq!(redelivered.event_id, event_id);
}

#[tokio::test]
async fn ack_crash_before_rename_keeps_old_offset() {
    let _g = with_test_env(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation, offset_before) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        rt.set_now_ms(Some(BASE_NOW)).await;
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("ack-g4");
        rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
        produce_n(&rt, &admin, 1).await;
        let d = rt
            .group_consume(&alice, &gid, &MemberId::from("A"), generation)
            .await
            .unwrap()
            .expect("event");
        let offset_before = offset_of(&rt, &alice, &gid, 0).await;
        set_test_group_crash_point(Some(GroupCrashPoint::G4_AfterGroupMetaTmpFsync));
        let err = rt
            .group_ack(
                &alice,
                &gid,
                &MemberId::from("A"),
                generation,
                &d.delivery.delivery_id,
            )
            .await
            .unwrap_err();
        assert!(is_simulated_group_crash(&err));
        disarm_group_crash();
        let (_, tmp) = group_meta_paths(&path);
        assert!(tmp.is_file(), "tmp should exist after G4");
        (master, gid, generation, offset_before)
    };
    set_test_partition_count(Some(1));
    let rt = reopen(&path, &master, BASE_NOW).await;
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, offset_before);
    let redelivered = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("redelivery");
    assert!(redelivered.sequence > offset_before);
}

#[tokio::test]
async fn ack_crash_after_rename_advances_offset() {
    let _g = with_test_env(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation, seq) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        rt.set_now_ms(Some(BASE_NOW)).await;
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("ack-g5");
        rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
        produce_n(&rt, &admin, 1).await;
        let d = rt
            .group_consume(&alice, &gid, &MemberId::from("A"), generation)
            .await
            .unwrap()
            .expect("event");
        set_test_group_crash_point(Some(GroupCrashPoint::G5_AfterGroupMetaRename));
        let err = rt
            .group_ack(
                &alice,
                &gid,
                &MemberId::from("A"),
                generation,
                &d.delivery.delivery_id,
            )
            .await
            .unwrap_err();
        assert!(is_simulated_group_crash(&err));
        disarm_group_crash();
        (master, gid, generation, d.sequence)
    };
    set_test_partition_count(Some(1));
    let rt = reopen(&path, &master, BASE_NOW).await;
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, seq);
    assert!(rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn ack_never_orphan_offset_without_pending() {
    let _g = with_test_env(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        rt.set_now_ms(Some(BASE_NOW)).await;
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("ack-orphan");
        rt.create_group_with_policy(
            &alice,
            gid.clone(),
            &stream,
            multi_flight_policy(4, 5, vec![1_000; 5]),
        )
        .await
        .unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
        produce_n(&rt, &admin, 2).await;
        let deliveries = consume_many(
            &rt,
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            2,
        )
        .await;
        set_test_group_crash_point(Some(GroupCrashPoint::G2_AfterStateMutation));
        let err = rt
            .group_ack(
                &alice,
                &gid,
                &MemberId::from("A"),
                generation,
                &deliveries[0].delivery.delivery_id,
            )
            .await
            .unwrap_err();
        assert!(is_simulated_group_crash(&err));
        disarm_group_crash();
        (master, gid, generation)
    };
    set_test_partition_count(Some(1));
    let rt = reopen(&path, &master, BASE_NOW).await;
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    assert_no_orphan_offset(
        &rt,
        &alice,
        &gid,
        &MemberId::from("A"),
        generation,
        0,
    )
    .await;

    let (master2, seq) = {
        set_test_partition_count(Some(1));
        let rt = Runtime::at_path(&path);
        rt.set_now_ms(Some(BASE_NOW)).await;
        rt.unlock(&master).await.unwrap();
        let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
        let deliveries = consume_many(
            &rt,
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            2,
        )
        .await;
        set_test_group_crash_point(Some(GroupCrashPoint::G5_AfterGroupMetaRename));
        let err = rt
            .group_ack(
                &alice,
                &gid,
                &MemberId::from("A"),
                generation,
                &deliveries[0].delivery.delivery_id,
            )
            .await
            .unwrap_err();
        assert!(is_simulated_group_crash(&err));
        disarm_group_crash();
        (master.clone(), deliveries[0].sequence)
    };
    let _ = master2;
    set_test_partition_count(Some(1));
    let rt = reopen(&path, &master, BASE_NOW).await;
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, seq);
    assert_no_orphan_offset(
        &rt,
        &alice,
        &gid,
        &MemberId::from("A"),
        generation,
        0,
    )
    .await;
}

// --- Retry (3) ---

#[tokio::test]
async fn retry_crash_before_persist_keeps_unscheduled_backoff() {
    let _g = with_test_env(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation, delivery_id) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        rt.set_now_ms(Some(BASE_NOW)).await;
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("retry-g2");
        rt.create_group_with_policy(
            &alice,
            gid.clone(),
            &stream,
            retry_policy(5, vec![7_000, 1_000, 5_000, 30_000, 60_000]),
        )
        .await
        .unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
        produce_n(&rt, &admin, 1).await;
        let d = rt
            .group_consume(&alice, &gid, &MemberId::from("A"), generation)
            .await
            .unwrap()
            .expect("event");
        rt.heartbeat_group_member(&alice, &gid, &MemberId::from("A"))
            .await
            .unwrap();
        set_test_group_crash_point(Some(GroupCrashPoint::G2_AfterStateMutation));
        let err = rt
            .group_retry(
                &alice,
                &gid,
                &MemberId::from("A"),
                generation,
                &d.delivery.delivery_id,
            )
            .await
            .unwrap_err();
        assert!(is_simulated_group_crash(&err));
        disarm_group_crash();
        (master, gid, generation, d.delivery.delivery_id)
    };
    set_test_partition_count(Some(1));
    let rt = reopen(&path, &master, BASE_NOW).await;
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    let redelivered = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("immediate redelivery without backoff schedule");
    assert_eq!(redelivered.delivery.attempt, 2);
    assert_ne!(redelivered.delivery.delivery_id, delivery_id);
}

#[tokio::test]
async fn retry_crash_after_rename_persists_backoff() {
    let _g = with_test_env(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        rt.set_now_ms(Some(BASE_NOW)).await;
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("retry-g5");
        rt.create_group_with_policy(
            &alice,
            gid.clone(),
            &stream,
            retry_policy(5, vec![7_000, 1_000, 5_000, 30_000, 60_000]),
        )
        .await
        .unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
        produce_n(&rt, &admin, 1).await;
        let d = rt
            .group_consume(&alice, &gid, &MemberId::from("A"), generation)
            .await
            .unwrap()
            .expect("event");
        set_test_group_crash_point(Some(GroupCrashPoint::G5_AfterGroupMetaRename));
        let err = rt
            .group_retry(
                &alice,
                &gid,
                &MemberId::from("A"),
                generation,
                &d.delivery.delivery_id,
            )
            .await
            .unwrap_err();
        assert!(is_simulated_group_crash(&err));
        disarm_group_crash();
        (master, gid, generation)
    };
    set_test_partition_count(Some(1));
    let rt = reopen(&path, &master, BASE_NOW).await;
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    let err = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap_err();
    match err {
        Error::GroupRetryBackoff { retry_at_ms, attempt, .. } => {
            assert_eq!(attempt, 1);
            assert_eq!(retry_at_ms, BASE_NOW + 7_000);
        }
        other => panic!("expected GroupRetryBackoff, got {other}"),
    }
}

#[tokio::test]
async fn retry_crash_before_rename_discards_scheduled_backoff() {
    let _g = with_test_env(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        rt.set_now_ms(Some(BASE_NOW)).await;
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("retry-g4");
        rt.create_group_with_policy(
            &alice,
            gid.clone(),
            &stream,
            retry_policy(5, vec![7_000, 1_000, 5_000, 30_000, 60_000]),
        )
        .await
        .unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
        produce_n(&rt, &admin, 1).await;
        let d = rt
            .group_consume(&alice, &gid, &MemberId::from("A"), generation)
            .await
            .unwrap()
            .expect("event");
        set_test_group_crash_point(Some(GroupCrashPoint::G4_AfterGroupMetaTmpFsync));
        let err = rt
            .group_retry(
                &alice,
                &gid,
                &MemberId::from("A"),
                generation,
                &d.delivery.delivery_id,
            )
            .await
            .unwrap_err();
        assert!(is_simulated_group_crash(&err));
        disarm_group_crash();
        (master, gid, generation)
    };
    set_test_partition_count(Some(1));
    let rt = reopen(&path, &master, BASE_NOW).await;
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    let redelivered = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("redelivery without persisted backoff");
    assert_eq!(redelivered.delivery.attempt, 2);
}

// --- DLQ (4) ---

#[tokio::test]
async fn dlq_crash_before_persist() {
    let _g = with_test_env(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation, offset_before, seq) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        rt.set_now_ms(Some(BASE_NOW)).await;
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("dlq-g2");
        rt.create_group_with_policy(&alice, gid.clone(), &stream, dlq_policy(1))
            .await
            .unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
        produce_n(&rt, &admin, 1).await;
        let d = rt
            .group_consume(&alice, &gid, &MemberId::from("A"), generation)
            .await
            .unwrap()
            .expect("event");
        let offset_before = offset_of(&rt, &alice, &gid, 0).await;
        set_test_group_crash_point(Some(GroupCrashPoint::G2_AfterStateMutation));
        let err = rt
            .group_retry(
                &alice,
                &gid,
                &MemberId::from("A"),
                generation,
                &d.delivery.delivery_id,
            )
            .await
            .unwrap_err();
        assert!(is_simulated_group_crash(&err));
        disarm_group_crash();
        (master, gid, generation, offset_before, d.sequence)
    };
    set_test_partition_count(Some(1));
    let rt = reopen(&path, &master, BASE_NOW).await;
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, offset_before);
    assert!(rt.list_group_dlq(&alice, &gid).await.unwrap().is_empty());
    let redelivered = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("pending survives");
    assert_eq!(redelivered.sequence, seq);
}

#[tokio::test]
async fn dlq_crash_before_rename() {
    let _g = with_test_env(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, _generation, offset_before) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        rt.set_now_ms(Some(BASE_NOW)).await;
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("dlq-g4");
        rt.create_group_with_policy(&alice, gid.clone(), &stream, dlq_policy(1))
            .await
            .unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
        produce_n(&rt, &admin, 1).await;
        let d = rt
            .group_consume(&alice, &gid, &MemberId::from("A"), generation)
            .await
            .unwrap()
            .expect("event");
        let offset_before = offset_of(&rt, &alice, &gid, 0).await;
        set_test_group_crash_point(Some(GroupCrashPoint::G4_AfterGroupMetaTmpFsync));
        let err = rt
            .group_retry(
                &alice,
                &gid,
                &MemberId::from("A"),
                generation,
                &d.delivery.delivery_id,
            )
            .await
            .unwrap_err();
        assert!(is_simulated_group_crash(&err));
        disarm_group_crash();
        (master, gid, generation, offset_before)
    };
    set_test_partition_count(Some(1));
    let rt = reopen(&path, &master, BASE_NOW).await;
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, offset_before);
    assert!(rt.list_group_dlq(&alice, &gid).await.unwrap().is_empty());
}

#[tokio::test]
async fn dlq_crash_after_rename_is_atomic() {
    let _g = with_test_env(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation, seq, event_id) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        rt.set_now_ms(Some(BASE_NOW)).await;
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("dlq-g5");
        rt.create_group_with_policy(&alice, gid.clone(), &stream, dlq_policy(1))
            .await
            .unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
        produce_n(&rt, &admin, 1).await;
        let d = rt
            .group_consume(&alice, &gid, &MemberId::from("A"), generation)
            .await
            .unwrap()
            .expect("event");
        set_test_group_crash_point(Some(GroupCrashPoint::G5_AfterGroupMetaRename));
        let err = rt
            .group_retry(
                &alice,
                &gid,
                &MemberId::from("A"),
                generation,
                &d.delivery.delivery_id,
            )
            .await
            .unwrap_err();
        assert!(is_simulated_group_crash(&err));
        disarm_group_crash();
        (master, gid, generation, d.sequence, d.event_id)
    };
    set_test_partition_count(Some(1));
    let rt = reopen(&path, &master, BASE_NOW).await;
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, seq);
    let entry = rt
        .get_group_dlq_entry(&alice, &gid, 0, seq)
        .await
        .unwrap();
    assert_eq!(entry.event_id, event_id);
    assert!(rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn dlq_no_duplicate_entry() {
    let _g = with_test_env(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation, delivery_id, seq) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        rt.set_now_ms(Some(BASE_NOW)).await;
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("dlq-dup");
        rt.create_group_with_policy(&alice, gid.clone(), &stream, dlq_policy(1))
            .await
            .unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
        produce_n(&rt, &admin, 1).await;
        let d = rt
            .group_consume(&alice, &gid, &MemberId::from("A"), generation)
            .await
            .unwrap()
            .expect("event");
        set_test_group_crash_point(Some(GroupCrashPoint::G5_AfterGroupMetaRename));
        let err = rt
            .group_retry(
                &alice,
                &gid,
                &MemberId::from("A"),
                generation,
                &d.delivery.delivery_id,
            )
            .await
            .unwrap_err();
        assert!(is_simulated_group_crash(&err));
        disarm_group_crash();
        (
            master,
            gid,
            generation,
            d.delivery.delivery_id,
            d.sequence,
        )
    };
    set_test_partition_count(Some(1));
    let rt = reopen(&path, &master, BASE_NOW).await;
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    assert_eq!(rt.list_group_dlq(&alice, &gid).await.unwrap().len(), 1);
    let err = rt
        .group_retry(
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            &delivery_id,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::StaleDelivery(_)), "got {err}");
    assert_eq!(rt.list_group_dlq(&alice, &gid).await.unwrap().len(), 1);
    let entry = rt
        .get_group_dlq_entry(&alice, &gid, 0, seq)
        .await
        .unwrap();
    assert_eq!(entry.reason, GroupDlqReason::MaxAttemptsExceeded);
}

// --- Rebalance (4) ---

#[tokio::test]
async fn rebalance_crash_before_persist() {
    let _g = with_test_env(2);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, gen_before, owners_before) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        rt.set_now_ms(Some(BASE_NOW)).await;
        let (_admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("rb-g2");
        rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let desc = rt.describe_group(&alice, &gid).await.unwrap();
        let gen_before = desc.generation;
        let owners_before = owners(&desc);
        set_test_group_crash_point(Some(GroupCrashPoint::G2_AfterStateMutation));
        let err = rt
            .join_group(&alice, &gid, MemberId::from("B"), None)
            .await
            .unwrap_err();
        assert!(is_simulated_group_crash(&err));
        disarm_group_crash();
        (master, gid, gen_before, owners_before)
    };
    set_test_partition_count(Some(2));
    let rt = reopen(&path, &master, BASE_NOW).await;
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.generation, gen_before);
    assert_eq!(owners(&desc), owners_before);
    assert_eq!(desc.members.len(), 1);
}

#[tokio::test]
async fn rebalance_crash_after_rename() {
    let _g = with_test_env(2);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, gen_before) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        rt.set_now_ms(Some(BASE_NOW)).await;
        let (_admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("rb-g5");
        rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let gen_before = rt.describe_group(&alice, &gid).await.unwrap().generation;
        set_test_group_crash_point(Some(GroupCrashPoint::G5_AfterGroupMetaRename));
        let err = rt
            .join_group(&alice, &gid, MemberId::from("B"), None)
            .await
            .unwrap_err();
        assert!(is_simulated_group_crash(&err));
        disarm_group_crash();
        (master, gid, gen_before)
    };
    set_test_partition_count(Some(2));
    let rt = reopen(&path, &master, BASE_NOW).await;
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.generation, gen_before + 1);
    assert_eq!(desc.members.len(), 2);
    assert_generation_assignment_aligned(&desc);
}

#[tokio::test]
async fn rebalance_pending_survives_crash() {
    let _g = with_test_env(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, gen_after, seq, event_id) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        rt.set_now_ms(Some(BASE_NOW)).await;
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("rb-pending");
        rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
        produce_n(&rt, &admin, 1).await;
        let d = rt
            .group_consume(&alice, &gid, &MemberId::from("A"), generation)
            .await
            .unwrap()
            .expect("event");
        set_test_group_crash_point(Some(GroupCrashPoint::G5_AfterGroupMetaRename));
        let err = rt
            .join_group(&alice, &gid, MemberId::from("B"), None)
            .await
            .unwrap_err();
        assert!(is_simulated_group_crash(&err));
        disarm_group_crash();
        (
            master,
            gid,
            generation + 1,
            d.sequence,
            d.event_id,
        )
    };
    set_test_partition_count(Some(1));
    let rt = reopen(&path, &master, BASE_NOW).await;
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.generation, gen_after);
    let redelivered = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), gen_after)
        .await
        .unwrap()
        .expect("pending survives rebalance crash");
    assert_eq!(redelivered.sequence, seq);
    assert_eq!(redelivered.event_id, event_id);
}

#[tokio::test]
async fn rebalance_crash_never_splits_generation_and_assignment() {
    let _g = with_test_env(3);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        rt.set_now_ms(Some(BASE_NOW)).await;
        let (_admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("rb-split");
        rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        set_test_group_crash_point(Some(GroupCrashPoint::G4_AfterGroupMetaTmpFsync));
        let err = rt
            .join_group(&alice, &gid, MemberId::from("B"), None)
            .await
            .unwrap_err();
        assert!(is_simulated_group_crash(&err));
        disarm_group_crash();
        (master, gid)
    };
    set_test_partition_count(Some(3));
    let rt = reopen(&path, &master, BASE_NOW).await;
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_generation_assignment_aligned(&desc);

    {
        set_test_partition_count(Some(3));
        let rt = Runtime::at_path(&path);
        rt.set_now_ms(Some(BASE_NOW)).await;
        rt.unlock(&master).await.unwrap();
        let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
        rt.join_group(&alice, &gid, MemberId::from("B"), None)
            .await
            .unwrap();
        set_test_group_crash_point(Some(GroupCrashPoint::G5_AfterGroupMetaRename));
        let err = rt
            .join_group(&alice, &gid, MemberId::from("C"), None)
            .await
            .unwrap_err();
        assert!(is_simulated_group_crash(&err));
        disarm_group_crash();
    }
    set_test_partition_count(Some(3));
    let rt = reopen(&path, &master, BASE_NOW).await;
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_generation_assignment_aligned(&desc);
    assert_eq!(desc.members.len(), 3);
}

// --- Expiry (2) ---

#[tokio::test]
async fn expiry_crash_before_persist() {
    let _g = with_test_env(2);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, gen_before) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        rt.set_now_ms(Some(BASE_NOW)).await;
        let (_admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("exp-g2");
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
        set_test_group_crash_point(Some(GroupCrashPoint::G2_AfterStateMutation));
        let err = rt.reconcile_group_leases().await.unwrap_err();
        assert!(is_simulated_group_crash(&err));
        disarm_group_crash();
        (master, gid, gen_before)
    };
    set_test_partition_count(Some(2));
    let rt = reopen(&path, &master, BASE_NOW).await;
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.generation, gen_before);
    assert_eq!(desc.members.len(), 2);
}

#[tokio::test]
async fn expiry_crash_after_rename() {
    let _g = with_test_env(2);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, gen_before) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        rt.set_now_ms(Some(BASE_NOW)).await;
        let (_admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("exp-g5");
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
        rt.set_now_ms(Some(BASE_NOW + DEFAULT_MEMBER_LEASE_MS))
            .await;
        set_test_group_crash_point(Some(GroupCrashPoint::G5_AfterGroupMetaRename));
        let err = rt.reconcile_group_leases().await.unwrap_err();
        assert!(is_simulated_group_crash(&err));
        disarm_group_crash();
        (master, gid, gen_before)
    };
    set_test_partition_count(Some(2));
    let rt = reopen(
        &path,
        &master,
        BASE_NOW + DEFAULT_MEMBER_LEASE_MS,
    )
    .await;
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.generation, gen_before + 1);
    assert_eq!(desc.members.len(), 1);
    assert_eq!(desc.members[0].member_id.as_str(), "A");
    assert_generation_assignment_aligned(&desc);
}

// --- Multi / gaps (2) ---

#[tokio::test]
async fn multi_pending_gapped_ack_survives_restart() {
    let _g = with_test_env(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation, gap_seq, acked_offset, final_offset) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        rt.set_now_ms(Some(BASE_NOW)).await;
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("multi-gap");
        rt.create_group_with_policy(
            &alice,
            gid.clone(),
            &stream,
            multi_flight_policy(8, 5, vec![1_000; 5]),
        )
        .await
        .unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
        produce_n(&rt, &admin, 4).await;
        let deliveries = consume_many(
            &rt,
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            4,
        )
        .await;
        let ack0 = rt
            .group_ack(
                &alice,
                &gid,
                &MemberId::from("A"),
                generation,
                &deliveries[0].delivery.delivery_id,
            )
            .await
            .unwrap();
        let acked_offset = ack0.new_offset;
        rt.group_ack(
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            &deliveries[2].delivery.delivery_id,
        )
        .await
        .unwrap();
        let gap_seq = deliveries[1].sequence;
        let final_offset = deliveries[2].sequence;
        set_test_group_crash_point(Some(GroupCrashPoint::G2_AfterStateMutation));
        let err = rt
            .group_ack(
                &alice,
                &gid,
                &MemberId::from("A"),
                generation,
                &deliveries[3].delivery.delivery_id,
            )
            .await
            .unwrap_err();
        assert!(is_simulated_group_crash(&err));
        disarm_group_crash();
        (master, gid, generation, gap_seq, acked_offset, final_offset)
    };
    set_test_partition_count(Some(1));
    let rt = reopen(&path, &master, BASE_NOW).await;
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, acked_offset);
    let gap = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("gap pending");
    assert_eq!(gap.sequence, gap_seq);
    let ack = rt
        .group_ack(
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            &gap.delivery.delivery_id,
        )
        .await
        .unwrap();
    assert!(ack.advanced);
    assert_eq!(ack.new_offset, final_offset);
}

#[tokio::test]
async fn dlq_gap_contiguous_offset_after_restart() {
    let _g = with_test_env(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation, final_offset) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        rt.set_now_ms(Some(BASE_NOW)).await;
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("dlq-gap");
        rt.create_group_with_policy(
            &alice,
            gid.clone(),
            &stream,
            multi_flight_policy(8, 1, vec![0]),
        )
        .await
        .unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
        produce_n(&rt, &admin, 4).await;
        let deliveries = consume_many(
            &rt,
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            4,
        )
        .await;
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
        rt.group_ack(
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            &deliveries[3].delivery.delivery_id,
        )
        .await
        .unwrap();
        let final_offset = offset_of(&rt, &alice, &gid, 0).await;
        rt.lock().await.unwrap();
        (master, gid, generation, final_offset)
    };
    set_test_partition_count(Some(1));
    let rt = reopen(&path, &master, BASE_NOW).await;
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, final_offset);
    assert_eq!(rt.list_group_dlq(&alice, &gid).await.unwrap().len(), 2);
    assert!(rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .is_none());
}

// --- Restart / GC (3) ---

#[tokio::test]
async fn restart_preserves_offsets_pending_dlq_and_generation() {
    let _g = with_test_env(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (
        master,
        gid,
        generation,
        offset_after_ack,
        pending_seq,
        dlq_seq,
        offset_final,
    ) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        rt.set_now_ms(Some(BASE_NOW)).await;
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("restart-all");
        rt.create_group_with_policy(
            &alice,
            gid.clone(),
            &stream,
            multi_flight_policy(4, 1, vec![0]),
        )
        .await
        .unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
        produce_n(&rt, &admin, 3).await;
        let deliveries = consume_many(
            &rt,
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            3,
        )
        .await;
        rt.heartbeat_group_member(&alice, &gid, &MemberId::from("A"))
            .await
            .unwrap();
        rt.group_ack(
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            &deliveries[0].delivery.delivery_id,
        )
        .await
        .unwrap();
        let offset_after_ack = offset_of(&rt, &alice, &gid, 0).await;
        retry_to_dlq(
            &rt,
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            &deliveries[1].delivery.delivery_id,
        )
        .await;
        let dlq_seq = deliveries[1].sequence;
        let pending_seq = deliveries[2].sequence;
        let offset_final = offset_of(&rt, &alice, &gid, 0).await;
        rt.lock().await.unwrap();
        (
            master,
            gid,
            generation,
            offset_after_ack,
            pending_seq,
            dlq_seq,
            offset_final,
        )
    };
    set_test_partition_count(Some(1));
    let rt = reopen(&path, &master, BASE_NOW).await;
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.generation, generation);
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, offset_final);
    assert!(offset_final >= offset_after_ack);
    assert!(rt
        .get_group_dlq_entry(&alice, &gid, 0, dlq_seq)
        .await
        .is_ok());
    let pending = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("pending preserved");
    assert_eq!(pending.sequence, pending_seq);
}

#[tokio::test]
async fn dlq_metadata_survives_while_offset_advances_for_gc_pin() {
    let _g = with_test_env(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, seq) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        rt.set_now_ms(Some(BASE_NOW)).await;
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("gc-pin");
        rt.create_group_with_policy(&alice, gid.clone(), &stream, dlq_policy(1))
            .await
            .unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
        produce_n(&rt, &admin, 1).await;
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
        assert!(dlq.advanced);
        assert_eq!(offset_of(&rt, &alice, &gid, 0).await, d.sequence);
        rt.lock().await.unwrap();
        (master, gid, d.sequence)
    };
    set_test_partition_count(Some(1));
    let rt = reopen(&path, &master, BASE_NOW).await;
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, seq);
    let entry = rt
        .get_group_dlq_entry(&alice, &gid, 0, seq)
        .await
        .unwrap();
    assert_eq!(entry.sequence, seq);
    assert_eq!(rt.list_group_dlq(&alice, &gid).await.unwrap().len(), 1);
}

#[tokio::test]
async fn tmp_file_after_crash_is_not_authoritative() {
    let _g = with_test_env(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation, offset_before, seq) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        rt.set_now_ms(Some(BASE_NOW)).await;
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("tmp-ignore");
        rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
        produce_n(&rt, &admin, 1).await;
        let d = rt
            .group_consume(&alice, &gid, &MemberId::from("A"), generation)
            .await
            .unwrap()
            .expect("event");
        let offset_before = offset_of(&rt, &alice, &gid, 0).await;
        set_test_group_crash_point(Some(GroupCrashPoint::G4_AfterGroupMetaTmpFsync));
        let err = rt
            .group_ack(
                &alice,
                &gid,
                &MemberId::from("A"),
                generation,
                &d.delivery.delivery_id,
            )
            .await
            .unwrap_err();
        assert!(is_simulated_group_crash(&err));
        disarm_group_crash();
        let (meta, tmp) = group_meta_paths(&path);
        assert!(tmp.is_file());
        assert!(meta.is_file());
        let tmp_bytes = fs::read(&tmp).unwrap();
        let meta_bytes = fs::read(&meta).unwrap();
        assert_ne!(tmp_bytes, meta_bytes, "tmp should differ from committed meta");
        (master, gid, generation, offset_before, d.sequence)
    };
    set_test_partition_count(Some(1));
    let rt = reopen(&path, &master, BASE_NOW).await;
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, offset_before);
    let redelivered = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("authoritative meta wins");
    assert_eq!(redelivered.sequence, seq);
}
