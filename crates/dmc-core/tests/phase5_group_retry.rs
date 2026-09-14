//! Phase 5.8.9 — explicit group_retry + deterministic retry policy.

use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{
    Error, GroupId, GroupPolicy, GroupRetryPolicy, GroupRetryResponse, GroupRetryResult, MemberId,
    SessionId, StreamId,
};
use dmc_journal::set_test_partition_count;
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};

const BASE_NOW: u64 = 100_000;

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

fn unwrap_retry(response: GroupRetryResponse) -> GroupRetryResult {
    match response {
        GroupRetryResponse::Retry(retry) => retry,
        GroupRetryResponse::Dlq(_) => panic!("expected retry schedule, got DLQ"),
    }
}

#[tokio::test]
async fn default_retry_policy_on_create() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("retry-default");
    let group = rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    assert_eq!(group.policy.retry.max_attempts, 5);
    assert_eq!(
        group.policy.retry.backoff_ms,
        vec![0, 1_000, 5_000, 30_000, 60_000]
    );
}

#[tokio::test]
async fn custom_max_attempts_and_backoff() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("retry-custom");
    let group = rt
        .create_group_with_policy(
            &alice,
            gid.clone(),
            &stream,
            retry_policy(3, vec![100, 200, 300]),
        )
        .await
        .unwrap();
    assert_eq!(group.policy.retry.max_attempts, 3);
    assert_eq!(group.policy.retry.backoff_ms, vec![100, 200, 300]);
}

#[tokio::test]
async fn retry_schedules_backoff_without_new_delivery() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    rt.set_now_ms(Some(BASE_NOW)).await;
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("retry-schedule");
    rt.create_group_with_policy(
        &alice,
        gid.clone(),
        &stream,
        retry_policy(5, vec![5_000, 1_000, 5_000, 30_000, 60_000]),
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
    let before = offset_of(&rt, &alice, &gid, 0).await;
    let d1 = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("event");
    assert_eq!(d1.delivery.attempt, 1);
    let retry = unwrap_retry(
        rt.group_retry(
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            &d1.delivery.delivery_id,
        )
        .await
        .unwrap(),
    );
    assert_eq!(retry.attempt, 1);
    assert_eq!(retry.retry_at_ms, BASE_NOW + 5_000);
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, before);
    assert!(rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap_err()
        .to_string()
        .contains("retry at"));
}

#[tokio::test]
async fn retry_after_backoff_issues_new_delivery() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    rt.set_now_ms(Some(BASE_NOW)).await;
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("retry-redeliver");
    rt.create_group_with_policy(
        &alice,
        gid.clone(),
        &stream,
        retry_policy(5, vec![0, 1_000, 5_000, 30_000, 60_000]),
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
    rt.set_now_ms(Some(BASE_NOW + 1_000)).await;
    let d2 = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("redelivery");
    assert_eq!(d1.sequence, d2.sequence);
    assert_eq!(d1.event_id, d2.event_id);
    assert_ne!(d1.delivery.delivery_id, d2.delivery.delivery_id);
    assert_eq!(d2.delivery.attempt, 2);
}

#[tokio::test]
async fn retry_invalidates_old_delivery_for_ack() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("retry-stale-ack");
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
}

#[tokio::test]
async fn consume_without_retry_does_not_redeliver_in_flight() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("retry-no-auto");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
    rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
        .await
        .unwrap();
    let _ = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("event");
    assert!(rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn retry_one_pending_while_others_remain() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    rt.set_now_ms(Some(BASE_NOW)).await;
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("retry-multi");
    rt.create_group_with_policy(
        &alice,
        gid.clone(),
        &stream,
        multi_flight_policy(3, 5, vec![0, 1_000, 5_000, 30_000, 60_000]),
    )
    .await
    .unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
    for i in 1..=3 {
        rt.put_data(
            &admin,
            &format!("company/finance/tx/{i}"),
            format!(r#"{{"v":{i}}}"#).as_bytes(),
        )
        .await
        .unwrap();
    }
    let mut deliveries = Vec::new();
    for _ in 0..3 {
        deliveries.push(
            rt.group_consume(&alice, &gid, &MemberId::from("A"), generation)
                .await
                .unwrap()
                .expect("event"),
        );
    }
    let before = offset_of(&rt, &alice, &gid, 0).await;
    let retry = unwrap_retry(
        rt.group_retry(
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            &deliveries[1].delivery.delivery_id,
        )
        .await
        .unwrap(),
    );
    assert_eq!(retry.sequence, deliveries[1].sequence);
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, before);
    assert!(rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn stale_generation_cannot_retry() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("retry-stale-gen");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    let old_gen = rt.describe_group(&alice, &gid).await.unwrap().generation;
    rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
        .await
        .unwrap();
    let d1 = rt
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
            &d1.delivery.delivery_id,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::StaleGeneration { .. }), "got {err}");
}

#[tokio::test]
async fn stale_delivery_cannot_retry_after_redelivery() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    rt.set_now_ms(Some(BASE_NOW)).await;
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("retry-stale-id");
    rt.create_group_with_policy(
        &alice,
        gid.clone(),
        &stream,
        retry_policy(5, vec![0, 0, 0, 0, 0]),
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
    let err = rt
        .group_retry(
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            &d1.delivery.delivery_id,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::StaleDelivery(_)), "got {err}");
    assert_ne!(d1.delivery.delivery_id, d2.delivery.delivery_id);
}

#[tokio::test]
async fn retry_state_survives_restart() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation, delivery_id, retry_at_ms) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        rt.set_now_ms(Some(BASE_NOW)).await;
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("retry-restart");
        rt.create_group_with_policy(
            &alice,
            gid.clone(),
            &stream,
            retry_policy(5, vec![0, 7_000, 7_000, 7_000, 7_000]),
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
            .expect("event");
        let retry = unwrap_retry(
            rt.group_retry(
                &alice,
                &gid,
                &MemberId::from("A"),
                generation,
                &d1.delivery.delivery_id,
            )
            .await
            .unwrap(),
        );
        rt.heartbeat_group_member(&alice, &gid, &MemberId::from("A"))
            .await
            .unwrap();
        rt.lock().await.unwrap();
        (
            master,
            gid,
            generation,
            d1.delivery.delivery_id,
            retry.retry_at_ms,
        )
    };
    set_test_partition_count(Some(1));
    let rt = Runtime::at_path(&path);
    rt.set_now_ms(Some(retry_at_ms - 1)).await;
    rt.unlock(&master).await.unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    let err = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::GroupRetryBackoff { .. }), "got {err}");
    rt.set_now_ms(Some(retry_at_ms)).await;
    let d2 = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("after restart");
    assert_eq!(d2.delivery.attempt, 2);
    assert_ne!(d2.delivery.delivery_id, delivery_id);
}

#[tokio::test]
async fn max_attempts_moves_to_dlq() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    rt.set_now_ms(Some(BASE_NOW)).await;
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("retry-exhaust");
    rt.create_group_with_policy(
        &alice,
        gid.clone(),
        &stream,
        retry_policy(2, vec![0, 0]),
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
        .expect("attempt 2");
    assert_eq!(d2.delivery.attempt, 2);
    match rt
        .group_retry(
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            &d2.delivery.delivery_id,
        )
        .await
        .unwrap()
    {
        GroupRetryResponse::Dlq(dlq) => {
            assert_eq!(dlq.sequence, d1.sequence);
            assert!(dlq.advanced);
            assert!(dlq.new_offset >= d1.sequence);
            let entry = rt
                .get_group_dlq_entry(&alice, &gid, 0, d1.sequence)
                .await
                .unwrap();
            assert_eq!(entry.event_id, d1.event_id);
        }
        other => panic!("expected DLQ, got {other:?}"),
    }
    let err = rt
        .group_retry(
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            &d2.delivery.delivery_id,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::StaleDelivery(_)), "got {err}");
    assert!(offset_of(&rt, &alice, &gid, 0).await >= d1.sequence);
}

#[tokio::test]
async fn retry_after_rebalance_uses_new_generation() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    rt.set_now_ms(Some(BASE_NOW)).await;
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("retry-rebalance");
    rt.create_group_with_policy(
        &alice,
        gid.clone(),
        &stream,
        retry_policy(5, vec![0, 0, 0, 0, 0]),
    )
    .await
    .unwrap();
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
        .expect("recovery redelivery");
    assert_eq!(d2.sequence, d1.sequence);
    assert_eq!(d2.delivery.generation, gen_b);
    assert!(d2.delivery.attempt >= 2);
}
