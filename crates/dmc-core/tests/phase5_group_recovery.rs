//! Phase 5.8.7 — Group delivery recovery (restart / crash / backoff / stale id).
//! No rebalance ownership transfer (5.8.8), no full retry/DLQ (5.8.9–5.8.10).

use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{
    Error, GroupId, GroupPolicy, GroupRetryResponse, MemberId, SessionId, StreamId,
};
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

fn multi_flight(max_in_flight: u32) -> GroupPolicy {
    GroupPolicy {
        max_in_flight,
        ..Default::default()
    }
}

fn backoff_policy(backoff_ms: u64) -> GroupPolicy {
    GroupPolicy {
        retry: dmc_core::GroupRetryPolicy {
            max_attempts: 5,
            backoff_ms: vec![backoff_ms, backoff_ms, backoff_ms, backoff_ms, backoff_ms],
        },
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
async fn restart_redelivers_pending_with_new_delivery_id() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation, seq, event_id, d1, offset_before) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("rec-basic");
        rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
        let offset_before = offset_of(&rt, &alice, &gid, 0).await;
        rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
            .await
            .unwrap();
        let d = rt
            .group_consume(&alice, &gid, &MemberId::from("A"), generation)
            .await
            .unwrap()
            .expect("event");
        assert_eq!(offset_of(&rt, &alice, &gid, 0).await, offset_before);
        rt.lock().await.unwrap();
        (
            master,
            gid,
            generation,
            d.sequence,
            d.event_id.clone(),
            d.delivery.delivery_id.clone(),
            offset_before,
        )
    };
    set_test_partition_count(Some(1));
    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, offset_before);
    let d2 = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("redelivery");
    assert_eq!(d2.sequence, seq);
    assert_eq!(d2.event_id, event_id);
    assert_ne!(d2.delivery.delivery_id, d1);
    assert_eq!(d2.delivery.attempt, 2);
}

#[tokio::test]
async fn multi_pending_recovery_is_sequence_asc() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation, old) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("rec-multi");
        rt.create_group_with_policy(
            &alice,
            gid.clone(),
            &stream,
            GroupPolicy {
                max_in_flight: 4,
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
        let seqs: Vec<_> = deliveries.iter().map(|d| d.sequence).collect();
        assert!(seqs.windows(2).all(|w| w[0] < w[1]));
        rt.lock().await.unwrap();
        (master, gid, generation, deliveries)
    };
    set_test_partition_count(Some(1));
    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();

    let mut recovered = Vec::new();
    for _ in 0..4 {
        recovered.push(
            rt.group_consume(&alice, &gid, &MemberId::from("A"), generation)
                .await
                .unwrap()
                .expect("recovery"),
        );
    }
    for (old_d, new_d) in old.iter().zip(recovered.iter()) {
        assert_eq!(new_d.sequence, old_d.sequence);
        assert_eq!(new_d.event_id, old_d.event_id);
        assert_ne!(new_d.delivery.delivery_id, old_d.delivery.delivery_id);
        assert!(new_d.delivery.attempt >= 2);
    }
    assert!(recovered.windows(2).all(|w| w[0].sequence < w[1].sequence));

    // Still at max_in_flight: explicit retry required before redelivery.
    let lowest_id = recovered[0].delivery.delivery_id.clone();
    rt.group_retry(
        &alice,
        &gid,
        &MemberId::from("A"),
        generation,
        &lowest_id,
    )
    .await
    .unwrap();
    let again = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("retry redelivery");
    assert_eq!(again.sequence, old[0].sequence);
}

#[tokio::test]
async fn stale_pre_restart_delivery_ids_rejected_after_recovery() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation, old_ids) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("rec-stale");
        rt.create_group_with_policy(&alice, gid.clone(), &stream, multi_flight(3))
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
        let mut ids = Vec::new();
        for _ in 0..3 {
            let d = rt
                .group_consume(&alice, &gid, &MemberId::from("A"), generation)
                .await
                .unwrap()
                .expect("event");
            ids.push(d.delivery.delivery_id.clone());
        }
        rt.lock().await.unwrap();
        (master, gid, generation, ids)
    };
    set_test_partition_count(Some(1));
    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();

    let mut new_ids = Vec::new();
    for _ in 0..3 {
        let d = rt
            .group_consume(&alice, &gid, &MemberId::from("A"), generation)
            .await
            .unwrap()
            .expect("recovery");
        new_ids.push(d.delivery.delivery_id.clone());
    }
    for old in &old_ids {
        let err = rt
            .group_ack(&alice, &gid, &MemberId::from("A"), generation, old)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::StaleDelivery(_)), "got {err}");
    }
    for new_id in &new_ids {
        rt.group_ack(&alice, &gid, &MemberId::from("A"), generation, new_id)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn ack_after_restart_advances_offset() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation, before) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("rec-ack");
        rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
        let before = offset_of(&rt, &alice, &gid, 0).await;
        rt.put_data(&admin, "company/finance/tx/1", br#"{"v":1}"#)
            .await
            .unwrap();
        let _ = rt
            .group_consume(&alice, &gid, &MemberId::from("A"), generation)
            .await
            .unwrap()
            .expect("event");
        rt.lock().await.unwrap();
        (master, gid, generation, before)
    };
    set_test_partition_count(Some(1));
    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, before);
    let d = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("redelivery");
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
    assert!(ack.advanced);
    assert_eq!(ack.new_offset, d.sequence);
}

#[tokio::test]
async fn backoff_does_not_bump_attempt() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    rt.set_now_ms(Some(10_000)).await;
    let (admin, alice, stream) = setup_finance(&rt).await;
    let gid = GroupId::from("rec-backoff");
    rt.create_group_with_policy(&alice, gid.clone(), &stream, backoff_policy(60_000))
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
    assert_eq!(d1.delivery.attempt, 1);
    let GroupRetryResponse::Retry(retry) = rt
        .group_retry(
            &alice,
            &gid,
            &MemberId::from("A"),
            generation,
            &d1.delivery.delivery_id,
        )
        .await
        .unwrap()
    else {
        panic!("expected retry schedule");
    };
    assert_eq!(retry.attempt, 1);
    assert_eq!(retry.retry_at_ms, 70_000);
    let err = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap_err();
    match err {
        Error::GroupRetryBackoff {
            sequence,
            attempt,
            retry_at_ms,
            ..
        } => {
            assert_eq!(sequence, d1.sequence);
            assert_eq!(attempt, 1, "backoff must not bump attempt");
            assert_eq!(retry_at_ms, 70_000);
        }
        other => panic!("expected GroupRetryBackoff, got {other}"),
    }
}

#[tokio::test]
async fn crash_recovery_bypasses_backoff() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation, seq, attempt) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("rec-bypass");
        rt.create_group_with_policy(&alice, gid.clone(), &stream, backoff_policy(60_000))
            .await
            .unwrap();
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
        (master, gid, generation, d.sequence, d.delivery.attempt)
    };
    set_test_partition_count(Some(1));
    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    let d2 = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .expect("crash recovery bypasses backoff");
    assert_eq!(d2.sequence, seq);
    assert_eq!(d2.delivery.attempt, attempt + 1);
}

#[tokio::test]
async fn recovery_does_not_change_group_offset() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation, offset) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("rec-offset");
        rt.create_group_with_policy(&alice, gid.clone(), &stream, multi_flight(2))
            .await
            .unwrap();
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
        let _ = rt
            .group_consume(&alice, &gid, &MemberId::from("A"), generation)
            .await
            .unwrap();
        let _ = rt
            .group_consume(&alice, &gid, &MemberId::from("A"), generation)
            .await
            .unwrap();
        let offset = offset_of(&rt, &alice, &gid, 0).await;
        rt.lock().await.unwrap();
        (master, gid, generation, offset)
    };
    set_test_partition_count(Some(1));
    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    let _ = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap();
    let _ = rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap();
    assert_eq!(offset_of(&rt, &alice, &gid, 0).await, offset);
}

#[tokio::test]
async fn authz_denied_before_pending_recovery() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("rec-authz");
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
        rt.lock().await.unwrap();
        (master, gid, generation)
    };
    set_test_partition_count(Some(1));
    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    rt.create_role(
        &admin,
        "hr".into(),
        "HR".into(),
        KeyPath::parse("company/hr").unwrap(),
        PermissionSet::empty().with(Permission::Read),
    )
    .await
    .unwrap();
    rt.create_user(&admin, "carol".into(), vec!["hr".into()])
        .await
        .unwrap();
    let carol = rt.open_user_session("carol", Some("dev-c")).await.unwrap();
    let err = rt
        .group_consume(&carol, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::AuthorizationDenied(_)),
        "pending must not bypass AuthZ, got {err}"
    );
}

#[tokio::test]
async fn max_in_flight_respected_after_recovery() {
    let _g = with_partitions(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, generation, first_four) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (admin, alice, stream) = setup_finance(&rt).await;
        let gid = GroupId::from("rec-cap");
        rt.create_group_with_policy(&alice, gid.clone(), &stream, multi_flight(4))
            .await
            .unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
        for i in 1..=6 {
            rt.put_data(
                &admin,
                &format!("company/finance/tx/{i}"),
                format!(r#"{{"v":{i}}}"#).as_bytes(),
            )
            .await
            .unwrap();
        }
        let mut first_four = Vec::new();
        for _ in 0..4 {
            first_four.push(
                rt.group_consume(&alice, &gid, &MemberId::from("A"), generation)
                    .await
                    .unwrap()
                    .expect("event")
                    .sequence,
            );
        }
        rt.lock().await.unwrap();
        (master, gid, generation, first_four)
    };
    set_test_partition_count(Some(1));
    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    let mut recovered = Vec::new();
    for _ in 0..4 {
        recovered.push(
            rt.group_consume(&alice, &gid, &MemberId::from("A"), generation)
                .await
                .unwrap()
                .expect("recovery")
                .sequence,
        );
    }
    assert_eq!(recovered, first_four);
    assert!(rt
        .group_consume(&alice, &gid, &MemberId::from("A"), generation)
        .await
        .unwrap()
        .is_none());
}
