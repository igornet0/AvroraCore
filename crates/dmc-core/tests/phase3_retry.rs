use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{Error, RetryPolicy, SessionId, StreamId};
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};

async fn setup_finance_read(rt: &Runtime) -> (SessionId, SessionId, StreamId) {
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

fn backoff_policy(max_attempts: u32, initial_ms: u64) -> RetryPolicy {
    RetryPolicy {
        max_attempts,
        initial_backoff_ms: initial_ms,
        max_backoff_ms: 30_000,
        multiplier: 2,
    }
}

#[tokio::test]
async fn consume_waits_exponential_backoff_before_next_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, backoff_policy(5, 1_000))
        .await
        .unwrap();
    rt.put_data(&admin, "company/finance/inv/1", b"one")
        .await
        .unwrap();

    rt.set_now_ms(Some(10_000)).await;
    let d1 = rt.consume(&sub.id, 1).await.unwrap();
    assert_eq!(d1[0].delivery.attempt, 1);

    let err = rt.consume(&sub.id, 1).await.unwrap_err();
    match err {
        Error::RetryBackoff {
            sequence,
            attempt,
            retry_at_ms,
            ..
        } => {
            assert_eq!(sequence, d1[0].sequence);
            assert_eq!(attempt, 1);
            assert_eq!(retry_at_ms, 11_000);
        }
        other => panic!("expected RetryBackoff, got {other}"),
    }
    let pending = rt.pending_delivery(&sub.id).await.unwrap().unwrap();
    assert_eq!(pending.attempt, 1);
    assert_eq!(pending.last_delivery_id, d1[0].delivery.delivery_id);

    rt.set_now_ms(Some(11_000)).await;
    let d2 = rt.consume(&sub.id, 1).await.unwrap();
    assert_eq!(d2[0].sequence, d1[0].sequence);
    assert_eq!(d2[0].delivery.attempt, 2);
    assert_ne!(d2[0].delivery.delivery_id, d1[0].delivery.delivery_id);

    let err = rt.consume(&sub.id, 1).await.unwrap_err();
    match err {
        Error::RetryBackoff { retry_at_ms, attempt, .. } => {
            assert_eq!(attempt, 2);
            assert_eq!(retry_at_ms, 13_000);
        }
        other => panic!("expected RetryBackoff after attempt 2, got {other}"),
    }
}

#[tokio::test]
async fn ack_during_backoff_advances_offset() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, backoff_policy(5, 5_000))
        .await
        .unwrap();
    rt.put_data(&admin, "company/finance/a", b"1").await.unwrap();
    rt.put_data(&admin, "company/finance/b", b"2").await.unwrap();
    rt.set_now_ms(Some(1_000)).await;
    let d1 = rt.consume(&sub.id, 1).await.unwrap();
    assert!(matches!(
        rt.consume(&sub.id, 1).await.unwrap_err(),
        Error::RetryBackoff { .. }
    ));
    rt.ack(&alice, &sub.id, &d1[0].delivery.delivery_id)
        .await
        .unwrap();
    let next = rt.consume(&sub.id, 1).await.unwrap();
    assert_eq!(next[0].payload, b"2");
    assert_eq!(next[0].delivery.attempt, 1);
}

#[tokio::test]
async fn max_attempts_moves_event_to_dlq_and_continues() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(
        &alice,
        &sub.id,
        RetryPolicy {
            max_attempts: 2,
            initial_backoff_ms: 0,
            max_backoff_ms: 0,
            multiplier: 2,
        },
    )
    .await
    .unwrap();
    rt.put_data(&admin, "company/finance/inv/1", b"one")
        .await
        .unwrap();
    rt.put_data(&admin, "company/finance/inv/2", b"two")
        .await
        .unwrap();

    let d1 = rt.consume(&sub.id, 1).await.unwrap();
    let d2 = rt.consume(&sub.id, 1).await.unwrap();
    assert_eq!(d2[0].delivery.attempt, 2);
    let next = rt.consume(&sub.id, 1).await.unwrap();
    assert_eq!(next[0].payload, b"two");
    assert_eq!(next[0].delivery.attempt, 1);
    assert!(rt.pending_delivery(&sub.id).await.unwrap().is_some());
    assert_eq!(rt.get_subscription(&sub.id).await.unwrap().position.sequence, 0);
    let dlq = rt.list_dlq(&admin, &sub.id).await.unwrap();
    assert_eq!(dlq.len(), 1);
    assert_eq!(dlq[0].original_sequence, d1[0].sequence);
    assert_eq!(dlq[0].attempts, 2);

    rt.ack(&alice, &sub.id, &next[0].delivery.delivery_id)
        .await
        .unwrap();
}

#[tokio::test]
async fn exhausted_subscription_does_not_block_another() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    rt.create_user(&admin, "bob".into(), vec!["finance".into()])
        .await
        .unwrap();
    let bob = rt.open_user_session("bob", Some("dev-b")).await.unwrap();
    let sub_a = rt.create_subscription(&alice, &stream, None).await.unwrap();
    let sub_b = rt.create_subscription(&bob, &stream, None).await.unwrap();
    let tight = RetryPolicy {
        max_attempts: 1,
        initial_backoff_ms: 0,
        max_backoff_ms: 0,
        multiplier: 2,
    };
    rt.set_retry_policy(&alice, &sub_a.id, tight).await.unwrap();
    rt.set_retry_policy(&bob, &sub_b.id, RetryPolicy::immediate())
        .await
        .unwrap();
    rt.put_data(&admin, "company/finance/inv/1", b"one")
        .await
        .unwrap();

    let _ = rt.consume(&sub_a.id, 1).await.unwrap();
    let drained = rt.consume(&sub_a.id, 1).await.unwrap();
    assert!(drained.is_empty());
    assert_eq!(rt.list_dlq(&admin, &sub_a.id).await.unwrap().len(), 1);
    let b1 = rt.consume(&sub_b.id, 1).await.unwrap();
    assert_eq!(b1[0].delivery.attempt, 1);
    assert_eq!(b1[0].payload, b"one");
}

#[tokio::test]
async fn backoff_survives_restart_until_clock_allows_retry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, sub_id, seq) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (admin, alice, stream) = setup_finance_read(&rt).await;
        let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
        rt.set_retry_policy(&alice, &sub.id, backoff_policy(5, 1_000))
            .await
            .unwrap();
        rt.put_data(&admin, "company/finance/inv/1", b"one")
            .await
            .unwrap();
        rt.set_now_ms(Some(50_000)).await;
        let d1 = rt.consume(&sub.id, 1).await.unwrap();
        (master, sub.id, d1[0].sequence)
    };

    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    rt.set_now_ms(Some(50_500)).await;
    assert!(matches!(
        rt.consume(&sub_id, 1).await.unwrap_err(),
        Error::RetryBackoff { retry_at_ms: 51_000, .. }
    ));
    rt.set_now_ms(Some(51_000)).await;
    let d2 = rt.consume(&sub_id, 1).await.unwrap();
    assert_eq!(d2[0].sequence, seq);
    assert_eq!(d2[0].delivery.attempt, 2);
}

#[tokio::test]
async fn replay_ignores_retry_backoff() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, backoff_policy(5, 10_000))
        .await
        .unwrap();
    rt.put_data(&admin, "company/finance/inv/1", b"one")
        .await
        .unwrap();
    rt.set_now_ms(Some(1)).await;
    let d1 = rt.consume(&sub.id, 1).await.unwrap();
    let replayed = rt.replay(&sub.id, d1[0].sequence, 1).await.unwrap();
    assert_eq!(replayed.len(), 1);
    assert_eq!(replayed[0].sequence, d1[0].sequence);
    assert!(rt.pending_delivery(&sub.id).await.unwrap().is_some());
}
