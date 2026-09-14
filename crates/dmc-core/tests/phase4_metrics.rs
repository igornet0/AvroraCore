use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{RetryPolicy, SessionId, StreamId};
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};

async fn setup(rt: &Runtime) -> (SessionId, SessionId, StreamId) {
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

#[tokio::test]
async fn lag_tracks_pending_and_clears_after_ack() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, RetryPolicy::immediate())
        .await
        .unwrap();
    rt.put_data(&admin, "company/finance/a", b"1").await.unwrap();
    rt.put_data(&admin, "company/finance/b", b"2").await.unwrap();

    let before = rt.consumer_lag(&sub.id).await.unwrap();
    let head = rt.last_sequence().await;
    assert_eq!(before.journal_head, head);
    assert_eq!(before.offset, 0);
    assert_eq!(before.lag_events, head);
    assert!(before.pending.is_none());

    let ev = rt.consume(&sub.id, 1).await.unwrap();
    let mid = rt.consumer_lag(&sub.id).await.unwrap();
    assert_eq!(mid.pending.as_ref().unwrap().sequence, ev[0].sequence);
    assert!(mid.lag_events > 0);

    rt.ack(&alice, &sub.id, &ev[0].delivery.delivery_id)
        .await
        .unwrap();
    let ev2 = rt.consume(&sub.id, 1).await.unwrap();
    rt.ack(&alice, &sub.id, &ev2[0].delivery.delivery_id)
        .await
        .unwrap();
    let done = rt.consumer_lag(&sub.id).await.unwrap();
    assert_eq!(done.offset, ev2[0].sequence);
    assert_eq!(done.lag_events, 0);
    assert!(done.pending.is_none());
    assert_eq!(done.dlq_count, 0);
}

#[tokio::test]
async fn metrics_count_dlq_entries() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(
        &alice,
        &sub.id,
        RetryPolicy {
            max_attempts: 1,
            initial_backoff_ms: 0,
            max_backoff_ms: 0,
            multiplier: 2,
        },
    )
    .await
    .unwrap();
    rt.put_data(&admin, "company/finance/a", b"1").await.unwrap();
    rt.put_data(&admin, "company/finance/b", b"2").await.unwrap();
    let _ = rt.consume(&sub.id, 1).await.unwrap();
    let next = rt.consume(&sub.id, 1).await.unwrap();
    assert_eq!(next[0].payload, b"2");
    let lag = rt.consumer_lag(&sub.id).await.unwrap();
    assert_eq!(lag.dlq_count, 1);
    let metrics = rt.consumer_metrics().await.unwrap();
    assert_eq!(metrics.total_dlq, 1);
    assert_eq!(metrics.journal_head, rt.last_sequence().await);
}
