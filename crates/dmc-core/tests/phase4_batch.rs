use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{BatchLimits, RetryPolicy, SessionId, StreamId};
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
async fn ack_batch_advances_offset_and_is_idempotent() {
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

    let batch = rt
        .consume_batch(&sub.id, BatchLimits::one())
        .await
        .unwrap();
    assert_eq!(batch.len(), 1);
    let id = batch[0].delivery.delivery_id.clone();
    let seq = batch[0].sequence;
    let result = rt
        .ack_batch(&alice, &sub.id, &[id.clone(), id.clone()])
        .await
        .unwrap();
    assert_eq!(result.offset, seq);
    assert_eq!(result.acked.len(), 2);
    assert!(result.stale.is_empty());
    assert_eq!(
        rt.get_subscription(&sub.id).await.unwrap().position.sequence,
        seq
    );
}

#[tokio::test]
async fn ack_batch_reports_stale_without_failing_current() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, RetryPolicy::immediate())
        .await
        .unwrap();
    rt.put_data(&admin, "company/finance/a", b"1").await.unwrap();

    let first = rt.consume(&sub.id, 1).await.unwrap();
    let stale = first[0].delivery.delivery_id.clone();
    let second = rt.consume(&sub.id, 1).await.unwrap();
    let current = second[0].delivery.delivery_id.clone();
    assert_ne!(stale, current);

    let result = rt
        .ack_batch(&alice, &sub.id, &[stale.clone(), current.clone()])
        .await
        .unwrap();
    assert_eq!(result.acked, vec![current.to_string()]);
    assert_eq!(result.stale, vec![stale.to_string()]);
    assert_eq!(result.offset, second[0].sequence);
    assert!(rt.pending_delivery(&sub.id).await.unwrap().is_none());
}

#[tokio::test]
async fn consume_batch_v1_returns_at_most_one_event() {
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
    let batch = rt
        .consume_batch(
            &sub.id,
            BatchLimits {
                max_events: 8,
                max_bytes: 1_048_576,
            },
        )
        .await
        .unwrap();
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].payload, b"1");
}
