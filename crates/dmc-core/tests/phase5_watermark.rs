use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{RetryPolicy, StreamId};
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};

async fn setup_finance_read(rt: &Runtime) -> (dmc_core::SessionId, dmc_core::SessionId, StreamId) {
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

async fn publish_snapshot(rt: &Runtime) -> u64 {
    rt.force_snapshot().await.unwrap()
}

#[tokio::test]
async fn fresh_database_has_no_trim_watermark() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let wm = rt.retention_watermark().await.unwrap();
    assert_eq!(wm.trim_through, None);
}

#[tokio::test]
async fn snapshot_pin_enables_trim_floor() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    rt.put_data(&admin, "company/finance/x", b"1").await.unwrap();
    publish_snapshot(&rt).await;
    let wm = rt.retention_watermark().await.unwrap();
    assert_eq!(wm.trim_through, Some(1));
}

#[tokio::test]
async fn consumer_offset_lowers_watermark_below_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, RetryPolicy::immediate())
        .await
        .unwrap();

    for i in 0..5 {
        rt.put_data(
            &admin,
            &format!("company/finance/x/{i}"),
            format!("{i}").as_bytes(),
        )
        .await
        .unwrap();
    }
    publish_snapshot(&rt).await;
    let ev = rt.consume(&sub.id, 1).await.unwrap();
    assert_eq!(ev.len(), 1);
    rt.ack(&alice, &sub.id, &ev[0].delivery.delivery_id)
        .await
        .unwrap();
    let ack_seq = ev[0].sequence;
    let wm = rt.retention_watermark().await.unwrap();
    assert_eq!(wm.trim_through, Some(ack_seq));
}

#[tokio::test]
async fn pending_delivery_preserves_next_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, RetryPolicy::immediate())
        .await
        .unwrap();

    rt.put_data(&admin, "company/finance/a", b"1").await.unwrap();
    rt.put_data(&admin, "company/finance/b", b"2").await.unwrap();
    publish_snapshot(&rt).await;
    let first = rt.consume(&sub.id, 1).await.unwrap();
    let seq = first[0].sequence;
    let wm = rt.retention_watermark().await.unwrap();
    assert_eq!(wm.trim_through, Some(0));
    assert!(rt.pending_delivery(&sub.id).await.unwrap().is_some());
    assert!(seq >= 1);
}

#[tokio::test]
async fn replay_lease_pins_history_below_consumer_offset() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, RetryPolicy::immediate())
        .await
        .unwrap();

    for i in 0..20 {
        rt.put_data(
            &admin,
            &format!("company/finance/n/{i}"),
            b"x",
        )
        .await
        .unwrap();
    }
    publish_snapshot(&rt).await;
    for _ in 0..15 {
        let batch = rt.consume(&sub.id, 1).await.unwrap();
        rt.ack(&alice, &sub.id, &batch[0].delivery.delivery_id)
            .await
            .unwrap();
    }
    let before = rt.retention_watermark().await.unwrap();
    assert!(before.trim_through.unwrap() >= 15);

    let lease = rt
        .begin_replay_lease(&sub.id, 5, 60_000)
        .await
        .unwrap();
    let with_replay = rt.retention_watermark().await.unwrap();
    assert_eq!(with_replay.trim_through, Some(4));

    rt.end_replay_lease(&lease).await.unwrap();
    let after = rt.retention_watermark().await.unwrap();
    assert_eq!(after.trim_through, before.trim_through);
}

#[tokio::test]
async fn trim_journal_requires_snapshot_pin() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    rt.put_data(&admin, "company/x", b"1").await.unwrap();
    let err = rt.trim_journal().await.unwrap_err();
    assert!(err.to_string().to_lowercase().contains("unsafe"));
}

#[tokio::test]
async fn trim_journal_through_watermark_succeeds_with_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    rt.put_data(&admin, "company/x", b"1").await.unwrap();
    rt.force_snapshot().await.unwrap();
    rt.trim_journal().await.unwrap();
}
