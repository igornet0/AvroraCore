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

async fn put_n(rt: &Runtime, admin: &dmc_core::SessionId, n: u64) {
    for i in 0..n {
        rt.put_data(
            admin,
            &format!("company/finance/item/{i}"),
            format!("v{i}").as_bytes(),
        )
        .await
        .unwrap();
    }
}

async fn restart(dir: &std::path::Path, master: &str, rt: &Runtime) -> Runtime {
    rt.lock().await.unwrap();
    let rt2 = Runtime::at_path(dir.join("store.dbs.json"));
    rt2.unlock(master).await.unwrap();
    rt2
}

#[tokio::test]
async fn trim_journal_uses_watermark_not_beyond_pins() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    put_n(&rt, &admin, 5).await;
    rt.force_snapshot().await.unwrap();
    let err = rt.trim_journal_through(999_999).await.unwrap_err();
    assert!(err.to_string().to_lowercase().contains("watermark"));
}

#[tokio::test]
async fn trim_journal_succeeds_with_snapshot_pin() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    put_n(&rt, &admin, 3).await;
    let snap = rt.force_snapshot().await.unwrap();
    let result = rt.trim_journal().await.unwrap();
    assert_eq!(result.trim_through, snap);
}

#[tokio::test]
async fn consumer_pin_lowers_watermark_below_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, RetryPolicy::immediate())
        .await
        .unwrap();
    put_n(&rt, &admin, 10).await;
    let snap = rt.force_snapshot().await.unwrap();
    let mut last_ack = 0u64;
    for _ in 0..7 {
        let batch = rt.consume(&sub.id, 1).await.unwrap();
        last_ack = batch[0].sequence;
        rt.ack(&alice, &sub.id, &batch[0].delivery.delivery_id)
            .await
            .unwrap();
    }
    let wm = rt.retention_watermark().await.unwrap();
    assert_eq!(wm.trim_through, Some(last_ack.min(snap)));
    assert!(wm.trim_through.unwrap() < snap);
}

#[tokio::test]
async fn replay_pin_lowers_watermark_below_consumer() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, RetryPolicy::immediate())
        .await
        .unwrap();
    put_n(&rt, &admin, 15).await;
    rt.force_snapshot().await.unwrap();
    for _ in 0..12 {
        let batch = rt.consume(&sub.id, 1).await.unwrap();
        rt.ack(&alice, &sub.id, &batch[0].delivery.delivery_id)
            .await
            .unwrap();
    }
    let _lease = rt.begin_replay_lease(&sub.id, 5, 60_000).await.unwrap();
    let wm = rt.retention_watermark().await.unwrap();
    assert_eq!(wm.trim_through, Some(4));
}

#[tokio::test]
async fn trim_idempotent_at_runtime_layer() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    put_n(&rt, &admin, 3).await;
    rt.force_snapshot().await.unwrap();
    rt.trim_journal().await.unwrap();
    let second = rt.trim_journal().await.unwrap();
    assert!(second.deleted_segments.is_empty());
    rt.trim_journal().await.unwrap();
}

#[tokio::test]
async fn trim_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (master, _) = rt.create_dev(false).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    put_n(&rt, &admin, 4).await;
    let seq = rt.force_snapshot().await.unwrap();
    rt.trim_journal().await.unwrap();
    let rt2 = restart(dir.path(), &master, &rt).await;
    assert_eq!(rt2.published_snapshot_sequence().await.unwrap(), Some(seq));
    assert_eq!(rt2.last_sequence().await, rt.last_sequence().await);
}

#[tokio::test]
async fn event_beyond_consumer_pin_not_trimmed_by_watermark() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, RetryPolicy::immediate())
        .await
        .unwrap();
    put_n(&rt, &admin, 10).await;
    rt.force_snapshot().await.unwrap();
    let mut last_ack = 0u64;
    for _ in 0..9 {
        let batch = rt.consume(&sub.id, 1).await.unwrap();
        last_ack = batch[0].sequence;
        rt.ack(&alice, &sub.id, &batch[0].delivery.delivery_id)
            .await
            .unwrap();
    }
    let wm = rt.retention_watermark().await.unwrap();
    assert_eq!(wm.trim_through, Some(last_ack));
    let pending = rt.consume(&sub.id, 1).await.unwrap();
    assert!(pending[0].sequence > last_ack);
}

#[tokio::test]
async fn trim_unsafe_without_snapshot_pin() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    put_n(&rt, &admin, 2).await;
    let err = rt.trim_journal().await.unwrap_err();
    assert!(err.to_string().to_lowercase().contains("unsafe"));
}

#[tokio::test]
async fn oldest_available_defaults_to_first_segment_start() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    put_n(&rt, &admin, 2).await;
    assert_eq!(rt.oldest_available_sequence().await.unwrap(), 1);
}
