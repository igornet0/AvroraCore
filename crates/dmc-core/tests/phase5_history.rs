use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{Error, RetryPolicy, StreamId};
use dmc_journal::codec::decode_segment_footer;
use dmc_journal::{layout::list_segment_ids, set_test_segment_max_bytes, StorageLayout};
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};

struct SmallJournalSegments;

impl SmallJournalSegments {
    fn enable() -> Self {
        set_test_segment_max_bytes(Some(900));
        Self
    }
}

impl Drop for SmallJournalSegments {
    fn drop(&mut self) {
        set_test_segment_max_bytes(None);
    }
}

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

async fn unlock_fresh(dir: &std::path::Path, master: &str) -> Runtime {
    set_test_segment_max_bytes(Some(900));
    let rt = Runtime::at_path(dir.join("store.dbs.json"));
    rt.unlock(master).await.unwrap();
    rt
}

async fn bump_oldest_available(
    dir: &std::path::Path,
    master: &str,
    rt: &Runtime,
    admin: &dmc_core::SessionId,
) -> (Runtime, u64) {
    put_n(rt, admin, 20).await;
    rt.force_snapshot().await.unwrap();
    let layout = StorageLayout::from_db_path(dir.join("store.dbs.json"));
    let ids = list_segment_ids(&layout.journal_dir()).unwrap();
    assert!(ids.len() > 1, "expected multiple segments, got {ids:?}");
    let first = layout
        .journal_dir()
        .join(format!("seg-{:012}.jnl", ids[0]));
    let bytes = std::fs::read(&first).unwrap();
    assert!(
        decode_segment_footer(&bytes).is_some(),
        "first segment must be sealed before simulated GC"
    );
    rt.lock().await.unwrap();
    std::fs::remove_file(&first).unwrap();
    let rt2 = unlock_fresh(dir, master).await;
    let oldest = rt2.oldest_available_sequence().await.unwrap();
    assert!(oldest > 1, "oldest={oldest} after removing seg {}", ids[0]);
    (rt2, oldest)
}

#[tokio::test]
async fn replay_before_oldest_returns_history_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, RetryPolicy::immediate())
        .await
        .unwrap();
    put_n(&rt, &admin, 2).await;
    let err = rt.replay(&sub.id, 0, 10).await.unwrap_err();
    match err {
        Error::HistoryUnavailable {
            requested_from,
            oldest_available,
        } => {
            assert_eq!(requested_from, 0);
            assert_eq!(oldest_available, 1);
        }
        other => panic!("expected HistoryUnavailable, got {other}"),
    }
}

#[tokio::test]
async fn replay_at_oldest_boundary_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, RetryPolicy::immediate())
        .await
        .unwrap();
    put_n(&rt, &admin, 3).await;
    let oldest = rt.oldest_available_sequence().await.unwrap();
    let events = rt.replay(&sub.id, oldest, 10).await.unwrap();
    assert!(!events.is_empty());
    assert!(events[0].sequence >= oldest);
}

#[tokio::test]
async fn replay_after_trim_rejects_trimmed_prefix() {
    let _seg = SmallJournalSegments::enable();
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, RetryPolicy::immediate())
        .await
        .unwrap();
    let (rt, oldest) = bump_oldest_available(dir.path(), &master, &rt, &admin).await;
    let err = rt.replay(&sub.id, oldest - 1, 10).await.unwrap_err();
    match err {
        Error::HistoryUnavailable {
            requested_from,
            oldest_available,
        } => {
            assert_eq!(requested_from, oldest - 1);
            assert_eq!(oldest_available, oldest);
        }
        other => panic!("expected HistoryUnavailable, got {other}"),
    }
    let ok = rt.replay(&sub.id, oldest, 5).await.unwrap();
    assert!(!ok.is_empty());
}

#[tokio::test]
async fn replay_history_unavailable_survives_restart() {
    let _seg = SmallJournalSegments::enable();
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, RetryPolicy::immediate())
        .await
        .unwrap();
    let (rt, oldest) = bump_oldest_available(dir.path(), &master, &rt, &admin).await;
    rt.lock().await.unwrap();
    let rt2 = unlock_fresh(dir.path(), &master).await;
    let err = rt2.replay(&sub.id, oldest - 1, 5).await.unwrap_err();
    assert!(matches!(err, Error::HistoryUnavailable { .. }));
    assert_eq!(rt2.oldest_available_sequence().await.unwrap(), oldest);
}

#[tokio::test]
async fn authz_is_checked_before_history_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    put_n(&rt, &admin, 2).await;
    let cap = rt
        .list_capabilities()
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.subject.as_str() == "alice")
        .unwrap();
    rt.revoke_capability(&admin, cap.id.as_str()).await.unwrap();
    let err = rt.replay(&sub.id, 0, 10).await.unwrap_err();
    assert!(
        matches!(err, Error::AuthorizationDenied(_)),
        "expected AuthorizationDenied before HistoryUnavailable, got {err}"
    );
}

#[tokio::test]
async fn replay_lease_does_not_bypass_history_unavailable() {
    let _seg = SmallJournalSegments::enable();
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    let (rt, oldest) = bump_oldest_available(dir.path(), &master, &rt, &admin).await;
    let _lease = rt
        .begin_replay_lease(&sub.id, oldest + 5, 60_000)
        .await
        .unwrap();
    let err = rt.replay(&sub.id, oldest - 1, 5).await.unwrap_err();
    assert!(matches!(err, Error::HistoryUnavailable { .. }));
}

#[tokio::test]
async fn consume_is_unaffected_by_history_gate() {
    let _seg = SmallJournalSegments::enable();
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, RetryPolicy::immediate())
        .await
        .unwrap();
    put_n(&rt, &admin, 20).await;
    rt.force_snapshot().await.unwrap();
    rt.trim_journal().await.unwrap();
    let batch = rt.consume(&sub.id, 1).await.unwrap();
    assert_eq!(batch.len(), 1);
}
