//! Phase 5.7.6 — replay/consume integration over partitioned journal storage.

use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{CompactionPolicy, Error, RetryPolicy, SessionId, StreamId};
use dmc_journal::codec::decode_segment_footer;
use dmc_journal::journal_manifest::read_manifest;
use dmc_journal::layout::{find_segment_path, list_segment_ids};
use dmc_journal::partition::resolve_partition;
use dmc_journal::{set_test_partition_count, set_test_segment_max_bytes, StorageLayout};
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};

struct PartitionEnv {
    _parts: u32,
}

impl PartitionEnv {
    fn new(parts: u32) -> Self {
        set_test_partition_count(Some(parts));
        Self { _parts: parts }
    }
}

impl Drop for PartitionEnv {
    fn drop(&mut self) {
        set_test_partition_count(None);
    }
}

struct SmallSegmentEnv {
    _seg: SmallSegments,
}

struct SmallSegments;

impl SmallSegments {
    fn enable() -> Self {
        set_test_segment_max_bytes(Some(900));
        Self
    }
}

impl Drop for SmallSegments {
    fn drop(&mut self) {
        set_test_segment_max_bytes(None);
    }
}

impl SmallSegmentEnv {
    fn enable() -> Self {
        Self {
            _seg: SmallSegments::enable(),
        }
    }
}

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

fn path_for_partition(target: u32, parts: u32) -> String {
    for i in 0..10_000 {
        let path = format!("company/finance/route-{i}");
        let kp = KeyPath::parse(&path).unwrap();
        if resolve_partition(&kp, None, parts).unwrap().as_u32() == target {
            return path;
        }
    }
    panic!("no path for partition {target}");
}

async fn put_interleaved(rt: &Runtime, admin: &SessionId, parts: u32, n: u64) {
    for i in 0..n {
        let path = path_for_partition(i as u32 % parts, parts);
        rt.put_data(admin, &path, format!("evt-{i}").as_bytes())
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn replay_inclusive_order_partition_count_one() {
    let _env = PartitionEnv::new(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    for i in 0..5 {
        rt.put_data(
            &admin,
            &format!("company/finance/item/{i}"),
            format!("{i}").as_bytes(),
        )
        .await
        .unwrap();
    }
    let from = rt.oldest_available_sequence().await.unwrap();
    let replayed = rt.replay(&sub.id, from, 10).await.unwrap();
    assert_eq!(replayed.len(), 5);
    assert_eq!(replayed[0].payload, b"0");
    assert_eq!(replayed.last().unwrap().payload, b"4");
    for w in replayed.windows(2) {
        assert!(w[1].sequence > w[0].sequence);
    }
}

#[tokio::test]
async fn multi_partition_replay_global_sequence_order() {
    let parts = 3;
    let _env = PartitionEnv::new(parts);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    put_interleaved(&rt, &admin, parts, 9).await;

    let from = rt.oldest_available_sequence().await.unwrap();
    let replayed = rt.replay(&sub.id, from, 50).await.unwrap();
    let payloads: Vec<_> = replayed
        .iter()
        .filter(|e| e.payload.starts_with(b"evt-"))
        .map(|e| e.payload.clone())
        .collect();
    assert_eq!(payloads.len(), 9);
    for i in 0..9 {
        assert_eq!(payloads[i], format!("evt-{i}").as_bytes());
    }
    for w in replayed.windows(2) {
        assert!(w[1].sequence > w[0].sequence);
    }
}

/// Simulated external GC of the first sealed segment while the runtime is locked: a forced
/// `trim_through` on the journal itself (bypasses runtime retention pins, like the previous
/// raw file removal) that also removes the segment from the published manifest.
fn force_gc_first_segment(db_path: &std::path::Path, master: &str, first_bytes: &[u8]) {
    let layout = StorageLayout::from_db_path(db_path);
    let snap = dmc_vault::persist::DbSnapshot::load(&layout.base_snapshot()).unwrap();
    let salt = snap.salt().unwrap();
    let master_key = dmc_vault::KeyMaterial::from_hex(master).unwrap();
    let kek = dmc_vault::crypto::derive_journal_kek(&master_key, &salt);
    let mut journal =
        dmc_journal::Journal::open(dmc_journal::JournalConfig::new(layout.journal_dir()), &kek)
            .unwrap();
    let (end, _) = decode_segment_footer(first_bytes).unwrap();
    let trimmed = journal.trim_through(end).unwrap();
    assert!(!trimmed.deleted_segments.is_empty(), "forced GC deleted nothing");
}

#[tokio::test]
async fn replay_after_gc_history_unavailable() {
    let _seg = SmallSegmentEnv::enable();
    let _parts = PartitionEnv::new(1);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    for i in 0..20 {
        rt.put_data(
            &admin,
            &format!("company/finance/item/{i}"),
            format!("v{i}").as_bytes(),
        )
        .await
        .unwrap();
    }
    rt.force_snapshot().await.unwrap();
    let layout = StorageLayout::from_db_path(dir.path().join("store.dbs.json"));
    let ids = list_segment_ids(&layout.journal_dir()).unwrap();
    assert!(ids.len() > 1);
    let first = find_segment_path(&layout.journal_dir(), ids[0]).unwrap();
    let first_bytes = std::fs::read(&first).unwrap();
    assert!(decode_segment_footer(&first_bytes).is_some());
    rt.lock().await.unwrap();
    force_gc_first_segment(&dir.path().join("store.dbs.json"), &master, &first_bytes);

    let rt2 = Runtime::at_path(dir.path().join("store.dbs.json"));
    rt2.unlock(&master).await.unwrap();
    let oldest = rt2.oldest_available_sequence().await.unwrap();
    assert!(oldest > 1);

    let err = rt2.replay(&sub.id, oldest - 1, 10).await.unwrap_err();
    assert!(matches!(err, Error::HistoryUnavailable { .. }));
    let ok = rt2.replay(&sub.id, oldest, 10).await.unwrap();
    assert!(!ok.is_empty());
    assert!(ok[0].sequence >= oldest);
}

#[tokio::test]
async fn consumer_ack_restart_resumes_at_next_sequence() {
    let parts = 4;
    let _env = PartitionEnv::new(parts);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, sub_id, last_ack) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (admin, alice, stream) = setup_finance_read(&rt).await;
        let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
        rt.set_retry_policy(&alice, &sub.id, RetryPolicy::immediate())
            .await
            .unwrap();
        put_interleaved(&rt, &admin, parts, 100).await;
        let mut last_ack = rt.get_subscription(&sub.id).await.unwrap().position.sequence;
        for _ in 0..40 {
            let mut batch = rt.consume(&sub.id, 1).await.unwrap();
            assert_eq!(batch.len(), 1);
            assert!(batch[0].sequence > last_ack);
            last_ack = batch[0].sequence;
            rt.ack(&alice, &sub.id, &batch.remove(0).delivery.delivery_id)
                .await
                .unwrap();
        }
        let stored = rt.get_subscription(&sub.id).await.unwrap();
        assert_eq!(stored.position.sequence, last_ack);
        (master, sub.id, last_ack)
    };

    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let batch = rt.consume(&sub_id, 1).await.unwrap();
    assert_eq!(batch[0].sequence, last_ack + 1);
    assert_eq!(batch[0].payload, b"evt-40");
}

#[tokio::test]
async fn crash_after_delivery_same_sequence_new_attempt() {
    let parts = 3;
    let _env = PartitionEnv::new(parts);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, sub_id, seq, event_id) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (admin, alice, stream) = setup_finance_read(&rt).await;
        let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
        rt.set_retry_policy(&alice, &sub.id, RetryPolicy::immediate())
            .await
            .unwrap();
        put_interleaved(&rt, &admin, parts, 5).await;
        let d1 = rt.consume(&sub.id, 1).await.unwrap();
        (
            master,
            sub.id,
            d1[0].sequence,
            d1[0].event_id.clone(),
        )
    };

    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let d2 = rt.consume(&sub_id, 1).await.unwrap();
    assert_eq!(d2[0].sequence, seq);
    assert_eq!(d2[0].event_id, event_id);
    assert_eq!(d2[0].delivery.attempt, 2);
}

#[tokio::test]
async fn retry_dlq_on_multi_partition_journal() {
    let parts = 3;
    let _env = PartitionEnv::new(parts);
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
    put_interleaved(&rt, &admin, parts, 2).await;

    let d1 = rt.consume(&sub.id, 1).await.unwrap();
    let d2 = rt.consume(&sub.id, 1).await.unwrap();
    assert_eq!(d2[0].sequence, d1[0].sequence);
    assert_eq!(d2[0].delivery.attempt, 2);
    let next = rt.consume(&sub.id, 1).await.unwrap();
    assert!(next[0].sequence > d1[0].sequence);
    assert_eq!(rt.list_dlq(&admin, &sub.id).await.unwrap().len(), 1);
}

#[tokio::test]
async fn capability_scope_independent_of_physical_partition() {
    let parts = 3;
    let _env = PartitionEnv::new(parts);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    rt.create_role(
        &admin,
        "invoices".into(),
        "Invoices".into(),
        KeyPath::parse("company/finance/invoices").unwrap(),
        PermissionSet::empty().with(Permission::Read),
    )
    .await
    .unwrap();
    rt.create_user(&admin, "carol".into(), vec!["invoices".into()])
        .await
        .unwrap();
    rt.configure_channel(ChannelSpec::internal("bus"))
        .await
        .unwrap();
    let stream = rt
        .create_stream(StreamSpec {
            id: StreamId::from("invoices-read"),
            direction: StreamDirection::Outbound,
            channel_id: "bus".into(),
            path_scope: KeyPath::parse("company/finance/invoices").unwrap(),
            required_perms: PermissionSet::empty().with(Permission::Read),
        })
        .await
        .unwrap();
    let carol = rt.open_user_session("carol", Some("dev-c")).await.unwrap();
    let sub = rt.create_subscription(&carol, &stream, None).await.unwrap();
    rt.set_retry_policy(&carol, &sub.id, RetryPolicy::immediate())
        .await
        .unwrap();

    let finance_path = path_for_partition(0, parts);
    let hr_path = "company/hr/payroll/1";
    let invoice_path = "company/finance/invoices/42";
    rt.put_data(&admin, &finance_path, b"finance").await.unwrap();
    rt.put_data(&admin, hr_path, b"hr").await.unwrap();
    rt.put_data(&admin, invoice_path, b"invoice").await.unwrap();

    let batch = rt.consume(&sub.id, 10).await.unwrap();
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].payload, b"invoice");
    assert_eq!(batch[0].path, "company/finance/invoices/42");
}

#[tokio::test]
async fn compaction_replay_equivalence_uses_merge_reader() {
    let _seg = SmallSegmentEnv::enable();
    let _parts = PartitionEnv::new(1);
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store.dbs.json");
    let rt = Runtime::at_path(store.clone());
    let (master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    for i in 0..40 {
        rt.put_data(
            &admin,
            &format!("company/finance/item/{i}"),
            format!("payload-{i}").as_bytes(),
        )
        .await
        .unwrap();
    }
    let _snap = rt.force_snapshot().await.unwrap();
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    let from = rt.oldest_available_sequence().await.unwrap();
    let before = rt.replay(&sub.id, from, 500).await.unwrap();

    rt.set_compaction_policy(
        &admin,
        CompactionPolicy {
            enabled: true,
            min_segments: 2,
            min_total_bytes: 0,
            max_input_bytes: 10 * 1024 * 1024,
        },
    )
    .await
    .unwrap();
    let artifact = rt.compact_journal().await.unwrap();
    rt.publish_compaction(artifact).await.unwrap();

    rt.lock().await.unwrap();
    let rt2 = Runtime::at_path(store.clone());
    rt2.unlock(&master).await.unwrap();
    let after = rt2.replay(&sub.id, from, 500).await.unwrap();

    assert_eq!(
        before.iter().map(|e| (e.sequence, e.event_id.clone())).collect::<Vec<_>>(),
        after.iter().map(|e| (e.sequence, e.event_id.clone())).collect::<Vec<_>>()
    );
    let manifest_path = store
        .parent()
        .unwrap()
        .join("runtime/journal/manifest.json");
    assert!(manifest_path.is_file());
    let _manifest = read_manifest(&manifest_path).unwrap().unwrap();
}

#[tokio::test]
async fn runtime_trim_journal_multi_partition_history_gate() {
    let parts = 3;
    let _env = PartitionEnv::new(parts);
    let _seg = SmallSegmentEnv::enable();
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store.dbs.json");
    let rt = Runtime::at_path(store.clone());
    let (master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    put_interleaved(&rt, &admin, parts, 24).await;
    let snap = rt.force_snapshot().await.unwrap();
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, RetryPolicy::immediate())
        .await
        .unwrap();

    let lease = rt
        .begin_replay_lease(&sub.id, 1, 60_000)
        .await
        .unwrap();
    rt.end_replay_lease(&lease).await.unwrap();

    for _ in 0..8 {
        let mut batch = rt.consume(&sub.id, 1).await.unwrap();
        rt.ack(&alice, &sub.id, &batch.remove(0).delivery.delivery_id)
            .await
            .unwrap();
    }

    let trim = rt.trim_journal().await.unwrap();
    assert!(!trim.deleted_segments.is_empty());

    let oldest = rt.oldest_available_sequence().await.unwrap();
    assert!(oldest > 1);
    let err = rt.replay(&sub.id, 1, 10).await.unwrap_err();
    assert!(matches!(err, Error::HistoryUnavailable { .. }));
    let ok = rt.replay(&sub.id, oldest, 10).await.unwrap();
    assert!(!ok.is_empty());
    assert!(snap <= oldest || !ok.is_empty());

    // Restart verifies journal topology only: runtime registries are rebuilt from
    // journal replay and are not trim targets in 5.7.7.
    let head_before = rt.last_sequence().await;
    rt.lock().await.unwrap();
    let rt2 = Runtime::at_path(store);
    rt2.unlock(&master).await.unwrap();
    assert_eq!(rt2.last_sequence().await, head_before);
    assert!(rt2.oldest_available_sequence().await.unwrap() >= oldest);
}
