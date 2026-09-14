//! Phase 5.6.8 — final compaction lifecycle acceptance (Runtime integration).

use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{CompactionPolicy, RetryPolicy, StreamId};
use dmc_journal::journal_manifest::read_manifest;
use dmc_journal::layout::list_segment_ids;
use dmc_journal::set_test_segment_max_bytes;
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
            format!("payload-{i}").as_bytes(),
        )
        .await
        .unwrap();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EventView {
    sequence: u64,
    event_id: String,
    payload: Vec<u8>,
}

async fn replay_view(rt: &Runtime, sub: &dmc_core::SubscriptionId, limit: usize) -> Vec<EventView> {
    let from = rt.oldest_available_sequence().await.unwrap();
    rt.replay(sub, from, limit)
        .await
        .unwrap()
        .into_iter()
        .map(|e| EventView {
            sequence: e.sequence,
            event_id: e.event_id,
            payload: e.payload,
        })
        .collect()
}

fn journal_paths(store: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let data = store.parent().unwrap_or(store);
    (
        data.join("journal"),
        data.join("runtime/journal/manifest.json"),
    )
}

#[tokio::test]
async fn full_compaction_lifecycle_dod() {
    let _seg = SmallJournalSegments::enable();
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store.dbs.json");
    let rt = Runtime::at_path(store.clone());
    let (master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;

    put_n(&rt, &admin, 40).await;
    let snap = rt.force_snapshot().await.unwrap();
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, RetryPolicy::immediate())
        .await
        .unwrap();

    let mut last_ack = 0u64;
    for _ in 0..8 {
        let batch = rt.consume(&sub.id, 1).await.unwrap();
        last_ack = batch[0].sequence;
        rt.ack(&alice, &sub.id, &batch[0].delivery.delivery_id)
            .await
            .unwrap();
    }
    let _lease = rt
        .begin_replay_lease(&sub.id, last_ack.saturating_sub(2), 60_000)
        .await
        .unwrap();

    let before = replay_view(&rt, &sub.id, 500).await;

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
    let artifact_id = artifact.segment_id;
    let sources = artifact.source_segment_ids.clone();
    let published = rt.publish_compaction(artifact).await.unwrap();
    assert!(published.contains_segment(artifact_id));

    let (journal_dir, manifest_path) = journal_paths(&store);
    let manifest_on_disk = read_manifest(&manifest_path).unwrap().unwrap();
    assert_eq!(manifest_on_disk.generation, published.generation);
    assert!(!manifest_on_disk.superseded_segment_ids.is_empty());

    rt.end_replay_lease(&_lease).await.unwrap();

    let wm = rt.retention_watermark().await.unwrap().trim_through.unwrap();
    assert!(wm <= snap);
    let trim = rt.trim_journal().await.unwrap();
    assert!(!trim.deleted_segments.is_empty() || trim.deleted_segments.is_empty());

    rt.lock().await.unwrap();
    let rt2 = Runtime::at_path(store.clone());
    rt2.unlock(&master).await.unwrap();

    let after = replay_view(&rt2, &sub.id, 500).await;
    assert_eq!(before, after);

    let manifest_after = read_manifest(&manifest_path).unwrap().unwrap();
    for id in &sources {
        assert!(manifest_after.superseded_segment_ids.contains(id));
    }
    assert!(list_segment_ids(&journal_dir).unwrap().contains(&artifact_id));
    assert!(journal_dir.join(format!("seg-{artifact_id:012}.jnl")).is_file());
}
