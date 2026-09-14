//! Phase 5.7.10 — Final DoD + Contract: partitioning is physical-only scaling.

mod partition_contract;

use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::subscription::JournalPosition;
use dmc_core::{CompactionPolicy, Error, RetryPolicy, StreamId};
use dmc_journal::journal_manifest::read_manifest;
use dmc_journal::layout::list_segment_ids;
use dmc_journal::partition::{resolve_partition, PartitionId};
use dmc_journal::{set_test_partition_count, set_test_segment_max_bytes, StorageLayout};
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};

use partition_contract::{
    assert_crypto_fingerprints_equal, assert_event_views_equivalent,
    assert_global_sequence_ordering_contract, assert_history_unavailable,
    assert_journal_position_global_only, assert_manifest_partition_topology,
    crypto_fingerprints_for_sequences, scan_journal_crypto_fingerprints, EventView,
};

const PARTS: u32 = 3;
/// Rounds × partitions = total data events (1200 × 3 = 3600). Increase to 3334+ for 10k+.
const EVENT_ROUNDS: u32 = 1200;
const COMPACTION_SAMPLE: usize = 100;

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

struct SmallSegmentEnv;

impl SmallSegmentEnv {
    fn enable() -> Self {
        set_test_segment_max_bytes(Some(900));
        Self
    }
}

impl Drop for SmallSegmentEnv {
    fn drop(&mut self) {
        set_test_segment_max_bytes(None);
    }
}

fn manifest_path(store: &std::path::Path) -> std::path::PathBuf {
    store
        .parent()
        .unwrap()
        .join("runtime/journal/manifest.json")
}

fn journal_dir(store: &std::path::Path) -> std::path::PathBuf {
    StorageLayout::from_db_path(store).journal_dir()
}

async fn setup_company_reader(
    rt: &Runtime,
) -> (
    dmc_core::SessionId,
    dmc_core::SessionId,
    StreamId,
    dmc_core::SessionId,
) {
    let admin = rt.admin_session().await.unwrap();
    rt.create_role(
        &admin,
        "company-reader".into(),
        "Company reader".into(),
        KeyPath::parse("company").unwrap(),
        PermissionSet::empty().with(Permission::Read),
    )
    .await
    .unwrap();
    rt.create_user(&admin, "alice".into(), vec!["company-reader".into()])
        .await
        .unwrap();
    rt.create_user(&admin, "bob".into(), vec!["company-reader".into()])
        .await
        .unwrap();
    rt.configure_channel(ChannelSpec::internal("bus"))
        .await
        .unwrap();
    let stream = rt
        .create_stream(StreamSpec {
            id: StreamId::from("company-read"),
            direction: StreamDirection::Outbound,
            channel_id: "bus".into(),
            path_scope: KeyPath::parse("company").unwrap(),
            required_perms: PermissionSet::empty().with(Permission::Read),
        })
        .await
        .unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    let bob = rt.open_user_session("bob", Some("dev-b")).await.unwrap();
    (admin, alice, stream, bob)
}

fn path_for_partition(prefix: &str, target: u32, parts: u32) -> String {
    for i in 0..20_000 {
        let path = format!("{prefix}/route-{i}");
        let kp = KeyPath::parse(&path).unwrap();
        if resolve_partition(&kp, None, parts).unwrap().as_u32() == target {
            return path;
        }
    }
    panic!("no path for partition {target} under {prefix}");
}

async fn put_interleaved_multi(
    rt: &Runtime,
    admin: &dmc_core::SessionId,
    parts: u32,
    rounds: u32,
) -> u64 {
    let prefixes = ["company/finance", "company/hr", "company/audit"];
    let mut global_idx = 0u64;
    for round in 0..rounds {
        let prefix = prefixes[round as usize % prefixes.len()];
        for p in 0..parts {
            let path = path_for_partition(prefix, p, parts);
            rt.put_data(
                admin,
                &path,
                format!("evt-{global_idx}").as_bytes(),
            )
            .await
            .unwrap();
            global_idx += 1;
        }
    }
    global_idx
}

async fn replay_data_view(
    rt: &Runtime,
    sub: &dmc_core::SubscriptionId,
    limit: usize,
) -> Vec<EventView> {
    let from = rt.oldest_available_sequence().await.unwrap();
    rt.replay(sub, from, limit)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.payload.starts_with(b"evt-"))
        .map(|e| EventView {
            sequence: e.sequence,
            event_id: e.event_id,
            path: e.path,
            payload: e.payload,
        })
        .collect()
}

fn assert_events_spread_across_partitions(
    journal: &std::path::Path,
    parts: u32,
    min_per_partition: usize,
) {
    let mut counts = vec![0usize; parts as usize];
    for segment_id in list_segment_ids(journal).unwrap() {
        for pid in 0..parts {
            let p = dmc_journal::layout::segment_path_for_partition(
                journal,
                PartitionId(pid),
                segment_id,
                parts,
            );
            if p.is_file() {
                counts[pid as usize] += 1;
            }
        }
    }
    let non_empty = counts.iter().filter(|&&c| c > 0).count();
    assert!(
        non_empty >= parts as usize,
        "expected segments in all {parts} partitions, got counts {counts:?}"
    );
    for (pid, &c) in counts.iter().enumerate() {
        assert!(
            c >= min_per_partition,
            "partition {pid} has only {c} segment files (need >={min_per_partition})"
        );
    }
}

async fn compact_all_partitions(rt: &Runtime, admin: &dmc_core::SessionId) {
    rt.set_compaction_policy(
        admin,
        CompactionPolicy {
            enabled: true,
            min_segments: 2,
            min_total_bytes: 0,
            max_input_bytes: 10 * 1024 * 1024,
        },
    )
    .await
    .unwrap();
    for pid in 0..PARTS {
        while rt
            .select_compaction_candidate_for_partition(pid)
            .await
            .unwrap()
            .is_some()
        {
            let artifact = rt.compact_journal_partition(pid).await.unwrap();
            rt.publish_compaction(artifact).await.unwrap();
        }
    }
}

#[tokio::test]
async fn contract_security_journal_position_and_aad() {
    let pos = JournalPosition { sequence: 41 };
    assert_journal_position_global_only(pos);
    partition_contract::assert_aad_excludes_partition_id(
        "company/finance/item/1",
        41,
        1,
        dmc_journal::JournalEventKind::OverlayApply,
    );
}

#[tokio::test]
async fn contract_history_authz_before_unavailable() {
    let _parts = PartitionEnv::new(3);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream, _bob) = setup_company_reader(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.put_data(&admin, "company/finance/x", b"1")
        .await
        .unwrap();
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
        "AuthZ must precede HistoryUnavailable, got {err}"
    );
}

#[tokio::test]
async fn contract_consumer_dlq_semantics_on_partitioned_journal() {
    let _parts = PartitionEnv::new(PARTS);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream, bob) = setup_company_reader(&rt).await;
    put_interleaved_multi(&rt, &admin, PARTS, 3).await;

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

    let offset_before = rt.get_subscription(&sub.id).await.unwrap().position.sequence;
    assert_journal_position_global_only(JournalPosition {
        sequence: offset_before,
    });

    let d1 = rt.consume(&sub.id, 1).await.unwrap();
    let d2 = rt.consume(&sub.id, 1).await.unwrap();
    assert_eq!(d2[0].sequence, d1[0].sequence);
    assert_eq!(d2[0].delivery.attempt, 2);
    let next = rt.consume(&sub.id, 1).await.unwrap();
    assert!(next[0].sequence > d1[0].sequence);

    let dlq = rt.list_dlq(&admin, &sub.id).await.unwrap();
    assert_eq!(dlq.len(), 1);
    assert_eq!(dlq[0].original_event_id, d1[0].event_id);
    assert_eq!(dlq[0].original_sequence, d1[0].sequence);
    assert_eq!(
        rt.get_subscription(&sub.id).await.unwrap().position.sequence,
        offset_before
    );
    assert!(rt.list_dlq(&bob, &sub.id).await.is_err());
}

#[tokio::test]
#[ignore = "slow acceptance (~4 min debug); run: make test-slow"]
async fn partition_final_dod_acceptance() {
    let _parts = PartitionEnv::new(PARTS);
    let _seg = SmallSegmentEnv::enable();
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store.dbs.json");
    let journal_path = journal_dir(&store);
    let manifest = manifest_path(&store);

    let rt = Runtime::at_path(store.clone());
    let (master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream, _bob) = setup_company_reader(&rt).await;

    let total_data = put_interleaved_multi(&rt, &admin, PARTS, EVENT_ROUNDS).await;
    assert!(total_data >= 3000, "need enough events for partition spread");

    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, RetryPolicy::immediate())
        .await
        .unwrap();

    let replayed = replay_data_view(&rt, &sub.id, total_data as usize + 100).await;
    assert_eq!(replayed.len(), total_data as usize);
    let sequences: Vec<_> = replayed.iter().map(|e| e.sequence).collect();
    assert_global_sequence_ordering_contract(&sequences);

    for i in 0..replayed.len() {
        assert_eq!(replayed[i].payload, format!("evt-{i}").as_bytes());
    }

    assert_events_spread_across_partitions(&journal_path, PARTS, 2);

    let sample_seqs: Vec<u64> = sequences.iter().take(5).copied().collect();
    let crypto_before = crypto_fingerprints_for_sequences(&journal_path, PARTS, &sample_seqs);

    let _snap = rt.force_snapshot().await.unwrap();

    // Consumer semantics: ACK 40 events, then crash redelivery on next.
    let mut last_ack = rt.get_subscription(&sub.id).await.unwrap().position.sequence;
    assert_journal_position_global_only(JournalPosition {
        sequence: last_ack,
    });
    for _ in 0..40 {
        let mut batch = rt.consume(&sub.id, 1).await.unwrap();
        assert_eq!(batch.len(), 1);
        assert!(batch[0].sequence > last_ack);
        last_ack = batch[0].sequence;
        rt.ack(&alice, &sub.id, &batch.remove(0).delivery.delivery_id)
            .await
            .unwrap();
    }
    assert_eq!(
        rt.get_subscription(&sub.id).await.unwrap().position.sequence,
        last_ack
    );

    let (crash_master, crash_sub, crash_seq, crash_event_id, crash_delivery_id) = {
        let d = rt.consume(&sub.id, 1).await.unwrap();
        (
            master.clone(),
            sub.id.clone(),
            d[0].sequence,
            d[0].event_id.clone(),
            d[0].delivery.delivery_id.clone(),
        )
    };
    rt.lock().await.unwrap();
    let rt_crash = Runtime::at_path(store.clone());
    rt_crash.unlock(&crash_master).await.unwrap();
    let alice_crash = rt_crash
        .open_user_session("alice", Some("dev-a2"))
        .await
        .unwrap();
    let redelivered = rt_crash.consume(&crash_sub, 1).await.unwrap();
    assert_eq!(redelivered[0].sequence, crash_seq);
    assert_eq!(redelivered[0].event_id, crash_event_id);
    assert_eq!(redelivered[0].delivery.attempt, 2);
    assert_ne!(redelivered[0].delivery.delivery_id, crash_delivery_id);
    assert_eq!(
        rt_crash
            .get_subscription(&crash_sub)
            .await
            .unwrap()
            .position
            .sequence,
        last_ack
    );
    rt_crash
        .ack(
            &alice_crash,
            &crash_sub,
            &redelivered[0].delivery.delivery_id,
        )
        .await
        .unwrap();

    let rt = rt_crash;
    let admin = rt.admin_session().await.unwrap();
    let alice = rt
        .open_user_session("alice", Some("dev-a3"))
        .await
        .unwrap();

    let before_compaction = replay_data_view(&rt, &sub.id, COMPACTION_SAMPLE).await;

    // Orphan artifact: compact without publish must not change replay.
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
    if rt
        .select_compaction_candidate_for_partition(0)
        .await
        .unwrap()
        .is_some()
    {
        let orphan_artifact = rt.compact_journal_partition(0).await.unwrap();
        assert!(orphan_artifact.path.is_file());
        let orphan_replay = replay_data_view(&rt, &sub.id, COMPACTION_SAMPLE).await;
        assert_event_views_equivalent(&before_compaction, &orphan_replay);
        rt.publish_compaction(orphan_artifact).await.unwrap();
    }

    compact_all_partitions(&rt, &admin).await;
    assert!(manifest.is_file());

    let after_compaction = replay_data_view(&rt, &sub.id, COMPACTION_SAMPLE).await;
    assert_event_views_equivalent(&before_compaction, &after_compaction);

    let crypto_after = crypto_fingerprints_for_sequences(&journal_path, PARTS, &sample_seqs);
    for seq in &sample_seqs {
        let before = crypto_before.get(seq).expect("missing before fingerprint");
        let after = crypto_after.get(seq).expect("missing after fingerprint");
        assert_crypto_fingerprints_equal(before, after);
    }

    // Pins: snapshot, consumer, replay lease → global watermark.
    // `replay()` registers short leases; advance test clock past their TTL.
    rt.set_now_ms(Some(u64::MAX / 2)).await;
    while let Some(pending) = rt.pending_delivery(&sub.id).await.unwrap() {
        rt.ack(&alice, &sub.id, &pending.last_delivery_id)
            .await
            .unwrap();
    }
    let snap_pin = rt.force_snapshot().await.unwrap();
    for _ in 0..20 {
        let batch = rt.consume(&sub.id, 1).await.unwrap();
        rt.ack(&alice, &sub.id, &batch[0].delivery.delivery_id)
            .await
            .unwrap();
    }
    let consumer_ack = rt.get_subscription(&sub.id).await.unwrap().position.sequence;
    let replay_from = consumer_ack.saturating_sub(5);
    let lease = rt
        .begin_replay_lease(&sub.id, replay_from, 60_000)
        .await
        .unwrap();
    assert!(
        rt.pending_delivery(&sub.id).await.unwrap().is_none(),
        "pending delivery floors watermark at 0"
    );
    let wm = rt.retention_watermark().await.unwrap();
    let safe_trim = wm.trim_through.unwrap();
    let replay_pin = replay_from.saturating_sub(1);
    assert_eq!(safe_trim, snap_pin.min(replay_pin));
    rt.end_replay_lease(&lease).await.unwrap();
    rt.set_now_ms(None).await;

    let head_before = rt.last_sequence().await;
    let trim1 = rt.trim_journal().await.unwrap();
    assert!(!trim1.deleted_segments.is_empty());
    let _trim2 = rt.trim_journal().await.unwrap();

    let oldest = rt.oldest_available_sequence().await.unwrap();
    let trimmed_prefix = if oldest > 1 { oldest - 1 } else { 0 };
    let err = rt
        .replay(&sub.id, trimmed_prefix, 10)
        .await
        .unwrap_err();
    assert_history_unavailable(err, trimmed_prefix, oldest);
    let ok = rt.replay(&sub.id, oldest, 50).await.unwrap();
    assert!(!ok.is_empty());
    assert_global_sequence_ordering_contract(
        &ok.iter().map(|e| e.sequence).collect::<Vec<_>>(),
    );

    rt.lock().await.unwrap();
    let rt2 = Runtime::at_path(store.clone());
    rt2.unlock(&master).await.unwrap();

    assert_eq!(rt2.last_sequence().await, head_before);
    assert_eq!(rt2.oldest_available_sequence().await.unwrap(), oldest);

    let final_replay = replay_data_view(&rt2, &sub.id, total_data as usize + 100).await;
    let final_seqs: Vec<_> = final_replay.iter().map(|e| e.sequence).collect();
    assert!(!final_replay.is_empty());
    assert_global_sequence_ordering_contract(&final_seqs);

    let stored = read_manifest(&manifest).unwrap().expect("manifest");
    assert!(stored.generation >= 1);
    assert_manifest_partition_topology(&manifest, PARTS);

    let merged_from_oldest = rt2
        .replay(&sub.id, oldest, 5000)
        .await
        .unwrap()
        .iter()
        .map(|e| e.sequence)
        .collect::<Vec<_>>();
    assert_global_sequence_ordering_contract(&merged_from_oldest);

    let _fingerprints = scan_journal_crypto_fingerprints(&journal_path, PARTS, 10);
}
