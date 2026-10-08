//! Encrypted durable journal (`phase-1-journal-v1`).
//!
//! Payload is AES-256-GCM under the path DEK with path-bound AAD.
//! Journal KEK identifies segments. Recovery truncates a CRC-invalid tail.

pub mod crash_injection;
pub mod codec;
pub mod error;
pub mod journal;
pub mod layout;
pub mod merge_reader;
pub mod meta;
pub mod migrate;
pub mod retention;
pub mod compaction;
pub mod compaction_write;
pub mod compaction_publish;
pub mod compactor;
pub mod authoritative;
pub mod journal_manifest;
pub mod journal_manifest_v2;
pub mod topology;
pub mod lifecycle;
pub mod partition;
pub mod reconciliation;
pub mod segment;
pub mod snapshot;
pub mod types;
pub mod watermark;

pub use error::{Error, Result};
pub use crash_injection::{
    set_test_crash_point, set_test_fail_fsync, set_test_group_sync_delay_ms, CrashPoint,
};
pub use codec::set_test_timestamp_ms;
pub use journal::{
    journal_fsync_count, set_test_partition_count, set_test_segment_max_bytes, GroupSync, Journal,
};
pub use retention::{age_trim_through, bytes_trim_through, combine_trim_through};
pub use compaction::{
    CompactionArtifact, CompactionCandidate, CompactionPolicy, CompactionResult,
    select_compaction_candidate, select_compaction_candidate_for_partition,
};
pub use compactor::{JournalSegmentCompactor, SegmentCompactor};
pub use journal_manifest::{
    manifest_active_segment, manifest_from_segment_infos, read_manifest, JournalManifest,
    SegmentManifestEntry, JOURNAL_MANIFEST_FORMAT_VERSION, JOURNAL_MANIFEST_FORMAT_VERSION_V2,
    MANIFEST_TMP,
};
pub use journal_manifest_v2::{
    build_compaction_manifest_v2, discover_segment_partitions, manifest_active_segments,
    manifest_v2_from_segment_infos, publish_manifest_v2, publish_stored_manifest,
    read_stored_manifest, validate_manifest_v2, validate_stored_manifest, JournalManifestV2,
    PartitionManifest, StoredJournalManifest,
};
pub use authoritative::{authoritative_segment_ids, legacy_topology_unambiguous};
pub use lifecycle::{
    classify_segment_disposition, is_gc_eligible, JournalSegmentLifecycle, SegmentDisposition,
};
pub use partition::{
    resolve_partition, routing_hash, PartitionId, PartitionKey, PartitionSpec,
};
pub use reconciliation::{
    inspect_reconciliation, reconcile, JournalReconciliation, JournalReconciliationResult,
};
pub use topology::{JournalTopology, JournalTopologyGuard};
pub use layout::StorageLayout;
pub use merge_reader::JournalMergeReader;
pub use meta::JournalMeta;
pub use migrate::migrate_v1_to_v2;
pub use segment::{
    JournalSegmentInfo, PartitionTrimCandidate, SegmentState, TrimCandidate, TrimResult,
};
pub use snapshot::{encode_snapshot_blob, RecoveredSnapshot, SnapshotManifest, SnapshotStore};
pub use types::{
    event_id_hex, session_bytes, FsyncPolicy, JournalConfig, JournalEntry, JournalEntryDraft,
    JournalEntryRef, JournalEventKind, Operation, RecoveryReport,
};
pub use watermark::{calculate_watermark, JournalPin, RetentionWatermark, SequencePin};

#[cfg(test)]
mod tests {
    use dmc_vault::access::Capability;
    use dmc_vault::crypto::derive_journal_kek;
    use dmc_vault::key::{KeyPath, KeyTree};
    use dmc_vault::store::EncryptedKv;

    use super::*;

    fn setup(dir: &std::path::Path) -> (Journal, KeyTree, dmc_vault::KeyMaterial) {
        let (mut tree, master) = KeyTree::create_new().unwrap();
        let path = KeyPath::parse("company/finance/invoices/1").unwrap();
        tree.ensure_node(&path).unwrap();
        let kek = derive_journal_kek(&master, tree.salt());
        let jdir = dir.join("journal");
        let journal = Journal::open(JournalConfig::new(jdir), &kek).unwrap();
        (journal, tree, master)
    }

    fn draft(tree: &mut KeyTree, payload: &[u8]) -> (JournalEntryDraft, dmc_vault::KeyMaterial) {
        let path = KeyPath::parse("company/finance/invoices/1").unwrap();
        let dek = tree.dek(&path).unwrap().clone();
        let key_version = tree.meta(&path).unwrap().generation;
        let bundle = tree
            .list_nodes()
            .into_iter()
            .filter(|n| {
                let p = n.key_path().unwrap();
                p.is_prefix_of(&path) || path.is_prefix_of(&p) || p.is_root()
            })
            .collect();
        (
            JournalEntryDraft {
                path,
                event_kind: JournalEventKind::OverlayApply,
                operation: Operation::OverlayPut,
                key_version,
                actor_session: [1u8; 16],
                actor_role: "root".into(),
                node_bundle: bundle,
                payload: payload.to_vec(),
                partition_key: None,
            },
            dek,
        )
    }

    #[test]
    fn append_replay_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let (mut journal, mut tree, _) = setup(dir.path());
        let (d, dek) = draft(&mut tree, b"hello");
        let r = journal.append(d, &dek).unwrap();
        journal.sync().unwrap();
        assert_eq!(r.sequence, 1);

        let replayed = journal.replay(0, &mut tree).unwrap();
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].payload, b"hello");
        assert_eq!(replayed[0].sequence, 1);
    }

    #[test]
    fn corrupt_tail_recovers_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let (mut journal, mut tree, master) = setup(dir.path());
        let (d1, dek) = draft(&mut tree, b"one");
        journal.append(d1, &dek).unwrap();
        journal.sync().unwrap();
        let (d2, dek) = draft(&mut tree, b"two");
        journal.append(d2, &dek).unwrap();
        journal.sync().unwrap();

        let seg = dir.path().join("journal/seg-000000000001.jnl");
        let mut bytes = std::fs::read(&seg).unwrap();
        let n = bytes.len();
        for b in bytes.iter_mut().skip(n.saturating_sub(64)) {
            *b ^= 0xff;
        }
        std::fs::write(&seg, &bytes).unwrap();

        drop(journal);
        let kek = derive_journal_kek(&master, tree.salt());
        let mut journal = Journal::open(JournalConfig::new(dir.path().join("journal")), &kek).unwrap();
        let report = journal.recover().unwrap();
        assert!(report.truncated_bytes > 0 || journal.last_sequence() >= 1);

        let replayed = journal.replay(0, &mut tree).unwrap();
        assert!(!replayed.is_empty());
        assert_eq!(replayed[0].payload, b"one");
        assert!(replayed.iter().all(|e| e.payload != b"two") || replayed.len() == 1);

        let (d3, dek) = draft(&mut tree, b"three");
        let r = journal.append(d3, &dek).unwrap();
        journal.sync().unwrap();
        assert!(r.sequence > replayed.last().map(|e| e.sequence).unwrap_or(0));
    }

    /// Per-commit sync no longer rewrites `journal.meta`; recovery must derive the head from
    /// segments regardless of whether meta is stale, missing or garbage (crash without close).
    #[test]
    fn crash_with_stale_missing_or_corrupt_meta_recovers_all_synced_entries() {
        for meta_state in ["stale", "missing", "garbage"] {
            let dir = tempfile::tempdir().unwrap();
            let (mut journal, mut tree, master) = setup(dir.path());
            let meta_path = dir.path().join("journal/journal.meta");
            let (d, dek) = draft(&mut tree, b"p0");
            journal.append(d, &dek).unwrap();
            journal.sync().unwrap();
            let meta_after_first = std::fs::read(&meta_path).unwrap();
            for i in 1..25u32 {
                let (d, dek) = draft(&mut tree, format!("p{i}").as_bytes());
                journal.append(d, &dek).unwrap();
                journal.sync().unwrap();
            }
            // Steady-state commits do not touch meta.
            assert_eq!(std::fs::read(&meta_path).unwrap(), meta_after_first);
            match meta_state {
                "missing" => std::fs::remove_file(&meta_path).unwrap(),
                "garbage" => std::fs::write(&meta_path, b"{not json").unwrap(),
                _ => {}
            }
            // Simulated crash: no close/flush beyond the acknowledged syncs.
            std::mem::forget(journal);

            let kek = derive_journal_kek(&master, tree.salt());
            let mut journal =
                Journal::open(JournalConfig::new(dir.path().join("journal")), &kek).unwrap();
            assert_eq!(journal.last_sequence(), 25, "{meta_state}");
            let replayed = journal.replay(0, &mut tree).unwrap();
            assert_eq!(replayed.len(), 25, "{meta_state}");
            for (i, e) in replayed.iter().enumerate() {
                assert_eq!(e.sequence, i as u64 + 1);
                assert_eq!(e.payload, format!("p{i}").into_bytes());
            }
            let (d, dek) = draft(&mut tree, b"after");
            assert_eq!(
                journal.append(d, &dek).unwrap().sequence,
                26,
                "{meta_state}"
            );
            journal.sync().unwrap();
        }
    }

    /// Rotation creates new segment files: topology (meta + dir fsync) must be persisted so a
    /// crash right after any rotation recovers every synced entry exactly once, in order.
    #[test]
    fn crash_after_rotations_recovers_all_synced_entries() {
        let dir = tempfile::tempdir().unwrap();
        let (mut tree, master) = KeyTree::create_new().unwrap();
        tree.ensure_node(&KeyPath::parse("company/finance/invoices/1").unwrap())
            .unwrap();
        let kek = derive_journal_kek(&master, tree.salt());
        let config = JournalConfig::new(dir.path().join("journal")).with_segment_max_bytes(2048);
        let mut journal = Journal::open(config.clone(), &kek).unwrap();
        for i in 0..60u32 {
            let (d, dek) = draft(&mut tree, format!("r{i}").as_bytes());
            journal.append(d, &dek).unwrap();
            journal.sync().unwrap();
        }
        let segments = std::fs::read_dir(dir.path().join("journal"))
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".jnl")
            })
            .count();
        assert!(segments > 2, "expected rotations, got {segments} segments");
        std::mem::forget(journal);

        let mut journal = Journal::open(config, &kek).unwrap();
        assert_eq!(journal.last_sequence(), 60);
        let replayed = journal.replay(0, &mut tree).unwrap();
        assert_eq!(replayed.len(), 60);
        for (i, e) in replayed.iter().enumerate() {
            assert_eq!(e.sequence, i as u64 + 1);
            assert_eq!(e.payload, format!("r{i}").into_bytes());
        }
        let (d, dek) = draft(&mut tree, b"next");
        assert_eq!(journal.append(d, &dek).unwrap().sequence, 61);
    }

    /// `scan_segment_after` (reader fast path) == `scan_segment` filtered by sequence, for
    /// every start position, including a corrupt tail (same stop point).
    #[test]
    fn scan_segment_after_matches_full_scan() {
        let dir = tempfile::tempdir().unwrap();
        let (mut journal, mut tree, _) = setup(dir.path());
        for i in 0..20u32 {
            let (d, dek) = draft(&mut tree, format!("s{i}").as_bytes());
            journal.append(d, &dek).unwrap();
            journal.sync().unwrap();
        }
        let seg = dir.path().join("journal/seg-000000000001.jnl");
        let mut bytes = std::fs::read(&seg).unwrap();
        for corrupt in [false, true] {
            if corrupt {
                let n = bytes.len();
                bytes[n - 10] ^= 0xff; // last record fails CRC → both scans stop before it
            }
            let (_, all, _) = codec::scan_segment(&bytes).unwrap();
            for from in 0..=22u64 {
                let fast = codec::scan_segment_after(&bytes, from).unwrap();
                let expected: Vec<u64> =
                    all.iter().map(|e| e.sequence).filter(|s| *s > from).collect();
                let got: Vec<u64> = fast.iter().map(|e| e.sequence).collect();
                assert_eq!(got, expected, "from={from} corrupt={corrupt}");
                for (a, b) in fast.iter().zip(all.iter().filter(|e| e.sequence > from)) {
                    assert_eq!(a.ciphertext, b.ciphertext);
                    assert_eq!(a.path, b.path);
                }
            }
        }
    }

    #[test]
    fn migrate_leaves_legacy_file() {
        let dir = tempfile::tempdir().unwrap();
        let layout = StorageLayout::from_db_path(dir.path().join("store.dbs.json"));
        let (tree, _master) = KeyTree::create_new().unwrap();
        let kv = EncryptedKv::new(tree);
        let roles = dmc_vault::RoleRegistry::with_root();
        let cap = Capability::root_admin();
        let _ = cap;
        let snap = dmc_vault::persist::DbSnapshot::from_kv(&kv, &roles).unwrap();
        snap.save(&layout.legacy_snapshot()).unwrap();

        assert!(migrate_v1_to_v2(&layout).unwrap());
        assert!(layout.legacy_snapshot().is_file());
        assert!(layout.legacy_backup().is_file());
        assert!(layout.base_snapshot().is_file());
        assert!(layout.migrated_marker().is_file());
        assert!(!migrate_v1_to_v2(&layout).unwrap());
    }
}
