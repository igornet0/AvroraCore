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
pub use crash_injection::{set_test_crash_point, CrashPoint};
pub use codec::set_test_timestamp_ms;
pub use journal::{set_test_partition_count, set_test_segment_max_bytes, Journal};
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
