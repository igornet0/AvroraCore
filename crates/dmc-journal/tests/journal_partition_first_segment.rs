//! First segment of a partition created after `manifest.json` exists must be published.
//!
//! Regression: with `partition_count > 1`, the first append to a partition without a segment
//! created the segment file but never added it to the manifest. Recovery trusts only the
//! manifest, so after reopen the acknowledged entry silently disappeared.

use dmc_vault::crypto::derive_journal_kek;
use dmc_vault::key::{KeyPath, KeyTree};

use dmc_journal::journal_manifest_v2::{StoredJournalManifest, read_stored_manifest};
use dmc_journal::partition::{PartitionId, PartitionKey, resolve_partition};
use dmc_journal::segment::SegmentState;
use dmc_journal::{
    CrashPoint, Journal, JournalConfig, JournalEntryDraft, JournalEventKind, Operation,
    set_test_crash_point,
};

const PARTS: u32 = 3;

struct Fixture {
    dir: tempfile::TempDir,
    tree: KeyTree,
    kek: dmc_vault::KeyMaterial,
    path: KeyPath,
    /// Payloads whose append + sync both returned Ok (acknowledged), in sequence order.
    acked: Vec<Vec<u8>>,
}

impl Fixture {
    fn new() -> Self {
        let (mut tree, master) = KeyTree::create_new().unwrap();
        let path = KeyPath::parse("company/finance/parts").unwrap();
        tree.ensure_node(&path).unwrap();
        let kek = derive_journal_kek(&master, tree.salt());
        Self {
            dir: tempfile::tempdir().unwrap(),
            tree,
            kek,
            path,
            acked: Vec::new(),
        }
    }

    fn config(&self) -> JournalConfig {
        JournalConfig::new(self.dir.path().join("journal")).with_partition_count(PARTS)
    }

    fn open(&self) -> Journal {
        Journal::open(self.config(), &self.kek).expect("journal must open")
    }

    fn key_for(&self, partition: u32) -> PartitionKey {
        (0..10_000)
            .map(|i| PartitionKey::new(format!("route-{i}")))
            .find(|k| {
                resolve_partition(&self.path, Some(k), PARTS)
                    .unwrap()
                    .as_u32()
                    == partition
            })
            .expect("routing key")
    }

    /// Append + sync to `partition`; recorded as acknowledged only if both succeed.
    fn try_append(&mut self, journal: &mut Journal, partition: u32) -> bool {
        let payload = format!("p{partition}-{:04}", self.acked.len()).into_bytes();
        let dek = self.tree.dek(&self.path).unwrap().clone();
        let draft = JournalEntryDraft {
            path: self.path.clone(),
            event_kind: JournalEventKind::OverlayApply,
            operation: Operation::OverlayPut,
            key_version: self.tree.meta(&self.path).unwrap().generation,
            actor_session: [3u8; 16],
            actor_role: "root".into(),
            node_bundle: Vec::new(),
            payload: payload.clone(),
            partition_key: Some(self.key_for(partition)),
        };
        if journal.append(draft, &dek).is_err() || journal.sync().is_err() {
            return false;
        }
        self.acked.push(payload);
        true
    }

    fn append(&mut self, journal: &mut Journal, partition: u32) {
        assert!(
            self.try_append(journal, partition),
            "append to p{partition}"
        );
    }

    /// Exactly the acknowledged entries are recovered, in order, with contiguous sequences.
    fn assert_recovered(&mut self, journal: &Journal) {
        let replayed = journal.replay(0, &mut self.tree).unwrap();
        let payloads: Vec<_> = replayed.iter().map(|e| e.payload.clone()).collect();
        assert_eq!(payloads, self.acked, "recovered != acknowledged");
        for (i, e) in replayed.iter().enumerate() {
            assert_eq!(e.sequence, i as u64 + 1, "sequence gap/duplicate");
        }
        assert_eq!(journal.last_sequence(), self.acked.len() as u64);
    }

    fn manifest(&self) -> StoredJournalManifest {
        read_stored_manifest(&self.dir.path().join("runtime/journal/manifest.json"))
            .unwrap()
            .expect("manifest published")
    }

    fn active_in_manifest(&self, partition: u32) -> Option<u64> {
        self.manifest()
            .all_segments()
            .into_iter()
            .find(|(pid, s)| *pid == PartitionId(partition) && s.state == SegmentState::Active)
            .map(|(_, s)| s.segment_id)
    }

    /// Session 1 writes partition 0 only; reopen bootstraps a manifest without partition 2.
    fn bootstrap_without_partition_2(&mut self) {
        let mut j = self.open();
        self.append(&mut j, 0);
        drop(j);
        drop(self.open());
        assert!(self.active_in_manifest(0).is_some());
        assert!(self.active_in_manifest(2).is_none());
    }
}

#[test]
fn first_partition_segment_after_manifest_survives_reopen() {
    let mut fx = Fixture::new();
    fx.bootstrap_without_partition_2();
    {
        let mut j = fx.open();
        fx.append(&mut j, 2);
        fx.append(&mut j, 0);
        fx.append(&mut j, 2);
        assert!(
            fx.active_in_manifest(2).is_some(),
            "segment must be published before its first entry is acknowledged"
        );
        std::mem::forget(j); // kill -9 after ACK
    }
    let mut j = fx.open();
    fx.assert_recovered(&j);
    fx.append(&mut j, 1);
    fx.append(&mut j, 2);
    drop(j);
    let j = fx.open();
    fx.assert_recovered(&j);
}

const FIRST_SEGMENT_CRASH_POINTS: [CrashPoint; 6] = [
    CrashPoint::AfterPartitionSegmentCreate,
    CrashPoint::AfterPartitionSegmentFsync,
    CrashPoint::BeforeManifestTmp,
    CrashPoint::AfterManifestTmpFsync,
    CrashPoint::BeforeManifestRename,
    CrashPoint::AfterManifestRename,
];

/// Crash at every boundary of first-segment creation for partition 2, then reopen:
/// the failed append was never acknowledged, exactly the acknowledged entries are recovered,
/// and partition 2 is usable afterwards (its entries survive a further crash/reopen).
#[test]
fn first_partition_segment_crash_points() {
    for point in FIRST_SEGMENT_CRASH_POINTS {
        let mut fx = Fixture::new();
        fx.bootstrap_without_partition_2();
        let mut j = fx.open();
        fx.append(&mut j, 0);
        fx.append(&mut j, 1);
        set_test_crash_point(Some(point));
        let acked = fx.try_append(&mut j, 2);
        set_test_crash_point(None);
        assert!(!acked, "{point:?}: crash point not reached");
        // Fail-stop until reopen, for every partition.
        assert!(
            !fx.try_append(&mut j, 2),
            "{point:?}: p2 append after failure"
        );
        assert!(
            !fx.try_append(&mut j, 0),
            "{point:?}: p0 append after failure"
        );
        std::mem::forget(j); // simulated kill -9

        let mut j = fx.open();
        fx.assert_recovered(&j);
        fx.append(&mut j, 2);
        fx.append(&mut j, 0);
        fx.append(&mut j, 2);
        assert!(fx.active_in_manifest(2).is_some(), "{point:?}");
        std::mem::forget(j);
        let j = fx.open();
        fx.assert_recovered(&j);
    }
}

/// journal.meta persisted pointing partition 2 at the unpublished segment (crash after the
/// directory fsync, before manifest publication). Recovery must not reuse that orphan as the
/// active segment — otherwise later ACKed entries would land in a segment replay ignores.
#[test]
fn stale_meta_never_reactivates_unpublished_partition_segment() {
    let mut fx = Fixture::new();
    fx.bootstrap_without_partition_2();
    let mut j = fx.open();
    set_test_crash_point(Some(CrashPoint::AfterPartitionSegmentFsync));
    assert!(!fx.try_append(&mut j, 2));
    set_test_crash_point(None);
    std::mem::forget(j);
    let meta_path = fx.dir.path().join("journal/journal.meta");
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&meta_path).unwrap()).unwrap();
    let orphan = meta["partition_active_segments"][2].as_u64().unwrap();
    assert!(orphan > 0, "meta should name the unpublished segment");

    let mut j = fx.open();
    fx.append(&mut j, 2);
    let active = fx.active_in_manifest(2).expect("published");
    assert_ne!(active, orphan, "orphan must not become the active segment");
    std::mem::forget(j);
    let j = fx.open();
    fx.assert_recovered(&j);
}

/// Single-partition journals never take the new path: no extra manifest generations.
#[test]
fn single_partition_appends_do_not_republish_manifest() {
    let (mut tree, master) = KeyTree::create_new().unwrap();
    let path = KeyPath::parse("company/finance/single").unwrap();
    tree.ensure_node(&path).unwrap();
    let kek = derive_journal_kek(&master, tree.salt());
    let dir = tempfile::tempdir().unwrap();
    let config = JournalConfig::new(dir.path().join("journal"));
    let append = |j: &mut Journal, tree: &mut KeyTree| {
        let dek = tree.dek(&path).unwrap().clone();
        let draft = JournalEntryDraft {
            path: path.clone(),
            event_kind: JournalEventKind::OverlayApply,
            operation: Operation::OverlayPut,
            key_version: tree.meta(&path).unwrap().generation,
            actor_session: [3u8; 16],
            actor_role: "root".into(),
            node_bundle: Vec::new(),
            payload: b"x".to_vec(),
            partition_key: None,
        };
        j.append(draft, &dek).unwrap();
        j.sync().unwrap();
    };
    {
        let mut j = Journal::open(config.clone(), &kek).unwrap();
        append(&mut j, &mut tree);
    }
    let manifest_path = dir.path().join("runtime/journal/manifest.json");
    let mut j = Journal::open(config.clone(), &kek).unwrap();
    let generation = read_stored_manifest(&manifest_path)
        .unwrap()
        .unwrap()
        .generation();
    for _ in 0..10 {
        append(&mut j, &mut tree);
    }
    drop(j);
    let j = Journal::open(config, &kek).unwrap();
    assert_eq!(
        read_stored_manifest(&manifest_path)
            .unwrap()
            .unwrap()
            .generation(),
        generation
    );
    assert_eq!(j.replay(0, &mut tree).unwrap().len(), 11);
}
