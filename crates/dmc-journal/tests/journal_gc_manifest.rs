//! Retention GC (`trim_through`) keeps the published manifest consistent.
//!
//! Regression: with a manifest present, trim deleted sealed segment files but left them listed
//! as authoritative, so the trim itself and every later open failed with
//! `segment file … missing`.

use dmc_vault::crypto::derive_journal_kek;
use dmc_vault::key::{KeyPath, KeyTree};

use dmc_journal::journal_manifest_v2::{StoredJournalManifest, read_stored_manifest};
use dmc_journal::layout::list_segment_ids;
use dmc_journal::partition::{PartitionKey, resolve_partition};
use dmc_journal::{
    CrashPoint, Journal, JournalConfig, JournalEntryDraft, JournalEventKind, Operation,
    set_test_crash_point,
};

const SEGMENT_MAX: u64 = 1024;

struct Fixture {
    dir: tempfile::TempDir,
    tree: KeyTree,
    kek: dmc_vault::KeyMaterial,
    path: KeyPath,
    partitions: u32,
    /// Payload of every acknowledged entry, indexed by `sequence - 1`.
    acked: Vec<Vec<u8>>,
}

impl Fixture {
    fn new(partitions: u32) -> Self {
        let (mut tree, master) = KeyTree::create_new().unwrap();
        let path = KeyPath::parse("company/finance/gc").unwrap();
        tree.ensure_node(&path).unwrap();
        let kek = derive_journal_kek(&master, tree.salt());
        Self {
            dir: tempfile::tempdir().unwrap(),
            tree,
            kek,
            path,
            partitions,
            acked: Vec::new(),
        }
    }

    fn config(&self) -> JournalConfig {
        JournalConfig::new(self.dir.path().join("journal"))
            .with_segment_max_bytes(SEGMENT_MAX)
            .with_partition_count(self.partitions)
    }

    fn open(&self) -> Journal {
        Journal::open(self.config(), &self.kek).expect("journal must open")
    }

    fn key(&self, n: usize) -> Option<PartitionKey> {
        if self.partitions <= 1 {
            return None;
        }
        let target = (n as u32) % self.partitions;
        (0..10_000)
            .map(|i| PartitionKey::new(format!("route-{i}")))
            .find(|k| {
                resolve_partition(&self.path, Some(k), self.partitions)
                    .unwrap()
                    .as_u32()
                    == target
            })
    }

    fn append_n(&mut self, journal: &mut Journal, n: usize) {
        for _ in 0..n {
            let i = self.acked.len();
            let payload = format!("gc-{i:05}").into_bytes();
            let dek = self.tree.dek(&self.path).unwrap().clone();
            let draft = JournalEntryDraft {
                path: self.path.clone(),
                event_kind: JournalEventKind::OverlayApply,
                operation: Operation::OverlayPut,
                key_version: self.tree.meta(&self.path).unwrap().generation,
                actor_session: [9u8; 16],
                actor_role: "root".into(),
                node_bundle: Vec::new(),
                payload: payload.clone(),
                partition_key: self.key(i),
            };
            let r = journal.append(draft, &dek).unwrap();
            journal.sync().unwrap();
            assert_eq!(r.sequence, i as u64 + 1);
            self.acked.push(payload);
        }
    }

    /// Everything replay returns is an acknowledged entry (right payload, strictly increasing
    /// sequence) and every acknowledged entry above `trimmed_through` is present. A single
    /// partition retains a contiguous suffix from `oldest_available_sequence`; with several
    /// partitions trim is per partition, so older entries of other partitions may remain.
    fn assert_retained(&mut self, journal: &Journal, trimmed_through: u64) -> u64 {
        let oldest = journal.oldest_available_sequence().unwrap();
        assert!(oldest >= 1 && oldest <= trimmed_through + 1, "oldest {oldest}");
        let replayed = journal.replay(0, &mut self.tree).unwrap();
        let mut prev = 0;
        for e in &replayed {
            assert!(e.sequence > prev, "sequence order");
            prev = e.sequence;
            assert_eq!(e.payload, self.acked[(e.sequence - 1) as usize], "seq {}", e.sequence);
        }
        let seqs: std::collections::HashSet<u64> = replayed.iter().map(|e| e.sequence).collect();
        for seq in (trimmed_through + 1)..=self.acked.len() as u64 {
            assert!(seqs.contains(&seq), "acknowledged entry {seq} lost");
        }
        if self.partitions <= 1 {
            let expected: Vec<u64> = (oldest..=self.acked.len() as u64).collect();
            let got: Vec<u64> = replayed.iter().map(|e| e.sequence).collect();
            assert_eq!(got, expected, "single partition retains a contiguous suffix");
        }
        assert_eq!(journal.last_sequence(), self.acked.len() as u64);
        oldest
    }

    fn segment_files(&self) -> Vec<u64> {
        let mut ids = list_segment_ids(&self.dir.path().join("journal")).unwrap();
        ids.sort_unstable();
        ids
    }

    fn manifest(&self) -> StoredJournalManifest {
        read_stored_manifest(&self.dir.path().join("runtime/journal/manifest.json"))
            .unwrap()
            .expect("manifest published")
    }

    /// Session 1 rotates several segments; reopen bootstraps the manifest.
    fn with_manifest_and_sealed_segments(partitions: u32) -> (Self, Journal) {
        let mut fx = Self::new(partitions);
        {
            let mut j = fx.open();
            fx.append_n(&mut j, 120);
        }
        let j = fx.open();
        assert!(
            fx.manifest()
                .all_segments()
                .iter()
                .filter(|(_, s)| s.state == dmc_journal::segment::SegmentState::Sealed)
                .count()
                >= 3
        );
        (fx, j)
    }
}

#[test]
fn trim_with_manifest_then_reopen() {
    for partitions in [1, 3] {
        let (mut fx, mut j) = Fixture::with_manifest_and_sealed_segments(partitions);
        let through = 60;
        let result = j.trim_through(through).expect("trim with manifest");
        assert!(!result.deleted_segments.is_empty(), "p={partitions}");
        let oldest = fx.assert_retained(&j, through);
        assert!(oldest > 1, "trim must advance oldest available (p={partitions})");
        for id in &result.deleted_segments {
            assert!(!fx.manifest().authoritative_segment_ids().contains(id), "manifest still lists {id}");
            assert!(!fx.segment_files().contains(id), "segment {id} still on disk");
        }
        fx.append_n(&mut j, 30);
        drop(j);
        let j = fx.open();
        assert_eq!(fx.assert_retained(&j, through), oldest, "p={partitions}");
    }
}

const GC_CRASH_POINTS: [CrashPoint; 6] = [
    CrashPoint::BeforeGc,
    CrashPoint::BeforeManifestTmp,
    CrashPoint::AfterManifestTmpFsync,
    CrashPoint::BeforeManifestRename,
    CrashPoint::AfterManifestRename,
    CrashPoint::AfterGc,
];

/// Crash at each boundary of trim (before/after manifest publication, between fsync and
/// rename, after deletion): reopen succeeds, every acknowledged entry above the trim point is
/// retained, and a retried trim converges (no leftover segment files of trimmed ranges).
fn gc_crash_matrix(partitions: u32) {
    let mut points: Vec<CrashPoint> = GC_CRASH_POINTS.to_vec();
    // Mid-deletion: crash right after the first deleted segment file.
    points.push(CrashPoint::DuringGcAfterDelete(0));
    for point in points {
        let (mut fx, mut j) = Fixture::with_manifest_and_sealed_segments(partitions);
        let through = 60;
        let point = match point {
            CrashPoint::DuringGcAfterDelete(_) => {
                let first = j.eligible_segments(through).unwrap()[0].segment_id;
                CrashPoint::DuringGcAfterDelete(first)
            }
            p => p,
        };
        set_test_crash_point(Some(point));
        let r = j.trim_through(through);
        set_test_crash_point(None);
        assert!(r.is_err(), "{point:?}: crash point not reached");
        std::mem::forget(j); // simulated kill -9

        let mut j = fx.open();
        fx.assert_retained(&j, through);
        fx.append_n(&mut j, 10);

        // Retry converges: trimmed ranges gone from manifest and disk, journal reopens.
        j.trim_through(through).expect("retry trim");
        let oldest = fx.assert_retained(&j, through);
        assert!(oldest > 1, "{point:?}");
        drop(j);
        let j = fx.open();
        assert_eq!(fx.assert_retained(&j, through), oldest, "{point:?}");
        let manifest = fx.manifest();
        for id in fx.segment_files() {
            let listed = manifest.authoritative_segment_ids().contains(&id);
            let superseded = manifest.superseded_segment_ids().contains(&id);
            assert!(listed || superseded, "{point:?}: unaccounted segment file {id}");
        }
        for (_, s) in manifest.all_segments() {
            assert!(s.end_sequence >= oldest || s.start_sequence >= oldest, "{point:?}");
        }
    }
}

#[test]
fn gc_crash_points_single_partition() {
    gc_crash_matrix(1);
}

#[test]
fn gc_crash_points_multi_partition() {
    gc_crash_matrix(3);
}

/// Regression: with several partitions, rotated segments of different partitions have
/// interleaved (overlapping) sequence ranges. Legacy authoritative selection treated them as
/// compaction orphans and replay silently dropped acknowledged entries (and the manifest
/// bootstrapped at reopen made the loss permanent).
#[test]
fn partitioned_rotation_replays_every_acked_entry() {
    let mut fx = Fixture::new(3);
    let mut j = fx.open();
    fx.append_n(&mut j, 120);
    assert!(fx.segment_files().len() > 3, "expected rotations");
    assert_eq!(j.replay(0, &mut fx.tree).unwrap().len(), 120, "before reopen");
    drop(j);
    let mut j = fx.open();
    assert_eq!(j.replay(0, &mut fx.tree).unwrap().len(), 120, "after reopen");
    fx.append_n(&mut j, 30);
    drop(j);
    let j = fx.open();
    let replayed = j.replay(0, &mut fx.tree).unwrap();
    let got: Vec<_> = replayed.iter().map(|e| e.payload.clone()).collect();
    assert_eq!(got, fx.acked);
}
