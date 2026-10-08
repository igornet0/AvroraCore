//! Segment rotation keeps the published journal manifest consistent across crash / reopen.
//!
//! Regression: rotation used to seal the manifest's active segment without publishing a new
//! manifest, so reopen failed with `active segment N must not have footer` and entries in the
//! new segment were orphans invisible to recovery.

use dmc_vault::crypto::derive_journal_kek;
use dmc_vault::key::{KeyPath, KeyTree};

use dmc_journal::journal_manifest_v2::{StoredJournalManifest, read_stored_manifest};
use dmc_journal::partition::{PartitionKey, resolve_partition};
use dmc_journal::segment::SegmentState;
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
    /// Payloads whose append + sync both returned Ok (acknowledged), in order.
    acked: Vec<Vec<u8>>,
}

impl Fixture {
    fn new(partitions: u32) -> Self {
        let (mut tree, master) = KeyTree::create_new().unwrap();
        let path = KeyPath::parse("company/finance/rot").unwrap();
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

    fn partition_key(&self) -> Option<PartitionKey> {
        if self.partitions <= 1 {
            return None;
        }
        (0..10_000)
            .map(|i| PartitionKey::new(format!("route-{i}")))
            .find(|k| {
                resolve_partition(&self.path, Some(k), self.partitions)
                    .unwrap()
                    .as_u32()
                    == 1
            })
    }

    /// Append + sync; records the payload as acknowledged only if both succeed.
    fn try_append(&mut self, journal: &mut Journal) -> bool {
        let payload = format!("entry-{:05}", self.acked.len()).into_bytes();
        let dek = self.tree.dek(&self.path).unwrap().clone();
        let draft = JournalEntryDraft {
            path: self.path.clone(),
            event_kind: JournalEventKind::OverlayApply,
            operation: Operation::OverlayPut,
            key_version: self.tree.meta(&self.path).unwrap().generation,
            actor_session: [7u8; 16],
            actor_role: "root".into(),
            node_bundle: Vec::new(),
            payload: payload.clone(),
            partition_key: self.partition_key(),
        };
        if journal.append(draft, &dek).is_err() || journal.sync().is_err() {
            return false;
        }
        self.acked.push(payload);
        true
    }

    fn append_n(&mut self, journal: &mut Journal, n: usize) {
        for _ in 0..n {
            assert!(self.try_append(journal), "append must succeed");
        }
    }

    /// Every acknowledged entry is recovered exactly once, in order, with contiguous sequences.
    fn assert_recovered(&mut self, journal: &Journal) {
        let replayed = journal.replay(0, &mut self.tree).unwrap();
        let payloads: Vec<_> = replayed.iter().map(|e| e.payload.clone()).collect();
        assert_eq!(
            payloads, self.acked,
            "recovered entries != acknowledged entries"
        );
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
}

fn sealed_count(m: &StoredJournalManifest) -> usize {
    m.all_segments()
        .iter()
        .filter(|(_, s)| s.state == SegmentState::Sealed)
        .count()
}

#[test]
fn reopen_after_rotation_with_bootstrapped_manifest() {
    let mut fx = Fixture::new(1);
    {
        let mut j = fx.open();
        fx.append_n(&mut j, 1);
    }
    {
        // Reopen bootstraps manifest.json with segment 1 Active, then rotate several times.
        let mut j = fx.open();
        fx.append_n(&mut j, 40);
    }
    let mut j = fx.open();
    fx.assert_recovered(&j);
    assert!(
        sealed_count(&fx.manifest()) >= 2,
        "rotations must be published"
    );
    fx.append_n(&mut j, 5);
    drop(j);
    let j = fx.open();
    fx.assert_recovered(&j);
}

/// A fresh journal publishes its manifest at open, so even first-session rotations are
/// published and survive a crash/reopen.
#[test]
fn first_session_rotation_publishes_manifest() {
    for partitions in [1, 3] {
        let mut fx = Fixture::new(partitions);
        let mut j = fx.open();
        assert!(
            fx.dir.path().join("runtime/journal/manifest.json").exists(),
            "fresh journal publishes its manifest at open (partitions={partitions})"
        );
        fx.append_n(&mut j, 40);
        assert!(sealed_count(&fx.manifest()) >= 2, "partitions={partitions}");
        std::mem::forget(j);
        let mut j = fx.open();
        fx.assert_recovered(&j);
        fx.append_n(&mut j, 40);
        std::mem::forget(j);
        let j = fx.open();
        fx.assert_recovered(&j);
    }
}

/// Previously open bug: crash right after the first-session rotation footer made reopen fail
/// with "manifest has no active segment". With the manifest published at open, recovery rolls
/// the interrupted rotation back.
#[test]
fn first_session_rotation_crash_after_footer_recovers() {
    for partitions in [1, 3] {
        let mut fx = Fixture::new(partitions);
        let mut j = fx.open();
        set_test_crash_point(Some(CrashPoint::AfterRotationFooter));
        let mut crashed = false;
        for _ in 0..200 {
            if !fx.try_append(&mut j) {
                crashed = true;
                break;
            }
        }
        set_test_crash_point(None);
        assert!(crashed);
        std::mem::forget(j);
        let mut j = fx.open();
        fx.assert_recovered(&j);
        fx.append_n(&mut j, 40);
        std::mem::forget(j);
        let j = fx.open();
        fx.assert_recovered(&j);
    }
}

const ROTATION_CRASH_POINTS: [CrashPoint; 6] = [
    CrashPoint::AfterRotationFooter,
    CrashPoint::AfterRotationNewSegment,
    CrashPoint::BeforeManifestTmp,
    CrashPoint::AfterManifestTmpFsync,
    CrashPoint::BeforeManifestRename,
    CrashPoint::AfterManifestRename,
];

/// Crash at each persistence boundary of a rotation (with an existing manifest), reopen:
/// the journal opens, no acknowledged entry is lost or duplicated, sequences stay contiguous,
/// and later rotations still publish consistently.
fn crash_matrix(partitions: u32) {
    for point in ROTATION_CRASH_POINTS {
        let mut fx = Fixture::new(partitions);
        {
            let mut j = fx.open();
            fx.append_n(&mut j, 1);
        }
        let mut j = fx.open(); // bootstraps manifest.json
        set_test_crash_point(Some(point));
        let mut crashed = false;
        for _ in 0..200 {
            if !fx.try_append(&mut j) {
                crashed = true;
                break;
            }
        }
        set_test_crash_point(None);
        assert!(crashed, "{point:?}: rotation never reached the crash point");
        // Fail-stop until reopen: no further entry may be acknowledged into this topology.
        assert!(
            !fx.try_append(&mut j),
            "{point:?}: append after failed rotation"
        );
        std::mem::forget(j); // simulated kill -9

        let mut j = fx.open();
        fx.assert_recovered(&j);
        fx.append_n(&mut j, 60);
        std::mem::forget(j);
        let j = fx.open();
        fx.assert_recovered(&j);
        assert!(sealed_count(&fx.manifest()) >= 2, "{point:?}");
    }
}

#[test]
fn rotation_crash_points_with_manifest() {
    crash_matrix(1);
}

#[test]
fn rotation_crash_points_partitioned() {
    crash_matrix(3);
}

/// A footer on the manifest-active segment that does not seal a valid segment is corruption,
/// not an interrupted rotation: open must keep failing closed.
#[test]
fn corrupt_footered_active_segment_still_fails_closed() {
    let mut fx = Fixture::new(1);
    {
        let mut j = fx.open();
        fx.append_n(&mut j, 3);
    }
    drop(fx.open()); // bootstrap manifest: segment 1 Active
    let seg = fx.dir.path().join("journal/seg-000000000001.jnl");
    let mut bytes = std::fs::read(&seg).unwrap();
    // Valid footer claiming the wrong entry count → validate_sealed_segment rejects it.
    bytes.extend_from_slice(&dmc_journal::codec::encode_footer(3, 99));
    std::fs::write(&seg, &bytes).unwrap();
    let err = Journal::open(fx.config(), &fx.kek)
        .err()
        .expect("must fail closed");
    assert!(
        matches!(
            err,
            dmc_journal::error::Error::JournalManifestInconsistent(_)
        ),
        "{err:?}"
    );
}
