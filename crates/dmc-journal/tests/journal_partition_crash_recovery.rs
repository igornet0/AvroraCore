//! Phase 5.7.9 — partition crash / recovery matrix (ADR-014).

use std::collections::HashMap;
use std::fs;

use dmc_vault::crypto::derive_journal_kek;
use dmc_vault::key::{KeyPath, KeyTree};

use dmc_journal::codec::{parse_entry_body, scan_segment_raw_records};
use dmc_journal::error::Error as JournalError;
use dmc_journal::journal_manifest::MANIFEST_TMP;
use dmc_journal::journal_manifest_v2::{
    build_compaction_manifest_v2, read_stored_manifest, StoredJournalManifest,
};
use dmc_journal::layout::{list_segment_ids, segment_path_for_partition};
use dmc_journal::lifecycle::SegmentDisposition;
use dmc_journal::partition::{resolve_partition, PartitionId, PartitionKey};
use dmc_journal::{
    calculate_watermark, CompactionPolicy, CrashPoint, Journal, JournalConfig, JournalEntryDraft,
    JournalEventKind, JournalPin, Operation, SequencePin, set_test_crash_point,
    set_test_partition_count, set_test_segment_max_bytes,
};

const PARTS: u32 = 3;

fn setup_tree() -> (KeyTree, dmc_vault::KeyMaterial, Vec<u8>, KeyPath) {
    let (mut tree, master) = KeyTree::create_new().unwrap();
    let path = KeyPath::parse("company/finance/x").unwrap();
    tree.ensure_node(&path).unwrap();
    let salt = tree.salt().to_vec();
    (tree, master, salt, path)
}

fn open_journal(dir: &std::path::Path, master: &dmc_vault::KeyMaterial, salt: &[u8]) -> Journal {
    let kek = derive_journal_kek(master, salt);
    Journal::open(
        JournalConfig::new(dir.join("journal"))
            .with_partition_count(PARTS)
            .with_segment_max_bytes(900),
        &kek,
    )
    .unwrap()
}

fn reopen(dir: &std::path::Path, master: &dmc_vault::KeyMaterial, salt: &[u8]) -> Journal {
    open_journal(dir, master, salt)
}

fn reopen_err(
    dir: &std::path::Path,
    master: &dmc_vault::KeyMaterial,
    salt: &[u8],
) -> JournalError {
    let kek = derive_journal_kek(master, salt);
    Journal::open(
        JournalConfig::new(dir.join("journal"))
            .with_partition_count(PARTS)
            .with_segment_max_bytes(900),
        &kek,
    )
    .err()
    .expect("expected open failure")
}

fn key_for_partition(path: &KeyPath, target: u32) -> PartitionKey {
    for i in 0..10_000 {
        let key = PartitionKey::new(format!("route-{i}"));
        if resolve_partition(path, Some(&key), PARTS).unwrap().as_u32() == target {
            return key;
        }
    }
    panic!("no routing key for partition {target}");
}

fn append_to_partition(
    journal: &mut Journal,
    tree: &mut KeyTree,
    path: &KeyPath,
    partition: u32,
    payload: &[u8],
) {
    let key = key_for_partition(path, partition);
    let dek = tree.dek(path).unwrap().clone();
    let draft = JournalEntryDraft {
        path: path.clone(),
        event_kind: JournalEventKind::OverlayApply,
        operation: Operation::OverlayPut,
        key_version: tree.meta(path).unwrap().generation,
        actor_session: [1u8; 16],
        actor_role: "root".into(),
        node_bundle: tree.list_nodes(),
        payload: payload.to_vec(),
        partition_key: Some(key),
    };
    journal.append(draft, &dek).unwrap();
    journal.sync().unwrap();
}

fn append_interleaved(journal: &mut Journal, tree: &mut KeyTree, path: &KeyPath, rounds: u32) {
    for r in 0..rounds {
        for p in 0..PARTS {
            append_to_partition(
                journal,
                tree,
                path,
                p,
                format!("r{r}-p{p}").as_bytes(),
            );
        }
    }
}

fn policy() -> CompactionPolicy {
    CompactionPolicy {
        enabled: true,
        min_segments: 2,
        min_total_bytes: 0,
        max_input_bytes: 10 * 1024 * 1024,
    }
}

fn bootstrap(journal: &Journal) {
    journal.bootstrap_journal_manifest(10).unwrap();
}

fn disposition_map(journal: &Journal) -> HashMap<u64, SegmentDisposition> {
    journal
        .inspect_reconciliation()
        .unwrap()
        .lifecycles
        .into_iter()
        .map(|l| (l.segment_id, l.disposition))
        .collect()
}

fn logical_stream(journal: &Journal, tree: &mut KeyTree) -> Vec<(u64, [u8; 16], Vec<u8>)> {
    journal
        .replay(0, tree)
        .unwrap()
        .into_iter()
        .map(|e| (e.sequence, e.event_id, e.payload))
        .collect()
}

fn merge_sequences(journal: &Journal, tree: &mut KeyTree) -> Vec<u64> {
    logical_stream(journal, tree)
        .into_iter()
        .map(|(s, _, _)| s)
        .collect()
}

fn prepare_manifested_interleaved(
    dir: &std::path::Path,
) -> (
    Journal,
    KeyTree,
    dmc_vault::KeyMaterial,
    Vec<u8>,
    Vec<(u64, [u8; 16], Vec<u8>)>,
) {
    let (mut tree, master, salt, path) = setup_tree();
    let mut journal = open_journal(dir, &master, &salt);
    append_interleaved(&mut journal, &mut tree, &path, 14);
    bootstrap(&journal);
    let expected = logical_stream(&journal, &mut tree);
    (journal, tree, master, salt, expected)
}

fn p0_candidate(journal: &Journal) -> (dmc_journal::CompactionCandidate, Vec<u64>) {
    let candidate = journal
        .select_compaction_candidate_for_partition(PartitionId(0), &policy())
        .unwrap()
        .unwrap();
    let sources = candidate.segment_ids.clone();
    (candidate, sources)
}

fn prepare_compacted_p0(
    dir: &std::path::Path,
) -> (
    Journal,
    KeyTree,
    dmc_vault::KeyMaterial,
    Vec<u8>,
    dmc_journal::CompactionArtifact,
    Vec<u64>,
    Vec<(u64, [u8; 16], Vec<u8>)>,
) {
    let (mut journal, mut tree, master, salt, expected) = prepare_manifested_interleaved(dir);
    let (candidate, sources) = p0_candidate(&journal);
    let artifact = journal.compact_candidate(&candidate).unwrap();
    (journal, tree, master, salt, artifact, sources, expected)
}

fn publish_p0(
    journal: &mut Journal,
    artifact: &dmc_journal::CompactionArtifact,
) -> dmc_journal::journal_manifest::JournalManifest {
    journal.publish_compaction(artifact).unwrap()
}

fn runtime_dir(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("runtime/journal")
}

fn is_simulated_crash(err: &JournalError) -> bool {
    err.to_string().contains("simulated crash")
}

struct Env;

impl Env {
    fn new() -> Self {
        set_test_segment_max_bytes(Some(900));
        set_test_partition_count(Some(PARTS));
        Self
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        set_test_crash_point(None);
        set_test_partition_count(None);
        set_test_segment_max_bytes(None);
    }
}

#[test]
fn p0_before_artifact_old_topology() {
    let _env = Env::new();
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, master, salt, expected) = prepare_manifested_interleaved(dir.path());
    let (candidate, sources) = p0_candidate(&journal);
    set_test_crash_point(Some(CrashPoint::BeforeArtifact));
    let err = journal.compact_candidate(&candidate).unwrap_err();
    assert!(is_simulated_crash(&err));

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    assert_eq!(logical_stream(&journal2, &mut tree), expected);
    for id in &sources {
        assert_eq!(
            disposition_map(&journal2).get(id),
            Some(&SegmentDisposition::Authoritative)
        );
    }
}

#[test]
fn p4_orphan_artifact_after_rename() {
    let _env = Env::new();
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, master, salt, expected) = prepare_manifested_interleaved(dir.path());
    let (candidate, sources) = p0_candidate(&journal);
    set_test_crash_point(Some(CrashPoint::AfterArtifactRename));
    let err = journal.compact_candidate(&candidate).unwrap_err();
    assert!(is_simulated_crash(&err));

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    assert_eq!(logical_stream(&journal2, &mut tree), expected);
    assert!(!journal2.inspect_reconciliation().unwrap().orphan.is_empty());
    for id in &sources {
        assert_eq!(
            disposition_map(&journal2).get(id),
            Some(&SegmentDisposition::Authoritative)
        );
    }
}

#[test]
fn p8_manifest_publish_new_topology_survives_restart() {
    let _env = Env::new();
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, master, salt, artifact, sources, expected) =
        prepare_compacted_p0(dir.path());
    let published = publish_p0(&mut journal, &artifact);

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    let stored = read_stored_manifest(&runtime_dir(dir.path()).join("manifest.json"))
        .unwrap()
        .unwrap();
    let StoredJournalManifest::V2(m) = stored else {
        panic!("expected V2");
    };
    assert_eq!(m.generation, published.generation);
    assert_eq!(
        disposition_map(&journal2).get(&artifact.segment_id),
        Some(&SegmentDisposition::Authoritative)
    );
    for id in &sources {
        assert_eq!(
            disposition_map(&journal2).get(id),
            Some(&SegmentDisposition::Obsolete)
        );
    }
    assert_eq!(logical_stream(&journal2, &mut tree), expected);
}

#[test]
fn p7_manifest_tmp_ignored_old_generation() {
    let _env = Env::new();
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, master, salt, artifact, sources, expected) =
        prepare_compacted_p0(dir.path());
    let current = journal.read_stored_journal_manifest().unwrap().unwrap();
    let StoredJournalManifest::V2(v2) = current else {
        panic!("expected v2");
    };
    let pending = build_compaction_manifest_v2(&v2, &artifact, &journal.segment_infos().unwrap())
        .unwrap();
    fs::write(
        runtime_dir(dir.path()).join(MANIFEST_TMP),
        serde_json::to_string_pretty(&pending).unwrap(),
    )
    .unwrap();

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    assert_eq!(
        journal2.read_stored_journal_manifest().unwrap().unwrap().generation(),
        10
    );
    assert_eq!(logical_stream(&journal2, &mut tree), expected);
    assert_eq!(
        disposition_map(&journal2).get(&artifact.segment_id),
        Some(&SegmentDisposition::Orphan)
    );
    for id in &sources {
        assert_eq!(
            disposition_map(&journal2).get(id),
            Some(&SegmentDisposition::Authoritative)
        );
    }
    journal2.reconcile().unwrap();
    assert!(!runtime_dir(dir.path()).join(MANIFEST_TMP).exists());
}

#[test]
fn p11_partial_gc_resumable() {
    let _env = Env::new();
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, master, salt, artifact, sources, expected) =
        prepare_compacted_p0(dir.path());
    publish_p0(&mut journal, &artifact);
    let obsolete_ends: Vec<u64> = journal
        .inspect_reconciliation()
        .unwrap()
        .lifecycles
        .into_iter()
        .filter(|l| sources.contains(&l.segment_id))
        .map(|l| l.end_sequence)
        .collect();
    assert!(!obsolete_ends.is_empty());
    let trim_end = *obsolete_ends.iter().min().unwrap();
    let trim = calculate_watermark([&SequencePin(trim_end) as &dyn JournalPin])
        .trim_through
        .unwrap();
    let eligible = journal.eligible_segments(trim).unwrap();
    let first_obsolete = eligible
        .iter()
        .find(|c| sources.contains(&c.segment_id))
        .expect("obsolete segment eligible at trim watermark")
        .segment_id;

    set_test_crash_point(Some(CrashPoint::DuringGcAfterDelete(first_obsolete)));
    assert!(journal.trim_through(trim).is_err());

    drop(journal);
    let mut journal2 = reopen(dir.path(), &master, &salt);
    assert_eq!(logical_stream(&journal2, &mut tree), expected);
    assert!(
        !segment_path_for_partition(&journal_dir, PartitionId(0), first_obsolete, PARTS).is_file()
    );
    set_test_crash_point(None);
    journal2.trim_through(trim).unwrap();
}

#[test]
fn p11_partial_gc_across_partitions() {
    let _env = Env::new();
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut tree, master, salt, path) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt);
    append_interleaved(&mut journal, &mut tree, &path, 16);
    bootstrap(&journal);

    for pid in [0u32, 1] {
        let c = journal
            .select_compaction_candidate_for_partition(PartitionId(pid), &policy())
            .unwrap()
            .unwrap();
        let a = journal.compact_candidate(&c).unwrap();
        journal.publish_compaction(&a).unwrap();
    }

    let expected = logical_stream(&journal, &mut tree);
    let inspection = journal.inspect_reconciliation().unwrap();
    let mut obsolete_paths = Vec::new();
    for id in &inspection.obsolete {
        let pid = journal
            .read_stored_journal_manifest()
            .unwrap()
            .and_then(|m| m.segment_partition(*id))
            .unwrap_or(PartitionId(0));
        obsolete_paths.push(segment_path_for_partition(
            &journal_dir,
            pid,
            *id,
            PARTS,
        ));
    }
    assert!(obsolete_paths.len() >= 2);
    let removed_id = inspection.obsolete[0];
    fs::remove_file(&obsolete_paths[0]).unwrap();

    drop(journal);
    let mut journal2 = reopen(dir.path(), &master, &salt);
    assert_eq!(logical_stream(&journal2, &mut tree), expected);
    let removed_end = journal2
        .inspect_reconciliation()
        .unwrap()
        .lifecycles
        .into_iter()
        .find(|l| l.segment_id == removed_id)
        .map(|l| l.end_sequence)
        .unwrap_or(0);
    if removed_end > 0 {
        journal2.trim_through(removed_end).ok();
    }
}

#[test]
fn pin_blocks_obsolete_gc_until_released() {
    let _env = Env::new();
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, master, salt, artifact, sources, _) =
        prepare_compacted_p0(dir.path());
    publish_p0(&mut journal, &artifact);
    let obsolete_end = journal
        .inspect_reconciliation()
        .unwrap()
        .lifecycles
        .into_iter()
        .find(|l| {
            l.disposition == SegmentDisposition::Obsolete && sources.contains(&l.segment_id)
        })
        .expect("obsolete source lifecycle")
        .end_sequence;
    let pin_low = obsolete_end.saturating_sub(1);
    let safe_low = calculate_watermark([&SequencePin(pin_low) as &dyn JournalPin])
        .trim_through
        .unwrap();
    assert!(
        !journal
            .eligible_segments(safe_low)
            .unwrap()
            .iter()
            .any(|c| c.segment_id == sources[0])
    );

    let safe_high = calculate_watermark([&SequencePin(obsolete_end) as &dyn JournalPin])
        .trim_through
        .unwrap();
    journal.trim_through(safe_high).unwrap();

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    assert!(!logical_stream(&journal2, &mut tree).is_empty());
}

#[test]
fn interleaved_global_order_monotonic_after_restart() {
    let _env = Env::new();
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, path) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt);
    append_interleaved(&mut journal, &mut tree, &path, 12);
    bootstrap(&journal);
    let seqs = merge_sequences(&journal, &mut tree);
    for w in seqs.windows(2) {
        assert!(w[1] > w[0], "global order must be strictly increasing");
    }

    let c = journal
        .select_compaction_candidate_for_partition(PartitionId(0), &policy())
        .unwrap()
        .unwrap();
    let a = journal.compact_candidate(&c).unwrap();
    journal.publish_compaction(&a).unwrap();

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    let after = merge_sequences(&journal2, &mut tree);
    for w in after.windows(2) {
        assert!(w[1] > w[0]);
    }
}

#[test]
fn missing_authoritative_segment_is_fatal() {
    let _env = Env::new();
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, _tree, master, salt, artifact, _, _) = prepare_compacted_p0(dir.path());
    publish_p0(&mut journal, &artifact);
    fs::remove_file(&artifact.path).unwrap();

    drop(journal);
    let err = reopen_err(dir.path(), &master, &salt);
    assert!(matches!(err, JournalError::JournalManifestInconsistent(_)));
}

#[test]
fn missing_obsolete_segment_tolerated() {
    let _env = Env::new();
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, master, salt, artifact, sources, expected) =
        prepare_compacted_p0(dir.path());
    publish_p0(&mut journal, &artifact);
    let src_path = segment_path_for_partition(&journal_dir, PartitionId(0), sources[0], PARTS);
    fs::remove_file(&src_path).unwrap();

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    assert_eq!(logical_stream(&journal2, &mut tree), expected);
    assert!(
        journal2
            .read_stored_journal_manifest()
            .unwrap()
            .unwrap()
            .superseded_segment_ids()
            .contains(&sources[0])
    );
}

#[test]
fn ciphertext_equivalent_after_compaction_restart() {
    let _env = Env::new();
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, master, salt, artifact, sources, _) =
        prepare_compacted_p0(dir.path());
    let before_cipher: Vec<_> = sources
        .iter()
        .flat_map(|id| {
            let p = segment_path_for_partition(&journal_dir, PartitionId(0), *id, PARTS);
            let bytes = fs::read(p).unwrap();
            let (_, records, _) = scan_segment_raw_records(&bytes).unwrap();
            records
                .into_iter()
                .map(|r| {
                    let len = u32::from_be_bytes(r[0..4].try_into().unwrap()) as usize;
                    parse_entry_body(&r[8..4 + len]).unwrap().ciphertext
                })
                .collect::<Vec<_>>()
        })
        .collect();
    publish_p0(&mut journal, &artifact);

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    let after_bytes = fs::read(&artifact.path).unwrap();
    let (_, after_records, _) = scan_segment_raw_records(&after_bytes).unwrap();
    let after_cipher: Vec<_> = after_records
        .into_iter()
        .map(|r| {
            let len = u32::from_be_bytes(r[0..4].try_into().unwrap()) as usize;
            parse_entry_body(&r[8..4 + len]).unwrap().ciphertext
        })
        .collect();
    assert_eq!(before_cipher, after_cipher);
    assert!(!logical_stream(&journal2, &mut tree).is_empty());
}

#[test]
fn reconcile_removes_compaction_tmp_without_topology_change() {
    let _env = Env::new();
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, master, salt, _, sources, expected) =
        prepare_compacted_p0(dir.path());
    let tmp = journal_dir.join("p-000/compacted-999999999999.tmp");
    fs::write(&tmp, b"partial").unwrap();

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    assert_eq!(logical_stream(&journal2, &mut tree), expected);
    for id in &sources {
        assert_eq!(
            disposition_map(&journal2).get(id),
            Some(&SegmentDisposition::Authoritative)
        );
    }
    journal2.reconcile().unwrap();
    assert!(!tmp.exists());
    assert!(!list_segment_ids(&journal_dir).unwrap().is_empty());
}
