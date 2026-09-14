//! Obsolete segment GC integration (Phase 5.6.6).

use std::fs;

use dmc_journal::layout::list_segment_ids;
use dmc_journal::{
    calculate_watermark, CompactionPolicy, Journal, JournalConfig, JournalPin, SegmentCompactor,
    SegmentDisposition, SequencePin, set_test_segment_max_bytes,
};
use dmc_vault::crypto::derive_journal_kek;
use dmc_vault::key::{KeyPath, KeyTree};

fn setup(dir: &std::path::Path) -> (Journal, KeyTree, dmc_vault::KeyMaterial, Vec<u8>) {
    set_test_segment_max_bytes(Some(900));
    let (mut tree, master) = KeyTree::create_new().unwrap();
    let salt = tree.salt().to_vec();
    let path = KeyPath::parse("company/finance/x").unwrap();
    tree.ensure_node(&path).unwrap();
    let kek = derive_journal_kek(&master, &salt);
    let config = JournalConfig::new(dir.join("journal")).with_segment_max_bytes(900);
    let journal = Journal::open(config, &kek).unwrap();
    (journal, tree, master, salt)
}

fn draft(tree: &mut KeyTree) -> (dmc_journal::JournalEntryDraft, dmc_vault::KeyMaterial) {
    let path = KeyPath::parse("company/finance/x").unwrap();
    let dek = tree.dek(&path).unwrap().clone();
    (
        dmc_journal::JournalEntryDraft {
            path,
            event_kind: dmc_journal::JournalEventKind::OverlayApply,
            operation: dmc_journal::Operation::OverlayPut,
            key_version: 1,
            actor_session: [1u8; 16],
            actor_role: "root".into(),
            node_bundle: Vec::new(),
            payload: vec![0u8; 200],
            partition_key: None,
        },
        dek,
    )
}

fn append_many(journal: &mut Journal, tree: &mut KeyTree, n: usize) {
    for _ in 0..n {
        let (d, dek) = draft(tree);
        journal.append(d, &dek).unwrap();
    }
    journal.sync().unwrap();
}

fn policy() -> CompactionPolicy {
    CompactionPolicy {
        enabled: true,
        min_segments: 2,
        min_total_bytes: 0,
        max_input_bytes: 10 * 1024 * 1024,
    }
}

fn publish_compacted(
    journal: &mut Journal,
    tree: &mut KeyTree,
) -> (dmc_journal::CompactionArtifact, Vec<u64>) {
    append_many(journal, tree, 40);
    let candidate = journal.select_compaction_candidate(&policy()).unwrap().unwrap();
    let sources = candidate.segment_ids.clone();
    let mut compactor = dmc_journal::JournalSegmentCompactor::new(journal);
    let artifact = compactor.compact(&candidate).unwrap();
    journal.bootstrap_journal_manifest(10).unwrap();
    journal.publish_compaction(&artifact).unwrap();
    (artifact, sources)
}

fn obsolete_end_sequence(journal: &Journal, source_id: u64) -> u64 {
    journal
        .inspect_reconciliation()
        .unwrap()
        .lifecycles
        .into_iter()
        .find(|l| l.segment_id == source_id)
        .unwrap()
        .end_sequence
}

fn reopen(dir: &std::path::Path, master: &dmc_vault::KeyMaterial, salt: &[u8]) -> Journal {
    let kek = derive_journal_kek(master, salt);
    Journal::open(
        JournalConfig::new(dir.join("journal")).with_segment_max_bytes(900),
        &kek,
    )
    .unwrap()
}

fn replay_count(journal: &Journal, tree: &mut KeyTree) -> usize {
    journal.replay(0, tree).unwrap().len()
}

// A. Obsolete + safe_trim → deleted

#[test]
fn obsolete_deleted_when_end_at_safe_trim() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    let (_artifact, sources) = publish_compacted(&mut journal, &mut tree);
    let source = sources[0];
    let end = obsolete_end_sequence(&journal, source);

    let eligible = journal.eligible_segments(end).unwrap();
    assert!(eligible.iter().any(|c| {
        c.segment_id == source && c.disposition == SegmentDisposition::Obsolete
    }));

    let result = journal.trim_through(end).unwrap();
    assert!(result.deleted_segments.contains(&source));
    assert!(!journal_dir.join(format!("seg-{source:012}.jnl")).exists());
    assert!(journal
        .read_journal_manifest()
        .unwrap()
        .unwrap()
        .superseded_segment_ids
        .contains(&source));
    set_test_segment_max_bytes(None);
}

// B. Obsolete + unsafe trim → retained

#[test]
fn obsolete_retained_when_end_above_safe_trim() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    let (_artifact, sources) = publish_compacted(&mut journal, &mut tree);
    let source = sources[0];
    let end = obsolete_end_sequence(&journal, source);
    assert!(end > 0);

    let trim = end.saturating_sub(1);
    let eligible = journal.eligible_segments(trim).unwrap();
    assert!(!eligible.iter().any(|c| c.segment_id == source));

    journal.trim_through(trim).unwrap();
    assert!(journal_dir.join(format!("seg-{source:012}.jnl")).exists());
    set_test_segment_max_bytes(None);
}

// C–F. Pins gate trim_through (journal-level simulation)

#[test]
fn consumer_pin_blocks_obsolete_gc() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    let (_artifact, sources) = publish_compacted(&mut journal, &mut tree);
    let source = sources[0];
    let end = obsolete_end_sequence(&journal, source);
    assert!(end > 1, "test setup must produce multi-sequence obsolete span");

    let consumer = SequencePin(end.saturating_sub(1));
    let safe = calculate_watermark([&consumer as &dyn JournalPin]).trim_through.unwrap();
    assert!(safe < end);

    let eligible = journal.eligible_segments(safe).unwrap();
    assert!(!eligible.iter().any(|c| c.segment_id == source));
    set_test_segment_max_bytes(None);
}

#[test]
fn snapshot_pin_blocks_obsolete_gc() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    let (_artifact, sources) = publish_compacted(&mut journal, &mut tree);
    let source = sources[0];
    let end = obsolete_end_sequence(&journal, source);
    assert!(end > 1);

    let snapshot = SequencePin(end.saturating_sub(1));
    let safe = calculate_watermark([&snapshot as &dyn JournalPin]).trim_through.unwrap();
    assert!(safe < end);
    assert!(!journal
        .eligible_segments(safe)
        .unwrap()
        .iter()
        .any(|c| c.segment_id == source));
    set_test_segment_max_bytes(None);
}

#[test]
fn replay_pin_blocks_obsolete_gc() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    let (_artifact, sources) = publish_compacted(&mut journal, &mut tree);
    let source = sources[0];
    let end = obsolete_end_sequence(&journal, source);
    assert!(end > 1);

    let replay = SequencePin(end.saturating_sub(1));
    let safe = calculate_watermark([&replay as &dyn JournalPin]).trim_through.unwrap();
    assert!(safe < end);
    set_test_segment_max_bytes(None);
}

#[test]
fn multiple_pins_use_minimum_safe_trim() {
    let snapshot = SequencePin(1000);
    let consumer = SequencePin(700);
    let replay = SequencePin(900);
    let safe = calculate_watermark([
        &snapshot as &dyn JournalPin,
        &consumer as &dyn JournalPin,
        &replay as &dyn JournalPin,
    ])
    .trim_through
    .unwrap();
    assert_eq!(safe, 700);
}

// G. Orphan never auto-deleted

#[test]
fn orphan_never_eligible_for_trim() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    append_many(&mut journal, &mut tree, 40);
    let candidate = journal.select_compaction_candidate(&policy()).unwrap().unwrap();
    let mut compactor = dmc_journal::JournalSegmentCompactor::new(&mut journal);
    let artifact = compactor.compact(&candidate).unwrap();
    journal.bootstrap_journal_manifest(10).unwrap();

    let trim = journal.last_sequence();
    let eligible = journal.eligible_segments(trim).unwrap();
    assert!(!eligible.iter().any(|c| c.segment_id == artifact.segment_id));
    assert!(!eligible
        .iter()
        .any(|c| c.segment_id == artifact.segment_id && c.disposition == SegmentDisposition::Orphan));

    assert!(artifact.path.is_file());
    assert!(list_segment_ids(&journal_dir).unwrap().contains(&artifact.segment_id));
    set_test_segment_max_bytes(None);
}

// H. Restart after GC

#[test]
fn gc_obsolete_survives_restart_with_superseded_history() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    let (artifact, sources) = publish_compacted(&mut journal, &mut tree);
    let replay_before = replay_count(&journal, &mut tree);
    let head_before = journal.last_sequence();
    let manifest = journal.read_journal_manifest().unwrap().unwrap();
    let superseded_before = manifest.superseded_segment_ids.clone();
    let compacted_end = manifest
        .segments
        .iter()
        .find(|s| s.segment_id == artifact.segment_id)
        .unwrap()
        .end_sequence;

    for id in &sources {
        let end = obsolete_end_sequence(&journal, *id);
        if end < compacted_end {
            journal.trim_through(end).unwrap();
        }
    }
    for id in &sources {
        let path = journal_dir.join(format!("seg-{id:012}.jnl"));
        if path.is_file() {
            fs::remove_file(&path).unwrap();
        }
    }

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    let manifest = journal2.read_journal_manifest().unwrap().unwrap();
    assert_eq!(manifest.superseded_segment_ids, superseded_before);
    for id in &sources {
        assert!(manifest.superseded_segment_ids.contains(id));
        assert!(!journal_dir.join(format!("seg-{id:012}.jnl")).exists());
    }
    assert_eq!(journal2.last_sequence(), head_before);
    assert_eq!(replay_count(&journal2, &mut tree), replay_before);
    set_test_segment_max_bytes(None);
}

// Partial delete during GC is tolerable for obsolete only

#[test]
fn partial_obsolete_delete_before_restart_is_tolerable() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    let (_artifact, sources) = publish_compacted(&mut journal, &mut tree);
    assert!(sources.len() >= 2);
    let first = sources[0];
    let end = obsolete_end_sequence(&journal, first);
    fs::remove_file(journal_dir.join(format!("seg-{first:012}.jnl"))).unwrap();

    drop(journal);
    let mut journal2 = reopen(dir.path(), &master, &salt);
    journal2.trim_through(end).unwrap();
    assert!(!journal_dir.join(format!("seg-{first:012}.jnl")).exists());
    assert!(journal2.read_journal_manifest().unwrap().is_some());
    assert!(replay_count(&journal2, &mut tree) > 0);
    set_test_segment_max_bytes(None);
}
