//! Segment lifecycle classification (Phase 5.6.5).

use std::fs;

use dmc_journal::layout::list_segment_ids;
use dmc_journal::{
    CompactionPolicy, Journal, JournalConfig, SegmentCompactor, SegmentDisposition,
    set_test_segment_max_bytes,
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

fn compact_artifact(journal: &mut Journal, tree: &mut KeyTree) -> dmc_journal::CompactionArtifact {
    append_many(journal, tree, 40);
    let candidate = journal.select_compaction_candidate(&policy()).unwrap().unwrap();
    let mut compactor = dmc_journal::JournalSegmentCompactor::new(journal);
    compactor.compact(&candidate).unwrap()
}

fn publish_compacted(
    journal: &mut Journal,
    tree: &mut KeyTree,
) -> (dmc_journal::CompactionArtifact, dmc_journal::JournalManifest) {
    let artifact = compact_artifact(journal, tree);
    journal.bootstrap_journal_manifest(10).unwrap();
    let published = journal.publish_compaction(&artifact).unwrap();
    (artifact, published)
}

fn reopen(dir: &std::path::Path, master: &dmc_vault::KeyMaterial, salt: &[u8]) -> Journal {
    let kek = derive_journal_kek(master, salt);
    Journal::open(
        JournalConfig::new(dir.join("journal")).with_segment_max_bytes(900),
        &kek,
    )
    .unwrap()
}

fn disposition_map(journal: &Journal) -> std::collections::HashMap<u64, SegmentDisposition> {
    journal
        .inspect_reconciliation()
        .unwrap()
        .lifecycles
        .into_iter()
        .map(|l| (l.segment_id, l.disposition))
        .collect()
}

#[test]
fn compaction_marks_sources_obsolete_and_compacted_authoritative() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    let artifact = compact_artifact(&mut journal, &mut tree);
    let sources = artifact.source_segment_ids.clone();
    journal.bootstrap_journal_manifest(10).unwrap();
    journal.publish_compaction(&artifact).unwrap();

    let map = disposition_map(&journal);
    for id in &sources {
        assert_eq!(map.get(id), Some(&SegmentDisposition::Obsolete));
    }
    assert_eq!(map.get(&artifact.segment_id), Some(&SegmentDisposition::Authoritative));

    let active_id = journal
        .segment_infos()
        .unwrap()
        .into_iter()
        .find(|s| s.state == dmc_journal::SegmentState::Active)
        .unwrap()
        .id;
    assert_eq!(map.get(&active_id), Some(&SegmentDisposition::Authoritative));

    let manifest = journal.read_journal_manifest().unwrap().unwrap();
    for id in &sources {
        assert!(manifest.superseded_segment_ids.contains(id));
    }
    set_test_segment_max_bytes(None);
}

#[test]
fn unpublished_artifact_is_orphan_not_obsolete() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    let artifact = compact_artifact(&mut journal, &mut tree);
    journal.bootstrap_journal_manifest(10).unwrap();

    let inspection = journal.inspect_reconciliation().unwrap();
    assert!(inspection.orphan.contains(&artifact.segment_id));
    assert!(!inspection.obsolete.contains(&artifact.segment_id));
    assert_eq!(
        disposition_map(&journal).get(&artifact.segment_id),
        Some(&SegmentDisposition::Orphan)
    );
    set_test_segment_max_bytes(None);
}

#[test]
fn lifecycle_classification_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    let (artifact, _published) = publish_compacted(&mut journal, &mut tree);
    let before = journal.inspect_reconciliation().unwrap();

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    let after = journal2.inspect_reconciliation().unwrap();

    assert_eq!(before.authoritative, after.authoritative);
    assert_eq!(before.obsolete, after.obsolete);
    assert_eq!(before.orphan, after.orphan);
    assert_eq!(
        disposition_map(&journal2).get(&artifact.segment_id),
        Some(&SegmentDisposition::Authoritative)
    );
    for id in &artifact.source_segment_ids {
        assert_eq!(
            disposition_map(&journal2).get(id),
            Some(&SegmentDisposition::Obsolete)
        );
    }
    set_test_segment_max_bytes(None);
}

#[test]
fn crash_before_publish_artifact_is_orphan_sources_authoritative() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    let artifact = compact_artifact(&mut journal, &mut tree);
    let sources = artifact.source_segment_ids.clone();
    journal.bootstrap_journal_manifest(10).unwrap();
    let before = disposition_map(&journal);

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    let after = disposition_map(&journal2);

    assert_eq!(after.get(&artifact.segment_id), Some(&SegmentDisposition::Orphan));
    for id in &sources {
        assert_eq!(after.get(id), Some(&SegmentDisposition::Authoritative));
        assert_eq!(before.get(id), Some(&SegmentDisposition::Authoritative));
    }
    set_test_segment_max_bytes(None);
}

#[test]
fn crash_after_publish_sources_obsolete_compacted_authoritative() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    let (artifact, _published) = publish_compacted(&mut journal, &mut tree);

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    let inspection = journal2.inspect_reconciliation().unwrap();

    assert!(inspection.authoritative.contains(&artifact.segment_id));
    for id in &artifact.source_segment_ids {
        assert!(inspection.obsolete.contains(id));
        assert!(!inspection.orphan.contains(id));
    }
    set_test_segment_max_bytes(None);
}

#[test]
fn obsolete_segments_not_in_topology_and_not_deleted_by_reconcile() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    let (_artifact, _published) = publish_compacted(&mut journal, &mut tree);
    let on_disk_before = list_segment_ids(&journal_dir).unwrap();

    let inspection = journal.inspect_reconciliation().unwrap();
    assert!(!inspection.obsolete.is_empty());

    journal.reconcile().unwrap();
    assert_eq!(list_segment_ids(&journal_dir).unwrap(), on_disk_before);

    let auth_ids: Vec<u64> = journal.segment_infos().unwrap().into_iter().map(|s| s.id).collect();
    for id in &inspection.obsolete {
        assert!(!auth_ids.contains(id));
    }

    let trim_through = journal.last_sequence();
    let eligible = journal.eligible_segments(trim_through).unwrap();
    for id in &inspection.obsolete {
        assert!(eligible.iter().any(|c| {
            c.segment_id == *id && c.disposition == dmc_journal::SegmentDisposition::Obsolete
        }));
    }
    set_test_segment_max_bytes(None);
}

#[test]
fn manual_orphan_file_is_not_obsolete() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    publish_compacted(&mut journal, &mut tree);

    let donor = list_segment_ids(&journal_dir)
        .unwrap()
        .into_iter()
        .max()
        .unwrap();
    let donor_path = journal_dir.join(format!("seg-{donor:012}.jnl"));
    let orphan_id = 999u64;
    fs::copy(&donor_path, journal_dir.join(format!("seg-{orphan_id:012}.jnl"))).unwrap();

    let inspection = journal.inspect_reconciliation().unwrap();
    assert!(inspection.orphan.contains(&orphan_id));
    assert!(!inspection.obsolete.contains(&orphan_id));
    set_test_segment_max_bytes(None);
}
