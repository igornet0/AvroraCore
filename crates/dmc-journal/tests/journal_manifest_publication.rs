//! Journal manifest publication for compaction (Phase 5.6.3).

use std::fs;

use dmc_journal::error::Error as JournalError;
use dmc_journal::journal_manifest::{build_compaction_manifest, read_manifest, MANIFEST_TMP};
use dmc_journal::layout::list_segment_ids;
use dmc_journal::{
    authoritative_segment_ids, CompactionPolicy, Journal, JournalConfig, SegmentCompactor,
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

fn runtime_journal_dir(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("runtime/journal")
}

fn manifest_path(dir: &std::path::Path) -> std::path::PathBuf {
    runtime_journal_dir(dir).join("manifest.json")
}

fn policy() -> CompactionPolicy {
    CompactionPolicy {
        enabled: true,
        min_segments: 2,
        min_total_bytes: 0,
        max_input_bytes: 10 * 1024 * 1024,
    }
}

fn compact_and_get_artifact(
    journal: &mut Journal,
    tree: &mut KeyTree,
) -> dmc_journal::CompactionArtifact {
    append_many(journal, tree, 40);
    let candidate = journal.select_compaction_candidate(&policy()).unwrap().unwrap();
    let mut compactor = dmc_journal::JournalSegmentCompactor::new(journal);
    compactor.compact(&candidate).unwrap()
}

fn replay_entries(journal: &Journal, tree: &mut KeyTree) -> Vec<dmc_journal::JournalEntry> {
    journal.replay(0, tree).unwrap()
}

#[test]
fn generation_bump_on_publish() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    let artifact = compact_and_get_artifact(&mut journal, &mut tree);
    let before = journal.bootstrap_journal_manifest(10).unwrap();
    assert_eq!(before.generation, 10);

    let published = journal.publish_compaction(&artifact).unwrap();
    assert_eq!(published.generation, 11);
    set_test_segment_max_bytes(None);
}

#[test]
fn manifest_contains_new_segment_and_drops_sources() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    let artifact = compact_and_get_artifact(&mut journal, &mut tree);
    let sources = artifact.source_segment_ids.clone();
    journal.bootstrap_journal_manifest(10).unwrap();
    let published = journal.publish_compaction(&artifact).unwrap();

    assert!(published.contains_segment(artifact.segment_id));
    for id in &sources {
        assert!(!published.contains_segment(*id));
    }
    set_test_segment_max_bytes(None);
}

#[test]
fn source_segments_remain_on_disk_after_publish() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    let artifact = compact_and_get_artifact(&mut journal, &mut tree);
    let sources = artifact.source_segment_ids.clone();
    journal.bootstrap_journal_manifest(10).unwrap();
    journal.publish_compaction(&artifact).unwrap();

    for id in &sources {
        assert!(journal_dir.join(format!("seg-{id:012}.jnl")).is_file());
    }
    assert!(artifact.path.is_file());
    set_test_segment_max_bytes(None);
}

#[test]
fn replay_identical_before_and_after_publication() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    append_many(&mut journal, &mut tree, 40);
    let candidate = journal.select_compaction_candidate(&policy()).unwrap().unwrap();
    let before = replay_entries(&journal, &mut tree);
    let mut compactor = dmc_journal::JournalSegmentCompactor::new(&mut journal);
    let artifact = compactor.compact(&candidate).unwrap();
    let mid = replay_entries(&journal, &mut tree);
    assert_eq!(before.len(), mid.len());

    let published = journal.publish_compaction(&artifact).unwrap();
    assert_eq!(published.generation, 1);
    let after = replay_entries(&journal, &mut tree);
    assert_eq!(before.len(), after.len());
    for (a, b) in before.iter().zip(after.iter()) {
        assert_eq!(a.sequence, b.sequence);
        assert_eq!(a.event_id, b.event_id);
        assert_eq!(a.payload, b.payload);
    }
    set_test_segment_max_bytes(None);
}

#[test]
fn manifest_tmp_is_ignored_before_rename() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    let artifact = compact_and_get_artifact(&mut journal, &mut tree);
    let _old = journal.bootstrap_journal_manifest(10).unwrap();
    let old = journal.read_journal_manifest().unwrap().unwrap();
    let infos = journal.segment_infos().unwrap();
    let pending = build_compaction_manifest(&old, &artifact, &infos).unwrap();
    let runtime_dir = runtime_journal_dir(dir.path());
    fs::write(
        runtime_dir.join(MANIFEST_TMP),
        serde_json::to_string_pretty(&pending).unwrap(),
    )
    .unwrap();

    let loaded = read_manifest(&manifest_path(dir.path())).unwrap().unwrap();
    assert_eq!(loaded.generation, 10);
    let auth: Vec<u64> = journal.segment_infos().unwrap().into_iter().map(|s| s.id).collect();
    for id in &artifact.source_segment_ids {
        assert!(auth.contains(id));
    }
    assert!(!auth.contains(&artifact.segment_id));
    set_test_segment_max_bytes(None);
}

#[test]
fn published_manifest_becomes_authoritative_after_rename() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    let artifact = compact_and_get_artifact(&mut journal, &mut tree);
    journal.bootstrap_journal_manifest(10).unwrap();
    let published = journal.publish_compaction(&artifact).unwrap();

    drop(journal);
    drop(tree);

    let kek = derive_journal_kek(&master, &salt);
    let journal2 = Journal::open(
        JournalConfig::new(dir.path().join("journal")).with_segment_max_bytes(900),
        &kek,
    )
    .unwrap();
    let loaded = journal2.read_journal_manifest().unwrap().unwrap();
    assert_eq!(loaded.generation, published.generation);
    let auth: Vec<u64> = journal2.segment_infos().unwrap().into_iter().map(|s| s.id).collect();
    assert!(auth.contains(&artifact.segment_id));
    for id in &artifact.source_segment_ids {
        assert!(!auth.contains(id));
    }
    set_test_segment_max_bytes(None);
}

#[test]
fn unpublished_artifact_not_in_bootstrap_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    let artifact = compact_and_get_artifact(&mut journal, &mut tree);
    let manifest = journal.bootstrap_journal_manifest(10).unwrap();
    assert!(!manifest.contains_segment(artifact.segment_id));
    assert!(artifact.path.is_file());
    set_test_segment_max_bytes(None);
}

#[test]
fn stale_candidate_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    let artifact = compact_and_get_artifact(&mut journal, &mut tree);
    journal.bootstrap_journal_manifest(10).unwrap();

    let mut current = journal.read_journal_manifest().unwrap().unwrap();
    current
        .segments
        .retain(|s| !artifact.source_segment_ids.contains(&s.segment_id));
    dmc_journal::journal_manifest::publish_manifest(&runtime_journal_dir(dir.path()), &current)
        .unwrap();

    let err = journal.publish_compaction(&artifact).unwrap_err();
    assert!(matches!(err, JournalError::CompactionStaleCandidate));
    set_test_segment_max_bytes(None);
}

#[test]
fn artifact_after_rename_old_manifest_until_publish() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    let artifact = compact_and_get_artifact(&mut journal, &mut tree);
    journal.bootstrap_journal_manifest(10).unwrap();
    assert!(artifact.path.is_file());

    drop(journal);
    drop(tree);

    let kek = derive_journal_kek(&master, &salt);
    let journal2 = Journal::open(
        JournalConfig::new(journal_dir.clone()).with_segment_max_bytes(900),
        &kek,
    )
    .unwrap();
    let loaded = journal2.read_journal_manifest().unwrap().unwrap();
    assert_eq!(loaded.generation, 10);
    let auth = authoritative_segment_ids(
        &journal_dir,
        &manifest_path(dir.path()),
        &[journal2.segment_infos().unwrap().last().unwrap().id],
        1,
    )
    .unwrap();
    assert!(!auth.contains(&artifact.segment_id));
    assert!(list_segment_ids(&journal_dir).unwrap().contains(&artifact.segment_id));
    set_test_segment_max_bytes(None);
}
