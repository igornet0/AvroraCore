//! Manifest recovery & reconciliation (Phase 5.6.4).

use std::fs;

use dmc_journal::error::Error as JournalError;
use dmc_journal::journal_manifest::{build_compaction_manifest, read_manifest, MANIFEST_TMP};
use dmc_journal::layout::list_segment_ids;
use dmc_journal::reconciliation::authoritative_journal_head;
use dmc_journal::{
    CompactionPolicy, Journal, JournalConfig, SegmentCompactor, set_test_segment_max_bytes,
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

fn auth_ids(journal: &Journal) -> Vec<u64> {
    journal
        .segment_infos()
        .unwrap()
        .into_iter()
        .map(|s| s.id)
        .collect()
}

fn replay_entries(journal: &Journal, tree: &mut KeyTree) -> Vec<dmc_journal::JournalEntry> {
    journal.replay(0, tree).unwrap()
}

// --- DoD: tmp ignored ---

#[test]
fn tmp_files_ignored_on_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    let (artifact, published) = publish_compacted(&mut journal, &mut tree);
    let head_before = journal.last_sequence();

    fs::write(journal_dir.join("compacted-kill9.tmp"), b"stale").unwrap();
    fs::write(runtime_journal_dir(dir.path()).join(MANIFEST_TMP), b"{invalid").unwrap();

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    assert_eq!(journal2.read_journal_manifest().unwrap().unwrap().generation, published.generation);
    assert_eq!(journal2.last_sequence(), head_before);
    assert!(auth_ids(&journal2).contains(&artifact.segment_id));

    let inspection = journal2.inspect_reconciliation().unwrap();
    assert!(inspection.temporary.iter().any(|p| p.ends_with("compacted-kill9.tmp")));
    assert!(inspection.temporary.iter().any(|p| p.ends_with(MANIFEST_TMP)));
    set_test_segment_max_bytes(None);
}

// --- DoD: unpublished artifact = orphan ---

#[test]
fn unpublished_artifact_classified_as_orphan() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    let artifact = compact_artifact(&mut journal, &mut tree);
    journal.bootstrap_journal_manifest(10).unwrap();

    let inspection = journal.inspect_reconciliation().unwrap();
    assert!(!inspection.authoritative.contains(&artifact.segment_id));
    assert!(inspection.orphan.contains(&artifact.segment_id));
    assert!(!inspection.obsolete.contains(&artifact.segment_id));
    assert!(!auth_ids(&journal).contains(&artifact.segment_id));
    set_test_segment_max_bytes(None);
}

// --- DoD: published manifest recovered ---

#[test]
fn published_manifest_topology_recovered_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    let (artifact, published) = publish_compacted(&mut journal, &mut tree);
    let auth_before = auth_ids(&journal);
    let head_before = journal.last_sequence();
    let oldest_before = journal.oldest_available_sequence().unwrap();

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    assert_eq!(
        journal2.read_journal_manifest().unwrap().unwrap().generation,
        published.generation
    );
    assert_eq!(auth_ids(&journal2), auth_before);
    assert_eq!(journal2.last_sequence(), head_before);
    assert_eq!(journal2.oldest_available_sequence().unwrap(), oldest_before);
    assert!(auth_ids(&journal2).contains(&artifact.segment_id));
    for id in &artifact.source_segment_ids {
        assert!(!auth_ids(&journal2).contains(id));
        assert!(list_segment_ids(dir.path().join("journal").as_path())
            .unwrap()
            .contains(id));
    }
    set_test_segment_max_bytes(None);
}

// --- DoD: missing authoritative segment = fatal ---

#[test]
fn missing_authoritative_segment_is_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    let (artifact, _published) = publish_compacted(&mut journal, &mut tree);
    fs::remove_file(journal_dir.join(format!("seg-{:012}.jnl", artifact.segment_id))).unwrap();

    drop(journal);
    let kek = derive_journal_kek(&master, &salt);
    let open_err = Journal::open(
        JournalConfig::new(journal_dir).with_segment_max_bytes(900),
        &kek,
    )
    .err()
    .expect("open should fail");
    assert!(matches!(
        open_err,
        JournalError::JournalManifestInconsistent(_)
    ));
    set_test_segment_max_bytes(None);
}

// --- DoD: corrupt authoritative segment = fatal ---

#[test]
fn corrupt_authoritative_segment_is_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    let (artifact, _published) = publish_compacted(&mut journal, &mut tree);
    let seg_path = journal_dir.join(format!("seg-{:012}.jnl", artifact.segment_id));
    let mut bytes = fs::read(&seg_path).unwrap();
    let n = bytes.len();
    for b in bytes.iter_mut().skip(n.saturating_sub(40)) {
        *b ^= 0xff;
    }
    fs::write(&seg_path, &bytes).unwrap();

    drop(journal);
    let kek = derive_journal_kek(&master, &salt);
    let open_err = Journal::open(
        JournalConfig::new(journal_dir).with_segment_max_bytes(900),
        &kek,
    )
    .err()
    .expect("open should fail");
    assert!(matches!(open_err, JournalError::JournalSegmentCorrupt(_)));
    set_test_segment_max_bytes(None);
}

// --- DoD: orphan does not affect head / oldest ---

#[test]
fn orphan_does_not_affect_head_or_oldest() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let manifest_file = manifest_path(dir.path());
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    let orphan = compact_artifact(&mut journal, &mut tree);
    journal.bootstrap_journal_manifest(10).unwrap();

    let head_with_orphan = journal.last_sequence();
    let oldest_with_orphan = journal.oldest_available_sequence().unwrap();
    let auth_with_orphan = auth_ids(&journal);
    assert!(!auth_with_orphan.contains(&orphan.segment_id));
    assert!(list_segment_ids(&journal_dir).unwrap().contains(&orphan.segment_id));

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    assert_eq!(journal2.last_sequence(), head_with_orphan);
    assert_eq!(journal2.oldest_available_sequence().unwrap(), oldest_with_orphan);
    assert_eq!(auth_ids(&journal2), auth_with_orphan);

    let head_fn = authoritative_journal_head(&journal_dir, &manifest_file, &[], 1).unwrap();
    assert_eq!(head_fn, head_with_orphan);

    let inspection = journal2.inspect_reconciliation().unwrap();
    assert!(inspection.orphan.contains(&orphan.segment_id));
    set_test_segment_max_bytes(None);
}

// --- DoD: orphan does not affect replay ---

#[test]
fn orphan_does_not_affect_replay() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    let orphan = compact_artifact(&mut journal, &mut tree);
    let before = replay_entries(&journal, &mut tree);
    journal.bootstrap_journal_manifest(10).unwrap();
    assert!(!auth_ids(&journal).contains(&orphan.segment_id));
    assert!(orphan.path.is_file());

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    let after = replay_entries(&journal2, &mut tree);
    assert_eq!(before.len(), after.len());
    for (a, b) in before.iter().zip(after.iter()) {
        assert_eq!(a.sequence, b.sequence);
        assert_eq!(a.event_id, b.event_id);
        assert_eq!(a.payload, b.payload);
    }
    set_test_segment_max_bytes(None);
}

// --- DoD: orphan cannot become active ---

#[test]
fn orphan_cannot_become_active_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    let (artifact, published) = publish_compacted(&mut journal, &mut tree);
    let active_before = journal
        .segment_infos()
        .unwrap()
        .into_iter()
        .find(|s| s.state == dmc_journal::SegmentState::Active)
        .unwrap()
        .id;

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    let active_after = journal2
        .segment_infos()
        .unwrap()
        .into_iter()
        .find(|s| s.state == dmc_journal::SegmentState::Active)
        .unwrap()
        .id;
    assert_eq!(active_before, active_after);
    assert_ne!(active_after, artifact.segment_id);

    let manifest = journal2.read_journal_manifest().unwrap().unwrap();
    assert_eq!(manifest.generation, published.generation);
    set_test_segment_max_bytes(None);
}

// --- Kill-9 Case A: artifact.tmp + restart → old topology ---

#[test]
fn kill9_case_a_artifact_tmp_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    append_many(&mut journal, &mut tree, 40);
    let auth_before = auth_ids(&journal);
    fs::write(journal_dir.join("compacted-999999.tmp"), b"partial write").unwrap();

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    assert_eq!(auth_ids(&journal2), auth_before);
    set_test_segment_max_bytes(None);
}

// --- Kill-9 Case B: artifact on disk, no publish → orphan ---

#[test]
fn kill9_case_b_unpublished_artifact_is_orphan() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    let artifact = compact_artifact(&mut journal, &mut tree);
    journal.bootstrap_journal_manifest(10).unwrap();
    let auth_before = auth_ids(&journal);

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    assert_eq!(auth_ids(&journal2), auth_before);
    let inspection = journal2.inspect_reconciliation().unwrap();
    assert!(inspection.orphan.contains(&artifact.segment_id));
    set_test_segment_max_bytes(None);
}

// --- Kill-9 Case C: manifest.tmp fsynced but not renamed ---

#[test]
fn kill9_case_c_manifest_tmp_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    let artifact = compact_artifact(&mut journal, &mut tree);
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
    assert!(!auth_ids(&journal).contains(&artifact.segment_id));
    set_test_segment_max_bytes(None);
}

// --- Kill-9 Case D: valid manifest.json is authoritative ---

#[test]
fn kill9_case_d_published_manifest_wins() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    let (artifact, published) = publish_compacted(&mut journal, &mut tree);

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    let loaded = journal2.read_journal_manifest().unwrap().unwrap();
    assert_eq!(loaded.generation, published.generation);
    assert!(auth_ids(&journal2).contains(&artifact.segment_id));
    set_test_segment_max_bytes(None);
}

// --- Invalid manifest never auto-repaired ---

#[test]
fn invalid_manifest_never_auto_repaired() {
    let dir = tempfile::tempdir().unwrap();
    let runtime_dir = runtime_journal_dir(dir.path());
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    publish_compacted(&mut journal, &mut tree);
    let manifest_file = manifest_path(dir.path());
    let raw_before = fs::read_to_string(&manifest_file).unwrap();

    fs::write(&manifest_file, r#"{"format_version":1,"generation":99,"segments":[]}"#).unwrap();

    drop(journal);
    let kek = derive_journal_kek(&master, &salt);
    let open_err = Journal::open(
        JournalConfig::new(dir.path().join("journal")).with_segment_max_bytes(900),
        &kek,
    )
    .err()
    .expect("open should fail");
    assert!(matches!(open_err, JournalError::JournalManifestInconsistent(_)));
    assert_eq!(fs::read_to_string(&manifest_file).unwrap(), r#"{"format_version":1,"generation":99,"segments":[]}"#);
    assert_ne!(fs::read_to_string(&manifest_file).unwrap(), raw_before);
    let _ = runtime_dir;
    set_test_segment_max_bytes(None);
}

// --- reconcile() removes .tmp only ---

#[test]
fn reconcile_removes_tmp_without_deleting_segments() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    let (artifact, _published) = publish_compacted(&mut journal, &mut tree);
    let seg_count_before = list_segment_ids(&journal_dir).unwrap().len();
    fs::write(journal_dir.join("orphan.tmp"), b"x").unwrap();
    fs::write(runtime_journal_dir(dir.path()).join(MANIFEST_TMP), b"y").unwrap();

    let result = journal.reconcile().unwrap();
    assert_eq!(result.temporary_removed.len(), 2);
    assert!(!journal_dir.join("orphan.tmp").exists());
    assert!(!runtime_journal_dir(dir.path()).join(MANIFEST_TMP).exists());
    assert_eq!(list_segment_ids(&journal_dir).unwrap().len(), seg_count_before);
    assert!(artifact.path.is_file());
    set_test_segment_max_bytes(None);
}

// --- Bootstrap succeeds with orphan on disk (authoritative view excludes orphan) ---

#[test]
fn bootstrap_with_orphan_on_disk_excludes_orphan() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    let artifact = compact_artifact(&mut journal, &mut tree);
    let manifest = journal.bootstrap_journal_manifest(0).unwrap();
    assert!(!manifest.contains_segment(artifact.segment_id));
    for id in &artifact.source_segment_ids {
        assert!(manifest.contains_segment(*id));
    }
    set_test_segment_max_bytes(None);
}
