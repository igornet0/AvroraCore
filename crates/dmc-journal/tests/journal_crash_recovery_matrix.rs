//! Crash / recovery verification matrix (Phase 5.6.7).
//!
//! Failure injection simulates kill -9 crash windows — no new journal mechanisms.

use std::collections::HashMap;
use std::fs;

use dmc_journal::codec::{parse_entry_body, scan_segment_raw_records};
use dmc_journal::error::Error as JournalError;
use dmc_journal::journal_manifest::{build_compaction_manifest, MANIFEST_TMP};
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

fn draft(tree: &mut KeyTree, n: u64) -> (dmc_journal::JournalEntryDraft, dmc_vault::KeyMaterial) {
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
            payload: format!("payload-{n}").into_bytes(),
            partition_key: None,
        },
        dek,
    )
}

fn append_many(journal: &mut Journal, tree: &mut KeyTree, n: usize) {
    for i in 1..=n {
        let (d, dek) = draft(tree, i as u64);
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

fn reopen(dir: &std::path::Path, master: &dmc_vault::KeyMaterial, salt: &[u8]) -> Journal {
    let kek = derive_journal_kek(master, salt);
    Journal::open(
        JournalConfig::new(dir.join("journal")).with_segment_max_bytes(900),
        &kek,
    )
    .unwrap()
}

fn reopen_err(dir: &std::path::Path, master: &dmc_vault::KeyMaterial, salt: &[u8]) -> JournalError {
    let kek = derive_journal_kek(master, salt);
    Journal::open(
        JournalConfig::new(dir.join("journal")).with_segment_max_bytes(900),
        &kek,
    )
    .err()
    .expect("expected open failure")
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct LogicalEvent {
    sequence: u64,
    event_id: [u8; 16],
    ciphertext: Vec<u8>,
}

fn logical_replay(journal: &Journal, tree: &mut KeyTree) -> Vec<LogicalEvent> {
    journal
        .replay(0, tree)
        .unwrap()
        .into_iter()
        .map(|e| LogicalEvent {
            sequence: e.sequence,
            event_id: e.event_id,
            ciphertext: e.payload.clone(),
        })
        .collect()
}

fn publish_compacted(
    journal: &mut Journal,
    tree: &mut KeyTree,
) -> (dmc_journal::CompactionArtifact, Vec<u64>, dmc_journal::JournalManifest) {
    append_many(journal, tree, 40);
    let candidate = journal.select_compaction_candidate(&policy()).unwrap().unwrap();
    let sources = candidate.segment_ids.clone();
    let mut compactor = dmc_journal::JournalSegmentCompactor::new(journal);
    let artifact = compactor.compact(&candidate).unwrap();
    journal.bootstrap_journal_manifest(10).unwrap();
    let published = journal.publish_compaction(&artifact).unwrap();
    (artifact, sources, published)
}

fn compact_unpublished(journal: &mut Journal, tree: &mut KeyTree) -> (dmc_journal::CompactionArtifact, Vec<u64>) {
    append_many(journal, tree, 40);
    let candidate = journal.select_compaction_candidate(&policy()).unwrap().unwrap();
    let sources = candidate.segment_ids.clone();
    journal.bootstrap_journal_manifest(10).unwrap();
    let mut compactor = dmc_journal::JournalSegmentCompactor::new(journal);
    let artifact = compactor.compact(&candidate).unwrap();
    (artifact, sources)
}

fn raw_ciphertexts(journal_dir: &std::path::Path, ids: &[u64]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for id in ids {
        let bytes = fs::read(journal_dir.join(format!("seg-{id:012}.jnl"))).unwrap();
        let (_, records, _) = scan_segment_raw_records(&bytes).unwrap();
        for record in records {
            let entry_len = u32::from_be_bytes(record[0..4].try_into().unwrap()) as usize;
            let body = &record[8..4 + entry_len];
            let scanned = parse_entry_body(body).unwrap();
            out.push(scanned.ciphertext);
        }
    }
    out
}

fn obsolete_end(journal: &Journal, id: u64) -> u64 {
    journal
        .inspect_reconciliation()
        .unwrap()
        .lifecycles
        .into_iter()
        .find(|l| l.segment_id == id)
        .unwrap()
        .end_sequence
}

// --- 5.6.7.2 Compaction crash matrix ---

#[test]
fn c0_crash_before_compaction_sources_authoritative() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    append_many(&mut journal, &mut tree, 40);
    journal.bootstrap_journal_manifest(10).unwrap();
    let auth_before = disposition_map(&journal);

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    assert_eq!(disposition_map(&journal2), auth_before);
    assert!(journal2.inspect_reconciliation().unwrap().orphan.is_empty());
    set_test_segment_max_bytes(None);
}

#[test]
fn c2_crash_after_compacted_tmp_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    let (_artifact, sources) = compact_unpublished(&mut journal, &mut tree);
    fs::write(journal_dir.join("compacted-000000999999.tmp"), b"partial").unwrap();

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    for id in &sources {
        assert_eq!(disposition_map(&journal2).get(id), Some(&SegmentDisposition::Authoritative));
    }
    assert!(journal_dir.join("compacted-000000999999.tmp").exists());
    journal2.reconcile().unwrap();
    assert!(!journal_dir.join("compacted-000000999999.tmp").exists());
    set_test_segment_max_bytes(None);
}

#[test]
fn c4_crash_after_artifact_rename_artifact_is_orphan() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    let (artifact, sources) = compact_unpublished(&mut journal, &mut tree);
    let head = journal.last_sequence();
    let oldest = journal.oldest_available_sequence().unwrap();
    let replay = logical_replay(&journal, &mut tree);

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    assert_eq!(disposition_map(&journal2).get(&artifact.segment_id), Some(&SegmentDisposition::Orphan));
    for id in &sources {
        assert_eq!(disposition_map(&journal2).get(id), Some(&SegmentDisposition::Authoritative));
    }
    assert_eq!(journal2.last_sequence(), head);
    assert_eq!(journal2.oldest_available_sequence().unwrap(), oldest);
    assert_eq!(logical_replay(&journal2, &mut tree), replay);
    set_test_segment_max_bytes(None);
}

// --- 5.6.7.3 Manifest publication crash matrix ---

#[test]
fn c7_crash_before_manifest_rename_old_manifest_wins() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    append_many(&mut journal, &mut tree, 40);
    let candidate = journal.select_compaction_candidate(&policy()).unwrap().unwrap();
    let mut compactor = dmc_journal::JournalSegmentCompactor::new(&mut journal);
    let artifact = compactor.compact(&candidate).unwrap();
    let _old = journal.bootstrap_journal_manifest(10).unwrap();
    let old = journal.read_journal_manifest().unwrap().unwrap();
    let pending = build_compaction_manifest(&old, &artifact, &journal.segment_infos().unwrap()).unwrap();
    fs::write(
        runtime_journal_dir(dir.path()).join(MANIFEST_TMP),
        serde_json::to_string_pretty(&pending).unwrap(),
    )
    .unwrap();

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    assert_eq!(journal2.read_journal_manifest().unwrap().unwrap().generation, 10);
    assert_eq!(disposition_map(&journal2).get(&artifact.segment_id), Some(&SegmentDisposition::Orphan));
    set_test_segment_max_bytes(None);
}

#[test]
fn c8_crash_after_manifest_rename_new_topology() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    let (artifact, sources, published) = publish_compacted(&mut journal, &mut tree);

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    assert_eq!(journal2.read_journal_manifest().unwrap().unwrap().generation, published.generation);
    assert_eq!(
        disposition_map(&journal2).get(&artifact.segment_id),
        Some(&SegmentDisposition::Authoritative)
    );
    for id in &sources {
        assert_eq!(disposition_map(&journal2).get(id), Some(&SegmentDisposition::Obsolete));
    }
    set_test_segment_max_bytes(None);
}

// --- 5.6.7.4 GC crash matrix ---

#[test]
fn c10_crash_before_gc_obsolete_retained_repeatable() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    let (_artifact, sources, _published) = publish_compacted(&mut journal, &mut tree);
    let inspection = journal.inspect_reconciliation().unwrap();
    assert!(!inspection.obsolete.is_empty());

    drop(journal);
    let mut journal2 = reopen(dir.path(), &master, &salt);
    let after = journal2.inspect_reconciliation().unwrap();
    assert_eq!(after.obsolete, inspection.obsolete);
    let end = obsolete_end(&journal2, sources[0]);
    journal2.trim_through(end.saturating_sub(1)).unwrap();
    set_test_segment_max_bytes(None);
}

#[test]
fn c11_crash_after_partial_obsolete_delete_tolerated() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    let (_artifact, sources, _published) = publish_compacted(&mut journal, &mut tree);
    let first = sources[0];
    fs::remove_file(journal_dir.join(format!("seg-{first:012}.jnl"))).unwrap();

    drop(journal);
    let mut journal2 = reopen(dir.path(), &master, &salt);
    assert!(journal2.read_journal_manifest().unwrap().unwrap().superseded_segment_ids.contains(&first));
    assert!(!journal_dir.join(format!("seg-{first:012}.jnl")).exists());
    if sources.len() > 1 {
        let second = sources[1];
        let end = obsolete_end(&journal2, second);
        journal2.trim_through(end.saturating_sub(1.max(end.saturating_sub(1)))).ok();
    }
    assert!(logical_replay(&journal2, &mut tree).len() > 0);
    set_test_segment_max_bytes(None);
}

#[test]
fn c12_all_obsolete_removed_superseded_history_retained() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    let (artifact, sources, _published) = publish_compacted(&mut journal, &mut tree);
    let compacted_end = journal
        .read_journal_manifest()
        .unwrap()
        .unwrap()
        .segments
        .iter()
        .find(|s| s.segment_id == artifact.segment_id)
        .unwrap()
        .end_sequence;

    for id in &sources {
        let end = obsolete_end(&journal, *id);
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
    let superseded = journal.read_journal_manifest().unwrap().unwrap().superseded_segment_ids;

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    let manifest = journal2.read_journal_manifest().unwrap().unwrap();
    assert_eq!(manifest.superseded_segment_ids, superseded);
    for id in &sources {
        assert!(manifest.superseded_segment_ids.contains(id));
        assert!(!journal_dir.join(format!("seg-{id:012}.jnl")).exists());
    }
    assert_eq!(
        disposition_map(&journal2).get(&artifact.segment_id),
        Some(&SegmentDisposition::Authoritative)
    );
    set_test_segment_max_bytes(None);
}

// --- 5.6.7.5 Pin matrix (obsolete end=90) ---

#[test]
fn pin_matrix_gates_obsolete_gc() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    let (_artifact, sources, _published) = publish_compacted(&mut journal, &mut tree);
    let source = sources[0];
    let end = obsolete_end(&journal, source);
    assert!(end > 0);

    let safe_delete = calculate_watermark([&SequencePin(end) as &dyn JournalPin])
        .trim_through
        .unwrap();
    assert!(journal
        .eligible_segments(safe_delete)
        .unwrap()
        .iter()
        .any(|c| c.segment_id == source));

    if end > 1 {
        let safe_keep = calculate_watermark([&SequencePin(end.saturating_sub(1)) as &dyn JournalPin])
            .trim_through
            .unwrap();
        assert!(safe_keep < end);
        assert!(!journal
            .eligible_segments(safe_keep)
            .unwrap()
            .iter()
            .any(|c| c.segment_id == source));
    }

    let safe = calculate_watermark([
        &SequencePin(1000) as &dyn JournalPin,
        &SequencePin(700) as &dyn JournalPin,
        &SequencePin(900) as &dyn JournalPin,
    ])
    .trim_through
    .unwrap();
    assert_eq!(safe, 700);
    set_test_segment_max_bytes(None);
}

// --- 5.6.7.6 Replay equivalence ---

#[test]
fn replay_equivalent_through_compaction_gc_restart() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    append_many(&mut journal, &mut tree, 500);
    let before = logical_replay(&journal, &mut tree);

    let candidate = journal.select_compaction_candidate(&policy()).unwrap().unwrap();
    let sources = candidate.segment_ids.clone();
    let mut compactor = dmc_journal::JournalSegmentCompactor::new(&mut journal);
    let artifact = compactor.compact(&candidate).unwrap();
    journal.bootstrap_journal_manifest(10).unwrap();
    journal.publish_compaction(&artifact).unwrap();

    let compacted_end = journal
        .read_journal_manifest()
        .unwrap()
        .unwrap()
        .segments
        .iter()
        .find(|s| s.segment_id == artifact.segment_id)
        .unwrap()
        .end_sequence;
    for id in &sources {
        let end = obsolete_end(&journal, *id);
        if end < compacted_end {
            journal.trim_through(end).unwrap();
        }
        let path = journal_dir.join(format!("seg-{id:012}.jnl"));
        if path.is_file() {
            fs::remove_file(&path).unwrap();
        }
    }

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    let after = logical_replay(&journal2, &mut tree);
    assert_eq!(before.len(), after.len());
    assert_eq!(before, after);
    set_test_segment_max_bytes(None);
}

// --- 5.6.7.7 Encryption invariant ---

#[test]
fn ciphertext_preserved_through_compaction_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    append_many(&mut journal, &mut tree, 40);
    let candidate = journal.select_compaction_candidate(&policy()).unwrap().unwrap();
    let sources = candidate.segment_ids.clone();
    let source_cipher = raw_ciphertexts(&journal_dir, &sources);

    let mut compactor = dmc_journal::JournalSegmentCompactor::new(&mut journal);
    let artifact = compactor.compact(&candidate).unwrap();
    let compact_cipher = raw_ciphertexts(&journal_dir, &[artifact.segment_id]);
    assert_eq!(source_cipher, compact_cipher);

    journal.bootstrap_journal_manifest(10).unwrap();
    journal.publish_compaction(&artifact).unwrap();

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    let recovered = raw_ciphertexts(&journal_dir, &[artifact.segment_id]);
    assert_eq!(source_cipher, recovered);
    let _ = journal2;
    set_test_segment_max_bytes(None);
}

// --- 5.6.7.8 Manifest corruption ---

#[test]
fn corrupt_manifest_is_fatal_no_auto_repair() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    publish_compacted(&mut journal, &mut tree);
    let path = manifest_path(dir.path());
    let corrupt = r#"{"format_version":1,"generation":99,"segments":[]}"#;
    fs::write(&path, corrupt).unwrap();

    drop(journal);
    let err = reopen_err(dir.path(), &master, &salt);
    assert!(matches!(err, JournalError::JournalManifestInconsistent(_)));
    assert_eq!(fs::read_to_string(&path).unwrap(), corrupt);
    set_test_segment_max_bytes(None);
}

// --- 5.6.7.9 Missing segment semantics ---

#[test]
fn missing_authoritative_segment_is_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    let (artifact, _sources, _published) = publish_compacted(&mut journal, &mut tree);
    fs::remove_file(journal_dir.join(format!("seg-{:012}.jnl", artifact.segment_id))).unwrap();

    drop(journal);
    let err = reopen_err(dir.path(), &master, &salt);
    assert!(
        matches!(err, JournalError::JournalManifestInconsistent(_))
            || matches!(err, JournalError::JournalSegmentCorrupt(_))
    );
    set_test_segment_max_bytes(None);
}

#[test]
fn missing_obsolete_segment_is_valid() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    let (artifact, sources, _published) = publish_compacted(&mut journal, &mut tree);
    let obsolete = sources[0];
    fs::remove_file(journal_dir.join(format!("seg-{obsolete:012}.jnl"))).unwrap();
    let replay_before = logical_replay(&journal, &mut tree);

    drop(journal);
    let journal2 = reopen(dir.path(), &master, &salt);
    assert!(journal2
        .read_journal_manifest()
        .unwrap()
        .unwrap()
        .superseded_segment_ids
        .contains(&obsolete));
    assert_eq!(logical_replay(&journal2, &mut tree), replay_before);
    assert_eq!(
        disposition_map(&journal2).get(&artifact.segment_id),
        Some(&SegmentDisposition::Authoritative)
    );
    set_test_segment_max_bytes(None);
}

// --- 5.6.7.10 Idempotency ---

#[test]
fn trim_through_is_idempotent_after_obsolete_gc() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    let (artifact, sources, _published) = publish_compacted(&mut journal, &mut tree);
    let compacted_end = journal
        .read_journal_manifest()
        .unwrap()
        .unwrap()
        .segments
        .iter()
        .find(|s| s.segment_id == artifact.segment_id)
        .unwrap()
        .end_sequence;

    let trim = sources
        .iter()
        .map(|id| obsolete_end(&journal, *id))
        .filter(|end| *end < compacted_end)
        .max()
        .unwrap_or(1);

    let first = journal.trim_through(trim).unwrap();
    let second = journal.trim_through(trim).unwrap();
    assert!(second.deleted_segments.is_empty());
    assert_eq!(first.trim_through, second.trim_through);
    assert!(journal.read_journal_manifest().unwrap().is_some());
    assert!(list_segment_ids(&journal_dir)
        .unwrap()
        .contains(&artifact.segment_id));
    let _ = journal.reconcile().unwrap();
    set_test_segment_max_bytes(None);
}
