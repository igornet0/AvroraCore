//! Compaction artifact write, byte equivalence, orphan semantics (Phase 5.6.2).

use std::fs;

use dmc_journal::codec::{parse_entry_body, scan_segment_raw_records};
use dmc_journal::error::Error as JournalError;
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

fn manifest_path(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("runtime/journal/manifest.json")
}

fn collect_raw_records_from_segments(journal_dir: &std::path::Path, ids: &[u64]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for id in ids {
        let bytes = fs::read(journal_dir.join(format!("seg-{id:012}.jnl"))).unwrap();
        let (_, records, _) = scan_segment_raw_records(&bytes).unwrap();
        out.extend(records);
    }
    out
}

fn record_fields(record: &[u8]) -> (u64, [u8; 16], Vec<u8>) {
    let entry_len = u32::from_be_bytes(record[0..4].try_into().unwrap()) as usize;
    let body = &record[8..4 + entry_len];
    let scanned = parse_entry_body(body).unwrap();
    (scanned.sequence, scanned.event_id, scanned.ciphertext)
}

#[test]
fn topology_mutation_is_serial() {
    let dir = tempfile::tempdir().unwrap();
    let (journal, _tree, _master, _salt) = setup(dir.path());
    let g1 = journal.begin_topology_mutation().unwrap();
    assert!(matches!(
        journal.begin_topology_mutation(),
        Err(JournalError::TopologyMutationActive)
    ));
    drop(g1);
    assert!(journal.begin_topology_mutation().is_ok());
    set_test_segment_max_bytes(None);
}

#[test]
fn select_candidate_ignores_active_segment() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    append_many(&mut journal, &mut tree, 40);
    let policy = CompactionPolicy {
        enabled: true,
        min_segments: 1,
        min_total_bytes: 0,
        max_input_bytes: 10 * 1024 * 1024,
    };
    let c = journal.select_compaction_candidate(&policy).unwrap().unwrap();
    let infos = journal.segment_infos().unwrap();
    let active_id = infos.last().unwrap().id;
    let active = infos.iter().find(|s| s.id == active_id).unwrap();
    assert!(!c.segment_ids.contains(&active.id));
    set_test_segment_max_bytes(None);
}

#[test]
fn compaction_byte_equivalence_and_encryption_preservation() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    append_many(&mut journal, &mut tree, 40);
    let policy = CompactionPolicy {
        enabled: true,
        min_segments: 2,
        min_total_bytes: 0,
        max_input_bytes: 10 * 1024 * 1024,
    };
    let candidate = journal.select_compaction_candidate(&policy).unwrap().unwrap();
    let before = journal.replay(0, &mut tree).unwrap();
    let source_ids = candidate.segment_ids.clone();

    let mut compactor = dmc_journal::JournalSegmentCompactor::new(&mut journal);
    let artifact = compactor.compact(&candidate).unwrap();

    let journal_dir = dir.path().join("journal");
    let source_records = collect_raw_records_from_segments(&journal_dir, &source_ids);
    let artifact_records =
        collect_raw_records_from_segments(&journal_dir, std::slice::from_ref(&artifact.segment_id));

    assert_eq!(source_records.len(), artifact_records.len());
    for (old, new) in source_records.iter().zip(artifact_records.iter()) {
        assert_eq!(old, new);
        let (seq_a, id_a, ct_a) = record_fields(old);
        let (seq_b, id_b, ct_b) = record_fields(new);
        assert_eq!(seq_a, seq_b);
        assert_eq!(id_a, id_b);
        assert_eq!(ct_a, ct_b);
    }

    assert_eq!(artifact.start_sequence, candidate.start_sequence);
    assert_eq!(artifact.end_sequence, candidate.end_sequence);
    assert_eq!(artifact.record_count, source_records.len() as u64);
    assert!(artifact.path.is_file());

    let after = journal.replay(0, &mut tree).unwrap();
    assert_eq!(before.len(), after.len());
    for (a, b) in before.iter().zip(after.iter()) {
        assert_eq!(a.sequence, b.sequence);
        assert_eq!(a.event_id, b.event_id);
        assert_eq!(a.payload, b.payload);
    }
    set_test_segment_max_bytes(None);
}

#[test]
fn compaction_replay_uses_authoritative_segments_only() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    append_many(&mut journal, &mut tree, 40);
    let policy = CompactionPolicy {
        enabled: true,
        min_segments: 2,
        min_total_bytes: 0,
        max_input_bytes: 10 * 1024 * 1024,
    };
    let candidate = journal.select_compaction_candidate(&policy).unwrap().unwrap();
    let before = journal.replay(0, &mut tree).unwrap();
    let auth_before: Vec<u64> = journal.segment_infos().unwrap().into_iter().map(|s| s.id).collect();

    let mut compactor = dmc_journal::JournalSegmentCompactor::new(&mut journal);
    let artifact = compactor.compact(&candidate).unwrap();

    let journal_dir = dir.path().join("journal");
    let all_on_disk = list_segment_ids(&journal_dir).unwrap();
    assert!(all_on_disk.contains(&artifact.segment_id));

    let auth_after: Vec<u64> = journal.segment_infos().unwrap().into_iter().map(|s| s.id).collect();
    assert!(!auth_after.contains(&artifact.segment_id));
    assert_eq!(auth_before, auth_after);

    let after = journal.replay(0, &mut tree).unwrap();
    assert_eq!(before.len(), after.len());
    for (a, b) in before.iter().zip(after.iter()) {
        assert_eq!(a.sequence, b.sequence);
        assert_eq!(a.event_id, b.event_id);
        assert_eq!(a.payload, b.payload);
    }
    set_test_segment_max_bytes(None);
}

#[test]
fn corrupted_source_aborts_without_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree, _master, _salt) = setup(dir.path());
    append_many(&mut journal, &mut tree, 40);
    let policy = CompactionPolicy {
        enabled: true,
        min_segments: 2,
        min_total_bytes: 0,
        max_input_bytes: 10 * 1024 * 1024,
    };
    let candidate = journal.select_compaction_candidate(&policy).unwrap().unwrap();
    let corrupt_id = candidate.segment_ids[0];
    let seg_path = dir
        .path()
        .join("journal")
        .join(format!("seg-{corrupt_id:012}.jnl"));
    let mut bytes = fs::read(&seg_path).unwrap();
    let n = bytes.len();
    for b in bytes.iter_mut().skip(n.saturating_sub(80)) {
        *b ^= 0xff;
    }
    fs::write(&seg_path, &bytes).unwrap();

    let ids_before = list_segment_ids(dir.path().join("journal").as_path()).unwrap();
    let mut compactor = dmc_journal::JournalSegmentCompactor::new(&mut journal);
    assert!(compactor.compact(&candidate).is_err());
    let ids_after = list_segment_ids(dir.path().join("journal").as_path()).unwrap();
    assert_eq!(ids_before, ids_after);
    assert!(!dir.path().join("journal").read_dir().unwrap().any(|e| {
        e.as_ref()
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp")
    }));
    set_test_segment_max_bytes(None);
}

#[test]
fn orphan_segment_and_tmp_not_authoritative_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let (mut journal, mut tree, master, salt) = setup(dir.path());
    append_many(&mut journal, &mut tree, 40);
    let policy = CompactionPolicy {
        enabled: true,
        min_segments: 2,
        min_total_bytes: 0,
        max_input_bytes: 10 * 1024 * 1024,
    };
    let candidate = journal.select_compaction_candidate(&policy).unwrap().unwrap();
    let mut compactor = dmc_journal::JournalSegmentCompactor::new(&mut journal);
    let artifact = compactor.compact(&candidate).unwrap();

    assert!(artifact.path.is_file());
    let active_id = journal.segment_infos().unwrap().last().unwrap().id;
    let auth = authoritative_segment_ids(&journal_dir, &manifest_path(dir.path()), &[active_id], 1).unwrap();
    assert!(!auth.contains(&artifact.segment_id));

    drop(journal);
    drop(tree);

    let kek = derive_journal_kek(&master, &salt);
    let config = JournalConfig::new(journal_dir.clone()).with_segment_max_bytes(900);
    let journal2 = Journal::open(config, &kek).unwrap();
    let auth2: Vec<u64> = journal2.segment_infos().unwrap().into_iter().map(|s| s.id).collect();
    assert!(!auth2.contains(&artifact.segment_id));
    assert!(list_segment_ids(&journal_dir).unwrap().contains(&artifact.segment_id));

    let tmp = journal_dir.join("compacted-000000009999.tmp");
    fs::write(&tmp, b"partial").unwrap();
    let active2 = journal2.segment_infos().unwrap().last().unwrap().id;
    let auth3 = authoritative_segment_ids(&journal_dir, &manifest_path(dir.path()), &[active2], 1).unwrap();
    assert!(!auth3.contains(&9999));
    let _ = fs::remove_file(tmp);
    set_test_segment_max_bytes(None);
}
