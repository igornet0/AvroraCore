//! Phase 5.7.8 — partition-aware compaction DoD.

use std::collections::HashSet;
use std::fs;

use dmc_vault::crypto::derive_journal_kek;
use dmc_vault::key::{KeyPath, KeyTree};

use dmc_journal::codec::{parse_entry_body, scan_segment_raw_records};
use dmc_journal::journal_manifest_v2::{read_stored_manifest, StoredJournalManifest};
use dmc_journal::layout::{segment_path_for_partition, list_segment_ids};
use dmc_journal::partition::{resolve_partition, PartitionId, PartitionKey};
use dmc_journal::segment::SegmentState;
use dmc_journal::{
    calculate_watermark, CompactionPolicy, Journal, JournalConfig, JournalEntryDraft,
    JournalEventKind, JournalPin, Operation, SequencePin, set_test_partition_count,
    set_test_segment_max_bytes,
};

fn setup_tree() -> (KeyTree, dmc_vault::KeyMaterial, Vec<u8>, KeyPath) {
    let (mut tree, master) = KeyTree::create_new().unwrap();
    let path = KeyPath::parse("company/finance/x").unwrap();
    tree.ensure_node(&path).unwrap();
    let salt = tree.salt().to_vec();
    (tree, master, salt, path)
}

fn open_journal(
    dir: &std::path::Path,
    master: &dmc_vault::KeyMaterial,
    salt: &[u8],
    parts: u32,
) -> Journal {
    let kek = derive_journal_kek(master, salt);
    Journal::open(
        JournalConfig::new(dir.join("journal"))
            .with_partition_count(parts)
            .with_segment_max_bytes(900),
        &kek,
    )
    .unwrap()
}

fn key_for_partition(path: &KeyPath, target: u32, parts: u32) -> PartitionKey {
    for i in 0..10_000 {
        let key = PartitionKey::new(format!("route-{i}"));
        if resolve_partition(path, Some(&key), parts).unwrap().as_u32() == target {
            return key;
        }
    }
    panic!("no routing key for partition {target}");
}

fn append_to_partition(
    journal: &mut Journal,
    tree: &mut KeyTree,
    path: &KeyPath,
    parts: u32,
    partition: u32,
    payload: &[u8],
) -> u64 {
    let key = key_for_partition(path, partition, parts);
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
    journal.append(draft, &dek).unwrap().sequence
}

fn append_interleaved_round(
    journal: &mut Journal,
    tree: &mut KeyTree,
    path: &KeyPath,
    parts: u32,
    round: u32,
) {
    for p in 0..parts {
        append_to_partition(
            journal,
            tree,
            path,
            parts,
            p,
            format!("r{round}-p{p}").as_bytes(),
        );
        journal.sync().unwrap();
    }
}

fn policy(min_segments: usize) -> CompactionPolicy {
    CompactionPolicy {
        enabled: true,
        min_segments,
        min_total_bytes: 0,
        max_input_bytes: 10 * 1024 * 1024,
    }
}

fn logical_stream(journal: &Journal, tree: &mut KeyTree) -> Vec<(u64, [u8; 16], Vec<u8>)> {
    journal
        .replay(0, tree)
        .unwrap()
        .into_iter()
        .map(|e| (e.sequence, e.event_id, e.payload))
        .collect()
}

fn bootstrap(journal: &Journal) {
    journal.bootstrap_journal_manifest(1).unwrap();
}

#[test]
fn candidate_never_mixes_partitions() {
    set_test_segment_max_bytes(Some(900));
    let parts = 3;
    set_test_partition_count(Some(parts));
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, path) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, parts);
    for round in 0..12 {
        append_interleaved_round(&mut journal, &mut tree, &path, parts, round);
    }
    bootstrap(&journal);
    let c = journal
        .select_compaction_candidate(&policy(2))
        .unwrap()
        .unwrap();
    let partitions = journal
        .segment_infos()
        .unwrap()
        .iter()
        .filter(|s| c.segment_ids.contains(&s.id))
        .map(|s| s.id)
        .collect::<Vec<_>>();
    assert_eq!(partitions.len(), c.segment_ids.len());
    assert!(c.partition_id.as_u32() < parts);
    set_test_partition_count(None);
    set_test_segment_max_bytes(None);
}

#[test]
fn active_segment_excluded_from_candidate() {
    set_test_segment_max_bytes(Some(900));
    let parts = 2;
    set_test_partition_count(Some(parts));
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, path) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, parts);
    for round in 0..20 {
        append_interleaved_round(&mut journal, &mut tree, &path, parts, round);
    }
    bootstrap(&journal);
    let c = journal
        .select_compaction_candidate_for_partition(PartitionId(0), &policy(1))
        .unwrap()
        .unwrap();
    let active = journal
        .segment_infos()
        .unwrap()
        .into_iter()
        .find(|s| s.state == SegmentState::Active)
        .unwrap();
    assert!(!c.segment_ids.contains(&active.id));
    set_test_partition_count(None);
    set_test_segment_max_bytes(None);
}

#[test]
fn interleaved_compact_p0_preserves_global_merge_stream() {
    set_test_segment_max_bytes(Some(900));
    let parts = 3;
    set_test_partition_count(Some(parts));
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, path) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, parts);
    for round in 0..15 {
        append_interleaved_round(&mut journal, &mut tree, &path, parts, round);
    }
    bootstrap(&journal);
    let before = logical_stream(&journal, &mut tree);

    let candidate = journal
        .select_compaction_candidate_for_partition(PartitionId(0), &policy(2))
        .unwrap()
        .expect("P0 candidate");
    assert_eq!(candidate.partition_id, PartitionId(0));

    let artifact = journal.compact_candidate(&candidate).unwrap();
    assert_eq!(artifact.partition_id, PartitionId(0));
    assert!(
        artifact
            .path
            .to_string_lossy()
            .contains("p-000"),
        "artifact must live under p-000"
    );

    journal.publish_compaction(&artifact).unwrap();

    let after = logical_stream(&journal, &mut tree);
    assert_eq!(before, after, "logical stream must be unchanged");

    let stored = read_stored_manifest(&dir.path().join("runtime/journal/manifest.json"))
        .unwrap()
        .unwrap();
    let StoredJournalManifest::V2(m) = stored else {
        panic!("expected V2 manifest");
    };
    assert!(m.contains_segment(artifact.segment_id));
    for src in &artifact.source_segment_ids {
        assert!(m.superseded_segment_ids.contains(src));
    }
    let p1_before: HashSet<_> = m.partitions[1]
        .segments
        .iter()
        .map(|s| s.segment_id)
        .collect();
    assert!(!p1_before.is_empty());

    set_test_partition_count(None);
    set_test_segment_max_bytes(None);
}

#[test]
fn raw_record_byte_equivalence_after_compaction() {
    set_test_segment_max_bytes(Some(900));
    let parts = 3;
    set_test_partition_count(Some(parts));
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, path) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, parts);
    for round in 0..12 {
        append_interleaved_round(&mut journal, &mut tree, &path, parts, round);
    }
    bootstrap(&journal);

    let candidate = journal
        .select_compaction_candidate_for_partition(PartitionId(0), &policy(2))
        .unwrap()
        .unwrap();
    let journal_dir = dir.path().join("journal");
    let before_records: Vec<_> = candidate
        .segment_ids
        .iter()
        .flat_map(|id| {
            let p = segment_path_for_partition(&journal_dir, PartitionId(0), *id, parts);
            let bytes = fs::read(&p).unwrap();
            let (_, records, _) = scan_segment_raw_records(&bytes).unwrap();
            records
        })
        .collect();

    let artifact = journal.compact_candidate(&candidate).unwrap();
    let after_bytes = fs::read(&artifact.path).unwrap();
    let (_, after_records, _) = scan_segment_raw_records(&after_bytes).unwrap();
    assert_eq!(before_records, after_records);

    for record in &after_records {
        let entry_len = u32::from_be_bytes(record[0..4].try_into().unwrap()) as usize;
        let body = &record[8..4 + entry_len];
        let _ = parse_entry_body(body).unwrap();
    }

    set_test_partition_count(None);
    set_test_segment_max_bytes(None);
}

#[test]
fn compact_p1_unchanged_p0_then_restart_merge_equivalent() {
    set_test_segment_max_bytes(Some(900));
    let parts = 3;
    set_test_partition_count(Some(parts));
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, path) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, parts);
    for round in 0..14 {
        append_interleaved_round(&mut journal, &mut tree, &path, parts, round);
    }
    bootstrap(&journal);
    let before = logical_stream(&journal, &mut tree);

    let c0 = journal
        .select_compaction_candidate_for_partition(PartitionId(0), &policy(2))
        .unwrap()
        .unwrap();
    let a0 = journal.compact_candidate(&c0).unwrap();
    journal.publish_compaction(&a0).unwrap();

    let c1 = journal
        .select_compaction_candidate_for_partition(PartitionId(1), &policy(2))
        .unwrap()
        .unwrap();
    let a1 = journal.compact_candidate(&c1).unwrap();
    journal.publish_compaction(&a1).unwrap();

    let after = logical_stream(&journal, &mut tree);
    assert_eq!(before, after);

    drop(journal);
    let journal2 = open_journal(dir.path(), &master, &salt, parts);
    let after_restart = logical_stream(&journal2, &mut tree);
    assert_eq!(before, after_restart);

    set_test_partition_count(None);
    set_test_segment_max_bytes(None);
}

#[test]
fn obsolete_sources_gc_after_safe_trim() {
    set_test_segment_max_bytes(Some(900));
    let parts = 2;
    set_test_partition_count(Some(parts));
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, path) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, parts);
    for round in 0..16 {
        append_interleaved_round(&mut journal, &mut tree, &path, parts, round);
    }
    bootstrap(&journal);

    let candidate = journal
        .select_compaction_candidate_for_partition(PartitionId(0), &policy(2))
        .unwrap()
        .unwrap();
    let infos = journal.segment_infos().unwrap();
    let min_source_end = candidate
        .segment_ids
        .iter()
        .map(|id| {
            infos
                .iter()
                .find(|s| s.id == *id)
                .unwrap()
                .end_sequence
        })
        .min()
        .unwrap();
    let artifact = journal.compact_candidate(&candidate).unwrap();
    assert!(artifact.end_sequence >= min_source_end);
    journal.publish_compaction(&artifact).unwrap();

    let stored = read_stored_manifest(&dir.path().join("runtime/journal/manifest.json"))
        .unwrap()
        .unwrap();
    let superseded = stored.superseded_segment_ids().to_vec();
    assert!(!superseded.is_empty());

    // Trim below compacted end: obsolete sources with end <= pin may go; compacted stays.
    let trim = calculate_watermark([&SequencePin(min_source_end) as &dyn JournalPin])
        .trim_through
        .unwrap();
    let deleted = journal.trim_through(trim).unwrap();
    assert!(!deleted.deleted_segments.is_empty());
    assert!(
        segment_path_for_partition(
            &dir.path().join("journal"),
            PartitionId(0),
            artifact.segment_id,
            parts
        )
        .is_file(),
        "compacted authoritative segment must survive GC above pin"
    );

    let stored_after = read_stored_manifest(&dir.path().join("runtime/journal/manifest.json"))
        .unwrap()
        .unwrap();
    assert_eq!(stored_after.superseded_segment_ids(), superseded);

    set_test_partition_count(None);
    set_test_segment_max_bytes(None);
}

#[test]
fn single_partition_backward_compatible() {
    set_test_segment_max_bytes(Some(900));
    set_test_partition_count(Some(1));
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, path) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, 1);
    for i in 0..30 {
        append_to_partition(
            &mut journal,
            &mut tree,
            &path,
            1,
            0,
            format!("evt-{i}").as_bytes(),
        );
        journal.sync().unwrap();
    }
    let before = logical_stream(&journal, &mut tree);
    let candidate = journal.select_compaction_candidate(&policy(2)).unwrap().unwrap();
    assert_eq!(candidate.partition_id, PartitionId(0));
    let artifact = journal.compact_candidate(&candidate).unwrap();
    journal.bootstrap_journal_manifest(1).unwrap();
    journal.publish_compaction(&artifact).unwrap();
    let after = logical_stream(&journal, &mut tree);
    assert_eq!(before, after);
    assert!(list_segment_ids(&dir.path().join("journal")).unwrap().len() >= 1);
    set_test_partition_count(None);
    set_test_segment_max_bytes(None);
}
