//! Phase 5.7.5 — JournalMergeReader DoD.

use std::fs;

use dmc_vault::crypto::derive_journal_kek;
use dmc_vault::key::{KeyPath, KeyTree};

use dmc_journal::codec::{encode_entry, encode_footer, encode_segment_header, SegmentHeader};
use dmc_journal::journal_manifest_v2::v2_to_stored;
use dmc_journal::layout::segment_path_for_partition;
use dmc_journal::partition::{resolve_partition, PartitionId, PartitionKey};
use dmc_journal::segment::SegmentState;
use dmc_journal::types::journal_key_id;
use dmc_journal::{
    Error, Journal, JournalConfig, JournalEntryDraft, JournalEventKind, JournalManifestV2,
    JournalMergeReader, Operation, PartitionManifest, SegmentManifestEntry,
    JOURNAL_MANIFEST_FORMAT_VERSION_V2,
};
use dmc_journal::{publish_stored_manifest, read_stored_manifest};

fn setup_tree() -> (KeyTree, dmc_vault::KeyMaterial, Vec<u8>, KeyPath) {
    let (mut tree, master) = KeyTree::create_new().unwrap();
    let path = KeyPath::parse("company/finance/invoices/1").unwrap();
    tree.ensure_node(&path).unwrap();
    let salt = tree.salt().to_vec();
    (tree, master, salt, path)
}

fn draft(
    tree: &mut KeyTree,
    path: &KeyPath,
    key: Option<PartitionKey>,
    payload: &[u8],
) -> (JournalEntryDraft, dmc_vault::KeyMaterial) {
    let dek = tree.dek(path).unwrap().clone();
    let key_version = tree.meta(path).unwrap().generation;
    (
        JournalEntryDraft {
            path: path.clone(),
            event_kind: JournalEventKind::OverlayApply,
            operation: Operation::OverlayPut,
            key_version,
            actor_session: [1u8; 16],
            actor_role: "root".into(),
            node_bundle: tree.list_nodes(),
            payload: payload.to_vec(),
            partition_key: key,
        },
        dek,
    )
}

fn open_journal(
    dir: &std::path::Path,
    master: &dmc_vault::KeyMaterial,
    salt: &[u8],
    parts: u32,
) -> Journal {
    let kek = derive_journal_kek(master, salt);
    Journal::open(
        JournalConfig::new(dir.join("journal")).with_partition_count(parts),
        &kek,
    )
    .unwrap()
}

fn manifest_path(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("runtime/journal/manifest.json")
}

fn runtime_dir(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("runtime/journal")
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
    let (d, dek) = draft(tree, path, Some(key), payload);
    journal.append(d, &dek).unwrap().sequence
}

fn merge_sequences(journal: &Journal, tree: &mut KeyTree, from: u64) -> Vec<u64> {
    let mut reader = journal.merge_reader(from).unwrap();
    let entries = reader.collect_all(tree).unwrap();
    entries.iter().map(|e| e.sequence).collect()
}

fn seg_entry(segment_id: u64, start: u64, end: u64, state: SegmentState) -> SegmentManifestEntry {
    SegmentManifestEntry {
        segment_id,
        start_sequence: start,
        end_sequence: end,
        start_timestamp_unix_ms: 1,
        end_timestamp_unix_ms: 1,
        byte_size: 1,
        state,
    }
}

fn write_segment_sequences(
    out_path: &std::path::Path,
    segment_id: u64,
    sequences: &[u64],
    tree: &mut KeyTree,
    path: &KeyPath,
    dek: &dmc_vault::KeyMaterial,
    kek: &dmc_vault::KeyMaterial,
    sealed: bool,
) {
    let kid = journal_key_id(kek);
    let mut blob = encode_segment_header(&SegmentHeader {
        segment_id,
        first_sequence: sequences[0],
        created_unix_ms: 1,
        journal_key_id: kid,
    })
    .to_vec();
    for &seq in sequences {
        let (d, _) = draft(tree, path, None, format!("seq-{seq}").as_bytes());
        let (entry, _) = encode_entry(&d, seq, dek).unwrap();
        blob.extend_from_slice(&entry);
    }
    if sealed {
        blob.extend_from_slice(
            &encode_footer(*sequences.last().unwrap(), sequences.len() as u64),
        );
    }
    fs::write(out_path, blob).unwrap();
}

fn publish_v2(dir: &std::path::Path, manifest: JournalManifestV2) {
    fs::create_dir_all(runtime_dir(dir)).unwrap();
    publish_stored_manifest(&runtime_dir(dir), &v2_to_stored(manifest)).unwrap();
}

#[test]
fn basic_interleaved_three_partitions() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, path) = setup_tree();
    let parts = 3;
    let mut journal = open_journal(dir.path(), &master, &salt, parts);

    let plan = [
        (0, 1u64),
        (1, 2),
        (2, 3),
        (0, 4),
        (1, 5),
        (2, 6),
        (0, 7),
        (1, 8),
        (2, 9),
    ];
    for (p, expected) in plan {
        let seq = append_to_partition(
            &mut journal,
            &mut tree,
            &path,
            parts,
            p,
            format!("e-{expected}").as_bytes(),
        );
        assert_eq!(seq, expected);
        journal.sync().unwrap();
    }
    drop(journal);

    let journal = open_journal(dir.path(), &master, &salt, parts);
    assert_eq!(merge_sequences(&journal, &mut tree, 0), (1..=9).collect::<Vec<_>>());
}

#[test]
fn single_partition_matches_legacy_replay_order() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, path) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, 1);
    for i in 1..=6 {
        let (d, dek) = draft(&mut tree, &path, None, format!("e-{i}").as_bytes());
        journal.append(d, &dek).unwrap();
        journal.sync().unwrap();
    }
    let replay = journal.replay(0, &mut tree).unwrap();
    drop(journal);

    let journal = open_journal(dir.path(), &master, &salt, 1);
    let merged = journal.merge_reader(0).unwrap().collect_all(&mut tree).unwrap();
    assert_eq!(
        merged.iter().map(|e| e.sequence).collect::<Vec<_>>(),
        replay.iter().map(|e| e.sequence).collect::<Vec<_>>()
    );
    assert_eq!(
        merged.iter().map(|e| e.event_id).collect::<Vec<_>>(),
        replay.iter().map(|e| e.event_id).collect::<Vec<_>>()
    );
}

#[test]
fn from_sequence_skips_lower_sequences() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, path) = setup_tree();
    let parts = 3;
    let mut journal = open_journal(dir.path(), &master, &salt, parts);
    for i in 0..9 {
        append_to_partition(
            &mut journal,
            &mut tree,
            &path,
            parts,
            i % parts,
            format!("e-{i}").as_bytes(),
        );
        journal.sync().unwrap();
    }
    drop(journal);

    let journal = open_journal(dir.path(), &master, &salt, parts);
    assert_eq!(merge_sequences(&journal, &mut tree, 4), (5..=9).collect::<Vec<_>>());
}

#[test]
fn gaps_do_not_block_merge() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, path) = setup_tree();
    let kek = derive_journal_kek(&master, &salt);
    let dek = tree.dek(&path).unwrap().clone();
    let journal_dir = dir.path().join("journal");
    fs::create_dir_all(&journal_dir).unwrap();

    write_segment_sequences(
        &journal_dir.join("seg-000000000001.jnl"),
        1,
        &[1, 2, 4, 7],
        &mut tree,
        &path,
        &dek,
        &kek,
        false,
    );

    publish_v2(
        dir.path(),
        JournalManifestV2 {
            format_version: JOURNAL_MANIFEST_FORMAT_VERSION_V2,
            generation: 1,
            partition_count: 1,
            partitions: vec![PartitionManifest {
                partition_id: 0,
                segments: vec![seg_entry(1, 1, 7, SegmentState::Active)],
            }],
            superseded_segment_ids: vec![],
        },
    );

    let mut reader =
        JournalMergeReader::new(&journal_dir, &manifest_path(dir.path()), 1, 0).unwrap();
    assert_eq!(
        reader.collect_all(&mut tree).unwrap().iter().map(|e| e.sequence).collect::<Vec<_>>(),
        vec![1, 2, 4, 7]
    );
}

#[test]
fn duplicate_sequence_is_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, path) = setup_tree();
    let kek = derive_journal_kek(&master, &salt);
    let dek = tree.dek(&path).unwrap().clone();
    let journal_dir = dir.path().join("journal");
    fs::create_dir_all(journal_dir.join("p-000")).unwrap();
    fs::create_dir_all(journal_dir.join("p-001")).unwrap();

    write_segment_sequences(
        &segment_path_for_partition(&journal_dir, PartitionId(0), 1, 3),
        1,
        &[1, 3],
        &mut tree,
        &path,
        &dek,
        &kek,
        false,
    );
    write_segment_sequences(
        &segment_path_for_partition(&journal_dir, PartitionId(1), 2, 3),
        2,
        &[2, 3],
        &mut tree,
        &path,
        &dek,
        &kek,
        false,
    );

    publish_v2(
        dir.path(),
        JournalManifestV2 {
            format_version: JOURNAL_MANIFEST_FORMAT_VERSION_V2,
            generation: 1,
            partition_count: 3,
            partitions: vec![
                PartitionManifest {
                    partition_id: 0,
                    segments: vec![seg_entry(1, 1, 3, SegmentState::Active)],
                },
                PartitionManifest {
                    partition_id: 1,
                    segments: vec![seg_entry(2, 2, 3, SegmentState::Active)],
                },
            ],
            superseded_segment_ids: vec![],
        },
    );

    let mut reader =
        JournalMergeReader::new(&journal_dir, &manifest_path(dir.path()), 3, 0).unwrap();
    let err = reader.collect_all(&mut tree).unwrap_err();
    assert!(matches!(err, Error::JournalSequenceConflict(_)));
}

#[test]
fn orphan_segment_not_read() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, path) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, 1);
    for i in 1..=3 {
        let (d, dek) = draft(&mut tree, &path, None, format!("e-{i}").as_bytes());
        journal.append(d, &dek).unwrap();
        journal.sync().unwrap();
    }
    drop(journal);
    open_journal(dir.path(), &master, &salt, 1);

    let journal_dir = dir.path().join("journal");
    fs::write(
        journal_dir.join("seg-000000000099.jnl"),
        fs::read(journal_dir.join("seg-000000000001.jnl")).unwrap(),
    )
    .unwrap();

    let journal = open_journal(dir.path(), &master, &salt, 1);
    assert_eq!(merge_sequences(&journal, &mut tree, 0), vec![1, 2, 3]);
}

#[test]
fn obsolete_superseded_segments_not_read() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, path) = setup_tree();
    let kek = derive_journal_kek(&master, &salt);
    let dek = tree.dek(&path).unwrap().clone();
    let journal_dir = dir.path().join("journal");
    fs::create_dir_all(&journal_dir).unwrap();

    write_segment_sequences(
        &journal_dir.join("seg-000000000001.jnl"),
        1,
        &[1, 2],
        &mut tree,
        &path,
        &dek,
        &kek,
        true,
    );
    write_segment_sequences(
        &journal_dir.join("seg-000000000002.jnl"),
        2,
        &[3, 4],
        &mut tree,
        &path,
        &dek,
        &kek,
        true,
    );
    write_segment_sequences(
        &journal_dir.join("seg-000000000010.jnl"),
        10,
        &[1, 2, 3, 4],
        &mut tree,
        &path,
        &dek,
        &kek,
        false,
    );

    publish_v2(
        dir.path(),
        JournalManifestV2 {
            format_version: JOURNAL_MANIFEST_FORMAT_VERSION_V2,
            generation: 2,
            partition_count: 1,
            partitions: vec![PartitionManifest {
                partition_id: 0,
                segments: vec![seg_entry(10, 1, 4, SegmentState::Active)],
            }],
            superseded_segment_ids: vec![1, 2],
        },
    );

    let mut reader =
        JournalMergeReader::new(&journal_dir, &manifest_path(dir.path()), 1, 0).unwrap();
    let seqs: Vec<_> = reader
        .collect_all(&mut tree)
        .unwrap()
        .into_iter()
        .map(|e| e.sequence)
        .collect();
    assert_eq!(seqs, vec![1, 2, 3, 4]);
    assert_eq!(seqs.len(), 4);
}

#[test]
fn restart_produces_same_merge_stream() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, path) = setup_tree();
    let parts = 4;
    let mut journal = open_journal(dir.path(), &master, &salt, parts);
    for i in 0..12 {
        append_to_partition(
            &mut journal,
            &mut tree,
            &path,
            parts,
            i % parts,
            format!("e-{i}").as_bytes(),
        );
        journal.sync().unwrap();
    }
    journal.sync().unwrap();
    drop(journal);

    let journal = open_journal(dir.path(), &master, &salt, parts);
    let before = journal.merge_reader(0).unwrap().collect_all(&mut tree).unwrap();
    drop(journal);

    let journal = open_journal(dir.path(), &master, &salt, parts);
    let after = journal.merge_reader(0).unwrap().collect_all(&mut tree).unwrap();
    assert_eq!(
        before.iter().map(|e| (e.sequence, e.event_id)).collect::<Vec<_>>(),
        after.iter().map(|e| (e.sequence, e.event_id)).collect::<Vec<_>>()
    );
}

#[test]
fn order_independent_of_manifest_partition_order() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, path) = setup_tree();
    let kek = derive_journal_kek(&master, &salt);
    let dek = tree.dek(&path).unwrap().clone();
    let journal_dir = dir.path().join("journal");
    fs::create_dir_all(journal_dir.join("p-000")).unwrap();
    fs::create_dir_all(journal_dir.join("p-001")).unwrap();
    fs::create_dir_all(journal_dir.join("p-002")).unwrap();

    write_segment_sequences(
        &segment_path_for_partition(&journal_dir, PartitionId(0), 1, 3),
        1,
        &[1, 4, 7],
        &mut tree,
        &path,
        &dek,
        &kek,
        false,
    );
    write_segment_sequences(
        &segment_path_for_partition(&journal_dir, PartitionId(1), 2, 3),
        2,
        &[2, 5, 8],
        &mut tree,
        &path,
        &dek,
        &kek,
        false,
    );
    write_segment_sequences(
        &segment_path_for_partition(&journal_dir, PartitionId(2), 3, 3),
        3,
        &[3, 6, 9],
        &mut tree,
        &path,
        &dek,
        &kek,
        false,
    );

    // Deliberately list partitions out of numeric order in manifest.
    publish_v2(
        dir.path(),
        JournalManifestV2 {
            format_version: JOURNAL_MANIFEST_FORMAT_VERSION_V2,
            generation: 1,
            partition_count: 3,
            partitions: vec![
                PartitionManifest {
                    partition_id: 2,
                    segments: vec![seg_entry(3, 3, 9, SegmentState::Active)],
                },
                PartitionManifest {
                    partition_id: 0,
                    segments: vec![seg_entry(1, 1, 7, SegmentState::Active)],
                },
                PartitionManifest {
                    partition_id: 1,
                    segments: vec![seg_entry(2, 2, 8, SegmentState::Active)],
                },
            ],
            superseded_segment_ids: vec![],
        },
    );

    let mut reader =
        JournalMergeReader::new(&journal_dir, &manifest_path(dir.path()), 3, 0).unwrap();
    assert_eq!(
        reader.collect_all(&mut tree).unwrap().iter().map(|e| e.sequence).collect::<Vec<_>>(),
        (1..=9).collect::<Vec<_>>()
    );
}

#[test]
fn large_partition_count_merge_is_globally_sorted() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, path) = setup_tree();
    let parts = 64;
    let events = 10_000u32;
    let mut journal = open_journal(dir.path(), &master, &salt, parts);
    for i in 0..events {
        append_to_partition(
            &mut journal,
            &mut tree,
            &path,
            parts,
            i % parts,
            format!("e-{i}").as_bytes(),
        );
        if i % 128 == 0 {
            journal.sync().unwrap();
        }
    }
    journal.sync().unwrap();
    drop(journal);

    let journal = open_journal(dir.path(), &master, &salt, parts);
    let seqs = merge_sequences(&journal, &mut tree, 0);
    assert_eq!(seqs.len(), events as usize);
    for w in seqs.windows(2) {
        assert!(w[1] > w[0]);
    }
    assert_eq!(seqs.first().copied(), Some(1));
    assert_eq!(seqs.last().copied(), Some(events as u64));
}

#[test]
fn next_batch_respects_limit() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, path) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, 1);
    for i in 1..=5 {
        let (d, dek) = draft(&mut tree, &path, None, format!("e-{i}").as_bytes());
        journal.append(d, &dek).unwrap();
        journal.sync().unwrap();
    }
    drop(journal);

    let journal = open_journal(dir.path(), &master, &salt, 1);
    let mut reader = journal.merge_reader(0).unwrap();
    let batch = reader.next_batch(&mut tree, 3).unwrap();
    assert_eq!(batch.len(), 3);
    assert_eq!(batch.iter().map(|e| e.sequence).collect::<Vec<_>>(), vec![1, 2, 3]);
    let rest = reader.collect_all(&mut tree).unwrap();
    assert_eq!(rest.iter().map(|e| e.sequence).collect::<Vec<_>>(), vec![4, 5]);
}

#[test]
fn missing_authoritative_segment_is_fatal_on_open() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, path) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, 1);
    let (d, dek) = draft(&mut tree, &path, None, b"one");
    journal.append(d, &dek).unwrap();
    journal.sync().unwrap();
    drop(journal);
    open_journal(dir.path(), &master, &salt, 1);

    let journal_dir = dir.path().join("journal");
    fs::remove_file(journal_dir.join("seg-000000000001.jnl")).unwrap();
    assert!(
        JournalMergeReader::new(&journal_dir, &manifest_path(dir.path()), 1, 0).is_err()
    );
}

#[test]
fn merge_uses_manifest_not_filesystem_scan() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, path) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, 1);
    for i in 1..=2 {
        let (d, dek) = draft(&mut tree, &path, None, format!("e-{i}").as_bytes());
        journal.append(d, &dek).unwrap();
        journal.sync().unwrap();
    }
    drop(journal);
    open_journal(dir.path(), &master, &salt, 1);
    let stored = read_stored_manifest(&manifest_path(dir.path()))
        .unwrap()
        .unwrap();

    // Extra on-disk segment without manifest entry must not appear in merge.
    let journal_dir = dir.path().join("journal");
    fs::write(journal_dir.join("seg-000000000050.jnl"), b"orphan").unwrap();

    let mut reader = JournalMergeReader::new(
        &journal_dir,
        &manifest_path(dir.path()),
        1,
        0,
    )
    .unwrap();
    let seqs = reader
        .collect_all(&mut tree)
        .unwrap()
        .into_iter()
        .map(|e| e.sequence)
        .collect::<Vec<_>>();
    assert_eq!(seqs, vec![1, 2]);
    assert!(stored.generation() >= 1);
}
