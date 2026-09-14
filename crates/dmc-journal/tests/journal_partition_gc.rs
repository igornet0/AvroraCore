//! Phase 5.7.7 — partition-aware GC DoD.

use std::fs;

use dmc_vault::crypto::derive_journal_kek;
use dmc_vault::key::{KeyPath, KeyTree};

use dmc_journal::layout::{
    find_segment_path, is_partitioned_layout, list_segment_ids, segment_path_for_partition,
};
use dmc_journal::partition::{resolve_partition, PartitionId};
use dmc_journal::segment::SegmentState;
use dmc_journal::{
    calculate_watermark, Journal, JournalConfig, JournalEntryDraft, JournalEventKind,
    JournalPin, Operation, SequencePin, set_test_partition_count,
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

fn path_for_partition(target: u32, parts: u32) -> KeyPath {
    for i in 0..10_000 {
        let p = KeyPath::parse(&format!("company/finance/route-{i}")).unwrap();
        if resolve_partition(&p, None, parts).unwrap().as_u32() == target {
            return p;
        }
    }
    panic!("no path for partition {target}");
}

fn draft(
    tree: &mut KeyTree,
    path: &KeyPath,
    payload: &[u8],
) -> (JournalEntryDraft, dmc_vault::KeyMaterial) {
    let dek = tree.dek(path).unwrap().clone();
    (
        JournalEntryDraft {
            path: path.clone(),
            event_kind: JournalEventKind::OverlayApply,
            operation: Operation::OverlayPut,
            key_version: tree.meta(path).unwrap().generation,
            actor_session: [1u8; 16],
            actor_role: "root".into(),
            node_bundle: tree.list_nodes(),
            payload: payload.to_vec(),
            partition_key: None,
        },
        dek,
    )
}

fn append_interleaved(journal: &mut Journal, tree: &mut KeyTree, parts: u32, n: u64) {
    for i in 0..n {
        let path = path_for_partition(i as u32 % parts, parts);
        tree.ensure_node(&path).unwrap();
        let (d, dek) = draft(tree, &path, format!("e-{i}").as_bytes());
        journal.append(d, &dek).unwrap();
        journal.sync().unwrap();
    }
}

fn bootstrap(journal: &Journal) {
    journal.bootstrap_journal_manifest(1).unwrap();
}

#[test]
fn single_partition_gc_matches_legacy_with_partition_id_zero() {
    set_test_segment_max_bytes(Some(900));
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, path) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, 1);
    for i in 1..=12 {
        let (d, dek) = draft(&mut tree, &path, format!("p-{i}").as_bytes());
        journal.append(d, &dek).unwrap();
        journal.sync().unwrap();
    }
    let sealed = journal
        .segment_infos()
        .unwrap()
        .into_iter()
        .find(|s| s.state == SegmentState::Sealed)
        .unwrap();
    let eligible = journal.eligible_segments(sealed.end_sequence).unwrap();
    assert!(eligible.iter().all(|c| c.partition_id == PartitionId(0)));
    assert!(eligible.iter().all(|c| c.end_sequence <= sealed.end_sequence));
    let result = journal.trim_through(sealed.end_sequence).unwrap();
    assert!(!result.deleted_segments.is_empty());
    set_test_segment_max_bytes(None);
}

#[test]
fn multi_partition_trim_deletes_per_partition_eligible_segments() {
    set_test_segment_max_bytes(Some(900));
    let parts = 3;
    set_test_partition_count(Some(parts));
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, _) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, parts);
    append_interleaved(&mut journal, &mut tree, parts, 24);

    let sealed: Vec<_> = journal
        .segment_infos()
        .unwrap()
        .into_iter()
        .filter(|s| s.state == SegmentState::Sealed)
        .collect();
    assert!(sealed.len() >= 2);
    let trim = sealed.iter().map(|s| s.end_sequence).min().unwrap();
    let eligible = journal.eligible_segments(trim).unwrap();
    assert!(!eligible.is_empty());
    assert!(
        eligible.iter().all(|c| c.partition_id.as_u32() < parts),
        "partition_id must be set per candidate"
    );

    let before_paths: Vec<_> = eligible
        .iter()
        .map(|c| {
            segment_path_for_partition(
                &dir.path().join("journal"),
                c.partition_id,
                c.segment_id,
                parts,
            )
        })
        .collect();
    assert!(before_paths.iter().all(|p| p.is_file()));

    journal.trim_through(trim).unwrap();
    for p in before_paths {
        assert!(!p.is_file());
    }
    set_test_partition_count(None);
    set_test_segment_max_bytes(None);
}

#[test]
fn empty_partition_does_not_error_on_gc() {
    set_test_segment_max_bytes(Some(900));
    let parts = 4;
    set_test_partition_count(Some(parts));
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, _) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, parts);
    // Only use partitions 0 and 1; 2 and 3 stay empty in manifest after bootstrap.
    for i in 0..16 {
        let path = path_for_partition(i as u32 % 2, parts);
        tree.ensure_node(&path).unwrap();
        let (d, dek) = draft(&mut tree, &path, format!("e-{i}").as_bytes());
        journal.append(d, &dek).unwrap();
        journal.sync().unwrap();
    }
    let trim = journal
        .segment_infos()
        .unwrap()
        .into_iter()
        .filter(|s| s.state == SegmentState::Sealed)
        .map(|s| s.end_sequence)
        .min()
        .unwrap_or(0);
    assert!(journal.eligible_segments(trim).unwrap().len() >= 1);
    journal.trim_through(trim).unwrap();
    set_test_partition_count(None);
    set_test_segment_max_bytes(None);
}

#[test]
fn active_segment_protected_per_partition() {
    set_test_segment_max_bytes(Some(900));
    let parts = 3;
    set_test_partition_count(Some(parts));
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, _) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, parts);
    append_interleaved(&mut journal, &mut tree, parts, 8);
    let head = journal.last_sequence();
    let actives: Vec<_> = journal
        .segment_infos()
        .unwrap()
        .into_iter()
        .filter(|s| s.state == SegmentState::Active)
        .map(|s| s.id)
        .collect();
    journal.trim_through(head).unwrap();
    let after = journal.segment_infos().unwrap();
    for id in actives {
        assert!(after.iter().any(|s| s.id == id && s.state == SegmentState::Active));
    }
    set_test_partition_count(None);
    set_test_segment_max_bytes(None);
}

#[test]
fn orphan_never_eligible_or_deleted() {
    set_test_segment_max_bytes(Some(900));
    let parts = 3;
    set_test_partition_count(Some(parts));
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, _) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, parts);
    append_interleaved(&mut journal, &mut tree, parts, 6);
    let journal_dir = dir.path().join("journal");
    fs::write(
        segment_path_for_partition(&journal_dir, PartitionId(2), 999, parts),
        b"orphan junk",
    )
    .unwrap();
    let trim = journal.last_sequence();
    assert!(
        !journal
            .eligible_segments(trim)
            .unwrap()
            .iter()
            .any(|c| c.segment_id == 999)
    );
    journal.trim_through(trim).unwrap();
    assert!(
        find_segment_path(&journal_dir, 999)
            .unwrap()
            .is_file()
    );
    set_test_partition_count(None);
    set_test_segment_max_bytes(None);
}

#[test]
fn oldest_available_is_global_min_across_partitions() {
    set_test_segment_max_bytes(Some(900));
    let parts = 3;
    set_test_partition_count(Some(parts));
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, _) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, parts);
    append_interleaved(&mut journal, &mut tree, parts, 18);
    let min_start = journal
        .segment_infos()
        .unwrap()
        .iter()
        .map(|s| s.start_sequence)
        .min()
        .unwrap();
    assert_eq!(journal.oldest_available_sequence().unwrap(), min_start);
    set_test_partition_count(None);
    set_test_segment_max_bytes(None);
}

#[test]
fn head_is_global_max_across_partitions() {
    set_test_segment_max_bytes(Some(900));
    let parts = 3;
    set_test_partition_count(Some(parts));
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, _) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, parts);
    append_interleaved(&mut journal, &mut tree, parts, 12);
    let max_end = journal
        .segment_infos()
        .unwrap()
        .iter()
        .map(|s| s.end_sequence)
        .max()
        .unwrap();
    assert_eq!(max_end, journal.last_sequence());
    set_test_partition_count(None);
    set_test_segment_max_bytes(None);
}

#[test]
fn gc_restart_survives_reopen() {
    set_test_segment_max_bytes(Some(900));
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, path) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, 1);
    for _ in 0..20 {
        let (d, dek) = draft(&mut tree, &path, b"x");
        journal.append(d, &dek).unwrap();
    }
    journal.sync().unwrap();
    let sealed = journal
        .segment_infos()
        .unwrap()
        .into_iter()
        .find(|s| s.state == SegmentState::Sealed)
        .unwrap();
    journal.trim_through(sealed.end_sequence).unwrap();
    drop(journal);
    let journal2 = open_journal(dir.path(), &master, &salt, 1);
    assert!(journal2.oldest_available_sequence().unwrap() > sealed.start_sequence);
    set_test_segment_max_bytes(None);
}

#[test]
fn snapshot_pin_blocks_gc_multi_partition() {
    set_test_segment_max_bytes(Some(900));
    let parts = 3;
    set_test_partition_count(Some(parts));
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, _) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, parts);
    append_interleaved(&mut journal, &mut tree, parts, 20);
    let snap = 15u64;
    let wm = calculate_watermark([&SequencePin(snap) as &dyn JournalPin]);
    let safe = wm.trim_through.unwrap();
    let eligible = journal.eligible_segments(safe).unwrap();
    assert!(eligible.iter().all(|c| c.end_sequence <= safe));
    set_test_partition_count(None);
    set_test_segment_max_bytes(None);
}

#[test]
fn boundary_end_sequence_equal_to_trim_is_eligible() {
    set_test_segment_max_bytes(Some(900));
    let parts = 2;
    set_test_partition_count(Some(parts));
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, _) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, parts);
    append_interleaved(&mut journal, &mut tree, parts, 14);
    let sealed = journal
        .segment_infos()
        .unwrap()
        .into_iter()
        .find(|s| s.state == SegmentState::Sealed)
        .unwrap();
    let eligible = journal.eligible_segments(sealed.end_sequence).unwrap();
    assert!(eligible.iter().any(|c| c.segment_id == sealed.id));
    set_test_partition_count(None);
    set_test_segment_max_bytes(None);
}

#[test]
fn segment_above_trim_retained() {
    set_test_segment_max_bytes(Some(900));
    let parts = 3;
    set_test_partition_count(Some(parts));
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, _) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, parts);
    append_interleaved(&mut journal, &mut tree, parts, 20);
    let sealed_end = journal
        .segment_infos()
        .unwrap()
        .into_iter()
        .filter(|s| s.state == SegmentState::Sealed)
        .map(|s| s.end_sequence)
        .min()
        .unwrap();
    let trim = sealed_end.saturating_sub(1);
    let keep: Vec<_> = journal
        .segment_infos()
        .unwrap()
        .into_iter()
        .filter(|s| s.end_sequence > trim || s.state == SegmentState::Active)
        .map(|s| s.id)
        .collect();
    journal.trim_through(trim).unwrap();
    let after: std::collections::HashSet<_> =
        journal.segment_infos().unwrap().into_iter().map(|s| s.id).collect();
    for id in keep {
        assert!(after.contains(&id));
    }
    set_test_partition_count(None);
    set_test_segment_max_bytes(None);
}

#[test]
fn gc_uses_manifest_not_orphan_on_disk() {
    set_test_segment_max_bytes(Some(900));
    let parts = 2;
    set_test_partition_count(Some(parts));
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, _) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, parts);
    append_interleaved(&mut journal, &mut tree, parts, 10);
    bootstrap(&journal);
    let auth_count = journal.segment_infos().unwrap().len();
    let on_disk = list_segment_ids(&dir.path().join("journal")).unwrap().len();
    fs::write(
        segment_path_for_partition(&dir.path().join("journal"), PartitionId(1), 888, parts),
        b"orphan",
    )
    .unwrap();
    assert!(on_disk + 1 >= auth_count);
    let trim = journal
        .segment_infos()
        .unwrap()
        .into_iter()
        .filter(|s| s.state == SegmentState::Sealed)
        .map(|s| s.end_sequence)
        .min()
        .unwrap();
    let eligible = journal.eligible_segments(trim).unwrap();
    assert!(!eligible.iter().any(|c| c.segment_id == 888));
    set_test_partition_count(None);
    set_test_segment_max_bytes(None);
}

#[test]
fn partitioned_layout_dirs_exist_after_append() {
    set_test_segment_max_bytes(Some(900));
    let parts = 3;
    set_test_partition_count(Some(parts));
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt, _) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, parts);
    append_interleaved(&mut journal, &mut tree, parts, 9);
    let journal_dir = dir.path().join("journal");
    assert!(is_partitioned_layout(parts));
    assert!(journal_dir.join("p-000").is_dir());
    assert!(journal_dir.join("p-001").is_dir());
    set_test_partition_count(None);
    set_test_segment_max_bytes(None);
}
