//! Phase 5.3 segment GC unit tests.

use dmc_journal::segment::SegmentState;
use dmc_journal::{Journal, JournalConfig, JournalEntryDraft, JournalEventKind, Operation};
use dmc_vault::access::Capability;
use dmc_vault::crypto::derive_journal_kek;
use dmc_vault::key::{KeyPath, KeyTree};

fn setup(dir: &std::path::Path, segment_max_bytes: u64) -> (Journal, KeyTree) {
    let (mut tree, master) = KeyTree::create_new().unwrap();
    let path = KeyPath::parse("company/finance/x").unwrap();
    tree.ensure_node(&path).unwrap();
    let kek = derive_journal_kek(&master, tree.salt());
    let jdir = dir.join("journal");
    let journal = Journal::open(
        JournalConfig::new(&jdir).with_segment_max_bytes(segment_max_bytes),
        &kek,
    )
    .unwrap();
    let _ = Capability::root_admin();
    (journal, tree)
}

fn draft(tree: &mut KeyTree, n: u64) -> (JournalEntryDraft, dmc_vault::KeyMaterial) {
    let path = KeyPath::parse("company/finance/x").unwrap();
    let dek = tree.dek(&path).unwrap().clone();
    let key_version = tree.meta(&path).unwrap().generation;
    let bundle = tree
        .list_nodes()
        .into_iter()
        .filter(|node| {
            let p = node.key_path().unwrap();
            p.is_prefix_of(&path) || path.is_prefix_of(&p) || p.is_root()
        })
        .collect();
    (
        JournalEntryDraft {
            path,
            event_kind: JournalEventKind::OverlayApply,
            operation: Operation::OverlayPut,
            key_version,
            actor_session: [1u8; 16],
            actor_role: "root".into(),
            node_bundle: bundle,
            payload: format!("payload-{n}").into_bytes(),
            partition_key: None,
        },
        dek,
    )
}

fn append_n(journal: &mut Journal, tree: &mut KeyTree, n: u64) -> u64 {
    let mut last = 0;
    for i in 1..=n {
        let (d, dek) = draft(tree, i);
        last = journal.append(d, &dek).unwrap().sequence;
        journal.sync().unwrap();
    }
    last
}

#[test]
fn eligible_segments_only_sealed_whose_end_is_at_or_below_trim() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree) = setup(dir.path(), 900);
    append_n(&mut journal, &mut tree, 12);
    let infos = journal.segment_infos().unwrap();
    assert!(infos.len() >= 3);
    let sealed: Vec<_> = infos
        .iter()
        .filter(|s| s.state == SegmentState::Sealed)
        .collect();
    assert!(!sealed.is_empty());
    let trim = sealed[0].end_sequence;
    let eligible = journal.eligible_segments(trim).unwrap();
    assert!(eligible.iter().all(|s| s.disposition == dmc_journal::SegmentDisposition::Authoritative));
    assert!(eligible.iter().all(|s| s.end_sequence <= trim));
    assert_eq!(eligible[0].segment_id, sealed[0].id);
}

#[test]
fn basic_trim_deletes_whole_sealed_segments() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree) = setup(dir.path(), 900);
    append_n(&mut journal, &mut tree, 12);
    let infos = journal.segment_infos().unwrap();
    let sealed: Vec<_> = infos
        .iter()
        .filter(|s| s.state == SegmentState::Sealed)
        .collect();
    let trim = sealed[0].end_sequence;
    let result = journal.trim_through(trim).unwrap();
    assert!(!result.deleted_segments.is_empty());
    let after = journal.segment_infos().unwrap();
    for id in result.deleted_segments {
        assert!(!after.iter().any(|s| s.id == id));
    }
    assert!(after.iter().any(|s| s.state == SegmentState::Active));
}

#[test]
fn active_segment_never_deleted_even_when_end_below_trim() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree) = setup(dir.path(), 900);
    let head = append_n(&mut journal, &mut tree, 5);
    let active_id = journal
        .segment_infos()
        .unwrap()
        .into_iter()
        .find(|s| s.state == SegmentState::Active)
        .unwrap()
        .id;
    journal.trim_through(head).unwrap();
    let after = journal.segment_infos().unwrap();
    assert!(after.iter().any(|s| s.id == active_id && s.state == SegmentState::Active));
}

#[test]
fn partial_segment_retained_when_end_above_trim() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree) = setup(dir.path(), 900);
    append_n(&mut journal, &mut tree, 12);
    let infos = journal.segment_infos().unwrap();
    let last_sealed = infos
        .iter()
        .filter(|s| s.state == SegmentState::Sealed)
        .max_by_key(|s| s.end_sequence)
        .unwrap();
    let trim = last_sealed.end_sequence.saturating_sub(1);
    let eligible = journal.eligible_segments(trim).unwrap();
    assert!(!eligible.iter().any(|s| s.segment_id == last_sealed.id));
}

#[test]
fn exact_boundary_deletes_segment() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree) = setup(dir.path(), 900);
    append_n(&mut journal, &mut tree, 12);
    let sealed = journal
        .segment_infos()
        .unwrap()
        .into_iter()
        .find(|s| s.state == SegmentState::Sealed)
        .unwrap();
    let result = journal.trim_through(sealed.end_sequence).unwrap();
    assert!(result.deleted_segments.contains(&sealed.id));
}

#[test]
fn trim_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree) = setup(dir.path(), 900);
    append_n(&mut journal, &mut tree, 10);
    let sealed = journal
        .segment_infos()
        .unwrap()
        .into_iter()
        .find(|s| s.state == SegmentState::Sealed)
        .unwrap();
    let trim = sealed.end_sequence;
    journal.trim_through(trim).unwrap();
    let second = journal.trim_through(trim).unwrap();
    assert!(second.deleted_segments.is_empty());
    journal.trim_through(trim).unwrap();
}

#[test]
fn oldest_available_moves_forward_after_trim() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree) = setup(dir.path(), 900);
    append_n(&mut journal, &mut tree, 12);
    let before = journal.oldest_available_sequence().unwrap();
    let sealed = journal
        .segment_infos()
        .unwrap()
        .into_iter()
        .find(|s| s.state == SegmentState::Sealed)
        .unwrap();
    journal.trim_through(sealed.end_sequence).unwrap();
    let after = journal.oldest_available_sequence().unwrap();
    assert!(after > before);
    assert_eq!(after, sealed.end_sequence.saturating_add(1));
}

#[test]
fn thread_local_segment_max_enables_gc() {
    use dmc_journal::set_test_segment_max_bytes;

    set_test_segment_max_bytes(Some(900));
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mut tree) = setup(dir.path(), 900);
    append_n(&mut journal, &mut tree, 12);
    let sealed = journal
        .segment_infos()
        .unwrap()
        .into_iter()
        .filter(|s| matches!(s.state, SegmentState::Sealed))
        .count();
    assert!(sealed >= 1, "expected sealed segments with thread-local max");
    set_test_segment_max_bytes(None);
}

#[test]
fn trim_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let jdir = dir.path().join("journal");
    let (mut tree, master) = KeyTree::create_new().unwrap();
    let path = KeyPath::parse("company/finance/x").unwrap();
    tree.ensure_node(&path).unwrap();
    let kek = derive_journal_kek(&master, tree.salt());
    {
        let mut journal = Journal::open(JournalConfig::new(&jdir).with_segment_max_bytes(900), &kek).unwrap();
        append_n(&mut journal, &mut tree, 10);
        let sealed = journal
            .segment_infos()
            .unwrap()
            .into_iter()
            .find(|s| s.state == SegmentState::Sealed)
            .unwrap();
        journal.trim_through(sealed.end_sequence).unwrap();
    }
    let mut journal = Journal::open(JournalConfig::new(&jdir).with_segment_max_bytes(900), &kek).unwrap();
    let ids: Vec<_> = journal.segment_infos().unwrap().into_iter().map(|s| s.id).collect();
    assert!(!ids.is_empty());
    journal.trim_through(1).unwrap();
}
