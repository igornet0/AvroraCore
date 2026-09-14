//! Phase 5.7.3 — partition-aware storage DoD.

use std::collections::{HashMap, HashSet};

use dmc_vault::crypto::derive_journal_kek;
use dmc_vault::key::{KeyPath, KeyTree};

use dmc_journal::layout::{is_partitioned_layout, list_segment_ids, segment_path_for_partition};
use dmc_journal::partition::{resolve_partition, PartitionKey};
use dmc_journal::{
    Journal, JournalConfig, JournalEntryDraft, JournalEventKind, Operation,
};

fn setup_tree() -> (KeyTree, dmc_vault::KeyMaterial, Vec<u8>) {
    let (mut tree, master) = KeyTree::create_new().unwrap();
    let path = KeyPath::parse("company/finance/invoices/1").unwrap();
    tree.ensure_node(&path).unwrap();
    let salt = tree.salt().to_vec();
    (tree, master, salt)
}

fn draft_with_key(
    tree: &mut KeyTree,
    path: &KeyPath,
    partition_key: Option<PartitionKey>,
    payload: &[u8],
) -> (JournalEntryDraft, dmc_vault::KeyMaterial) {
    let dek = tree.dek(path).unwrap().clone();
    let key_version = tree.meta(path).unwrap().generation;
    let bundle = tree
        .list_nodes()
        .into_iter()
        .filter(|n| {
            let p = n.key_path().unwrap();
            p.is_prefix_of(path) || path.is_prefix_of(&p) || p.is_root()
        })
        .collect();
    (
        JournalEntryDraft {
            path: path.clone(),
            event_kind: JournalEventKind::OverlayApply,
            operation: Operation::OverlayPut,
            key_version,
            actor_session: [1u8; 16],
            actor_role: "root".into(),
            node_bundle: bundle,
            payload: payload.to_vec(),
            partition_key,
        },
        dek,
    )
}

fn open_journal(
    dir: &std::path::Path,
    master: &dmc_vault::KeyMaterial,
    salt: &[u8],
    partitions: u32,
) -> Journal {
    let kek = derive_journal_kek(master, salt);
    let config = JournalConfig::new(dir.join("journal")).with_partition_count(partitions);
    Journal::open(config, &kek).unwrap()
}

#[test]
fn global_sequence_interleaved_across_partitions() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt) = setup_tree();
    let path = KeyPath::parse("company/finance/invoices/1").unwrap();
    let mut journal = open_journal(dir.path(), &master, &salt, 4);

    let keys: Vec<_> = (0..5)
        .map(|i| PartitionKey::new(format!("routing-key-{i}")))
        .collect();
    let mut sequences = Vec::new();
    let mut partition_by_seq = Vec::new();

    for (i, key) in keys.iter().enumerate() {
        let (d, dek) = draft_with_key(
            &mut tree,
            &path,
            Some(key.clone()),
            format!("evt-{i}").as_bytes(),
        );
        let partition = resolve_partition(&path, Some(key), 4).unwrap();
        let r = journal.append(d, &dek).unwrap();
        journal.sync().unwrap();
        sequences.push(r.sequence);
        partition_by_seq.push((r.sequence, partition));
    }

    assert_eq!(sequences, vec![1, 2, 3, 4, 5]);
    for w in sequences.windows(2) {
        assert!(w[1] > w[0], "global sequence must be strictly monotonic");
    }
    let distinct_partitions: HashSet<_> = partition_by_seq.iter().map(|(_, p)| p.0).collect();
    assert!(
        distinct_partitions.len() > 1,
        "events should spread across partitions"
    );
}

#[test]
fn same_path_and_key_routes_to_same_partition() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt) = setup_tree();
    let path = KeyPath::parse("company/finance/invoices/1").unwrap();
    let key = PartitionKey::new(b"stable-customer");
    let partition = resolve_partition(&path, Some(&key), 4).unwrap();
    let mut journal = open_journal(dir.path(), &master, &salt, 4);

    for i in 0..3 {
        let (d, dek) = draft_with_key(
            &mut tree,
            &path,
            Some(key.clone()),
            format!("evt-{i}").as_bytes(),
        );
        journal.append(d, &dek).unwrap();
        journal.sync().unwrap();
    }

    let journal_dir = dir.path().join("journal");
    let seg_ids = list_segment_ids(&journal_dir).unwrap();
    let mut hits = 0;
    for id in seg_ids {
        let p = segment_path_for_partition(&journal_dir, partition, id, 4);
        if p.is_file() {
            hits += 1;
        }
    }
    assert!(
        hits >= 1,
        "all appends for same key should land in one partition dir"
    );
}

#[test]
fn partition_count_one_matches_legacy_replay() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt) = setup_tree();
    let path = KeyPath::parse("company/finance/invoices/1").unwrap();

    let mut journal = open_journal(dir.path(), &master, &salt, 1);
    for i in 0..5 {
        let (d, dek) = draft_with_key(&mut tree, &path, None, format!("legacy-{i}").as_bytes());
        journal.append(d, &dek).unwrap();
        journal.sync().unwrap();
    }
    let before = journal.replay(0, &mut tree).unwrap();

    drop(journal);
    let journal2 = open_journal(dir.path(), &master, &salt, 1);
    let after = journal2.replay(0, &mut tree).unwrap();

    assert_eq!(before.len(), after.len());
    for (a, b) in before.iter().zip(after.iter()) {
        assert_eq!(a.sequence, b.sequence);
        assert_eq!(a.event_id, b.event_id);
        assert_eq!(a.payload, b.payload);
    }
    assert!(!is_partitioned_layout(1));
    assert!(dir.path().join("journal/seg-000000000001.jnl").is_file());
    assert!(!dir.path().join("journal/p-000").exists());
}

#[test]
fn restart_does_not_reuse_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt) = setup_tree();
    let path = KeyPath::parse("company/finance/invoices/1").unwrap();
    let mut journal = open_journal(dir.path(), &master, &salt, 4);

    let mut max_seq = 0;
    for i in 0..8 {
        let key = PartitionKey::new(format!("k-{i}"));
        let (d, dek) = draft_with_key(&mut tree, &path, Some(key), b"x");
        let r = journal.append(d, &dek).unwrap();
        journal.sync().unwrap();
        max_seq = max_seq.max(r.sequence);
    }

    drop(journal);
    let mut journal2 = open_journal(dir.path(), &master, &salt, 4);
    let (d, dek) = draft_with_key(
        &mut tree,
        &path,
        Some(PartitionKey::new("after-restart")),
        b"y",
    );
    let r = journal2.append(d, &dek).unwrap();
    journal2.sync().unwrap();
    assert!(r.sequence > max_seq);
}

#[test]
fn encryption_aad_excludes_partition_id() {
    use dmc_journal::types::{journal_aad, JournalEventKind};

    let path = "company/finance/invoices/1";
    let kind = JournalEventKind::OverlayApply.as_u16();
    let aad = journal_aad(path, 42, 1, kind);
    assert_eq!(aad, journal_aad(path, 42, 1, kind));
    assert!(aad.starts_with(b"avrora/journal/v1"));
    // partition routing material must not appear in AAD
    assert!(!aad.windows(3).any(|w| w == b"p-0"));
}

#[test]
fn different_keys_distribute_across_partitions() {
    let path = KeyPath::parse("company/finance/x").unwrap();
    let mut counts: HashMap<u32, u32> = HashMap::new();
    for i in 0..64 {
        let key = PartitionKey::new(format!("distinct-{i}"));
        let p = resolve_partition(&path, Some(&key), 8).unwrap();
        *counts.entry(p.0).or_default() += 1;
    }
    assert!(counts.len() >= 3, "expected distribution across partitions");
}
