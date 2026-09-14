//! Phase 5.7.4 — JournalManifestV2 + recovery DoD.

use std::fs;

use dmc_vault::crypto::derive_journal_kek;
use dmc_vault::key::{KeyPath, KeyTree};

use dmc_journal::journal_manifest::{read_manifest, MANIFEST_TMP};
use dmc_journal::layout::{list_segment_ids, segment_path_for_partition};
use dmc_journal::partition::{PartitionId, PartitionKey};
use dmc_journal::reconciliation::authoritative_journal_head;
use dmc_journal::segment::SegmentState;
use dmc_journal::{
    Error, Journal, JournalConfig, JournalEntryDraft, JournalEventKind, JournalManifestV2,
    Operation, PartitionManifest, SegmentManifestEntry,
    JOURNAL_MANIFEST_FORMAT_VERSION_V2,
};
use dmc_journal::{
    publish_manifest_v2, read_stored_manifest, validate_manifest_v2, validate_stored_manifest,
};

fn setup_tree() -> (KeyTree, dmc_vault::KeyMaterial, Vec<u8>) {
    let (mut tree, master) = KeyTree::create_new().unwrap();
    let path = KeyPath::parse("company/finance/invoices/1").unwrap();
    tree.ensure_node(&path).unwrap();
    let salt = tree.salt().to_vec();
    (tree, master, salt)
}

fn draft(
    tree: &mut KeyTree,
    key: Option<PartitionKey>,
    payload: &[u8],
) -> (JournalEntryDraft, dmc_vault::KeyMaterial) {
    let path = KeyPath::parse("company/finance/invoices/1").unwrap();
    let dek = tree.dek(&path).unwrap().clone();
    let key_version = tree.meta(&path).unwrap().generation;
    (
        JournalEntryDraft {
            path,
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

fn runtime_dir(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("runtime/journal")
}

fn manifest_path(dir: &std::path::Path) -> std::path::PathBuf {
    runtime_dir(dir).join("manifest.json")
}

fn append_events(journal: &mut Journal, tree: &mut KeyTree, parts: u32, n: u32) {
    for i in 0..n {
        let key = if parts > 1 {
            Some(PartitionKey::new(format!("k-{i}")))
        } else {
            None
        };
        let (d, dek) = draft(tree, key, format!("e-{i}").as_bytes());
        journal.append(d, &dek).unwrap();
        journal.sync().unwrap();
    }
}

#[test]
fn manifest_v2_roundtrip_and_auto_bootstrap() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, 1);
    append_events(&mut journal, &mut tree, 1, 3);
    drop(journal);

    let journal2 = open_journal(dir.path(), &master, &salt, 1);
    let stored = read_stored_manifest(&manifest_path(dir.path()))
        .unwrap()
        .unwrap();
    assert_eq!(stored.format_version(), JOURNAL_MANIFEST_FORMAT_VERSION_V2);
    assert_eq!(stored.partition_count(), 1);
    assert!(!stored.authoritative_segment_ids().is_empty());
    let replay = journal2.replay(0, &mut tree).unwrap();
    assert_eq!(replay.len(), 3);
}

#[test]
fn generation_bump_on_explicit_bootstrap() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, 4);
    append_events(&mut journal, &mut tree, 4, 6);
    let m1 = journal.bootstrap_journal_manifest(5).unwrap();
    assert_eq!(m1.generation, 5);
    let m2 = journal.bootstrap_journal_manifest(7).unwrap();
    assert_eq!(m2.generation, 7);
}

#[test]
fn partition_count_validation_rejects_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, 4);
    append_events(&mut journal, &mut tree, 4, 4);
    drop(journal);
    open_journal(dir.path(), &master, &salt, 4);
    let manifest = read_stored_manifest(&manifest_path(dir.path())).unwrap().unwrap();
    let err = validate_stored_manifest(&manifest, dir.path().join("journal").as_path(), 2).unwrap_err();
    assert!(matches!(err, Error::JournalManifestInconsistent(_)));
}

#[test]
fn duplicate_partition_and_segment_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let bad = JournalManifestV2 {
        format_version: JOURNAL_MANIFEST_FORMAT_VERSION_V2,
        generation: 1,
        partition_count: 2,
        partitions: vec![
            PartitionManifest {
                partition_id: 0,
                segments: vec![entry(1, 1, 1, SegmentState::Active)],
            },
            PartitionManifest {
                partition_id: 0,
                segments: vec![],
            },
        ],
        superseded_segment_ids: vec![],
    };
    assert!(validate_manifest_v2(&bad, dir.path(), 2).is_err());

    let bad2 = JournalManifestV2 {
        format_version: JOURNAL_MANIFEST_FORMAT_VERSION_V2,
        generation: 1,
        partition_count: 2,
        partitions: vec![
            PartitionManifest {
                partition_id: 0,
                segments: vec![entry(1, 1, 1, SegmentState::Active)],
            },
            PartitionManifest {
                partition_id: 1,
                segments: vec![entry(1, 2, 2, SegmentState::Sealed)],
            },
        ],
        superseded_segment_ids: vec![],
    };
    assert!(validate_manifest_v2(&bad2, dir.path(), 2).is_err());
}

#[test]
fn invalid_sequence_range_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let bad = JournalManifestV2 {
        format_version: JOURNAL_MANIFEST_FORMAT_VERSION_V2,
        generation: 1,
        partition_count: 1,
        partitions: vec![PartitionManifest {
            partition_id: 0,
            segments: vec![entry(1, 10, 5, SegmentState::Active)],
        }],
        superseded_segment_ids: vec![],
    };
    assert!(validate_manifest_v2(&bad, dir.path(), 1).is_err());
}

#[test]
fn recover_multi_partition_from_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, 4);
    append_events(&mut journal, &mut tree, 4, 8);
    drop(journal);
    let journal2 = open_journal(dir.path(), &master, &salt, 4);
    let stored = read_stored_manifest(&manifest_path(dir.path())).unwrap().unwrap();
    assert_eq!(stored.partition_count(), 4);
    let replay = journal2.replay(0, &mut tree).unwrap();
    assert_eq!(replay.len(), 8);
    assert_eq!(replay.last().unwrap().sequence, 8);
}

#[test]
fn head_uses_authoritative_only() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, 1);
    append_events(&mut journal, &mut tree, 1, 3);
    let journal_dir = dir.path().join("journal");
    fs::write(journal_dir.join("seg-000000000099.jnl"), b"orphan junk").unwrap();
    drop(journal);
    let journal2 = open_journal(dir.path(), &master, &salt, 1);
    assert_eq!(journal2.last_sequence(), 3);
    let head = authoritative_journal_head(&journal_dir, &manifest_path(dir.path()), &[], 1).unwrap();
    assert_eq!(head, 3);
}

#[test]
fn missing_authoritative_segment_is_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, 1);
    append_events(&mut journal, &mut tree, 1, 2);
    drop(journal);
    open_journal(dir.path(), &master, &salt, 1);
    let seg = dir.path().join("journal/seg-000000000001.jnl");
    fs::remove_file(&seg).unwrap();
    let kek = derive_journal_kek(&master, &salt);
    let err = Journal::open(
        JournalConfig::new(dir.path().join("journal")).with_partition_count(1),
        &kek,
    );
    assert!(err.is_err());
}

#[test]
fn orphan_does_not_affect_replay_or_head() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, 4);
    append_events(&mut journal, &mut tree, 4, 5);
    let before = journal.replay(0, &mut tree).unwrap();
    let auth_count = journal.inspect_reconciliation().unwrap().authoritative.len();
    let on_disk = list_segment_ids(&dir.path().join("journal")).unwrap().len();
    assert!(on_disk >= auth_count);
    let after = journal.replay(0, &mut tree).unwrap();
    assert_eq!(before.len(), after.len());
    assert_eq!(journal.last_sequence(), 5);
}

#[test]
fn manifest_tmp_ignored_and_rename_commits() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, 1);
    append_events(&mut journal, &mut tree, 1, 2);
    drop(journal);
    open_journal(dir.path(), &master, &salt, 1);
    let current = read_stored_manifest(&manifest_path(dir.path()))
        .unwrap()
        .unwrap();
    let mut pending = match current {
        dmc_journal::StoredJournalManifest::V2(m) => m,
        _ => panic!("expected v2"),
    };
    pending.generation = 99;
    fs::create_dir_all(runtime_dir(dir.path())).unwrap();
    fs::write(
        runtime_dir(dir.path()).join(MANIFEST_TMP),
        serde_json::to_string_pretty(&pending).unwrap(),
    )
    .unwrap();
    let loaded = read_manifest(&manifest_path(dir.path())).unwrap().unwrap();
    assert_ne!(loaded.generation, 99);

    publish_manifest_v2(&runtime_dir(dir.path()), &pending).unwrap();
    let loaded2 = read_stored_manifest(&manifest_path(dir.path())).unwrap().unwrap();
    assert_eq!(loaded2.generation(), 99);
}

#[test]
fn partition_count_one_legacy_flat_layout_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, master, salt) = setup_tree();
    let mut journal = open_journal(dir.path(), &master, &salt, 1);
    append_events(&mut journal, &mut tree, 1, 2);
    drop(journal);
    open_journal(dir.path(), &master, &salt, 1);
    assert!(dir.path().join("journal/seg-000000000001.jnl").is_file());
    assert!(!dir.path().join("journal/p-000").exists());
    let stored = read_stored_manifest(&manifest_path(dir.path())).unwrap().unwrap();
    assert_eq!(stored.partition_count(), 1);
}

fn entry(id: u64, start: u64, end: u64, state: SegmentState) -> SegmentManifestEntry {
    SegmentManifestEntry {
        segment_id: id,
        start_sequence: start,
        end_sequence: end,
        start_timestamp_unix_ms: 0,
        end_timestamp_unix_ms: 0,
        byte_size: 100,
        state,
    }
}
