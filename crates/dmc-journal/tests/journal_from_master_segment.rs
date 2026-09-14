#[test]
fn from_master_honors_thread_local_segment_max() {
    use dmc_journal::{set_test_segment_max_bytes, Journal, JournalConfig, StorageLayout};
    use dmc_vault::crypto::derive_journal_kek;
    use dmc_vault::key::{KeyPath, KeyTree};

    set_test_segment_max_bytes(Some(900));
    let dir = tempfile::tempdir().unwrap();
    let layout = StorageLayout::from_db_path(dir.path().join("store.dbs.json"));
    let (mut tree, master) = KeyTree::create_new().unwrap();
    let path = KeyPath::parse("company/finance/x").unwrap();
    tree.ensure_node(&path).unwrap();
    let kek = derive_journal_kek(&master, tree.salt());
    let mut journal = Journal::from_master(&layout, &master, tree.salt()).unwrap();
    for i in 1..=12u64 {
        let (d, dek) = {
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
                dmc_journal::JournalEntryDraft {
                    path,
                    event_kind: dmc_journal::JournalEventKind::OverlayApply,
                    operation: dmc_journal::Operation::OverlayPut,
                    key_version,
                    actor_session: [1u8; 16],
                    actor_role: "root".into(),
                    node_bundle: bundle,
                    payload: format!("payload-{i}").into_bytes(),
                    partition_key: None,
                },
                dek,
            )
        };
        journal.append(d, &dek).unwrap();
        journal.sync().unwrap();
    }
    let sealed = journal
        .segment_infos()
        .unwrap()
        .into_iter()
        .filter(|s| matches!(s.state, dmc_journal::SegmentState::Sealed))
        .count();
    assert!(sealed >= 1, "from_master should honor thread-local segment max");
    set_test_segment_max_bytes(None);
}
