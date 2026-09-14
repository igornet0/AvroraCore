use dmc_core::channel::ChannelSpec;
use dmc_core::event::EventKind;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::trigger::{TriggerAction, TriggerDef};
use dmc_core::{StreamId, TriggerId};
use dmc_journal::{Journal, JournalConfig, StorageLayout};
use dmc_vault::crypto::derive_journal_kek;
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};

#[tokio::test]
async fn scenario_a_drop_runtime_recovers_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let master = {
        let rt = Runtime::at_path(&path);
        let (master, _db_id) = rt.create_dev(false).await.unwrap();
        let admin = rt.admin_session().await.unwrap();
        rt.create_role(
            &admin,
            "finance".into(),
            "Finance".into(),
            KeyPath::parse("company/finance").unwrap(),
            PermissionSet::read_write(),
        )
        .await
        .unwrap();
        let session = rt.open_session("finance").await.unwrap();
        rt.put_data(&session, "company/finance/invoices/1", b"one")
            .await
            .unwrap();
        rt.put_data(&session, "company/finance/invoices/2", b"two")
            .await
            .unwrap();
        rt.configure_channel(ChannelSpec::internal("bus"))
            .await
            .unwrap();
        rt.create_stream(StreamSpec {
            id: StreamId::from("in-finance"),
            direction: StreamDirection::Inbound,
            channel_id: "bus".into(),
            path_scope: KeyPath::parse("company/finance").unwrap(),
            required_perms: PermissionSet::empty().with(Permission::Write),
        })
        .await
        .unwrap();
        let outbound = rt
            .create_stream(StreamSpec {
                id: StreamId::from("out-finance"),
                direction: StreamDirection::Outbound,
                channel_id: "bus".into(),
                path_scope: KeyPath::parse("company/finance").unwrap(),
                required_perms: PermissionSet::empty().with(Permission::Write),
            })
            .await
            .unwrap();
        rt.register_trigger(TriggerDef {
            id: TriggerId::from("fwd-invoices"),
            on: EventKind::OverlayApply,
            path_prefix: "company/finance".into(),
            action: TriggerAction::forward(outbound),
        })
        .await
        .unwrap();
        rt.commit_offset(&session, "orders-processor", "company/finance", 2)
            .await
            .unwrap();
        let seq = rt.force_snapshot().await.unwrap();
        assert!(seq >= 2);
        let _ = session;
        master
    };

    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let session = rt.open_session("finance").await.unwrap();
    let got1 = rt
        .get_data(&session, "company/finance/invoices/1")
        .await
        .unwrap();
    let got2 = rt
        .get_data(&session, "company/finance/invoices/2")
        .await
        .unwrap();
    assert_eq!(got1, b"one");
    assert_eq!(got2, b"two");

    let streams = rt.list_streams().await;
    assert!(streams.iter().any(|s| s.id.as_str() == "in-finance"));
    assert!(streams.iter().any(|s| s.id.as_str() == "out-finance"));
    let triggers = rt.list_triggers().await;
    assert!(triggers.iter().any(|t| t.id.as_str() == "fwd-invoices"));
    let offset = rt.get_offset("orders-processor").await.unwrap();
    assert_eq!(offset.sequence, 2);
    let audit = rt.audit_log().await;
    assert!(audit.iter().any(|r| !r.event_id.is_empty() && r.sequence > 0));
    let after = rt.last_sequence().await;
    assert!(after >= 2);
}

#[tokio::test]
async fn scenario_b_corrupt_tail_truncates_and_continues() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let rt = Runtime::at_path(&path);
    let (master, _db_id) = rt.create_dev(false).await.unwrap();
    let session = rt.admin_session().await.unwrap();
    rt.put_data(&session, "company/finance/invoices/1", b"one")
        .await
        .unwrap();
    rt.put_data(&session, "company/finance/invoices/2", b"two")
        .await
        .unwrap();
    let seq_before = rt.last_sequence().await;
    drop(rt);

    let layout = StorageLayout::from_db_path(&path);
    let seg = layout.segment_path(1);
    let mut bytes = std::fs::read(&seg).unwrap();
    let n = bytes.len();
    for b in bytes.iter_mut().skip(n.saturating_sub(64)) {
        *b ^= 0xff;
    }
    std::fs::write(&seg, &bytes).unwrap();

    let snap = dmc_vault::persist::DbSnapshot::load(&layout.base_snapshot()).unwrap();
    let salt = snap.salt().unwrap();
    let master_key = dmc_vault::KeyMaterial::from_hex(&master).unwrap();
    let kek = derive_journal_kek(&master_key, &salt);
    let mut journal = Journal::open(JournalConfig::new(layout.journal_dir()), &kek).unwrap();
    let report = journal.recover().unwrap();
    assert!(report.truncated_bytes > 0 || journal.last_sequence() < seq_before);
    let recovered_seq = journal.last_sequence();
    drop(journal);

    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let session = rt.admin_session().await.unwrap();
    let one = rt
        .get_data(&session, "company/finance/invoices/1")
        .await
        .unwrap();
    assert_eq!(one, b"one");
    rt.put_data(&session, "company/finance/invoices/3", b"three")
        .await
        .unwrap();
    let next = rt.last_sequence().await;
    assert!(next > recovered_seq);
}
