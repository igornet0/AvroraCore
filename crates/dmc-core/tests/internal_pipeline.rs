use dmc_core::channel::ChannelSpec;
use dmc_core::event::EventKind;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::trigger::{TriggerAction, TriggerDef};
use dmc_core::{StreamId, TriggerId};
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};

#[tokio::test]
async fn inbound_overlay_trigger_outbound_and_audit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let rt = Runtime::at_path(&path);
    let (master, _db_id) = rt.create_dev(false).await.unwrap();
    assert!(!master.is_empty());

    let bus = rt
        .configure_channel(ChannelSpec::internal("bus"))
        .await
        .unwrap();

    let inbound = rt
        .create_stream(StreamSpec {
            id: StreamId::from("in-finance"),
            direction: StreamDirection::Inbound,
            channel_id: bus.clone(),
            path_scope: KeyPath::parse("company/finance").unwrap(),
            required_perms: PermissionSet::empty().with(Permission::Write),
        })
        .await
        .unwrap();
    let outbound = rt
        .create_stream(StreamSpec {
            id: StreamId::from("out-finance"),
            direction: StreamDirection::Outbound,
            channel_id: bus,
            path_scope: KeyPath::parse("company/finance").unwrap(),
            required_perms: PermissionSet::empty().with(Permission::Write),
        })
        .await
        .unwrap();

    let session = rt.admin_session().await.unwrap();
    // Static base reference stays sealed; processing writes overlays only.
    rt.seal_base(&session, "company/finance/invoices/1", b"BASE")
        .await
        .unwrap();

    rt.register_trigger(TriggerDef {
        id: TriggerId::from("fwd-invoices"),
        on: EventKind::OverlayApply,
        path_prefix: "company/finance".into(),
        action: TriggerAction::forward(outbound.clone()),
    })
    .await
    .unwrap();

    let mut rx = rt.subscribe_stream(&outbound).await.unwrap();
    rt.ingest(
        session.clone(),
        inbound,
        "company/finance/invoices/1",
        b"secret-invoice",
    )
    .await
    .unwrap();

    let msg = rx.recv().await.expect("outbound message");
    assert_eq!(msg.path, "company/finance/invoices/1");
    assert_eq!(msg.payload, b"secret-invoice");

    let got = rt
        .get_data(&session, "company/finance/invoices/1")
        .await
        .unwrap();
    assert_eq!(got, b"secret-invoice");

    let view = rt
        .resolve(&session, "company/finance/invoices/1")
        .await
        .unwrap();
    assert!(view.base_present);
    assert!(view.overlay_present);
    assert_eq!(view.payload.as_deref(), Some(b"secret-invoice".as_slice()));

    let audit = rt.audit_log().await;
    assert!(audit.iter().any(|r| r.op == "OVERLAY" && r.outcome == "ok"));

    let hr = rt.open_session("root").await.unwrap();
    let err = rt
        .ingest(hr, StreamId::from("in-finance"), "company/hr/x", b"nope")
        .await
        .unwrap_err();
    assert!(matches!(err, dmc_core::Error::OutsideScope(_)));
}
