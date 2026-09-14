//! Phase 6.14 — atomic transaction batch apply + recovery.

use dmc_materialized::StateMaterializer;
use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, ColumnDef, DataEvent, RowValue, SqlDataType,
    TransactionEvent, TransactionId,
};
use tempfile::tempdir;

fn open_with_users(dir: &tempfile::TempDir) -> (Catalog, StateMaterializer<dmc_materialized::FileStateEventLog>, dmc_model::TableId) {
    let mut catalog = Catalog::new();
    let mut events = catalog.bootstrap_default().unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let create = catalog
        .create_table_event(
            schema,
            "users",
            vec![
                ColumnDef {
                    name: "id".into(),
                    data_type: SqlDataType::BigInt,
                    nullable: false,
                    default: None,
                },
                ColumnDef {
                    name: "email".into(),
                    data_type: SqlDataType::Text,
                    nullable: false,
                    default: None,
                },
            ],
            Some(vec!["id".into()]),
        )
        .unwrap();
    catalog.apply(&create, ApplyMode::Live).unwrap();
    events.push(create.clone());
    let table_id = match &create {
        dmc_model::CatalogEvent::CreateTable { id, .. } => *id,
        _ => panic!("create table"),
    };
    let snapshot = dir.path().join("snapshot.json");
    let log = dir.path().join("events.json");
    let rows = dir.path().join("rows");
    let mut mat = StateMaterializer::open(rows, snapshot, log).unwrap();
    for event in events {
        mat.mutate_catalog(event).unwrap();
    }
    (catalog, mat, table_id)
}

#[test]
fn transaction_commit_batch_applies_catalog_then_data() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut mat, _users_id) = open_with_users(&dir);

    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let accounts = catalog
        .create_table_event(
            schema,
            "accounts",
            vec![ColumnDef {
                name: "id".into(),
                data_type: SqlDataType::BigInt,
                nullable: false,
                default: None,
            }],
            Some(vec!["id".into()]),
        )
        .unwrap();
    let accounts_id = match &accounts {
        dmc_model::CatalogEvent::CreateTable { id, .. } => *id,
        _ => panic!(),
    };

    mat.mutate_transaction_commit(
        TransactionId::new(1),
        vec![
            TransactionEvent::Catalog(accounts),
            TransactionEvent::Data(DataEvent::InsertRow {
                table_id: accounts_id,
                row_id: dmc_model::RowId::new(1),
                values: vec![RowValue::Int64(42)],
            }),
        ],
    )
    .unwrap();

    assert!(mat.catalog().table_by_name(schema, "accounts").is_some());
    assert_eq!(
        mat.shared_table_store(accounts_id)
            .unwrap()
            .lock()
            .unwrap()
            .row_count(),
        1
    );
}

#[test]
fn replay_transaction_commit_three_times_is_idempotent() {
    let dir = tempdir().unwrap();
    let (_catalog, mut mat, table_id) = open_with_users(&dir);
    let rows = dir.path().join("rows");
    let snapshot = dir.path().join("snapshot.json");
    let log = dir.path().join("events.json");
    mat.mutate_transaction_commit(
        TransactionId::new(1),
        vec![TransactionEvent::Data(DataEvent::InsertRow {
            table_id,
            row_id: dmc_model::RowId::new(1),
            values: vec![RowValue::Int64(1), RowValue::String("a@x.com".into())],
        })],
    )
    .unwrap();

    for _ in 0..3 {
        let mut replay = StateMaterializer::open(rows.clone(), snapshot.clone(), log.clone()).unwrap();
        replay.replay_from_log().unwrap();
        assert_eq!(
            replay
                .shared_table_store(table_id)
                .unwrap()
                .lock()
                .unwrap()
                .row_count(),
            1
        );
    }
}

#[test]
fn recover_from_watermark_replays_transaction_commit() {
    let dir = tempdir().unwrap();
    let (_catalog, mut mat, table_id) = open_with_users(&dir);
    mat.mutate_transaction_commit(
        TransactionId::new(7),
        vec![TransactionEvent::Data(DataEvent::InsertRow {
            table_id,
            row_id: dmc_model::RowId::new(9),
            values: vec![RowValue::Int64(9), RowValue::String("wm@x.com".into())],
        })],
    )
    .unwrap();
    let wm = mat.watermark();
    mat.override_watermark(dmc_model::MaterializedWatermark::at(wm.sequence.saturating_sub(1)));
    mat.recover_from_watermark().unwrap();
    assert_eq!(mat.watermark(), wm);
    assert_eq!(
        mat.shared_table_store(table_id)
            .unwrap()
            .lock()
            .unwrap()
            .row_count(),
        1
    );
}
