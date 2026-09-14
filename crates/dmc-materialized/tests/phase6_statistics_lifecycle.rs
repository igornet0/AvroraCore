//! Phase 6.15.3 — statistics lifecycle (refresh / remove / recovery / rollback invariants).

use dmc_materialized::{StateMaterializer, StatisticsCatalog};
use dmc_model::{
    statistics_snapshot_to_bytes, ApplyMode, Catalog, CatalogApplier, ColumnDef, DataEvent,
    RowValue, SqlDataType, StatValue, TableId, TransactionEvent, TransactionId,
};
use tempfile::tempdir;

fn open_bootstrap(
    dir: &tempfile::TempDir,
) -> (
    Catalog,
    StateMaterializer<dmc_materialized::FileStateEventLog>,
    dmc_model::SchemaId,
) {
    let mut catalog = Catalog::new();
    let events = catalog.bootstrap_default().unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let rows = dir.path().join("rows");
    let snapshot = dir.path().join("snapshot.json");
    let log = dir.path().join("events.json");
    let mut mat = StateMaterializer::open(rows, snapshot, log).unwrap();
    for event in events {
        mat.mutate_catalog(event).unwrap();
    }
    (catalog, mat, schema)
}

fn create_table(
    catalog: &mut Catalog,
    mat: &mut StateMaterializer<dmc_materialized::FileStateEventLog>,
    schema: dmc_model::SchemaId,
    name: &str,
    columns: Vec<ColumnDef>,
) -> dmc_model::TableId {
    let create = catalog
        .create_table_event(schema, name, columns, None)
        .unwrap();
    catalog.apply(&create, ApplyMode::Live).unwrap();
    let table_id = match &create {
        dmc_model::CatalogEvent::CreateTable { id, .. } => *id,
        _ => panic!("create table"),
    };
    mat.mutate_catalog(create).unwrap();
    table_id
}

fn stats_bytes(catalog: &StatisticsCatalog) -> Vec<u8> {
    statistics_snapshot_to_bytes(&catalog.snapshot().unwrap()).unwrap()
}

fn value_col(table: &dmc_model::Table) -> dmc_model::ColumnId {
    table.columns[0].id
}

#[test]
fn multi_event_transaction_refreshes_each_table_once() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut mat, schema) = open_bootstrap(&dir);
    let t = create_table(
        &mut catalog,
        &mut mat,
        schema,
        "t",
        vec![ColumnDef {
            name: "v".into(),
            data_type: SqlDataType::BigInt,
            nullable: false,
            default: None,
        }],
    );
    for id in 1..=3 {
        mat.mutate_data(DataEvent::InsertRow {
            table_id: t,
            row_id: dmc_model::RowId::new(id),
            values: vec![RowValue::Int64(id as i64)],
        })
        .unwrap();
    }

    mat.mutate_transaction_commit(
        TransactionId::new(1),
        vec![
            TransactionEvent::Data(DataEvent::InsertRow {
                table_id: t,
                row_id: dmc_model::RowId::new(4),
                values: vec![RowValue::Int64(4)],
            }),
            TransactionEvent::Data(DataEvent::UpdateRow {
                table_id: t,
                row_id: dmc_model::RowId::new(1),
                values: vec![RowValue::Int64(10)],
            }),
            TransactionEvent::Data(DataEvent::DeleteRow {
                table_id: t,
                row_id: dmc_model::RowId::new(2),
            }),
        ],
    )
    .unwrap();

    let table = mat.catalog().table(t).unwrap();
    let col = value_col(table);
    let stats = mat.statistics().get(t).unwrap();
    assert_eq!(stats.row_count, 3);
    let c = stats.columns.get(&col).unwrap();
    assert_eq!(c.ndv, 3);
    assert_eq!(c.min, Some(StatValue::Int64(3)));
    assert_eq!(c.max, Some(StatValue::Int64(10)));
}

#[test]
fn multi_table_transaction_refreshes_both() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut mat, schema) = open_bootstrap(&dir);
    let t1 = create_table(
        &mut catalog,
        &mut mat,
        schema,
        "t1",
        vec![ColumnDef {
            name: "v".into(),
            data_type: SqlDataType::BigInt,
            nullable: false,
            default: None,
        }],
    );
    let t2 = create_table(
        &mut catalog,
        &mut mat,
        schema,
        "t2",
        vec![ColumnDef {
            name: "v".into(),
            data_type: SqlDataType::BigInt,
            nullable: false,
            default: None,
        }],
    );

    mat.mutate_transaction_commit(
        TransactionId::new(2),
        vec![
            TransactionEvent::Data(DataEvent::InsertRow {
                table_id: t1,
                row_id: dmc_model::RowId::new(1),
                values: vec![RowValue::Int64(1)],
            }),
            TransactionEvent::Data(DataEvent::InsertRow {
                table_id: t2,
                row_id: dmc_model::RowId::new(1),
                values: vec![RowValue::Int64(2)],
            }),
        ],
    )
    .unwrap();

    assert_eq!(mat.statistics().get(t1).unwrap().row_count, 1);
    assert_eq!(mat.statistics().get(t2).unwrap().row_count, 1);
}

#[test]
fn drop_then_create_table_gets_fresh_empty_statistics() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut mat, schema) = open_bootstrap(&dir);
    let t = create_table(
        &mut catalog,
        &mut mat,
        schema,
        "t",
        vec![ColumnDef {
            name: "v".into(),
            data_type: SqlDataType::BigInt,
            nullable: false,
            default: None,
        }],
    );
    mat.mutate_data(DataEvent::InsertRow {
        table_id: t,
        row_id: dmc_model::RowId::new(1),
        values: vec![RowValue::Int64(99)],
    })
    .unwrap();
    assert_eq!(mat.statistics().get(t).unwrap().row_count, 1);

    let drop = catalog.drop_table_event(t).unwrap();
    catalog.apply(&drop, ApplyMode::Live).unwrap();
    mat.mutate_catalog(drop).unwrap();
    assert!(!mat.statistics().contains(t));

    let create = catalog
        .create_table_event(
            schema,
            "t",
            vec![ColumnDef {
                name: "v".into(),
                data_type: SqlDataType::BigInt,
                nullable: false,
                default: None,
            }],
            None,
        )
        .unwrap();
    let new_id = match &create {
        dmc_model::CatalogEvent::CreateTable { id, .. } => *id,
        _ => panic!(),
    };
    catalog.apply(&create, ApplyMode::Live).unwrap();
    mat.mutate_catalog(create).unwrap();

    assert!(mat.statistics().contains(new_id));
    assert_eq!(mat.statistics().get(new_id).unwrap().row_count, 0);
    assert!(!mat.statistics().contains(t));
}

#[test]
fn drop_index_does_not_change_statistics() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut mat, schema) = open_bootstrap(&dir);
    let t = create_table(
        &mut catalog,
        &mut mat,
        schema,
        "t",
        vec![
            ColumnDef {
                name: "id".into(),
                data_type: SqlDataType::BigInt,
                nullable: false,
                default: None,
            },
            ColumnDef {
                name: "v".into(),
                data_type: SqlDataType::Text,
                nullable: false,
                default: None,
            },
        ],
    );
    mat.mutate_data(DataEvent::InsertRow {
        table_id: t,
        row_id: dmc_model::RowId::new(1),
        values: vec![RowValue::Int64(1), RowValue::String("x".into())],
    })
    .unwrap();
    let v_col = mat
        .catalog()
        .table(t)
        .unwrap()
        .columns
        .iter()
        .find(|c| c.name == "v")
        .unwrap()
        .id;
    let idx = catalog
        .create_index_event(t, "t_v_idx", vec![v_col], false)
        .unwrap();
    catalog.apply(&idx, ApplyMode::Live).unwrap();
    mat.mutate_catalog(idx).unwrap();
    let before = stats_bytes(mat.statistics());

    let index_id = mat
        .catalog()
        .table(t)
        .unwrap()
        .indexes
        .iter()
        .find(|i| i.name == "t_v_idx")
        .unwrap()
        .id;
    let drop_idx = mat.catalog().drop_index_event(index_id).unwrap();
    mat.mutate_catalog(drop_idx).unwrap();
    assert_eq!(stats_bytes(mat.statistics()), before);
}

#[test]
fn recovery_rebuild_matches_incremental_statistics() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut mat, schema) = open_bootstrap(&dir);
    let t = create_table(
        &mut catalog,
        &mut mat,
        schema,
        "t",
        vec![ColumnDef {
            name: "v".into(),
            data_type: SqlDataType::BigInt,
            nullable: false,
            default: None,
        }],
    );
    for id in 1..=3 {
        mat.mutate_data(DataEvent::InsertRow {
            table_id: t,
            row_id: dmc_model::RowId::new(id),
            values: vec![RowValue::Int64(id as i64)],
        })
        .unwrap();
    }
    mat.mutate_transaction_commit(
        TransactionId::new(3),
        vec![
            TransactionEvent::Data(DataEvent::InsertRow {
                table_id: t,
                row_id: dmc_model::RowId::new(4),
                values: vec![RowValue::Int64(4)],
            }),
            TransactionEvent::Data(DataEvent::UpdateRow {
                table_id: t,
                row_id: dmc_model::RowId::new(1),
                values: vec![RowValue::Int64(10)],
            }),
            TransactionEvent::Data(DataEvent::DeleteRow {
                table_id: t,
                row_id: dmc_model::RowId::new(2),
            }),
        ],
    )
    .unwrap();

    let incremental = stats_bytes(mat.statistics());

    let rows = dir.path().join("rows");
    let snapshot = dir.path().join("snapshot.json");
    let log = dir.path().join("events.json");
    let mut replay = StateMaterializer::open(rows.clone(), snapshot.clone(), log.clone()).unwrap();
    replay.replay_from_log().unwrap();
    assert_eq!(stats_bytes(replay.statistics()), incremental);

    let mut rebuilt = StateMaterializer::open(rows, snapshot, log).unwrap();
    rebuilt.replay_from_log().unwrap();
    rebuilt.rebuild_all_statistics().unwrap();
    assert_eq!(stats_bytes(rebuilt.statistics()), incremental);
}

#[test]
fn restart_preserves_lifecycle_statistics() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut mat, schema) = open_bootstrap(&dir);
    let t = create_table(
        &mut catalog,
        &mut mat,
        schema,
        "t",
        vec![ColumnDef {
            name: "v".into(),
            data_type: SqlDataType::BigInt,
            nullable: false,
            default: None,
        }],
    );
    for id in 1..=3 {
        mat.mutate_data(DataEvent::InsertRow {
            table_id: t,
            row_id: dmc_model::RowId::new(id),
            values: vec![RowValue::Int64(id as i64)],
        })
        .unwrap();
    }
    let before = mat.statistics().get(t).unwrap().clone();

    let rows = dir.path().join("rows");
    let snapshot = dir.path().join("snapshot.json");
    let log = dir.path().join("events.json");
    let reopened = StateMaterializer::open(rows, snapshot, log).unwrap();
    assert_eq!(reopened.statistics().get(t).unwrap(), &before);
}

#[test]
fn acceptance_commit_batch_updates_statistics_deterministically() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut mat, schema) = open_bootstrap(&dir);
    let t = create_table(
        &mut catalog,
        &mut mat,
        schema,
        "t",
        vec![ColumnDef {
            name: "v".into(),
            data_type: SqlDataType::BigInt,
            nullable: false,
            default: None,
        }],
    );
    for id in 1..=3 {
        mat.mutate_data(DataEvent::InsertRow {
            table_id: t,
            row_id: dmc_model::RowId::new(id),
            values: vec![RowValue::Int64(id as i64)],
        })
        .unwrap();
    }
    let col = value_col(mat.catalog().table(t).unwrap());
    let initial = mat.statistics().get(t).unwrap();
    assert_eq!(initial.row_count, 3);
    assert_eq!(initial.columns.get(&col).unwrap().ndv, 3);
    assert_eq!(
        initial.columns.get(&col).unwrap().min,
        Some(StatValue::Int64(1))
    );
    assert_eq!(
        initial.columns.get(&col).unwrap().max,
        Some(StatValue::Int64(3))
    );

    mat.mutate_transaction_commit(
        TransactionId::new(5),
        vec![
            TransactionEvent::Data(DataEvent::InsertRow {
                table_id: t,
                row_id: dmc_model::RowId::new(4),
                values: vec![RowValue::Int64(4)],
            }),
            TransactionEvent::Data(DataEvent::UpdateRow {
                table_id: t,
                row_id: dmc_model::RowId::new(1),
                values: vec![RowValue::Int64(10)],
            }),
            TransactionEvent::Data(DataEvent::DeleteRow {
                table_id: t,
                row_id: dmc_model::RowId::new(2),
            }),
        ],
    )
    .unwrap();

    let after = mat.statistics().get(t).unwrap();
    assert_eq!(after.row_count, 3);
    assert_eq!(after.columns.get(&col).unwrap().ndv, 3);
    assert_eq!(after.columns.get(&col).unwrap().min, Some(StatValue::Int64(3)));
    assert_eq!(after.columns.get(&col).unwrap().max, Some(StatValue::Int64(10)));

    let rows = dir.path().join("rows");
    let snapshot = dir.path().join("snapshot.json");
    let log = dir.path().join("events.json");
    let reopened = StateMaterializer::open(rows.clone(), snapshot.clone(), log.clone()).unwrap();
    assert_eq!(reopened.statistics().get(t).unwrap(), after);

    let mut replay = StateMaterializer::open(rows, snapshot, log).unwrap();
    replay.replay_from_log().unwrap();
    assert_eq!(replay.statistics().get(t).unwrap(), after);
}

#[test]
fn failed_transaction_leaves_statistics_byte_identical() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut mat, schema) = open_bootstrap(&dir);
    let t = create_table(
        &mut catalog,
        &mut mat,
        schema,
        "t",
        vec![ColumnDef {
            name: "v".into(),
            data_type: SqlDataType::BigInt,
            nullable: false,
            default: None,
        }],
    );
    mat.mutate_data(DataEvent::InsertRow {
        table_id: t,
        row_id: dmc_model::RowId::new(1),
        values: vec![RowValue::Int64(1)],
    })
    .unwrap();
    let before = stats_bytes(mat.statistics());

    let err = mat.mutate_transaction_commit(
        TransactionId::new(9),
        vec![TransactionEvent::Data(DataEvent::InsertRow {
            table_id: TableId::new(999_999),
            row_id: dmc_model::RowId::new(1),
            values: vec![RowValue::Int64(1)],
        })],
    );
    assert!(err.is_err());
    assert_eq!(stats_bytes(mat.statistics()), before);
}

#[test]
fn missing_statistics_file_sql_materialized_state_unaffected() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut mat, schema) = open_bootstrap(&dir);
    let t = create_table(
        &mut catalog,
        &mut mat,
        schema,
        "t",
        vec![ColumnDef {
            name: "v".into(),
            data_type: SqlDataType::BigInt,
            nullable: false,
            default: None,
        }],
    );
    mat.mutate_data(DataEvent::InsertRow {
        table_id: t,
        row_id: dmc_model::RowId::new(1),
        values: vec![RowValue::Int64(1)],
    })
    .unwrap();
    std::fs::remove_file(StatisticsCatalog::statistics_path(mat.storage_root())).unwrap();
    let empty = StatisticsCatalog::open(mat.storage_root()).unwrap();
    assert!(empty.get(t).is_none());
    assert_eq!(
        mat.shared_table_store(t)
            .unwrap()
            .lock()
            .unwrap()
            .row_count(),
        1
    );
}
