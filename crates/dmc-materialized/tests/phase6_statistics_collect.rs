//! Phase 6.15.2 — materializer statistics collect + persistence hook.

use dmc_materialized::{StateMaterializer, StatisticsCatalog};
use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, ColumnDef, DataEvent, RowValue, SqlDataType, TableId,
    TransactionEvent, TransactionId,
};
use tempfile::tempdir;

fn open_with_users(
    dir: &tempfile::TempDir,
) -> (
    Catalog,
    StateMaterializer<dmc_materialized::FileStateEventLog>,
    dmc_model::TableId,
) {
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
                    nullable: true,
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
    let rows = dir.path().join("rows");
    let snapshot = dir.path().join("snapshot.json");
    let log = dir.path().join("events.json");
    let mut mat = StateMaterializer::open(rows, snapshot, log).unwrap();
    for event in events {
        mat.mutate_catalog(event).unwrap();
    }
    (catalog, mat, table_id)
}

#[test]
fn create_table_materialization_collects_empty_statistics() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut mat, _) = open_with_users(&dir);
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let create = catalog
        .create_table_event(
            schema,
            "empty_stats",
            vec![ColumnDef {
                name: "id".into(),
                data_type: SqlDataType::BigInt,
                nullable: false,
                default: None,
            }],
            None,
        )
        .unwrap();
    let table_id = match &create {
        dmc_model::CatalogEvent::CreateTable { id, .. } => *id,
        _ => panic!(),
    };
    mat.mutate_catalog(create).unwrap();
    let stats = mat.statistics().get(table_id).unwrap();
    assert_eq!(stats.row_count, 0);
}

#[test]
fn insert_updates_statistics() {
    let dir = tempdir().unwrap();
    let (_catalog, mut mat, table_id) = open_with_users(&dir);
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: dmc_model::RowId::new(1),
        values: vec![RowValue::Int64(1), RowValue::String("a@x.com".into())],
    })
    .unwrap();
    let stats = mat.statistics().get(table_id).unwrap();
    assert_eq!(stats.row_count, 1);
}

#[test]
fn update_changes_statistics() {
    let dir = tempdir().unwrap();
    let (_catalog, mut mat, table_id) = open_with_users(&dir);
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: dmc_model::RowId::new(1),
        values: vec![RowValue::Int64(1), RowValue::String("old@x.com".into())],
    })
    .unwrap();
    mat.mutate_data(DataEvent::UpdateRow {
        table_id,
        row_id: dmc_model::RowId::new(1),
        values: vec![RowValue::Int64(1), RowValue::Null],
    })
    .unwrap();
    let email_col = mat
        .catalog()
        .table(table_id)
        .unwrap()
        .columns
        .iter()
        .find(|c| c.name == "email")
        .unwrap()
        .id;
    let col_stats = mat.statistics().get(table_id).unwrap().columns.get(&email_col).unwrap();
    assert!((col_stats.null_fraction - 1.0).abs() < f64::EPSILON);
}

#[test]
fn delete_changes_statistics() {
    let dir = tempdir().unwrap();
    let (_catalog, mut mat, table_id) = open_with_users(&dir);
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: dmc_model::RowId::new(1),
        values: vec![RowValue::Int64(1), RowValue::String("a@x.com".into())],
    })
    .unwrap();
    mat.mutate_data(DataEvent::DeleteRow {
        table_id,
        row_id: dmc_model::RowId::new(1),
    })
    .unwrap();
    assert_eq!(mat.statistics().get(table_id).unwrap().row_count, 0);
}

#[test]
fn failed_transaction_batch_leaves_statistics_unchanged() {
    let dir = tempdir().unwrap();
    let (_catalog, mut mat, table_id) = open_with_users(&dir);
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: dmc_model::RowId::new(1),
        values: vec![RowValue::Int64(1), RowValue::String("a@x.com".into())],
    })
    .unwrap();
    let before = mat.statistics().get(table_id).unwrap().row_count;

    let err = mat.mutate_transaction_commit(
        TransactionId::new(99),
        vec![TransactionEvent::Data(DataEvent::InsertRow {
            table_id: TableId::new(999_999),
            row_id: dmc_model::RowId::new(1),
            values: vec![RowValue::Int64(1)],
        })],
    );
    assert!(err.is_err());
    assert_eq!(
        mat.statistics().get(table_id).unwrap().row_count,
        before
    );
    assert!(mat.statistics().get(TableId::new(999_999)).is_none());
}

#[test]
fn restart_restores_statistics_from_disk() {
    let dir = tempdir().unwrap();
    let (_catalog, mut mat, table_id) = open_with_users(&dir);
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: dmc_model::RowId::new(1),
        values: vec![RowValue::Int64(1), RowValue::String("a@x.com".into())],
    })
    .unwrap();

    let rows = dir.path().join("rows");
    let snapshot = dir.path().join("snapshot.json");
    let log = dir.path().join("events.json");
    let reopened = StateMaterializer::open(rows, snapshot, log).unwrap();
    let stats = reopened.statistics().get(table_id).unwrap();
    assert_eq!(stats.row_count, 1);
}

#[test]
fn replay_rebuilds_statistics() {
    let dir = tempdir().unwrap();
    let (_catalog, mut mat, table_id) = open_with_users(&dir);
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: dmc_model::RowId::new(1),
        values: vec![RowValue::Int64(1), RowValue::String("a@x.com".into())],
    })
    .unwrap();

    let rows = dir.path().join("rows");
    let snapshot = dir.path().join("snapshot.json");
    let log = dir.path().join("events.json");
    let mut replay = StateMaterializer::open(rows, snapshot, log).unwrap();
    replay.replay_from_log().unwrap();
    assert_eq!(replay.statistics().get(table_id).unwrap().row_count, 1);
}

#[test]
fn drop_table_removes_statistics() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut mat, table_id) = open_with_users(&dir);
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: dmc_model::RowId::new(1),
        values: vec![RowValue::Int64(1), RowValue::String("a@x.com".into())],
    })
    .unwrap();
    assert!(mat.statistics().contains(table_id));
    let drop = catalog.drop_table_event(table_id).unwrap();
    mat.mutate_catalog(drop).unwrap();
    assert!(!mat.statistics().contains(table_id));
}

#[test]
fn create_index_does_not_change_statistics() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut mat, table_id) = open_with_users(&dir);
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: dmc_model::RowId::new(1),
        values: vec![RowValue::Int64(1), RowValue::String("a@x.com".into())],
    })
    .unwrap();
    let before = mat.statistics().get(table_id).unwrap().clone();
    let email_col = mat
        .catalog()
        .table(table_id)
        .unwrap()
        .columns
        .iter()
        .find(|c| c.name == "email")
        .unwrap()
        .id;
    let idx = catalog
        .create_index_event(table_id, "users_email_idx", vec![email_col], false)
        .unwrap();
    mat.mutate_catalog(idx).unwrap();
    assert_eq!(mat.statistics().get(table_id).unwrap(), &before);
}

#[test]
fn failed_statistics_persistence_does_not_break_materialization() {
    let dir = tempdir().unwrap();
    let (_catalog, mut mat, table_id) = open_with_users(&dir);
    let stats_path = StatisticsCatalog::statistics_path(mat.storage_root());
    std::fs::remove_file(stats_path).ok();
    std::fs::create_dir(&mat.storage_root().join("statistics.json")).unwrap();

    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: dmc_model::RowId::new(1),
        values: vec![RowValue::Int64(1), RowValue::String("a@x.com".into())],
    })
    .unwrap();

    assert_eq!(
        mat.shared_table_store(table_id)
            .unwrap()
            .lock()
            .unwrap()
            .row_count(),
        1
    );
    assert_eq!(mat.statistics().get(table_id).unwrap().row_count, 1);
}

#[test]
fn missing_statistics_on_disk_sql_state_still_valid() {
    let dir = tempdir().unwrap();
    let (_catalog, mut mat, table_id) = open_with_users(&dir);
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: dmc_model::RowId::new(1),
        values: vec![RowValue::Int64(1), RowValue::String("a@x.com".into())],
    })
    .unwrap();
    let stats_path = StatisticsCatalog::statistics_path(mat.storage_root());
    std::fs::remove_file(&stats_path).unwrap();

    let empty_stats = StatisticsCatalog::open(mat.storage_root()).unwrap();
    assert!(empty_stats.get(table_id).is_none());
    assert_eq!(
        mat.shared_table_store(table_id)
            .unwrap()
            .lock()
            .unwrap()
            .row_count(),
        1
    );
}
