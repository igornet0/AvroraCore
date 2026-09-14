//! Phase 6.13 — index materialization via catalog + journal.

use dmc_materialized::StateMaterializer;
use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, ColumnDef, ColumnId, DataEvent, IndexId, RowId, RowValue,
    SqlDataType, TableId, TransactionEvent,
};
use dmc_storage::{IndexKey, IndexKeyComponent, MANIFEST_TMP};
use tempfile::tempdir;

fn users_columns() -> Vec<ColumnDef> {
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
    ]
}

fn bootstrap_mat(dir: &tempfile::TempDir) -> (Catalog, StateMaterializer<dmc_materialized::FileStateEventLog>, TableId) {
    let mut catalog = Catalog::new();
    let mut events = catalog.bootstrap_default().unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let create = catalog
        .create_table_event(schema, "users", users_columns(), Some(vec!["id".into()]))
        .unwrap();
    catalog.apply(&create, ApplyMode::Live).unwrap();
    events.push(create);
    let table_id = match events.last().unwrap() {
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

fn email_column_id(catalog: &Catalog, table_id: TableId) -> ColumnId {
    catalog
        .table(table_id)
        .unwrap()
        .columns
        .iter()
        .find(|c| c.name == "email")
        .unwrap()
        .id
}

#[test]
fn create_index_builds_from_existing_rows() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut mat, table_id) = bootstrap_mat(&dir);
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: RowId::new(1),
        values: vec![RowValue::Int64(1), RowValue::String("a@x.com".into())],
    })
    .unwrap();

    let email_col = email_column_id(&catalog, table_id);
    let create_idx = catalog
        .create_index_event(table_id, "idx_email", vec![email_col], false)
        .unwrap();
    catalog.apply(&create_idx, ApplyMode::Live).unwrap();
    let index_id = match &create_idx {
        dmc_model::CatalogEvent::CreateIndex { id, .. } => *id,
        _ => panic!("create index"),
    };
    mat.mutate_catalog(create_idx).unwrap();

    let index = mat.shared_index_store(index_id).unwrap();
    let table = mat.shared_table_store(table_id).unwrap();
    let key = IndexKey::new(vec![IndexKeyComponent::String("a@x.com".into())]);
    assert_eq!(
        index.lock().unwrap().lookup(&key),
        vec![RowId::new(1)]
    );
    assert!(index.lock().unwrap().validate(&table.lock().unwrap()).unwrap());
}

#[test]
fn dml_maintains_index_on_commit_batch() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut mat, table_id) = bootstrap_mat(&dir);
    let email_col = email_column_id(&catalog, table_id);
    let create_idx = catalog
        .create_index_event(table_id, "idx_email", vec![email_col], false)
        .unwrap();
    catalog.apply(&create_idx, ApplyMode::Live).unwrap();
    let index_id = match &create_idx {
        dmc_model::CatalogEvent::CreateIndex { id, .. } => *id,
        _ => panic!(),
    };
    mat.mutate_catalog(create_idx).unwrap();

    mat.mutate_transaction_commit(
        dmc_model::TransactionId::new(1),
        vec![TransactionEvent::Data(DataEvent::InsertRow {
            table_id,
            row_id: RowId::new(1),
            values: vec![RowValue::Int64(1), RowValue::String("t@x.com".into())],
        })],
    )
    .unwrap();

    let key = IndexKey::new(vec![IndexKeyComponent::String("t@x.com".into())]);
    let index = mat.shared_index_store(index_id).unwrap();
    assert_eq!(index.lock().unwrap().lookup(&key), vec![RowId::new(1)]);
}

#[test]
fn restart_reopens_index_store() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut mat, table_id) = bootstrap_mat(&dir);
    let email_col = email_column_id(&catalog, table_id);
    let create_idx = catalog
        .create_index_event(table_id, "idx_email", vec![email_col], false)
        .unwrap();
    catalog.apply(&create_idx, ApplyMode::Live).unwrap();
    let index_id = match &create_idx {
        dmc_model::CatalogEvent::CreateIndex { id, .. } => *id,
        _ => panic!(),
    };
    mat.mutate_catalog(create_idx).unwrap();
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: RowId::new(1),
        values: vec![RowValue::Int64(1), RowValue::String("r@x.com".into())],
    })
    .unwrap();
    drop(mat);

    let snapshot = dir.path().join("snapshot.json");
    let log = dir.path().join("events.json");
    let rows = dir.path().join("rows");
    let reopened = StateMaterializer::open(rows, snapshot, log).unwrap();
    let index = reopened.shared_index_store(index_id).unwrap();
    let key = IndexKey::new(vec![IndexKeyComponent::String("r@x.com".into())]);
    assert_eq!(index.lock().unwrap().lookup(&key), vec![RowId::new(1)]);
}

#[test]
fn drop_index_removes_store() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut mat, table_id) = bootstrap_mat(&dir);
    let create_idx = catalog
        .create_index_event(table_id, "idx_email", vec![email_column_id(&catalog, table_id)], false)
        .unwrap();
    catalog.apply(&create_idx, ApplyMode::Live).unwrap();
    let index_id = match &create_idx {
        dmc_model::CatalogEvent::CreateIndex { id, .. } => *id,
        _ => panic!(),
    };
    mat.mutate_catalog(create_idx).unwrap();
    let drop = catalog.drop_index_event(index_id).unwrap();
    catalog.apply(&drop, ApplyMode::Live).unwrap();
    mat.mutate_catalog(drop).unwrap();
    assert!(mat.shared_index_store(index_id).is_err());
    assert!(!dmc_storage::index_manifest_exists(
        &dir.path().join("rows"),
        index_id
    ));
}

#[test]
fn drop_table_removes_table_indexes() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut mat, table_id) = bootstrap_mat(&dir);
    let create_idx = catalog
        .create_index_event(table_id, "idx_email", vec![email_column_id(&catalog, table_id)], false)
        .unwrap();
    catalog.apply(&create_idx, ApplyMode::Live).unwrap();
    let index_id = match &create_idx {
        dmc_model::CatalogEvent::CreateIndex { id, .. } => *id,
        _ => panic!(),
    };
    mat.mutate_catalog(create_idx).unwrap();
    let drop_table = catalog.drop_table_event(table_id).unwrap();
    catalog.apply(&drop_table, ApplyMode::Live).unwrap();
    mat.mutate_catalog(drop_table).unwrap();
    assert!(mat.shared_index_store(index_id).is_err());
}

#[test]
fn rebuild_after_index_drift() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut mat, table_id) = bootstrap_mat(&dir);
    let create_idx = catalog
        .create_index_event(table_id, "idx_email", vec![email_column_id(&catalog, table_id)], false)
        .unwrap();
    catalog.apply(&create_idx, ApplyMode::Live).unwrap();
    let index_id = match &create_idx {
        dmc_model::CatalogEvent::CreateIndex { id, .. } => *id,
        _ => panic!(),
    };
    mat.mutate_catalog(create_idx).unwrap();
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: RowId::new(1),
        values: vec![RowValue::Int64(1), RowValue::String("a@x.com".into())],
    })
    .unwrap();

    let table = mat.shared_table_store(table_id).unwrap();
    let index = mat.shared_index_store(index_id).unwrap();
    {
        let mut idx = index.lock().unwrap();
        let ghost = IndexKey::new(vec![IndexKeyComponent::String("ghost".into())]);
        idx.insert_row(
            RowId::new(99),
            &[RowValue::Int64(99), RowValue::String("ghost".into())],
            table.lock().unwrap().schema(),
        )
        .unwrap();
    }
    assert!(!index.lock().unwrap().validate(&table.lock().unwrap()).unwrap());
    index.lock().unwrap().rebuild_from_table(&table.lock().unwrap()).unwrap();
    assert!(index.lock().unwrap().validate(&table.lock().unwrap()).unwrap());
}

#[test]
fn manifest_tmp_does_not_break_reopen() {
    let dir = tempdir().unwrap();
    let (mut catalog, mut mat, table_id) = bootstrap_mat(&dir);
    let create_idx = catalog
        .create_index_event(table_id, "idx_email", vec![email_column_id(&catalog, table_id)], false)
        .unwrap();
    catalog.apply(&create_idx, ApplyMode::Live).unwrap();
    let index_id = IndexId::new(match &create_idx {
        dmc_model::CatalogEvent::CreateIndex { id, .. } => id.raw(),
        _ => panic!(),
    });
    mat.mutate_catalog(create_idx).unwrap();
    let index_root = dmc_storage::index_dir(&dir.path().join("rows"), index_id);
    std::fs::write(index_root.join(MANIFEST_TMP), b"tmp").unwrap();
    drop(mat);

    let snapshot = dir.path().join("snapshot.json");
    let log = dir.path().join("events.json");
    let rows = dir.path().join("rows");
    let reopened = StateMaterializer::open(rows, snapshot, log).unwrap();
    assert!(reopened.shared_index_store(index_id).is_ok());
}
