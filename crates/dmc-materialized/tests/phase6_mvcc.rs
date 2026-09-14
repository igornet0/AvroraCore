//! Phase 6.12 — journal transaction batch + MVCC materialization.

use dmc_materialized::{StateEventLog, StateMaterializer};
use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, ColumnDef, DataEvent, RowId, RowValue, SnapshotSequence,
    SqlDataType, StateEvent, TableId, TransactionEvent, TransactionId,
};
use tempfile::tempdir;

fn bootstrap_users(catalog: &mut Catalog) -> (TableId, Vec<dmc_model::CatalogEvent>) {
    let mut events = catalog.bootstrap_default().unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let columns = vec![
        ColumnDef {
            name: "id".into(),
            data_type: SqlDataType::BigInt,
            nullable: false,
            default: None,
        },
        ColumnDef {
            name: "name".into(),
            data_type: SqlDataType::Text,
            nullable: true,
            default: None,
        },
    ];
    let create = catalog
        .create_table_event(schema, "users", columns, Some(vec!["id".into()]))
        .unwrap();
    catalog.apply(&create, ApplyMode::Live).unwrap();
    let table_id = match &create {
        dmc_model::CatalogEvent::CreateTable { id, .. } => *id,
        _ => panic!("create table"),
    };
    events.push(create);
    (table_id, events)
}

fn row(id: i64, name: &str) -> Vec<RowValue> {
    vec![RowValue::Int64(id), RowValue::String(name.into())]
}

fn in_memory_mat(
    dir: &tempfile::TempDir,
    catalog: &mut Catalog,
) -> (TableId, StateMaterializer<dmc_materialized::MemoryStateEventLog>) {
    let (table_id, events) = bootstrap_users(catalog);
    let mut mat = StateMaterializer::in_memory(dir.path().join("rows"));
    for event in &events {
        mat.mutate_catalog(event.clone()).unwrap();
    }
    (table_id, mat)
}

fn data_events(events: Vec<DataEvent>) -> Vec<TransactionEvent> {
    events.into_iter().map(TransactionEvent::Data).collect()
}

#[test]
fn transaction_commit_single_journal_sequence() {
    let dir = tempdir().unwrap();
    let mut catalog = Catalog::new();
    let (table_id, mut mat) = in_memory_mat(&dir, &mut catalog);
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: RowId::new(1),
        values: row(1, "base"),
    })
    .unwrap();
    let base_seq = mat.watermark().sequence;
    mat.mutate_transaction_commit(
        TransactionId::new(1),
        data_events(vec![
            DataEvent::InsertRow {
                table_id,
                row_id: RowId::new(2),
                values: row(2, "t2"),
            },
            DataEvent::InsertRow {
                table_id,
                row_id: RowId::new(3),
                values: row(3, "t3"),
            },
        ]),
    )
    .unwrap();
    assert_eq!(mat.watermark().sequence, base_seq + 1);
    let store = mat.shared_table_store(table_id).unwrap();
    assert_eq!(store.lock().unwrap().row_count_at(SnapshotSequence::latest()), 3);
}

#[test]
fn transaction_batch_replay_idempotent() {
    let dir = tempdir().unwrap();
    let mut catalog = Catalog::new();
    let (table_id, mut mat) = in_memory_mat(&dir, &mut catalog);
    let batch = vec![DataEvent::InsertRow {
        table_id,
        row_id: RowId::new(1),
        values: row(1, "x"),
    }];
    mat.mutate_transaction_commit(TransactionId::new(1), data_events(batch))
        .unwrap();
    let wm = mat.watermark();
    mat.replay_from_log().unwrap();
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

#[test]
fn snapshot_sequence_follows_watermark() {
    let dir = tempdir().unwrap();
    let mut catalog = Catalog::new();
    let (table_id, mut mat) = in_memory_mat(&dir, &mut catalog);
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: RowId::new(1),
        values: row(1, "a"),
    })
    .unwrap();
    assert_eq!(
        mat.snapshot_sequence(),
        SnapshotSequence::at(mat.watermark().sequence)
    );
}

#[test]
fn update_visibility_across_sequences() {
    let dir = tempdir().unwrap();
    let mut catalog = Catalog::new();
    let (table_id, mut mat) = in_memory_mat(&dir, &mut catalog);
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: RowId::new(1),
        values: row(1, "alice"),
    })
    .unwrap();
    let insert_seq = mat.watermark().sequence;
    mat.mutate_data(DataEvent::UpdateRow {
        table_id,
        row_id: RowId::new(1),
        values: row(1, "bob"),
    })
    .unwrap();
    let update_seq = mat.watermark().sequence;
    let store = mat.shared_table_store(table_id).unwrap();
    let guard = store.lock().unwrap();
    assert_eq!(
        guard
            .get_at_snapshot(RowId::new(1), SnapshotSequence::at(insert_seq))
            .unwrap()
            .unwrap()[1],
        dmc_storage::StoredValue::String("alice".into())
    );
    assert_eq!(
        guard
            .get_at_snapshot(RowId::new(1), SnapshotSequence::at(update_seq))
            .unwrap()
            .unwrap()[1],
        dmc_storage::StoredValue::String("bob".into())
    );
}

#[test]
fn delete_hides_row_after_sequence() {
    let dir = tempdir().unwrap();
    let mut catalog = Catalog::new();
    let (table_id, mut mat) = in_memory_mat(&dir, &mut catalog);
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: RowId::new(1),
        values: row(1, "gone"),
    })
    .unwrap();
    let before = mat.watermark().sequence;
    mat.mutate_data(DataEvent::DeleteRow {
        table_id,
        row_id: RowId::new(1),
    })
    .unwrap();
    let store = mat.shared_table_store(table_id).unwrap();
    let guard = store.lock().unwrap();
    assert_eq!(guard.row_count_at(SnapshotSequence::at(before)), 1);
    assert_eq!(guard.row_count_at(SnapshotSequence::latest()), 0);
}

#[test]
fn file_restart_preserves_mvcc_versions() {
    let dir = tempdir().unwrap();
    let mut catalog = Catalog::new();
    let (table_id, events) = bootstrap_users(&mut catalog);
    let rows = dir.path().join("rows");
    let snapshot = dir.path().join("snap.json");
    let log = dir.path().join("log.json");
    {
        let mut mat = StateMaterializer::open(rows.clone(), snapshot.clone(), log.clone()).unwrap();
        for event in &events {
            mat.mutate_catalog(event.clone()).unwrap();
        }
        mat.mutate_data(DataEvent::InsertRow {
            table_id,
            row_id: RowId::new(1),
            values: row(1, "persist"),
        })
        .unwrap();
    }
    let mat = StateMaterializer::open(rows, snapshot, log).unwrap();
    let store = mat.shared_table_store(table_id).unwrap();
    assert_eq!(store.lock().unwrap().row_count(), 1);
}

#[test]
fn transaction_commit_event_in_log() {
    let dir = tempdir().unwrap();
    let mut catalog = Catalog::new();
    let (table_id, mut mat) = in_memory_mat(&dir, &mut catalog);
    mat.mutate_transaction_commit(
        TransactionId::new(7),
        data_events(vec![DataEvent::InsertRow {
            table_id,
            row_id: RowId::new(1),
            values: row(1, "batch"),
        }]),
    )
    .unwrap();
    let last = mat.event_log().events().last().unwrap();
    assert!(matches!(
        last.event,
        StateEvent::TransactionCommit { .. }
    ));
}

#[test]
fn autocommit_and_batch_interleave_sequences() {
    let dir = tempdir().unwrap();
    let mut catalog = Catalog::new();
    let (table_id, mut mat) = in_memory_mat(&dir, &mut catalog);
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: RowId::new(1),
        values: row(1, "a"),
    })
    .unwrap();
    let after_autocommit = mat.watermark().sequence;
    mat.mutate_transaction_commit(
        TransactionId::new(1),
        data_events(vec![DataEvent::InsertRow {
            table_id,
            row_id: RowId::new(2),
            values: row(2, "b"),
        }]),
    )
    .unwrap();
    assert_eq!(mat.watermark().sequence, after_autocommit + 1);
    assert_eq!(
        mat.shared_table_store(table_id)
            .unwrap()
            .lock()
            .unwrap()
            .row_count(),
        2
    );
}
