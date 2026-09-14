//! Phase 6.12 — MVCC row versions and visibility.

use dmc_model::{RowId, SnapshotSequence, TableId};
use dmc_storage::{ensure_table_store, StoredValue};
use tempfile::tempdir;

fn users_store(dir: &tempfile::TempDir) -> dmc_storage::TableStore {
    let table_id = TableId::new(1);
    let cols = vec![(dmc_model::ColumnId::new(1), dmc_model::SqlDataType::Text, true)];
    ensure_table_store(dir.path(), table_id, &cols).unwrap()
}

fn name_value(name: &str) -> Vec<StoredValue> {
    vec![StoredValue::String(name.into())]
}

#[test]
fn visibility_alice_insert_update_delete() {
    let dir = tempdir().unwrap();
    let mut store = users_store(&dir);
    store
        .insert_with_sequence(RowId::new(1), &name_value("Alice"), 100)
        .unwrap();
    store
        .update_with_sequence(RowId::new(1), &name_value("Alice2"), 120)
        .unwrap();
    store.delete_with_sequence(RowId::new(1), 150).unwrap();

    let s110 = SnapshotSequence::at(110);
    let s130 = SnapshotSequence::at(130);
    let s160 = SnapshotSequence::at(160);

    assert_eq!(
        store
            .get_at_snapshot(RowId::new(1), s110)
            .unwrap()
            .unwrap()[0],
        StoredValue::String("Alice".into())
    );
    assert_eq!(
        store
            .get_at_snapshot(RowId::new(1), s130)
            .unwrap()
            .unwrap()[0],
        StoredValue::String("Alice2".into())
    );
    assert!(store
        .get_at_snapshot(RowId::new(1), s160)
        .unwrap()
        .is_none());
}

#[test]
fn delete_at_sequence_zero_invisible_at_latest() {
    let dir = tempdir().unwrap();
    let mut store = users_store(&dir);
    store
        .insert_with_sequence(RowId::new(1), &name_value("x"), 0)
        .unwrap();
    store.delete_with_sequence(RowId::new(1), 0).unwrap();
    assert!(store
        .get_at_snapshot(RowId::new(1), SnapshotSequence::latest())
        .unwrap()
        .is_none());
    assert!(store.visible_row_ids_at(SnapshotSequence::latest()).is_empty());
}

#[test]
fn row_changed_since_detects_head_move() {
    let dir = tempdir().unwrap();
    let mut store = users_store(&dir);
    store
        .insert_with_sequence(RowId::new(1), &name_value("a"), 10)
        .unwrap();
    let snapshot = SnapshotSequence::at(10);
    assert!(!store.row_changed_since(RowId::new(1), snapshot));
    store
        .update_with_sequence(RowId::new(1), &name_value("b"), 20)
        .unwrap();
    assert!(store.row_changed_since(RowId::new(1), snapshot));
}

#[test]
fn visible_row_ids_respects_end_sequence() {
    let dir = tempdir().unwrap();
    let mut store = users_store(&dir);
    store
        .insert_with_sequence(RowId::new(1), &name_value("a"), 5)
        .unwrap();
    store
        .insert_with_sequence(RowId::new(2), &name_value("b"), 6)
        .unwrap();
    store.delete_with_sequence(RowId::new(1), 7).unwrap();

    assert_eq!(
        store.visible_row_ids_at(SnapshotSequence::at(6)),
        vec![RowId::new(1), RowId::new(2)]
    );
    assert_eq!(
        store.visible_row_ids_at(SnapshotSequence::at(7)),
        vec![RowId::new(2)]
    );
}

#[test]
fn batch_apply_shares_commit_sequence() {
    let dir = tempdir().unwrap();
    let mut store = users_store(&dir);
    let events = vec![
        dmc_model::DataEvent::InsertRow {
            table_id: TableId::new(1),
            row_id: RowId::new(1),
            values: vec![dmc_model::RowValue::String("a".into())],
        },
        dmc_model::DataEvent::InsertRow {
            table_id: TableId::new(1),
            row_id: RowId::new(2),
            values: vec![dmc_model::RowValue::String("b".into())],
        },
    ];
    dmc_storage::apply_data_event_batch(&mut store, &events, 42, false).unwrap();
    assert_eq!(store.row_count_at(SnapshotSequence::at(41)), 0);
    assert_eq!(store.row_count_at(SnapshotSequence::at(42)), 2);
}

#[test]
fn legacy_zero_sequence_still_readable_at_latest() {
    let dir = tempdir().unwrap();
    let mut store = users_store(&dir);
    store.insert_with_id(RowId::new(1), &name_value("legacy")).unwrap();
    assert_eq!(store.row_count_at(SnapshotSequence::latest()), 1);
}

#[test]
fn update_closes_prior_version_at_sequence() {
    let dir = tempdir().unwrap();
    let mut store = users_store(&dir);
    store
        .insert_with_sequence(RowId::new(1), &name_value("v1"), 1)
        .unwrap();
    store
        .update_with_sequence(RowId::new(1), &name_value("v2"), 2)
        .unwrap();
    assert!(store
        .get_at_snapshot(RowId::new(1), SnapshotSequence::at(1))
        .unwrap()
        .is_some());
    assert_eq!(
        store
            .get_at_snapshot(RowId::new(1), SnapshotSequence::at(2))
            .unwrap()
            .unwrap()[0],
        StoredValue::String("v2".into())
    );
}

#[test]
fn row_changed_since_false_for_unrelated_row() {
    let dir = tempdir().unwrap();
    let mut store = users_store(&dir);
    store
        .insert_with_sequence(RowId::new(1), &name_value("a"), 1)
        .unwrap();
    store
        .insert_with_sequence(RowId::new(2), &name_value("b"), 2)
        .unwrap();
    assert!(!store.row_changed_since(RowId::new(1), SnapshotSequence::at(1)));
}
