//! Phase 6.10 — materialized row store tests.

use dmc_model::{ColumnId, RowId, SqlDataType, TableId};
use dmc_storage::{
    ColumnSchema, StoredValue, TableSchema, TableStore, MANIFEST_TMP,
};
use tempfile::tempdir;

fn users_schema(table_id: TableId) -> TableSchema {
    TableSchema {
        table_id: table_id.raw(),
        columns: vec![
            ColumnSchema {
                column_id: 1,
                data_type: SqlDataType::BigInt,
                nullable: false,
            },
            ColumnSchema {
                column_id: 2,
                data_type: SqlDataType::Text,
                nullable: true,
            },
            ColumnSchema {
                column_id: 3,
                data_type: SqlDataType::Integer,
                nullable: true,
            },
        ],
    }
}

fn sample_row(id: i64, name: &str, age: i64) -> Vec<StoredValue> {
    vec![
        StoredValue::Int64(id),
        StoredValue::String(name.into()),
        StoredValue::Int64(age),
    ]
}

#[test]
fn create_table_store_empty() {
    let dir = tempdir().unwrap();
    let table_id = TableId::new(1);
    let store = TableStore::create(dir.path(), table_id, users_schema(table_id)).unwrap();
    assert_eq!(store.row_count(), 0);
    assert!(store.table_root().join("manifest.json").exists());
}

#[test]
fn reopen_empty_table() {
    let dir = tempdir().unwrap();
    let table_id = TableId::new(2);
    TableStore::create(dir.path(), table_id, users_schema(table_id)).unwrap();
    let reopened = TableStore::open(dir.path(), table_id).unwrap();
    assert_eq!(reopened.row_count(), 0);
}

#[test]
fn insert_one_row_and_reopen() {
    let dir = tempdir().unwrap();
    let table_id = TableId::new(3);
    let mut store = TableStore::create(dir.path(), table_id, users_schema(table_id)).unwrap();
    let row_id = store.insert(&sample_row(1, "alice", 30)).unwrap();
    assert_eq!(row_id, RowId::new(1));
    let reopened = TableStore::open(dir.path(), table_id).unwrap();
    assert_eq!(reopened.row_count(), 1);
    assert_eq!(reopened.get(row_id).unwrap().unwrap()[1], StoredValue::String("alice".into()));
}

#[test]
fn insert_many_rows_stable_row_ids() {
    let dir = tempdir().unwrap();
    let table_id = TableId::new(4);
    let mut store = TableStore::create(dir.path(), table_id, users_schema(table_id)).unwrap();
    let mut ids = Vec::new();
    for i in 0..1000 {
        ids.push(store.insert(&sample_row(i, "u", i)).unwrap());
    }
    assert_eq!(ids[0], RowId::new(1));
    assert_eq!(ids[999], RowId::new(1000));
    let reopened = TableStore::open(dir.path(), table_id).unwrap();
    assert_eq!(reopened.row_count(), 1000);
    assert_eq!(reopened.get(RowId::new(500)).unwrap().unwrap()[0], StoredValue::Int64(499));
}

#[test]
fn full_scan_returns_all_rows() {
    let dir = tempdir().unwrap();
    let table_id = TableId::new(5);
    let mut store = TableStore::create(dir.path(), table_id, users_schema(table_id)).unwrap();
    store.insert(&sample_row(1, "a", 1)).unwrap();
    store.insert(&sample_row(2, "b", 2)).unwrap();
    let rows: Vec<_> = store.scan().map(|r| r.unwrap()).collect();
    assert_eq!(rows.len(), 2);
}

#[test]
fn projection_reads_subset() {
    let dir = tempdir().unwrap();
    let table_id = TableId::new(6);
    let mut store = TableStore::create(dir.path(), table_id, users_schema(table_id)).unwrap();
    store.insert(&sample_row(1, "bob", 40)).unwrap();
    let scanner = store.scan_projection(&[ColumnId::new(2)]).unwrap();
    let (_, values) = scanner.map(|r| r.unwrap()).next().unwrap();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0], StoredValue::String("bob".into()));
}

#[test]
fn empty_scan() {
    let dir = tempdir().unwrap();
    let table_id = TableId::new(7);
    let store = TableStore::create(dir.path(), table_id, users_schema(table_id)).unwrap();
    assert_eq!(store.scan().count(), 0);
}

#[test]
fn update_row_keeps_row_id() {
    let dir = tempdir().unwrap();
    let table_id = TableId::new(8);
    let mut store = TableStore::create(dir.path(), table_id, users_schema(table_id)).unwrap();
    let row_id = store.insert(&sample_row(1, "old", 10)).unwrap();
    store.update(row_id, &sample_row(1, "new", 11)).unwrap();
    let values = store.get(row_id).unwrap().unwrap();
    assert_eq!(values[1], StoredValue::String("new".into()));
    let reopened = TableStore::open(dir.path(), table_id).unwrap();
    assert_eq!(reopened.get(row_id).unwrap().unwrap()[1], StoredValue::String("new".into()));
}

#[test]
fn delete_makes_row_invisible() {
    let dir = tempdir().unwrap();
    let table_id = TableId::new(9);
    let mut store = TableStore::create(dir.path(), table_id, users_schema(table_id)).unwrap();
    let row_id = store.insert(&sample_row(1, "gone", 1)).unwrap();
    store.delete(row_id).unwrap();
    assert!(store.get(row_id).unwrap().is_none());
    assert_eq!(store.scan().count(), 0);
    let reopened = TableStore::open(dir.path(), table_id).unwrap();
    assert_eq!(reopened.row_count(), 0);
}

#[test]
fn manifest_tmp_is_ignored_on_open() {
    let dir = tempdir().unwrap();
    let table_id = TableId::new(10);
    TableStore::create(dir.path(), table_id, users_schema(table_id)).unwrap();
    let table_root = dir.path().join(format!("table_{}", table_id.raw()));
    std::fs::write(table_root.join(MANIFEST_TMP), b"{\"format_version\":999}").unwrap();
    let reopened = TableStore::open(dir.path(), table_id).unwrap();
    assert_eq!(reopened.row_count(), 0);
}

#[test]
fn multiple_segments_via_small_limit() {
    let dir = tempdir().unwrap();
    let table_id = TableId::new(11);
    let mut store =
        TableStore::create_with_segment_limit(dir.path(), table_id, users_schema(table_id), 512)
            .unwrap();
    for i in 0..50 {
        store.insert(&sample_row(i, "x", i)).unwrap();
    }
    let reopened = TableStore::open_with_segment_limit(dir.path(), table_id, 512).unwrap();
    assert_eq!(reopened.row_count(), 50);
    assert!(reopened.table_root().join("segments").read_dir().unwrap().count() >= 2);
}

#[test]
fn partial_record_truncated_on_open() {
    use dmc_storage::segment_path;
    let dir = tempdir().unwrap();
    let table_id = TableId::new(12);
    let mut store = TableStore::create(dir.path(), table_id, users_schema(table_id)).unwrap();
    store.insert(&sample_row(1, "ok", 1)).unwrap();
    let seg = segment_path(&store.table_root().join("segments"), 1);
    let mut bytes = std::fs::read(&seg).unwrap();
    bytes.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
    std::fs::write(&seg, bytes).unwrap();
    let reopened = TableStore::open(dir.path(), table_id).unwrap();
    assert_eq!(reopened.row_count(), 1);
}

#[test]
fn next_row_id_survives_restart() {
    let dir = tempdir().unwrap();
    let table_id = TableId::new(13);
    let mut store = TableStore::create(dir.path(), table_id, users_schema(table_id)).unwrap();
    store.insert(&sample_row(1, "a", 1)).unwrap();
    store.insert(&sample_row(2, "b", 2)).unwrap();
    let mut reopened = TableStore::open(dir.path(), table_id).unwrap();
    let row_id = reopened.insert(&sample_row(3, "c", 3)).unwrap();
    assert_eq!(row_id, RowId::new(3));
}

#[test]
#[ignore = "slow durability scan (~2 min debug); run: make test-slow"]
fn large_scan_batch() {
    let dir = tempdir().unwrap();
    let table_id = TableId::new(14);
    let mut store = TableStore::create(dir.path(), table_id, users_schema(table_id)).unwrap();
    for i in 0..5000 {
        store.insert(&sample_row(i, "u", i)).unwrap();
    }
    let reopened = TableStore::open(dir.path(), table_id).unwrap();
    assert_eq!(reopened.scan().count(), 5000);
}

#[test]
fn corrupt_record_magic_is_fatal_on_open() {
    use dmc_storage::segment_path;
    let dir = tempdir().unwrap();
    let table_id = TableId::new(15);
    let mut store = TableStore::create(dir.path(), table_id, users_schema(table_id)).unwrap();
    store.insert(&sample_row(1, "ok", 1)).unwrap();
    let seg = segment_path(&store.table_root().join("segments"), 1);
    let mut bytes = std::fs::read(&seg).unwrap();
    let corrupt_offset = 16usize;
    bytes[corrupt_offset] = 0x00;
    bytes[corrupt_offset + 1] = 0x00;
    std::fs::write(&seg, bytes).unwrap();
    assert!(TableStore::open(dir.path(), table_id).is_err());
}

#[test]
fn manifest_generation_increments() {
    let dir = tempdir().unwrap();
    let table_id = TableId::new(16);
    let mut store = TableStore::create(dir.path(), table_id, users_schema(table_id)).unwrap();
    store.insert(&sample_row(1, "a", 1)).unwrap();
    let manifest = dmc_storage::read_manifest(store.table_root()).unwrap().unwrap();
    assert!(manifest.generation >= 2);
}
