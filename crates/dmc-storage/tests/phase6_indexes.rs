//! Phase 6.13 — derived index storage (B-Tree, key encoding, MVCC lookup).

use std::sync::{Arc, Mutex};

use dmc_model::{
    ColumnId, DataEvent, IndexDefinition, IndexId, RowId, RowValue, SnapshotSequence, SqlDataType,
    TableId,
};
use dmc_storage::{
    apply_data_event_batch_with_index_arcs, build_index_from_table, BTree, ColumnSchema,
    IndexKey, IndexKeyComponent, IndexStore, StoredValue, TableSchema, TableStore, MANIFEST_TMP,
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

fn email_index(table_id: TableId) -> IndexDefinition {
    IndexDefinition::new(
        IndexId::new(10),
        table_id,
        "idx_email",
        vec![ColumnId::new(2)],
        false,
    )
}

fn composite_index(table_id: TableId) -> IndexDefinition {
    IndexDefinition::new(
        IndexId::new(11),
        table_id,
        "idx_name_age",
        vec![ColumnId::new(2), ColumnId::new(3)],
        false,
    )
}

fn row_values(id: i64, email: Option<&str>, age: Option<i64>) -> Vec<RowValue> {
    vec![
        RowValue::Int64(id),
        email.map(|s| RowValue::String(s.into()))
            .unwrap_or(RowValue::Null),
        age.map(RowValue::Int64).unwrap_or(RowValue::Null),
    ]
}

fn stored_row(id: i64, email: &str, age: i64) -> Vec<StoredValue> {
    vec![
        StoredValue::Int64(id),
        StoredValue::String(email.into()),
        StoredValue::Int64(age),
    ]
}

#[test]
fn btree_insert_lookup_delete() {
    let mut tree = BTree::new();
    let key = IndexKey::new(vec![IndexKeyComponent::String("a@x.com".into())]);
    tree.insert(&key, RowId::new(1), false).unwrap();
    assert_eq!(tree.lookup(&key), vec![RowId::new(1)]);
    tree.delete(&key, RowId::new(1));
    assert!(tree.lookup(&key).is_empty());
}

#[test]
fn btree_duplicate_non_unique_key() {
    let mut tree = BTree::new();
    let key = IndexKey::new(vec![IndexKeyComponent::String("dup".into())]);
    tree.insert(&key, RowId::new(1), false).unwrap();
    tree.insert(&key, RowId::new(2), false).unwrap();
    let mut ids = tree.lookup(&key);
    ids.sort_by_key(|id| id.raw());
    assert_eq!(ids, vec![RowId::new(1), RowId::new(2)]);
}

#[test]
fn btree_unique_rejects_duplicate_non_null() {
    let mut tree = BTree::new();
    let key = IndexKey::new(vec![IndexKeyComponent::String("u@x.com".into())]);
    tree.insert(&key, RowId::new(1), true).unwrap();
    let err = tree.insert(&key, RowId::new(2), true).unwrap_err();
    assert!(matches!(err, dmc_storage::Error::UniqueViolation { .. }));
}

#[test]
fn btree_unique_allows_multiple_nulls() {
    let mut tree = BTree::new();
    let key = IndexKey::new(vec![IndexKeyComponent::Null]);
    tree.insert(&key, RowId::new(1), true).unwrap();
    tree.insert(&key, RowId::new(2), true).unwrap();
    assert_eq!(tree.lookup(&key).len(), 2);
}

#[test]
fn btree_range_scan_ordering() {
    let mut tree = BTree::new();
    for (email, id) in [("a", 1), ("c", 3), ("b", 2)] {
        let key = IndexKey::new(vec![IndexKeyComponent::String(email.into())]);
        tree.insert(&key, RowId::new(id), false).unwrap();
    }
    let lower = IndexKey::new(vec![IndexKeyComponent::String("a".into())]);
    let upper = IndexKey::new(vec![IndexKeyComponent::String("c".into())]);
    let ids: Vec<_> = tree
        .range_scan(Some(&lower), Some(&upper))
        .into_iter()
        .map(|id| id.raw())
        .collect();
    assert_eq!(ids, vec![1, 2, 3]);
}

#[test]
fn btree_range_scan_exclusive_inclusive_bounds() {
    use std::ops::Bound;

    let mut tree = BTree::new();
    for id in 1_i64..=12 {
        let key = IndexKey::new(vec![IndexKeyComponent::Int64(id)]);
        tree.insert(&key, RowId::new(id as u64), false).unwrap();
    }
    let enc = |n: i64| IndexKey::new(vec![IndexKeyComponent::Int64(n)]).encode();

    let lt10: Vec<_> = tree
        .range_scan_bounds(Bound::Unbounded, Bound::Excluded(enc(10)))
        .into_iter()
        .map(|id| id.raw())
        .collect();
    assert_eq!(lt10, (1..10).collect::<Vec<_>>());

    let le10: Vec<_> = tree
        .range_scan_bounds(Bound::Unbounded, Bound::Included(enc(10)))
        .into_iter()
        .map(|id| id.raw())
        .collect();
    assert_eq!(le10, (1..=10).collect::<Vec<_>>());

    let gt10: Vec<_> = tree
        .range_scan_bounds(Bound::Excluded(enc(10)), Bound::Unbounded)
        .into_iter()
        .map(|id| id.raw())
        .collect();
    assert_eq!(gt10, (11..=12).collect::<Vec<_>>());

    let ge10: Vec<_> = tree
        .range_scan_bounds(Bound::Included(enc(10)), Bound::Unbounded)
        .into_iter()
        .map(|id| id.raw())
        .collect();
    assert_eq!(ge10, (10..=12).collect::<Vec<_>>());
}

#[test]
fn range_scan_visible_respects_inclusive_bounds() {
    let dir = tempdir().unwrap();
    let table_id = TableId::new(10);
    let mut table = TableStore::create(dir.path(), table_id, users_schema(table_id)).unwrap();
    for (id, email, age) in [(1_i64, "a", 1), (2, "b", 2), (8, "c", 8), (10, "d", 10), (11, "e", 11)] {
        table.insert(&stored_row(id, email, age)).unwrap();
    }
    let id_index = IndexDefinition::new(
        IndexId::new(20),
        table_id,
        "idx_id",
        vec![ColumnId::new(1)],
        false,
    );
    let index = build_index_from_table(dir.path(), id_index, &table).unwrap();
    use std::ops::Bound;
    let bound = |n: i64| IndexKey::new(vec![IndexKeyComponent::Int64(n)]);
    let snapshot = SnapshotSequence::at(100);

    let le10: Vec<_> = index
        .range_scan_visible(Bound::Unbounded, Bound::Included(&bound(10)), &table, snapshot)
        .unwrap()
        .into_iter()
        .map(|id| id.raw())
        .collect();
    assert_eq!(le10, vec![1, 2, 3, 4]);

    let ge10: Vec<_> = index
        .range_scan_visible(Bound::Included(&bound(10)), Bound::Unbounded, &table, snapshot)
        .unwrap()
        .into_iter()
        .map(|id| id.raw())
        .collect();
    assert_eq!(ge10, vec![4, 5]);
}

#[test]
fn lookup_visible_dedupes_duplicate_row_ids() {
    let dir = tempdir().unwrap();
    let table_id = TableId::new(9);
    let mut table = TableStore::create(dir.path(), table_id, users_schema(table_id)).unwrap();
    table.insert(&stored_row(1, "a@x.com", 1)).unwrap();

    let mut index = build_index_from_table(dir.path(), email_index(table_id), &table).unwrap();
    let key = IndexKey::new(vec![IndexKeyComponent::String("a@x.com".into())]);
    index
        .insert_row(
            RowId::new(1),
            &row_values(1, Some("a@x.com"), Some(1)),
            table.schema(),
        )
        .unwrap();

    let s = SnapshotSequence::at(100);
    let ids = index.lookup_visible(&key, &table, s).unwrap();
    assert_eq!(ids, vec![RowId::new(1)]);
}

#[test]
fn key_encoding_is_not_debug_repr() {
    let key = IndexKey::new(vec![
        IndexKeyComponent::Int64(42),
        IndexKeyComponent::Null,
    ]);
    let encoded = key.encode();
    assert_ne!(encoded, format!("{key:?}").into_bytes());
    assert_eq!(IndexKey::decode(&encoded).unwrap(), key);
}

#[test]
fn index_store_create_open_rebuild() {
    let dir = tempdir().unwrap();
    let table_id = TableId::new(1);
    let mut table = TableStore::create(dir.path(), table_id, users_schema(table_id)).unwrap();
    table
        .insert(&stored_row(1, "alice@x.com", 30))
        .unwrap();
    table
        .insert(&stored_row(2, "bob@x.com", 25))
        .unwrap();

    let definition = email_index(table_id);
    let mut index = build_index_from_table(dir.path(), definition.clone(), &table).unwrap();
    assert!(index.validate(&table).unwrap());

    let key = IndexKey::from_row_values(
        &row_values(1, Some("alice@x.com"), Some(30)),
        &[1],
        table.schema(),
    )
    .unwrap();
    assert_eq!(index.lookup(&key), vec![RowId::new(1)]);

    table
        .update(RowId::new(1), &stored_row(1, "alice2@x.com", 31))
        .unwrap();
    index.rebuild_from_table(&table).unwrap();
    let new_key = IndexKey::from_row_values(
        &row_values(1, Some("alice2@x.com"), Some(31)),
        &[1],
        table.schema(),
    )
    .unwrap();
    assert_eq!(index.lookup(&new_key), vec![RowId::new(1)]);

    let reopened = IndexStore::open(dir.path(), definition, table.schema()).unwrap();
    assert_eq!(reopened.lookup(&new_key), vec![RowId::new(1)]);
}

#[test]
fn composite_index_lookup() {
    let dir = tempdir().unwrap();
    let table_id = TableId::new(2);
    let mut table = TableStore::create(dir.path(), table_id, users_schema(table_id)).unwrap();
    table.insert(&stored_row(1, "alice", 30)).unwrap();
    table.insert(&stored_row(2, "alice", 40)).unwrap();

    let index = build_index_from_table(dir.path(), composite_index(table_id), &table).unwrap();
    let key = IndexKey::from_row_values(
        &row_values(2, Some("alice"), Some(40)),
        &[1, 2],
        table.schema(),
    )
    .unwrap();
    assert_eq!(index.lookup(&key), vec![RowId::new(2)]);
}

#[test]
fn null_values_are_indexed() {
    let dir = tempdir().unwrap();
    let table_id = TableId::new(3);
    let mut table = TableStore::create(dir.path(), table_id, users_schema(table_id)).unwrap();
    table
        .insert(&vec![
            StoredValue::Int64(1),
            StoredValue::Null,
            StoredValue::Int64(10),
        ])
        .unwrap();

    let index = build_index_from_table(dir.path(), email_index(table_id), &table).unwrap();
    let key = IndexKey::new(vec![IndexKeyComponent::Null]);
    assert_eq!(index.lookup(&key), vec![RowId::new(1)]);
}

#[test]
fn lookup_visible_respects_snapshot() {
    let dir = tempdir().unwrap();
    let table_id = TableId::new(4);
    let mut table = TableStore::create(dir.path(), table_id, users_schema(table_id)).unwrap();
    table
        .insert_with_sequence(RowId::new(1), &stored_row(1, "alice@x.com", 30), 100)
        .unwrap();
    table
        .update_with_sequence(
            RowId::new(1),
            &stored_row(1, "bob@x.com", 30),
            150,
        )
        .unwrap();

    let index = build_index_from_table(dir.path(), email_index(table_id), &table).unwrap();
    let alice = IndexKey::new(vec![IndexKeyComponent::String("alice@x.com".into())]);
    let bob = IndexKey::new(vec![IndexKeyComponent::String("bob@x.com".into())]);

    let s120 = SnapshotSequence::at(120);
    assert_eq!(
        index.lookup_visible(&alice, &table, s120).unwrap(),
        vec![RowId::new(1)]
    );
    assert!(index.lookup_visible(&bob, &table, s120).unwrap().is_empty());

    let s160 = SnapshotSequence::at(160);
    assert!(index
        .lookup_visible(&alice, &table, s160)
        .unwrap()
        .is_empty());
    assert_eq!(
        index.lookup_visible(&bob, &table, s160).unwrap(),
        vec![RowId::new(1)]
    );
}

#[test]
fn apply_batch_updates_table_and_index_atomically() {
    let dir = tempdir().unwrap();
    let table_id = TableId::new(5);
    let mut table = TableStore::create(dir.path(), table_id, users_schema(table_id)).unwrap();
    let mut index = IndexStore::create(dir.path(), email_index(table_id), table.schema()).unwrap();
    let indexes = vec![Arc::new(Mutex::new(index))];

    apply_data_event_batch_with_index_arcs(
        &mut table,
        &indexes,
        &[DataEvent::InsertRow {
            table_id,
            row_id: RowId::new(1),
            values: row_values(1, Some("x@y.com"), Some(1)),
        }],
        10,
        false,
    )
    .unwrap();

    let key = IndexKey::new(vec![IndexKeyComponent::String("x@y.com".into())]);
    let idx = indexes[0].lock().unwrap();
    assert_eq!(idx.lookup(&key), vec![RowId::new(1)]);
    drop(idx);
    assert_eq!(table.row_count(), 1);
}

#[test]
fn index_validate_detects_drift() {
    let dir = tempdir().unwrap();
    let table_id = TableId::new(6);
    let mut table = TableStore::create(dir.path(), table_id, users_schema(table_id)).unwrap();
    table.insert(&stored_row(1, "a@x.com", 1)).unwrap();
    let mut index = build_index_from_table(dir.path(), email_index(table_id), &table).unwrap();
    assert!(index.validate(&table).unwrap());

    table.insert(&stored_row(2, "b@x.com", 2)).unwrap();
    assert!(!index.validate(&table).unwrap());
    index.rebuild_from_table(&table).unwrap();
    assert!(index.validate(&table).unwrap());
}

#[test]
fn reopen_ignores_manifest_tmp() {
    let dir = tempdir().unwrap();
    let table_id = TableId::new(7);
    let table = TableStore::create(dir.path(), table_id, users_schema(table_id)).unwrap();
    build_index_from_table(dir.path(), email_index(table_id), &table).unwrap();
    let index_root = dmc_storage::index_dir(dir.path(), IndexId::new(10));
    std::fs::write(index_root.join(MANIFEST_TMP), b"partial").unwrap();
    let reopened = IndexStore::open(dir.path(), email_index(table_id), table.schema()).unwrap();
    assert_eq!(reopened.definition().name, "idx_email");
}

#[test]
fn row_store_wins_over_stale_index_entry() {
    let dir = tempdir().unwrap();
    let table_id = TableId::new(8);
    let mut table = TableStore::create(dir.path(), table_id, users_schema(table_id)).unwrap();
    table
        .insert_with_sequence(RowId::new(1), &stored_row(1, "live@x.com", 1), 10)
        .unwrap();
    table.delete_with_sequence(RowId::new(1), 20).unwrap();

    let mut index = build_index_from_table(dir.path(), email_index(table_id), &table).unwrap();
    let ghost = IndexKey::new(vec![IndexKeyComponent::String("ghost@x.com".into())]);
    index
        .insert_row(
            RowId::new(1),
            &row_values(1, Some("ghost@x.com"), Some(1)),
            table.schema(),
        )
        .unwrap();

    let s30 = SnapshotSequence::at(30);
    assert!(index.lookup_visible(&ghost, &table, s30).unwrap().is_empty());
}
