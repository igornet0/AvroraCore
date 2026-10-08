//! D4-A stage 4.4: secondary index data is sealed at rest.
//!
//! `index.data` holds the indexed column values (hex-encoded keys): it is sealed whole with
//! the `Index` storage key and bound to its index id; a missing data file is an error with
//! keys (never an "empty index"); plaintext index data is never converted implicitly.

#[path = "d4_support/mod.rs"]
mod d4;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use dmc_materialized::{FileStateEventLog, StateMaterializer};
use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, CatalogEvent, ColumnDef, DataEvent, IndexId, RowId,
    RowValue, SqlDataType, TableId,
};
use dmc_storage::{
    INDEX_DATA_FILE, IndexKey, IndexKeyComponent, IndexStore, index_data_context, index_dir,
};
use dmc_vault::storage_cipher::{file_context, looks_sealed};
use dmc_vault::{StorageCipher, StoragePurpose};

const MARKER_A: &str = "D4_INDEX_PLAINTEXT_MARKER_A_93d0";
const MARKER_B: &str = "D4_INDEX_PLAINTEXT_MARKER_B_93d0";
const MARKER_C: &str = "D4_INDEX_PLAINTEXT_MARKER_C_93d0";

struct Fixture {
    table: TableId,
    index: IndexId,
    second_index: IndexId,
}

/// Table `t (id BIGINT PK, note TEXT)`, two rows, two secondary indexes on `note`.
fn build(root: &Path, c: Option<Arc<StorageCipher>>) -> Fixture {
    let mut mat = d4::open(root, c).unwrap();
    let mut catalog = Catalog::new();
    let mut events = catalog.bootstrap_default().unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let cols = vec![
        ColumnDef {
            name: "id".into(),
            data_type: SqlDataType::BigInt,
            nullable: false,
            default: None,
        },
        ColumnDef {
            name: "note".into(),
            data_type: SqlDataType::Text,
            nullable: true,
            default: None,
        },
    ];
    let create = catalog
        .create_table_event(schema, "t", cols, Some(vec!["id".into()]))
        .unwrap();
    catalog.apply(&create, ApplyMode::Live).unwrap();
    let table = match &create {
        CatalogEvent::CreateTable { id, .. } => *id,
        _ => unreachable!(),
    };
    events.push(create);
    for e in events {
        mat.mutate_catalog(e).unwrap();
    }
    for (i, m) in [MARKER_A, MARKER_B].iter().enumerate() {
        mat.mutate_data(DataEvent::InsertRow {
            table_id: table,
            row_id: RowId::new(i as u64 + 1),
            values: vec![RowValue::Int64(i as i64 + 1), RowValue::String((*m).into())],
        })
        .unwrap();
    }
    let note = catalog
        .table(table)
        .unwrap()
        .columns
        .iter()
        .find(|c| c.name == "note")
        .unwrap()
        .id;
    let mut ids = Vec::new();
    for name in ["idx_note", "idx_note_2"] {
        let ev = catalog
            .create_index_event(table, name, vec![note], false)
            .unwrap();
        catalog.apply(&ev, ApplyMode::Live).unwrap();
        ids.push(match &ev {
            CatalogEvent::CreateIndex { id, .. } => *id,
            _ => unreachable!(),
        });
        mat.mutate_catalog(ev).unwrap();
    }
    mat.persist_snapshot_if_configured().unwrap();
    Fixture {
        table,
        index: ids[0],
        second_index: ids[1],
    }
}

fn data_file(root: &Path, index: IndexId) -> PathBuf {
    index_dir(&root.join("rows"), index).join(INDEX_DATA_FILE)
}

fn key(m: &str) -> IndexKey {
    IndexKey::new(vec![IndexKeyComponent::String(m.into())])
}

/// Reopen one index store directly with the given keys (definition/schema from `mat`).
fn reopen(
    root: &Path,
    mat: &StateMaterializer<FileStateEventLog>,
    f: &Fixture,
    index: IndexId,
    c: Option<Arc<StorageCipher>>,
) -> dmc_storage::Result<IndexStore> {
    let definition = mat
        .shared_index_store(index)
        .unwrap()
        .lock()
        .unwrap()
        .definition()
        .clone();
    let schema = mat
        .shared_table_store(f.table)
        .unwrap()
        .lock()
        .unwrap()
        .schema()
        .clone();
    IndexStore::open_with_cipher(root.join("rows"), definition, &schema, c)
}

#[test]
fn index_data_is_sealed_and_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let c = d4::cipher();
    let f = build(root, Some(c.clone()));

    let path = data_file(root, f.index);
    let raw = std::fs::read(&path).unwrap();
    assert!(looks_sealed(&raw), "index data sealed");
    for m in [MARKER_A, MARKER_B] {
        assert!(
            !d4::reveals(&raw, m),
            "index data reveals a value (raw/hex/base64)"
        );
    }
    assert!(
        !path
            .with_file_name(format!("{INDEX_DATA_FILE}.tmp"))
            .exists()
    );
    // bound to purpose and index id
    let ctx = |id: IndexId| file_context(&index_data_context(id));
    assert!(c.open(StoragePurpose::Index, &ctx(f.index), &raw).is_ok());
    assert!(
        c.open(StoragePurpose::Index, &ctx(f.second_index), &raw)
            .is_err()
    );
    assert!(c.open(StoragePurpose::Rows, &ctx(f.index), &raw).is_err());

    // no file anywhere in the data root reveals a value
    let residual: Vec<_> = [MARKER_A, MARKER_B]
        .iter()
        .flat_map(|m| d4::revealing_files(root, m))
        .collect();
    println!("still plaintext after 4.4: {residual:?}");
    assert!(
        residual.is_empty(),
        "no plaintext value at rest: {residual:?}"
    );

    // unlocked (same keys): reopened index answers lookups and matches the table
    let mat = d4::open(root, Some(c.clone())).unwrap();
    let index = mat.shared_index_store(f.index).unwrap();
    let table = mat.shared_table_store(f.table).unwrap();
    assert_eq!(
        index.lock().unwrap().lookup(&key(MARKER_A)),
        vec![RowId::new(1)]
    );
    assert_eq!(
        index.lock().unwrap().lookup(&key(MARKER_B)),
        vec![RowId::new(2)]
    );
    assert!(
        index
            .lock()
            .unwrap()
            .validate(&table.lock().unwrap())
            .unwrap()
    );
    assert!(index.lock().unwrap().is_encrypted());

    // locked (no keys) / another installation's keys: refused
    let err = reopen(root, &mat, &f, f.index, None).err().unwrap();
    assert!(err.to_string().contains("keys required"), "{err}");
    assert!(reopen(root, &mat, &f, f.index, Some(d4::cipher())).is_err());

    let refused = |bytes: Option<&[u8]>, what: &str, expect: &str| {
        match bytes {
            Some(b) => std::fs::write(&path, b).unwrap(),
            None => std::fs::remove_file(&path).unwrap(),
        }
        let err = reopen(root, &mat, &f, f.index, Some(c.clone()))
            .err()
            .unwrap_or_else(|| panic!("{what}: accepted"));
        assert!(err.to_string().contains(expect), "{what}: {err}");
        std::fs::write(&path, &raw).unwrap();
    };
    // tampered
    let mut t = raw.clone();
    let i = t.len() / 2;
    t[i] ^= 0x04;
    refused(Some(&t), "tampered", "cannot be decrypted");
    // another index's data copied over this one
    let other = std::fs::read(data_file(root, f.second_index)).unwrap();
    refused(Some(&other), "relocated", "cannot be decrypted");
    // deleted: an error, never an empty index that silently misses rows
    refused(None, "deleted", "index data missing");
    assert!(reopen(root, &mat, &f, f.index, Some(c.clone())).is_ok());
}

#[test]
fn aborted_batch_keeps_index_data_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let c = d4::cipher();
    let f = build(root, Some(c.clone()));
    let mat = d4::open(root, Some(c.clone())).unwrap();
    let schema = mat
        .shared_table_store(f.table)
        .unwrap()
        .lock()
        .unwrap()
        .schema()
        .clone();
    let mut store = reopen(root, &mat, &f, f.index, Some(c.clone())).unwrap();
    let row = |m: &str| vec![RowValue::Int64(3), RowValue::String(m.into())];
    store.begin_batch();
    store
        .insert_row(RowId::new(3), &row(MARKER_C), &schema)
        .unwrap();
    store.abort_batch().unwrap();
    assert!(store.is_encrypted(), "reopen after abort keeps the keys");
    assert!(
        store.lookup(&key(MARKER_C)).is_empty(),
        "aborted entry gone"
    );
    store
        .insert_row(RowId::new(3), &row(MARKER_C), &schema)
        .unwrap();
    let raw = std::fs::read(data_file(root, f.index)).unwrap();
    assert!(looks_sealed(&raw) && !d4::reveals(&raw, MARKER_C));
}

#[test]
fn plaintext_index_data_is_not_converted_implicitly() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let f = build(root, None);
    let path = data_file(root, f.index);
    let before = std::fs::read(&path).unwrap();
    assert!(!looks_sealed(&before));
    assert!(
        d4::reveals(&before, MARKER_A),
        "dev/test plaintext path (negative control: hex-encoded keys)"
    );
    let mat = d4::open(root, None).unwrap();
    let err = reopen(root, &mat, &f, f.index, Some(d4::cipher()))
        .err()
        .unwrap();
    assert!(err.to_string().contains("explicit migration"), "{err}");
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "plaintext index data untouched"
    );
}
