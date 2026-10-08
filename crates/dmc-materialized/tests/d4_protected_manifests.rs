//! D4-B: protected live manifests — tampering, truncation and rollback of table / index
//! storage are detected and refused (fail closed) when storage keys are in use.
//!
//! * a table's authoritative manifest is sealed (`manifest.sealed`, bound to the table);
//!   the plaintext `manifest.json` is metadata only and never trusted;
//! * a published segment that is missing or shorter than published is refused;
//! * an index's generation lives inside its sealed data;
//! * the sealed snapshot records every store's generation: a store found older is a
//!   rollback, on both open paths (journal replay and recovered open);
//! * crash windows are not mistaken for attacks (stale plaintext manifest, snapshot older
//!   than the stores, a drop not yet in the snapshot).

#[path = "d4_support/mod.rs"]
mod d4;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use dmc_materialized::{FileStateEventLog, StateMaterializer};
use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, CatalogEvent, ColumnDef, DataEvent, IndexId, RowId,
    RowValue, SqlDataType, TableId,
};
use dmc_storage::{index_dir, table_dir};
use dmc_vault::StorageCipher;
use dmc_vault::storage_cipher::looks_sealed;

const MARKER: &str = "D4B_PROTECTED_MANIFEST_MARKER_7a41";

struct Store {
    catalog: Catalog,
    t: TableId,
    u: TableId,
    idx: IndexId,
}

fn cols() -> Vec<ColumnDef> {
    vec![
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
    ]
}

fn open(
    root: &Path,
    c: &Arc<StorageCipher>,
) -> dmc_materialized::Result<StateMaterializer<FileStateEventLog>> {
    d4::open(root, Some(c.clone()))
}

fn open_recovered(
    root: &Path,
    c: &Arc<StorageCipher>,
) -> dmc_materialized::Result<StateMaterializer<FileStateEventLog>> {
    StateMaterializer::open_recovered_with_cipher(
        root.join("rows"),
        root.join("snapshot.json"),
        root.join("state_events.json"),
        Some(c.clone()),
    )
}

/// Tables `t` (with an index on `note`) and `u`, one row each.
fn build(root: &Path, c: &Arc<StorageCipher>) -> Store {
    let mut mat = open(root, c).unwrap();
    let mut catalog = Catalog::new();
    let mut events = catalog.bootstrap_default().unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let mut ids = Vec::new();
    for name in ["t", "u"] {
        let ev = catalog
            .create_table_event(schema, name, cols(), Some(vec!["id".into()]))
            .unwrap();
        catalog.apply(&ev, ApplyMode::Live).unwrap();
        ids.push(match &ev {
            CatalogEvent::CreateTable { id, .. } => *id,
            _ => unreachable!(),
        });
        events.push(ev);
    }
    let note = catalog.table(ids[0]).unwrap().columns[1].id;
    let ev = catalog
        .create_index_event(ids[0], "idx_t_note", vec![note], false)
        .unwrap();
    catalog.apply(&ev, ApplyMode::Live).unwrap();
    let idx = match &ev {
        CatalogEvent::CreateIndex { id, .. } => *id,
        _ => unreachable!(),
    };
    events.push(ev);
    for e in events {
        mat.mutate_catalog(e).unwrap();
    }
    let s = Store {
        catalog,
        t: ids[0],
        u: ids[1],
        idx,
    };
    insert(&mut mat, s.t, 1, MARKER);
    insert(&mut mat, s.u, 1, "u-row");
    s
}

fn insert(mat: &mut StateMaterializer<FileStateEventLog>, table: TableId, id: u64, note: &str) {
    mat.mutate_data(DataEvent::InsertRow {
        table_id: table,
        row_id: RowId::new(id),
        values: vec![RowValue::Int64(id as i64), RowValue::String(note.into())],
    })
    .unwrap();
}

fn tdir(root: &Path, t: TableId) -> PathBuf {
    table_dir(&root.join("rows"), t)
}

fn idir(root: &Path, i: IndexId) -> PathBuf {
    index_dir(&root.join("rows"), i)
}

fn copy_dir(from: &Path, to: &Path) {
    let _ = std::fs::remove_dir_all(to);
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        let target = to.join(e.file_name());
        if e.path().is_dir() {
            copy_dir(&e.path(), &target);
        } else {
            std::fs::copy(e.path(), target).unwrap();
        }
    }
}

fn refused(
    r: dmc_materialized::Result<StateMaterializer<FileStateEventLog>>,
    what: &str,
    needle: &str,
) {
    let err = r.err().unwrap_or_else(|| panic!("{what}: accepted"));
    assert!(err.to_string().contains(needle), "{what}: {err}");
}

fn rows_of(mat: &StateMaterializer<FileStateEventLog>, t: TableId) -> usize {
    mat.shared_table_store(t)
        .unwrap()
        .lock()
        .unwrap()
        .live_row_ids()
        .len()
}

#[test]
fn table_manifest_is_authenticated() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let c = d4::cipher();
    let s = build(root, &c);
    let t = tdir(root, s.t);
    let sealed = t.join(dmc_storage::SEALED_MANIFEST_FILE);
    assert!(looks_sealed(&std::fs::read(&sealed).unwrap()));
    assert!(d4::revealing_files(root, MARKER).is_empty());

    // the plaintext copy is metadata only: tampering with it changes nothing
    let plain = t.join("manifest.json");
    let original = std::fs::read(&plain).unwrap();
    let mut m: serde_json::Value = serde_json::from_slice(&original).unwrap();
    m["next_row_id"] = 1.into();
    m["segments"] = serde_json::json!([]);
    std::fs::write(&plain, serde_json::to_vec(&m).unwrap()).unwrap();
    let mat = open(root, &c).unwrap();
    assert_eq!(rows_of(&mat, s.t), 1);
    drop(mat);
    std::fs::write(&plain, &original).unwrap();

    // the authoritative copy: removed, tampered or from another table → refused
    let saved = std::fs::read(&sealed).unwrap();
    std::fs::remove_file(&sealed).unwrap();
    refused(
        open(root, &c),
        "sealed manifest removed",
        "not authenticated",
    );
    let mut flipped = saved.clone();
    let i = flipped.len() - 10;
    flipped[i] ^= 1;
    std::fs::write(&sealed, &flipped).unwrap();
    refused(
        open(root, &c),
        "sealed manifest tampered",
        "cannot be decrypted",
    );
    std::fs::copy(
        tdir(root, s.u).join(dmc_storage::SEALED_MANIFEST_FILE),
        &sealed,
    )
    .unwrap();
    refused(
        open(root, &c),
        "another table's manifest",
        "cannot be decrypted",
    );
    std::fs::write(&sealed, &saved).unwrap();
    assert!(open(root, &c).is_ok());
}

#[test]
fn missing_or_truncated_segments_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let c = d4::cipher();
    let s = build(root, &c);
    let mut mat = open(root, &c).unwrap();
    insert(&mut mat, s.t, 2, "second");
    drop(mat);
    let seg = tdir(root, s.t).join("segments/000001.dat");
    let raw = std::fs::read(&seg).unwrap();

    // cut the last record off at its frame boundary (a well-formed, shorter segment)
    let mut at = dmc_storage::SEGMENT_HEADER_LEN;
    let mut last = at;
    while at + 4 <= raw.len() {
        last = at;
        at += 4 + u32::from_le_bytes(raw[at..at + 4].try_into().unwrap()) as usize;
    }
    std::fs::write(&seg, &raw[..last]).unwrap();
    for (what, r) in [
        ("replay open", open(root, &c)),
        ("recovered open", open_recovered(root, &c)),
    ] {
        refused(r, what, "shorter than published");
    }
    std::fs::remove_file(&seg).unwrap();
    refused(open(root, &c), "segment deleted", "missing or shorter");
    std::fs::write(&seg, &raw).unwrap();
    assert_eq!(rows_of(&open(root, &c).unwrap(), s.t), 2);
}

#[test]
fn table_and_index_rollback_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let c = d4::cipher();
    let s = build(root, &c);
    let saved = dir.path().join("saved");
    copy_dir(&tdir(root, s.t), &saved.join("table"));
    copy_dir(&idir(root, s.idx), &saved.join("index"));

    let mut mat = open(root, &c).unwrap();
    insert(&mut mat, s.t, 2, "newer");
    drop(mat);
    let current_t = dir.path().join("current_t");
    let current_i = dir.path().join("current_i");
    copy_dir(&tdir(root, s.t), &current_t);
    copy_dir(&idir(root, s.idx), &current_i);

    // the whole table (sealed manifest + segments, consistent with each other) rolled back
    copy_dir(&saved.join("table"), &tdir(root, s.t));
    refused(open(root, &c), "table rollback (replay open)", "rollback");
    refused(
        open_recovered(root, &c),
        "table rollback (recovered open)",
        "rollback",
    );
    copy_dir(&current_t, &tdir(root, s.t));

    // the index rolled back (it would silently miss the newer row)
    copy_dir(&saved.join("index"), &idir(root, s.idx));
    refused(open(root, &c), "index rollback (replay open)", "rollback");
    refused(
        open_recovered(root, &c),
        "index rollback (recovered open)",
        "rollback",
    );
    copy_dir(&current_i, &idir(root, s.idx));

    // a table / index directory removed entirely
    std::fs::remove_dir_all(tdir(root, s.u)).unwrap();
    refused(open(root, &c), "table removed", "missing");
    let _ = s.catalog;
}

#[test]
fn index_manifest_plaintext_is_not_trusted() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let c = d4::cipher();
    let s = build(root, &c);
    let m = idir(root, s.idx).join("manifest.json");
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&m).unwrap()).unwrap();
    v["generation"] = 99_999.into();
    std::fs::write(&m, serde_json::to_vec(&v).unwrap()).unwrap();
    let mat = open_recovered(root, &c).unwrap();
    let idx = mat.shared_index_store(s.idx).unwrap();
    assert!(
        idx.lock().unwrap().generation() < 99_999,
        "generation comes from sealed data"
    );
}

#[test]
fn crash_windows_are_not_mistaken_for_tampering() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let c = d4::cipher();
    let s = build(root, &c);
    let snap = root.join("snapshot.json");
    let plain = tdir(root, s.t).join("manifest.json");
    let old_snapshot = std::fs::read(&snap).unwrap();
    let old_plain = std::fs::read(&plain).unwrap();

    let mut mat = open(root, &c).unwrap();
    insert(&mut mat, s.t, 2, "after");
    drop(mat);
    // crash after the sealed manifest, before the plaintext copy: stale plaintext copy
    std::fs::write(&plain, &old_plain).unwrap();
    // crash after the stores were published, before the snapshot: older snapshot
    std::fs::write(&snap, &old_snapshot).unwrap();
    let mat = open(root, &c).unwrap();
    assert_eq!(rows_of(&mat, s.t), 2);
    drop(mat);

    // crash after DROP TABLE / DROP INDEX, before the snapshot recorded it
    let before_drop = std::fs::read(&snap).unwrap();
    let mut mat = open(root, &c).unwrap();
    let catalog = mat.catalog().clone();
    mat.mutate_catalog(catalog.drop_index_event(s.idx).unwrap())
        .unwrap();
    let catalog = mat.catalog().clone();
    mat.mutate_catalog(catalog.drop_table_event(s.u).unwrap())
        .unwrap();
    drop(mat);
    assert!(!tdir(root, s.u).exists() && !idir(root, s.idx).exists());
    std::fs::write(&snap, &before_drop).unwrap();
    assert!(
        open(root, &c).is_ok(),
        "drops after the snapshot are in the journal"
    );
}

#[test]
fn keyless_mode_is_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let table = d4::write_rows(root, None, &["plain"]);
    assert!(
        !tdir(root, table)
            .join(dmc_storage::SEALED_MANIFEST_FILE)
            .exists()
    );
    assert!(d4::open(root, None).is_ok());
}
