//! D4-A stage 4.3: table row segments are sealed per record at rest.
//!
//! Every record is sealed with the `Rows` storage key and bound to (table, segment,
//! offset): a record copied, swapped or moved does not open; tampering is never
//! "repaired" by truncation; plaintext segments are never converted implicitly.

#[path = "d4_support/mod.rs"]
mod d4;

use std::path::{Path, PathBuf};

use dmc_model::{ColumnId, RowId, SqlDataType, TableId};
use dmc_storage::{
    DEFAULT_MAX_SEGMENT_BYTES, SEGMENT_HEADER_LEN, SEGMENT_VERSION_PLAIN, SEGMENT_VERSION_SEALED,
    SegmentSeal, SegmentWriter, StoredValue, TableStore, schema_from_catalog_columns, segment_path,
    table_dir,
};
use dmc_vault::StoragePurpose;
use dmc_vault::storage_cipher::{looks_sealed, row_record_context};

// Equal length on purpose: their sealed frames can be swapped in place.
const MARKER_A: &str = "D4_ROW_SEGMENT_PLAINTEXT_MARKER_A_4c19";
const MARKER_B: &str = "D4_ROW_SEGMENT_PLAINTEXT_MARKER_B_4c19";

fn rows_root(root: &Path) -> PathBuf {
    root.join("rows")
}

fn segments_dir(root: &Path, table: TableId) -> PathBuf {
    table_dir(&rows_root(root), table).join("segments")
}

fn segment_version(raw: &[u8]) -> u32 {
    u32::from_le_bytes(raw[4..8].try_into().unwrap())
}

/// `(offset, frame length)` of every sealed frame.
fn frames(raw: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut at = SEGMENT_HEADER_LEN;
    while at + 4 <= raw.len() {
        let len = u32::from_le_bytes(raw[at..at + 4].try_into().unwrap()) as usize;
        out.push((at, 4 + len));
        at += 4 + len;
    }
    assert_eq!(at, raw.len(), "segment is a whole number of frames");
    out
}

fn open_table(
    root: &Path,
    table: TableId,
    c: Option<std::sync::Arc<dmc_vault::StorageCipher>>,
) -> dmc_storage::Result<TableStore> {
    TableStore::open_with_cipher(rows_root(root), table, DEFAULT_MAX_SEGMENT_BYTES, c)
}

fn note(store: &TableStore, row: u64) -> Option<StoredValue> {
    store
        .get(RowId::new(row))
        .unwrap()
        .map(|values| values[1].clone())
}

#[test]
fn row_segments_are_sealed_per_record_and_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let c = d4::cipher();
    let table = d4::write_rows(root, Some(c.clone()), &[MARKER_A, MARKER_B]);

    let seg = segment_path(&segments_dir(root, table), 1);
    let raw = std::fs::read(&seg).unwrap();
    assert_eq!(segment_version(&raw), SEGMENT_VERSION_SEALED);
    for m in [MARKER_A, MARKER_B] {
        assert!(
            !d4::reveals(&raw, m),
            "segment reveals a value (raw/hex/base64)"
        );
    }
    let frames = frames(&raw);
    assert_eq!(frames.len(), 2, "one sealed frame per row version");

    // each record: Rows key, bound to (table, segment, offset)
    let (off, len) = frames[0];
    let sealed = &raw[off + 4..off + len];
    assert!(looks_sealed(sealed));
    let ctx = |t: &str, s: u64, o: u64| row_record_context(t, s, o);
    let this_table = format!("table_{}", table.raw());
    assert!(
        c.open(
            StoragePurpose::Rows,
            &ctx(&this_table, 1, off as u64),
            sealed
        )
        .is_ok()
    );
    for (t, s, o) in [
        (format!("table_{}", table.raw() + 1), 1, off as u64),
        (this_table.clone(), 2, off as u64),
        (this_table.clone(), 1, frames[1].0 as u64),
    ] {
        assert!(
            c.open(StoragePurpose::Rows, &ctx(&t, s, o), sealed)
                .is_err()
        );
    }
    assert!(
        c.open(
            StoragePurpose::Index,
            &ctx(&this_table, 1, off as u64),
            sealed
        )
        .is_err()
    );

    // no file anywhere in the data root reveals a row value any more
    let residual: Vec<_> = [MARKER_A, MARKER_B]
        .iter()
        .flat_map(|m| d4::revealing_files(root, m))
        .collect();
    println!("still plaintext after 4.3: {residual:?}");
    assert!(
        residual.is_empty(),
        "no plaintext row value at rest: {residual:?}"
    );

    // unlocked (same keys): values readable, through the store and the materializer
    let store = open_table(root, table, Some(c.clone())).unwrap();
    assert!(store.is_encrypted());
    assert_eq!(note(&store, 1), Some(StoredValue::String(MARKER_A.into())));
    assert_eq!(note(&store, 2), Some(StoredValue::String(MARKER_B.into())));
    drop(store);
    assert!(d4::open(root, Some(c.clone())).is_ok());

    // locked (no keys) / another installation's keys: refused, never read as empty
    let err = open_table(root, table, None).err().unwrap();
    assert!(err.to_string().contains("keys required"), "{err}");
    assert!(open_table(root, table, Some(d4::cipher())).is_err());
    assert_eq!(
        std::fs::read(&seg).unwrap(),
        raw,
        "refusals leave the segment untouched"
    );
}

#[test]
fn swapped_relocated_or_tampered_records_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let c = d4::cipher();
    let table = d4::write_rows(root, Some(c.clone()), &[MARKER_A, MARKER_B]);
    let seg = segment_path(&segments_dir(root, table), 1);
    let raw = std::fs::read(&seg).unwrap();
    let fr = frames(&raw);
    assert_eq!(fr[0].1, fr[1].1, "equal-length frames");

    let refused = |bytes: &[u8], what: &str| {
        std::fs::write(&seg, bytes).unwrap();
        let err = open_table(root, table, Some(c.clone()))
            .err()
            .unwrap_or_else(|| panic!("{what}: accepted"));
        assert!(
            err.to_string().contains("cannot be decrypted"),
            "{what}: {err}"
        );
        assert_eq!(
            std::fs::read(&seg).unwrap(),
            bytes,
            "{what}: not truncated away"
        );
    };

    // swap the two records in place (each is a valid ciphertext, at the wrong offset)
    let mut swapped = raw.clone();
    let (a, b, n) = (fr[0].0, fr[1].0, fr[0].1);
    swapped[a..a + n].copy_from_slice(&raw[b..b + n]);
    swapped[b..b + n].copy_from_slice(&raw[a..a + n]);
    refused(&swapped, "swapped records");

    // duplicate the first record over the second (replay inside the segment)
    let mut replayed = raw.clone();
    replayed[b..b + n].copy_from_slice(&raw[a..a + n]);
    refused(&replayed, "replayed record");

    // flip one ciphertext bit of the last record
    let mut tampered = raw.clone();
    let i = raw.len() - 20;
    tampered[i] ^= 0x01;
    refused(&tampered, "tampered record");

    // a complete but forged frame appended: refused, never cut off as a "torn tail"
    let mut forged = raw.clone();
    let fake = vec![0x5au8; 64];
    forged.extend_from_slice(&(fake.len() as u32).to_le_bytes());
    forged.extend_from_slice(&fake);
    refused(&forged, "forged frame");

    std::fs::write(&seg, &raw).unwrap();
    assert!(open_table(root, table, Some(c.clone())).is_ok());

    // the whole table directory moved under another table id: refused
    let rows = rows_root(root);
    let other = TableId::new(table.raw() + 100);
    copy_dir(&table_dir(&rows, table), &table_dir(&rows, other));
    let manifest = table_dir(&rows, other).join("manifest.json");
    let mut m: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    m["table_id"] = other.raw().into();
    m["schema"]["table_id"] = other.raw().into();
    std::fs::write(&manifest, serde_json::to_vec(&m).unwrap()).unwrap();
    let err = open_table(root, other, Some(c.clone())).err().unwrap();
    assert!(err.to_string().contains("cannot be decrypted"), "{err}");
}

#[test]
fn only_a_torn_tail_is_truncated() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let c = d4::cipher();
    let table = d4::write_rows(root, Some(c.clone()), &[MARKER_A]);
    let seg = segment_path(&segments_dir(root, table), 1);
    let raw = std::fs::read(&seg).unwrap();

    // crash mid-append: a partial length prefix, or a prefix with a short body
    for torn in [vec![0x10u8, 0x00], {
        let mut t = 200u32.to_le_bytes().to_vec();
        t.extend_from_slice(&[0xa5; 50]);
        t
    }] {
        let mut bytes = raw.clone();
        bytes.extend_from_slice(&torn);
        std::fs::write(&seg, &bytes).unwrap();
        let store = open_table(root, table, Some(c.clone())).unwrap();
        assert_eq!(note(&store, 1), Some(StoredValue::String(MARKER_A.into())));
        drop(store);
        assert_eq!(std::fs::read(&seg).unwrap(), raw, "torn tail removed");
    }
}

#[test]
fn plaintext_segments_are_not_converted_implicitly() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let table = d4::write_rows(root, None, &[MARKER_A]);
    let segs = segments_dir(root, table);
    let seg = segment_path(&segs, 1);
    let before = std::fs::read(&seg).unwrap();
    assert_eq!(segment_version(&before), SEGMENT_VERSION_PLAIN);
    assert!(
        d4::reveals(&before, MARKER_A),
        "dev/test plaintext path (negative control)"
    );

    let c = d4::cipher();
    let err = open_table(root, table, Some(c.clone())).err().unwrap();
    assert!(err.to_string().contains("explicit migration"), "{err}");
    let seal = SegmentSeal::new(c, table.raw());
    let err = SegmentWriter::open_append_with(&segs, 1, DEFAULT_MAX_SEGMENT_BYTES, Some(seal))
        .err()
        .unwrap();
    assert!(err.to_string().contains("explicit migration"), "{err}");
    assert_eq!(
        std::fs::read(&seg).unwrap(),
        before,
        "plaintext segment untouched"
    );
}

#[test]
fn aborted_batch_and_reopen_keep_segments_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let rows = dir.path().join("rows");
    let c = d4::cipher();
    let table = TableId::new(7);
    let cols = [
        (ColumnId::new(1), SqlDataType::BigInt, false),
        (ColumnId::new(2), SqlDataType::Text, true),
    ];
    let schema = schema_from_catalog_columns(table, &cols);
    let mut store = TableStore::create_with_cipher(
        &rows,
        table,
        schema,
        DEFAULT_MAX_SEGMENT_BYTES,
        Some(c.clone()),
    )
    .unwrap();
    let row = |m: &str| vec![StoredValue::Int64(1), StoredValue::String(m.into())];
    store.begin_batch();
    store.insert(&row(MARKER_A)).unwrap();
    store.abort_batch().unwrap();
    assert!(store.is_encrypted(), "reopen after abort keeps the keys");
    store.insert(&row(MARKER_B)).unwrap();
    drop(store);

    let segs = table_dir(&rows, table).join("segments");
    for f in d4::walk(&segs) {
        let raw = std::fs::read(&f).unwrap();
        assert_eq!(
            segment_version(&raw),
            SEGMENT_VERSION_SEALED,
            "{}",
            f.display()
        );
        assert!(!d4::reveals(&raw, MARKER_A) && !d4::reveals(&raw, MARKER_B));
    }
    let reopened =
        TableStore::open_with_cipher(&rows, table, DEFAULT_MAX_SEGMENT_BYTES, Some(c)).unwrap();
    assert!(reopened.scan().count() >= 1);
}

fn copy_dir(from: &Path, to: &Path) {
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
