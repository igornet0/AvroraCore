//! D4-A stage 4.1: the SQL-plane state event log is sealed at rest.
//!
//! Only the event-log file is asserted here; segments / statistics / snapshot are
//! converted in later sub-steps and are reported, not hidden.

use std::path::Path;
use std::sync::Arc;

use dmc_materialized::{
    EVENT_LOG_CONTEXT, StateEventLog, StateMaterializer, write_state_event_log_with,
};
use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, ColumnDef, DataEvent, RowId, RowValue, SqlDataType,
};
use dmc_vault::storage_cipher::{file_context, looks_sealed};
use dmc_vault::{KeyMaterial, StorageCipher, StoragePurpose};

const MARKER: &str = "D4_EVENT_LOG_PLAINTEXT_MARKER_5b2e";

fn cipher() -> Arc<StorageCipher> {
    Arc::new(
        StorageCipher::new(
            StoragePurpose::ALL
                .into_iter()
                .map(|p| (p, 1, KeyMaterial::random())),
        )
        .unwrap(),
    )
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..=c.len() {
            out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

/// Marker in raw / hex / base64 (all alignments) anywhere in `bytes`.
fn reveals(bytes: &[u8]) -> bool {
    let m = MARKER.as_bytes();
    let mut needles = vec![
        m.to_vec(),
        hex::encode(m).into_bytes(),
        hex::encode_upper(m).into_bytes(),
    ];
    for pad in 0..3usize {
        let mut buf = vec![0u8; pad];
        buf.extend_from_slice(m);
        let e = b64(&buf);
        needles.push(
            e[if pad == 0 { 0 } else { 4 }..e.len() - 4]
                .as_bytes()
                .to_vec(),
        );
    }
    needles
        .iter()
        .any(|n| bytes.windows(n.len()).any(|w| w == n.as_slice()))
}

fn open(
    root: &Path,
    c: Option<Arc<StorageCipher>>,
) -> dmc_materialized::Result<StateMaterializer<dmc_materialized::FileStateEventLog>> {
    StateMaterializer::open_with_cipher(
        root.join("rows"),
        root.join("snapshot.json"),
        root.join("state_events.json"),
        c,
    )
}

fn write_marker_row(root: &Path, c: &Arc<StorageCipher>) {
    let mut mat = open(root, Some(c.clone())).unwrap();
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
    let table_id = match &create {
        dmc_model::CatalogEvent::CreateTable { id, .. } => *id,
        _ => unreachable!(),
    };
    events.push(create);
    for e in events {
        mat.mutate_catalog(e).unwrap();
    }
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: RowId::new(1),
        values: vec![RowValue::Int64(1), RowValue::String(MARKER.into())],
    })
    .unwrap();
}

#[test]
fn event_log_is_sealed_and_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let c = cipher();
    write_marker_row(root, &c);

    let log = root.join("state_events.json");
    let raw = std::fs::read(&log).unwrap();
    assert!(looks_sealed(&raw), "event log is sealed");
    assert!(
        !reveals(&raw),
        "no plaintext value in the event log (raw/hex/base64)"
    );
    assert!(
        !root.join("state_events.tmp").exists(),
        "no plaintext temp file left"
    );

    // unlocked (same keys): replay works and the value is there
    let mat = open(root, Some(c.clone())).unwrap();
    assert!(format!("{:?}", mat.event_log().events()).contains(MARKER));
    drop(mat);

    // locked (no keys): refused, not read as empty
    let err = open(root, None).err().expect("no keys → refused");
    assert!(err.to_string().contains("keys required"), "{err}");
    // another installation's keys: refused
    assert!(open(root, Some(cipher())).is_err());
    // any tampering: refused
    let mut t = raw.clone();
    let mid = t.len() / 2;
    t[mid] ^= 1;
    std::fs::write(&log, &t).unwrap();
    assert!(open(root, Some(c.clone())).is_err());
    std::fs::write(&log, &raw).unwrap();
    assert!(open(root, Some(c.clone())).is_ok());
}

#[test]
fn plaintext_log_is_never_converted_implicitly() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // legacy plaintext data root
    {
        let mut mat = StateMaterializer::open(
            root.join("rows"),
            root.join("snapshot.json"),
            root.join("state_events.json"),
        )
        .unwrap();
        let mut catalog = Catalog::new();
        for e in catalog.bootstrap_default().unwrap() {
            mat.mutate_catalog(e).unwrap();
        }
    }
    let before = std::fs::read(root.join("state_events.json")).unwrap();
    assert!(!looks_sealed(&before));
    let err = open(root, Some(cipher()))
        .err()
        .expect("plaintext + keys → refused");
    assert!(err.to_string().contains("explicit migration"), "{err}");
    assert_eq!(
        std::fs::read(root.join("state_events.json")).unwrap(),
        before,
        "file untouched"
    );
}

#[test]
fn whole_log_writer_seals_with_the_events_purpose_and_context() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("live").join("state_events.json");
    let c = cipher();
    write_state_event_log_with(&path, Vec::new(), Some(c.clone())).unwrap();
    let raw = std::fs::read(&path).unwrap();
    assert!(
        c.open(
            StoragePurpose::Events,
            &file_context(EVENT_LOG_CONTEXT),
            &raw
        )
        .is_ok()
    );
    // bound to its purpose: not openable as another purpose
    assert!(
        c.open(
            StoragePurpose::Snapshot,
            &file_context(EVENT_LOG_CONTEXT),
            &raw
        )
        .is_err()
    );
}
