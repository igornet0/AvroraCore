//! Shared helpers for the D4-A at-rest tests of this crate.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use dmc_materialized::{FileStateEventLog, StateMaterializer};
use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, ColumnDef, DataEvent, RowId, RowValue, SqlDataType, TableId,
};
use dmc_vault::{KeyMaterial, StorageCipher, StoragePurpose};

pub fn cipher() -> Arc<StorageCipher> {
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

/// `marker` in raw / hex / HEX / base64 (all alignments) anywhere in `bytes`.
pub fn reveals(bytes: &[u8], marker: &str) -> bool {
    let m = marker.as_bytes();
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

pub fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

/// Files under `root` revealing `marker`, as paths relative to `root`.
pub fn revealing_files(root: &Path, marker: &str) -> Vec<String> {
    walk(root)
        .into_iter()
        .filter(|f| reveals(&std::fs::read(f).unwrap_or_default(), marker))
        .map(|f| f.strip_prefix(root).unwrap().display().to_string())
        .collect()
}

pub fn open(
    root: &Path,
    c: Option<Arc<StorageCipher>>,
) -> dmc_materialized::Result<StateMaterializer<FileStateEventLog>> {
    StateMaterializer::open_with_cipher(
        root.join("rows"),
        root.join("snapshot.json"),
        root.join("state_events.json"),
        c,
    )
}

/// Fresh store: table `t (id BIGINT PK, note TEXT)` with one row per marker.
pub fn write_rows(root: &Path, c: Option<Arc<StorageCipher>>, markers: &[&str]) -> TableId {
    let mut mat = open(root, c).unwrap();
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
    for (i, m) in markers.iter().enumerate() {
        mat.mutate_data(DataEvent::InsertRow {
            table_id,
            row_id: RowId::new(i as u64 + 1),
            values: vec![RowValue::Int64(i as i64 + 1), RowValue::String((*m).into())],
        })
        .unwrap();
    }
    mat.persist_snapshot_if_configured().unwrap();
    table_id
}
