//! D4-A stage 4.6: no keyless fallback path downgrades encrypted storage.
//!
//! A writer without keys refuses to replace a sealed file with plaintext, and keyless
//! rebuild / replay of an encrypted store fails instead of defaulting (e.g. to empty
//! statistics) and writing plaintext. Every refusal leaves the sealed files untouched.

#[path = "d4_support/mod.rs"]
mod d4;

use std::path::Path;

use dmc_materialized::{
    StatisticsCatalog, load_materialized_snapshot_with, rebuild_materialized_from_event_log,
    rebuild_materialized_from_event_log_with, save_materialized_snapshot_with,
    save_statistics_catalog, write_state_event_log_with,
};

const MARKER: &str = "D4_KEYLESS_WRITER_MARKER_51c3";

fn sealed_files(root: &Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    d4::walk(root)
        .into_iter()
        .map(|p| {
            let raw = std::fs::read(&p).unwrap();
            (p, raw)
        })
        .collect()
}

#[test]
fn keyless_writers_never_overwrite_sealed_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let c = d4::cipher();
    d4::write_rows(root, Some(c.clone()), &[MARKER]);
    let before = sealed_files(root);

    let snap_path = root.join("snapshot.json");
    let snapshot = load_materialized_snapshot_with(&snap_path, Some(&c))
        .unwrap()
        .unwrap();
    let err = save_materialized_snapshot_with(&snap_path, &snapshot, None)
        .err()
        .unwrap();
    assert!(err.to_string().contains("refusing to overwrite"), "{err}");

    let stats_path = StatisticsCatalog::statistics_path(&root.join("rows"));
    let err = save_statistics_catalog(&stats_path, &StatisticsCatalog::default())
        .err()
        .unwrap();
    assert!(err.to_string().contains("refusing to overwrite"), "{err}");

    assert!(write_state_event_log_with(root.join("state_events.json"), Vec::new(), None).is_err());

    // keyless rebuild of an encrypted store: refused (no default-and-continue)
    assert!(
        rebuild_materialized_from_event_log(&root.join("rows"), &root.join("state_events.json"))
            .is_err()
    );
    // with the keys it works
    assert!(
        rebuild_materialized_from_event_log_with(
            &root.join("rows"),
            &root.join("state_events.json"),
            Some(c.clone()),
        )
        .is_ok()
    );

    // every refusal left the encrypted files as they were; nothing plaintext appeared
    for (p, raw) in &before {
        if p.ends_with("state_events.json") || p.ends_with("snapshot.json") {
            assert_eq!(&std::fs::read(p).unwrap(), raw, "{} untouched", p.display());
        }
    }
    assert!(d4::revealing_files(root, MARKER).is_empty());
    assert!(
        d4::walk(root)
            .iter()
            .all(|p| p.extension().is_none_or(|e| e != "tmp"))
    );
}
