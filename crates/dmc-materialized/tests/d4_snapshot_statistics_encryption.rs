//! D4-A stage 4.2: materialized snapshot (catalog checkpoint) and planner statistics are
//! sealed at rest. Row segments and indexes are converted in later sub-steps; files that
//! still reveal the marker are printed (not hidden) and asserted only for this step.

#[path = "d4_support/mod.rs"]
mod d4;

use dmc_materialized::{
    SNAPSHOT_CONTEXT, STATISTICS_CONTEXT, StateMaterializer, StatisticsCatalog,
    load_materialized_snapshot_with,
};
use dmc_vault::StoragePurpose;
use dmc_vault::storage_cipher::{file_context, looks_sealed};

const MARKER: &str = "D4_SNAPSHOT_STATS_PLAINTEXT_MARKER_83af";

#[test]
fn snapshot_and_statistics_are_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let c = d4::cipher();
    let table = d4::write_rows(root, Some(c.clone()), &[MARKER]);

    let snapshot = std::fs::read(root.join("snapshot.json")).unwrap();
    let stats = std::fs::read(StatisticsCatalog::statistics_path(&root.join("rows"))).unwrap();
    for (name, raw) in [("snapshot", &snapshot), ("statistics", &stats)] {
        assert!(looks_sealed(raw), "{name} sealed");
        assert!(!d4::reveals(raw, MARKER), "{name} reveals the value");
    }
    // bound to purpose and context
    assert!(
        c.open(
            StoragePurpose::Snapshot,
            &file_context(SNAPSHOT_CONTEXT),
            &snapshot
        )
        .is_ok()
    );
    assert!(
        c.open(
            StoragePurpose::Statistics,
            &file_context(STATISTICS_CONTEXT),
            &stats
        )
        .is_ok()
    );
    assert!(
        c.open(
            StoragePurpose::Snapshot,
            &file_context(STATISTICS_CONTEXT),
            &stats
        )
        .is_err()
    );
    // no plaintext temp files
    assert!(
        d4::walk(root)
            .iter()
            .all(|p| p.extension().is_none_or(|e| e != "tmp"))
    );

    // unlocked (same keys): snapshot-based recovered open + statistics load
    let recovered = StateMaterializer::open_recovered_with_cipher(
        root.join("rows"),
        root.join("snapshot.json"),
        root.join("state_events.json"),
        Some(c.clone()),
    )
    .unwrap();
    assert!(recovered.catalog().tables().any(|t| t.id == table));
    assert!(
        recovered.statistics().get(table).is_some(),
        "statistics decrypted"
    );

    // locked (no keys) / other keys: refused, never read as empty
    let err = load_materialized_snapshot_with(&root.join("snapshot.json"), None)
        .err()
        .unwrap();
    assert!(err.to_string().contains("keys required"), "{err}");
    let err = StatisticsCatalog::open_with(root.join("rows"), None)
        .err()
        .unwrap();
    assert!(err.to_string().contains("keys required"), "{err}");
    let other = d4::cipher();
    assert!(load_materialized_snapshot_with(&root.join("snapshot.json"), Some(&other)).is_err());
    assert!(StatisticsCatalog::open_with(root.join("rows"), Some(other)).is_err());

    // residual (later sub-steps): which files still reveal the value
    println!(
        "still plaintext after 4.2: {:?}",
        d4::revealing_files(root, MARKER)
    );
    let residual = d4::revealing_files(root, MARKER);
    assert!(
        residual.iter().all(|f| f.contains("segments")),
        "only row segments may still reveal values after 4.2: {residual:?}"
    );
}

#[test]
fn plaintext_snapshot_and_statistics_are_not_converted_implicitly() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    d4::write_rows(root, None, &[MARKER]);
    let snap_before = std::fs::read(root.join("snapshot.json")).unwrap();
    let stats_path = StatisticsCatalog::statistics_path(&root.join("rows"));
    let stats_before = std::fs::read(&stats_path).unwrap();
    assert!(!looks_sealed(&snap_before) && !looks_sealed(&stats_before));
    let c = d4::cipher();
    let e = load_materialized_snapshot_with(&root.join("snapshot.json"), Some(&c))
        .err()
        .unwrap();
    assert!(e.to_string().contains("explicit migration"), "{e}");
    let e = StatisticsCatalog::open_with(root.join("rows"), Some(c))
        .err()
        .unwrap();
    assert!(e.to_string().contains("explicit migration"), "{e}");
    assert_eq!(
        std::fs::read(root.join("snapshot.json")).unwrap(),
        snap_before
    );
    assert_eq!(std::fs::read(&stats_path).unwrap(), stats_before);
}

#[test]
fn tampered_snapshot_or_statistics_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let c = d4::cipher();
    d4::write_rows(root, Some(c.clone()), &[MARKER]);
    for path in [
        root.join("snapshot.json"),
        StatisticsCatalog::statistics_path(&root.join("rows")),
    ] {
        let raw = std::fs::read(&path).unwrap();
        let mut t = raw.clone();
        let i = t.len() - 3;
        t[i] ^= 0x10;
        std::fs::write(&path, &t).unwrap();
        let snap = load_materialized_snapshot_with(&root.join("snapshot.json"), Some(&c));
        let stats = StatisticsCatalog::open_with(root.join("rows"), Some(c.clone()));
        assert!(
            snap.is_err() || stats.is_err(),
            "{} tampering detected",
            path.display()
        );
        std::fs::write(&path, &raw).unwrap();
    }
}
