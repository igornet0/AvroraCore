//! Phase 6.15.1 — statistics model + catalog persistence skeleton.

use std::collections::BTreeMap;

use dmc_materialized::StatisticsCatalog;
use dmc_model::{
    ColumnId, ColumnStatistics, StatValue, TableId, TableStatistics,
};
use tempfile::tempdir;

fn sample_stats(table_id: u64, row_count: u64, ndv: u64) -> TableStatistics {
    TableStatistics {
        table_id: TableId::new(table_id),
        row_count,
        columns: BTreeMap::from([(
            ColumnId::new(1),
            ColumnStatistics {
                null_fraction: 0.0,
                ndv,
                min: Some(StatValue::Int64(1)),
                max: Some(StatValue::Int64(row_count as i64)),
            },
        )]),
    }
}

#[test]
fn catalog_upsert_and_get() {
    let mut catalog = StatisticsCatalog::new();
    assert!(catalog.get(TableId::new(1)).is_none());
    catalog.upsert(sample_stats(1, 100, 50)).unwrap();
    let got = catalog.get(TableId::new(1)).unwrap();
    assert_eq!(got.row_count, 100);
    assert_eq!(got.columns.get(&ColumnId::new(1)).unwrap().ndv, 50);
}

#[test]
fn catalog_replace_existing_table() {
    let mut catalog = StatisticsCatalog::new();
    catalog.upsert(sample_stats(1, 10, 10)).unwrap();
    catalog.upsert(sample_stats(1, 200, 100)).unwrap();
    assert_eq!(catalog.get(TableId::new(1)).unwrap().row_count, 200);
    assert_eq!(catalog.len(), 1);
}

#[test]
fn catalog_remove_table() {
    let mut catalog = StatisticsCatalog::new();
    catalog.upsert(sample_stats(1, 5, 5)).unwrap();
    let removed = catalog.remove(TableId::new(1)).unwrap();
    assert_eq!(removed.row_count, 5);
    assert!(catalog.is_empty());
    assert!(catalog.get(TableId::new(1)).is_none());
}

#[test]
fn restart_persistence_roundtrip() {
    let dir = tempdir().unwrap();
    {
        let mut catalog = StatisticsCatalog::open(dir.path()).unwrap();
        catalog.upsert(sample_stats(3, 42, 40)).unwrap();
        catalog.upsert(TableStatistics::empty(TableId::new(7))).unwrap();
        catalog.persist().unwrap();
    }
    let reloaded = StatisticsCatalog::open(dir.path()).unwrap();
    assert_eq!(reloaded.len(), 2);
    assert_eq!(
        reloaded.get(TableId::new(3)).unwrap().row_count,
        42
    );
    assert_eq!(reloaded.get(TableId::new(7)).unwrap().row_count, 0);
}

#[test]
fn missing_statistics_file_is_empty_fallback() {
    let dir = tempdir().unwrap();
    let catalog = StatisticsCatalog::open(dir.path()).unwrap();
    assert!(catalog.is_empty());
    assert!(catalog.get(TableId::new(99)).is_none());
}

#[test]
fn reload_after_external_persist() {
    let dir = tempdir().unwrap();
    let mut catalog = StatisticsCatalog::open(dir.path()).unwrap();
    catalog.upsert(sample_stats(1, 1, 1)).unwrap();
    catalog.persist().unwrap();
    catalog.remove(TableId::new(1));
    assert!(catalog.is_empty());
    catalog.reload().unwrap();
    assert!(catalog.contains(TableId::new(1)));
}

#[test]
fn invalid_statistics_rejected_on_upsert() {
    let mut catalog = StatisticsCatalog::new();
    let bad = TableStatistics {
        table_id: TableId::new(1),
        row_count: 2,
        columns: BTreeMap::from([(
            ColumnId::new(1),
            ColumnStatistics {
                null_fraction: 0.0,
                ndv: 10,
                min: None,
                max: None,
            },
        )]),
    };
    assert!(catalog.upsert(bad).is_err());
}

#[test]
fn catalog_delete_does_not_affect_other_tables() {
    let mut catalog = StatisticsCatalog::new();
    catalog.upsert(sample_stats(1, 1, 1)).unwrap();
    catalog.upsert(sample_stats(2, 2, 2)).unwrap();
    catalog.remove(TableId::new(1));
    assert!(catalog.get(TableId::new(2)).is_some());
}
