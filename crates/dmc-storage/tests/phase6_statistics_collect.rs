//! Phase 6.15.2 — collect_table_statistics from live RowStore rows.

use dmc_model::{CatalogApplier, ColumnDef, SqlDataType, StatValue};
use dmc_storage::{collect_table_statistics, schema_from_catalog_columns, StoredValue, TableStore};

fn table_from_defs(columns: Vec<ColumnDef>) -> dmc_model::Table {
    let mut catalog = dmc_model::Catalog::new();
    catalog.bootstrap_default().unwrap();
    let schema = catalog.schemas().next().unwrap().id;
    let create = catalog
        .create_table_event(schema, "t", columns, None)
        .unwrap();
    catalog
        .apply(&create, dmc_model::ApplyMode::Live)
        .unwrap();
    let table_id = match create {
        dmc_model::CatalogEvent::CreateTable { id, .. } => id,
        _ => panic!("create table"),
    };
    catalog.table(table_id).unwrap().clone()
}

fn store_with_rows(
    dir: &tempfile::TempDir,
    table: &dmc_model::Table,
    rows: Vec<Vec<StoredValue>>,
) -> TableStore {
    let cols: Vec<_> = table
        .columns
        .iter()
        .map(|c| (c.id, c.data_type.clone(), c.nullable))
        .collect();
    let schema = schema_from_catalog_columns(table.id, &cols);
    let mut store = TableStore::create(dir.path(), table.id, schema).unwrap();
    for (idx, values) in rows.into_iter().enumerate() {
        store
            .insert_with_sequence(
                dmc_model::RowId::new((idx + 1) as u64),
                &values,
                idx as u64 + 1,
            )
            .unwrap();
    }
    store
}

#[test]
fn empty_table() {
    let dir = tempfile::tempdir().unwrap();
    let table = table_from_defs(vec![ColumnDef {
        name: "n".into(),
        data_type: SqlDataType::BigInt,
        nullable: true,
        default: None,
    }]);
    let store = store_with_rows(&dir, &table, vec![]);
    let stats = collect_table_statistics(&store, &table).unwrap();
    assert_eq!(stats.row_count, 0);
    let col = stats.columns.get(&table.columns[0].id).unwrap();
    assert_eq!(col.ndv, 0);
    assert_eq!(col.null_fraction, 0.0);
    assert!(col.min.is_none());
    assert!(col.max.is_none());
}

#[test]
fn single_column_row_count() {
    let dir = tempfile::tempdir().unwrap();
    let table = table_from_defs(vec![ColumnDef {
        name: "n".into(),
        data_type: SqlDataType::Integer,
        nullable: false,
        default: None,
    }]);
    let store = store_with_rows(
        &dir,
        &table,
        vec![vec![StoredValue::Int64(1)], vec![StoredValue::Int64(2)]],
    );
    let stats = collect_table_statistics(&store, &table).unwrap();
    assert_eq!(stats.row_count, 2);
}

#[test]
fn nullable_column_null_fraction() {
    let dir = tempfile::tempdir().unwrap();
    let table = table_from_defs(vec![ColumnDef {
        name: "v".into(),
        data_type: SqlDataType::Text,
        nullable: true,
        default: None,
    }]);
    let col = table.columns[0].id;
    let store = store_with_rows(
        &dir,
        &table,
        vec![
            vec![StoredValue::Null],
            vec![StoredValue::String("x".into())],
        ],
    );
    let stats = collect_table_statistics(&store, &table).unwrap();
    let c = stats.columns.get(&col).unwrap();
    assert!((c.null_fraction - 0.5).abs() < f64::EPSILON);
}

#[test]
fn duplicate_values_ndv() {
    let dir = tempfile::tempdir().unwrap();
    let table = table_from_defs(vec![ColumnDef {
        name: "v".into(),
        data_type: SqlDataType::Text,
        nullable: true,
        default: None,
    }]);
    let col = table.columns[0].id;
    let store = store_with_rows(
        &dir,
        &table,
        vec![
            vec![StoredValue::Null],
            vec![StoredValue::Null],
            vec![StoredValue::String("A".into())],
            vec![StoredValue::String("A".into())],
            vec![StoredValue::String("B".into())],
        ],
    );
    let stats = collect_table_statistics(&store, &table).unwrap();
    assert_eq!(stats.row_count, 5);
    let c = stats.columns.get(&col).unwrap();
    assert!((c.null_fraction - 0.4).abs() < f64::EPSILON);
    assert_eq!(c.ndv, 2);
}

#[test]
fn all_null_column() {
    let dir = tempfile::tempdir().unwrap();
    let table = table_from_defs(vec![ColumnDef {
        name: "v".into(),
        data_type: SqlDataType::BigInt,
        nullable: true,
        default: None,
    }]);
    let col = table.columns[0].id;
    let store = store_with_rows(
        &dir,
        &table,
        vec![
            vec![StoredValue::Null],
            vec![StoredValue::Null],
            vec![StoredValue::Null],
        ],
    );
    let stats = collect_table_statistics(&store, &table).unwrap();
    let c = stats.columns.get(&col).unwrap();
    assert_eq!(c.ndv, 0);
    assert!((c.null_fraction - 1.0).abs() < f64::EPSILON);
    assert!(c.min.is_none());
    assert!(c.max.is_none());
}

#[test]
fn numeric_min_max() {
    let dir = tempfile::tempdir().unwrap();
    let table = table_from_defs(vec![ColumnDef {
        name: "n".into(),
        data_type: SqlDataType::BigInt,
        nullable: true,
        default: None,
    }]);
    let col = table.columns[0].id;
    let store = store_with_rows(
        &dir,
        &table,
        vec![
            vec![StoredValue::Null],
            vec![StoredValue::Int64(10)],
            vec![StoredValue::Int64(20)],
            vec![StoredValue::Int64(30)],
        ],
    );
    let stats = collect_table_statistics(&store, &table).unwrap();
    let c = stats.columns.get(&col).unwrap();
    assert_eq!(c.min, Some(StatValue::Int64(10)));
    assert_eq!(c.max, Some(StatValue::Int64(30)));
}

#[test]
fn double_min_max() {
    let dir = tempfile::tempdir().unwrap();
    let table = table_from_defs(vec![ColumnDef {
        name: "f".into(),
        data_type: SqlDataType::Double,
        nullable: false,
        default: None,
    }]);
    let col = table.columns[0].id;
    let store = store_with_rows(
        &dir,
        &table,
        vec![
            vec![StoredValue::Float64(1.5)],
            vec![StoredValue::Float64(3.0)],
        ],
    );
    let stats = collect_table_statistics(&store, &table).unwrap();
    let c = stats.columns.get(&col).unwrap();
    assert_eq!(c.min, Some(StatValue::Float64(1.5)));
    assert_eq!(c.max, Some(StatValue::Float64(3.0)));
}

#[test]
fn string_min_max() {
    let dir = tempfile::tempdir().unwrap();
    let table = table_from_defs(vec![ColumnDef {
        name: "s".into(),
        data_type: SqlDataType::Text,
        nullable: false,
        default: None,
    }]);
    let col = table.columns[0].id;
    let store = store_with_rows(
        &dir,
        &table,
        vec![
            vec![StoredValue::String("zebra".into())],
            vec![StoredValue::String("alpha".into())],
        ],
    );
    let stats = collect_table_statistics(&store, &table).unwrap();
    let c = stats.columns.get(&col).unwrap();
    assert_eq!(c.min, Some(StatValue::String("alpha".into())));
    assert_eq!(c.max, Some(StatValue::String("zebra".into())));
}

#[test]
fn date_and_timestamp_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let table = table_from_defs(vec![
        ColumnDef {
            name: "d".into(),
            data_type: SqlDataType::Date,
            nullable: false,
            default: None,
        },
        ColumnDef {
            name: "ts".into(),
            data_type: SqlDataType::Timestamp,
            nullable: false,
            default: None,
        },
    ]);
    let date_col = table.columns[0].id;
    let ts_col = table.columns[1].id;
    let store = store_with_rows(
        &dir,
        &table,
        vec![
            vec![StoredValue::Date(100), StoredValue::Timestamp(200)],
            vec![StoredValue::Date(300), StoredValue::Timestamp(400)],
        ],
    );
    let stats = collect_table_statistics(&store, &table).unwrap();
    let d = stats.columns.get(&date_col).unwrap();
    assert_eq!(d.min, Some(StatValue::Date(100)));
    assert_eq!(d.max, Some(StatValue::Date(300)));
    let ts = stats.columns.get(&ts_col).unwrap();
    assert_eq!(ts.min, Some(StatValue::Timestamp(200)));
    assert_eq!(ts.max, Some(StatValue::Timestamp(400)));
}

#[test]
fn unsupported_type_has_ndv_without_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let table = table_from_defs(vec![ColumnDef {
        name: "b".into(),
        data_type: SqlDataType::Boolean,
        nullable: true,
        default: None,
    }]);
    let col = table.columns[0].id;
    let store = store_with_rows(
        &dir,
        &table,
        vec![
            vec![StoredValue::Boolean(true)],
            vec![StoredValue::Boolean(false)],
            vec![StoredValue::Boolean(true)],
        ],
    );
    let stats = collect_table_statistics(&store, &table).unwrap();
    let c = stats.columns.get(&col).unwrap();
    assert_eq!(c.ndv, 2);
    assert!(c.min.is_none());
    assert!(c.max.is_none());
}

#[test]
fn multiple_columns_independent() {
    let dir = tempfile::tempdir().unwrap();
    let table = table_from_defs(vec![
        ColumnDef {
            name: "a".into(),
            data_type: SqlDataType::BigInt,
            nullable: false,
            default: None,
        },
        ColumnDef {
            name: "b".into(),
            data_type: SqlDataType::Text,
            nullable: true,
            default: None,
        },
    ]);
    let a = table.columns[0].id;
    let b = table.columns[1].id;
    let store = store_with_rows(
        &dir,
        &table,
        vec![
            vec![StoredValue::Int64(1), StoredValue::Null],
            vec![StoredValue::Int64(2), StoredValue::String("x".into())],
        ],
    );
    let stats = collect_table_statistics(&store, &table).unwrap();
    assert_eq!(stats.columns.len(), 2);
    assert_eq!(stats.columns.get(&a).unwrap().ndv, 2);
    assert!((stats.columns.get(&b).unwrap().null_fraction - 0.5).abs() < f64::EPSILON);
}

#[test]
fn collect_is_deterministic() {
    let dir = tempfile::tempdir().unwrap();
    let table = table_from_defs(vec![ColumnDef {
        name: "s".into(),
        data_type: SqlDataType::Text,
        nullable: false,
        default: None,
    }]);
    let store = store_with_rows(
        &dir,
        &table,
        vec![
            vec![StoredValue::String("b".into())],
            vec![StoredValue::String("a".into())],
        ],
    );
    let a = collect_table_statistics(&store, &table).unwrap();
    let b = collect_table_statistics(&store, &table).unwrap();
    assert_eq!(a, b);
}
