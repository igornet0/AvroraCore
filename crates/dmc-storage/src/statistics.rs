//! Collect table statistics from live RowStore state (Phase 6.15.2).

use std::collections::{BTreeMap, BTreeSet};

use dmc_model::{
    ColumnStatistics, SnapshotSequence, SqlDataType, StatValue, Table, TableStatistics,
};

use crate::codec::StoredValue;
use crate::error::{Error, Result};
use crate::index::total_order_f64;
use crate::table_store::TableStore;

/// Canonical distinct-value key for exact NDV (V1 — no HyperLogLog).
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum NdvKey {
    Bool(bool),
    I64(i64),
    F64(u64),
    Str(String),
    Bytes(Vec<u8>),
}

/// Collect optimizer statistics from **live** visible rows (not historical MVCC versions).
pub fn collect_table_statistics(
    table_store: &TableStore,
    table: &Table,
) -> Result<TableStatistics> {
    let snapshot = SnapshotSequence::latest();
    let row_ids = table_store.live_row_ids();
    let row_count = row_ids.len() as u64;

    let mut columns: BTreeMap<dmc_model::ColumnId, ColumnAccumulator> = BTreeMap::new();
    for column in &table.columns {
        columns.insert(
            column.id,
            ColumnAccumulator::new(column.data_type.clone()),
        );
    }

    for row_id in row_ids {
        let values = table_store
            .get_at_snapshot(row_id, snapshot)?
            .ok_or_else(|| Error::RowNotFound(row_id.raw()))?;
        for column in &table.columns {
            let idx = table_store
                .schema()
                .column_index(column.id.raw())
                .ok_or(Error::ColumnNotFound)?;
            let stored = values.get(idx).unwrap_or(&StoredValue::Null);
            columns
                .get_mut(&column.id)
                .expect("column initialized")
                .observe(stored);
        }
    }

    let mut out_columns = BTreeMap::new();
    for (column_id, acc) in columns {
        out_columns.insert(column_id, acc.finish(row_count));
    }

    let stats = TableStatistics {
        table_id: table.id,
        row_count,
        columns: out_columns,
    };
    stats.validate().map_err(map_model_error)?;
    Ok(stats)
}

struct ColumnAccumulator {
    data_type: SqlDataType,
    null_count: u64,
    ndv: BTreeSet<NdvKey>,
    min: Option<StatValue>,
    max: Option<StatValue>,
}

impl ColumnAccumulator {
    fn new(data_type: SqlDataType) -> Self {
        Self {
            data_type,
            null_count: 0,
            ndv: BTreeSet::new(),
            min: None,
            max: None,
        }
    }

    fn observe(&mut self, value: &StoredValue) {
        if matches!(value, StoredValue::Null) {
            self.null_count += 1;
            return;
        }
        if let Some(key) = ndv_key(value) {
            self.ndv.insert(key);
        }
        if let Some(bound) = stat_bound(value, &self.data_type) {
            update_min(&mut self.min, &bound);
            update_max(&mut self.max, &bound);
        }
    }

    fn finish(self, row_count: u64) -> ColumnStatistics {
        let null_fraction = if row_count == 0 {
            0.0
        } else {
            self.null_count as f64 / row_count as f64
        };
        ColumnStatistics {
            null_fraction,
            ndv: self.ndv.len() as u64,
            min: self.min,
            max: self.max,
        }
    }
}

fn ndv_key(value: &StoredValue) -> Option<NdvKey> {
    Some(match value {
        StoredValue::Null => return None,
        StoredValue::Boolean(v) => NdvKey::Bool(*v),
        StoredValue::Int64(v) => NdvKey::I64(*v),
        StoredValue::Float64(v) => NdvKey::F64(total_order_f64(*v)),
        StoredValue::String(v) => NdvKey::Str(v.clone()),
        StoredValue::Binary(v) => NdvKey::Bytes(v.clone()),
        StoredValue::Date(v) => NdvKey::I64(*v as i64),
        StoredValue::Timestamp(v) => NdvKey::I64(*v),
        StoredValue::Decimal(v) => NdvKey::Str(v.clone()),
    })
}

fn stat_bound(value: &StoredValue, data_type: &SqlDataType) -> Option<StatValue> {
    match (data_type, value) {
        (SqlDataType::Integer | SqlDataType::BigInt, StoredValue::Int64(v)) => {
            Some(StatValue::Int64(*v))
        }
        (SqlDataType::Double, StoredValue::Float64(v)) => Some(StatValue::Float64(*v)),
        (SqlDataType::Text, StoredValue::String(v)) => Some(StatValue::String(v.clone())),
        (SqlDataType::Date, StoredValue::Date(v)) => Some(StatValue::Date(*v)),
        (SqlDataType::Timestamp, StoredValue::Timestamp(v)) => Some(StatValue::Timestamp(*v)),
        _ => None,
    }
}

fn update_min(current: &mut Option<StatValue>, candidate: &StatValue) {
    match (current.as_ref(), candidate) {
        (None, _) => *current = Some(candidate.clone()),
        (Some(a), b) if stat_value_cmp(b, a).is_lt() => *current = Some(b.clone()),
        _ => {}
    }
}

fn update_max(current: &mut Option<StatValue>, candidate: &StatValue) {
    match (current.as_ref(), candidate) {
        (None, _) => *current = Some(candidate.clone()),
        (Some(a), b) if stat_value_cmp(b, a).is_gt() => *current = Some(b.clone()),
        _ => {}
    }
}

fn stat_value_cmp(a: &StatValue, b: &StatValue) -> std::cmp::Ordering {
    use StatValue::*;
    match (a, b) {
        (Int64(x), Int64(y)) => x.cmp(y),
        (Float64(x), Float64(y)) => x.total_cmp(y),
        (String(x), String(y)) => x.cmp(y),
        (Date(x), Date(y)) => x.cmp(y),
        (Timestamp(x), Timestamp(y)) => x.cmp(y),
        _ => std::cmp::Ordering::Equal,
    }
}

fn map_model_error(err: dmc_model::Error) -> Error {
    Error::Manifest(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmc_model::{CatalogApplier, ColumnDef};
    use crate::manifest::schema_from_catalog_columns;

    fn table_from_defs(columns: Vec<ColumnDef>) -> Table {
        let mut catalog = dmc_model::Catalog::new();
        catalog.bootstrap_default().unwrap();
        let schema = catalog.schemas().next().unwrap().id;
        let create = catalog
            .create_table_event(schema, "t", columns, None)
            .unwrap();
        catalog.apply(&create, dmc_model::ApplyMode::Live).unwrap();
        let table_id = match create {
            dmc_model::CatalogEvent::CreateTable { id, .. } => id,
            _ => panic!("create table"),
        };
        catalog.table(table_id).unwrap().clone()
    }

    fn store_with_rows(dir: &tempfile::TempDir, table: &Table, rows: Vec<Vec<StoredValue>>) -> TableStore {
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
    fn empty_table_statistics() {
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
    fn nullable_ndv_and_null_fraction() {
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
    fn numeric_min_max_ignores_null() {
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
}
