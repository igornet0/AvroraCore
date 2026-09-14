//! Index candidate resolution for IndexScan (Phase 6.15.6).

use std::collections::HashSet;
use std::ops::Bound;

use dmc_model::{RowValue, SnapshotSequence, SqlDataType};
use dmc_sql_bind::{BoundColumnRef, BoundExpr, BoundValue};
use dmc_sql_front::BinaryOp;
use dmc_storage::{IndexKey, IndexStore, TableStore, row_value_to_component};

use crate::error::{ExecutionError, Result};

/// Returns true when the executor can use this expression for index lookup.
pub fn supports_index_lookup(predicate: &BoundExpr) -> bool {
    match predicate {
        BoundExpr::Binary { op, left, right, .. } => {
            matches!(
                op,
                BinaryOp::Eq | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge
            ) && (column_literal_pair(left, right).is_some()
                || column_literal_pair(right, left).is_some())
        }
        _ => false,
    }
}

pub fn resolve_index_row_ids(
    index_predicate: &BoundExpr,
    index: &IndexStore,
    table: &TableStore,
    snapshot: SnapshotSequence,
    data_type: &SqlDataType,
) -> Result<Vec<dmc_model::RowId>> {
    if !supports_index_lookup(index_predicate) {
        return Err(ExecutionError::IndexScanFallback(
            "unsupported index lookup predicate".into(),
        ));
    }
    let ids = match index_predicate {
        BoundExpr::Binary {
            op: BinaryOp::Eq,
            left,
            right,
            ..
        } => {
            let (_, lit) = column_literal_pair(left, right)
                .or_else(|| column_literal_pair(right, left))
                .ok_or_else(|| ExecutionError::InvalidPlan("index predicate shape".into()))?;
            let key = index_key_from_literal(lit, data_type)?;
            index
                .lookup_visible(&key, table, snapshot)
                .map_err(storage_error)?
        }
        BoundExpr::Binary { op, left, right, .. } => {
            let (_, lit) = column_literal_pair(left, right)
                .or_else(|| column_literal_pair(right, left))
                .ok_or_else(|| ExecutionError::InvalidPlan("index predicate shape".into()))?;
            let key = index_key_from_literal(lit, data_type)?;
            let (lower, upper) = match op {
                BinaryOp::Lt => (Bound::Unbounded, Bound::Excluded(&key)),
                BinaryOp::Le => (Bound::Unbounded, Bound::Included(&key)),
                BinaryOp::Gt => (Bound::Excluded(&key), Bound::Unbounded),
                BinaryOp::Ge => (Bound::Included(&key), Bound::Unbounded),
                _ => {
                    return Err(ExecutionError::InvalidPlan(
                        "unsupported index range op".into(),
                    ))
                }
            };
            index
                .range_scan_visible(lower, upper, table, snapshot)
                .map_err(storage_error)?
        }
        _ => {
            return Err(ExecutionError::IndexScanFallback(
                "unsupported index lookup predicate".into(),
            ))
        }
    };
    Ok(dedupe_preserve_order(ids))
}

fn index_key_from_literal(lit: &BoundValue, data_type: &SqlDataType) -> Result<IndexKey> {
    let row = literal_to_row_value(lit);
    Ok(IndexKey::new(vec![row_value_to_component(&row, data_type)]))
}

fn literal_to_row_value(lit: &BoundValue) -> RowValue {
    use dmc_sql_front::SqlValue;
    match &lit.value {
        SqlValue::Null => RowValue::Null,
        SqlValue::Boolean(v) => RowValue::Boolean(*v),
        SqlValue::Integer(v) => RowValue::Int64(*v),
        SqlValue::Double(v) => RowValue::Float64(*v),
        SqlValue::Text(v) => RowValue::String(v.clone()),
        SqlValue::Decimal(v) => RowValue::Decimal(v.clone()),
        SqlValue::Blob(v) => RowValue::Binary(v.clone()),
        SqlValue::Date(v) => RowValue::Date(parse_date(v)),
        SqlValue::Timestamp(v) => RowValue::Timestamp(parse_timestamp(v)),
    }
}

fn parse_date(raw: &str) -> i32 {
    raw.parse().unwrap_or(0)
}

fn parse_timestamp(raw: &str) -> i64 {
    raw.parse().unwrap_or(0)
}

fn column_literal_pair<'a>(
    left: &'a BoundExpr,
    right: &'a BoundExpr,
) -> Option<(&'a BoundColumnRef, &'a BoundValue)> {
    match (left, right) {
        (BoundExpr::Column(col), BoundExpr::Literal { value, .. }) => Some((col, value)),
        _ => None,
    }
}

fn dedupe_preserve_order(ids: Vec<dmc_model::RowId>) -> Vec<dmc_model::RowId> {
    let mut seen = HashSet::new();
    ids.into_iter()
        .filter(|id| seen.insert(*id))
        .collect()
}

fn storage_error(err: dmc_storage::Error) -> ExecutionError {
    ExecutionError::Storage(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedupe_preserves_first_occurrence_order() {
        let ids = vec![
            dmc_model::RowId::new(1),
            dmc_model::RowId::new(1),
            dmc_model::RowId::new(2),
        ];
        let out = dedupe_preserve_order(ids);
        assert_eq!(out, vec![dmc_model::RowId::new(1), dmc_model::RowId::new(2)]);
    }
}
