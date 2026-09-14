//! Cardinality estimation (Phase 6.15.4).

use dmc_model::{ColumnId, TableId, TableStatistics};
use dmc_sql_bind::{BoundColumnRef, BoundExpr, BoundValue};
use dmc_sql_front::BinaryOp;

use super::{
    selectivity::estimate_predicate_selectivity, StatisticsProvider, DEFAULT_FALLBACK_SELECTIVITY,
    FALLBACK_NDV, FALLBACK_TABLE_ROW_COUNT,
};

pub fn clamp_rows(estimated: f64, max_rows: f64) -> f64 {
    if estimated.is_nan() || max_rows.is_nan() {
        return 0.0;
    }
    if max_rows <= 0.0 {
        return 0.0;
    }
    estimated.max(0.0).min(max_rows)
}

pub fn estimate_scan_rows(table_stats: Option<&TableStatistics>) -> f64 {
    match table_stats {
        Some(stats) => stats.row_count as f64,
        None => FALLBACK_TABLE_ROW_COUNT,
    }
}

pub fn estimate_filter_rows(
    input_rows: f64,
    predicate: &BoundExpr,
    stats: &StatisticsProvider,
) -> f64 {
    if input_rows <= 0.0 {
        return 0.0;
    }
    let selectivity = estimate_predicate_selectivity(predicate, stats);
    clamp_rows(input_rows * selectivity, input_rows)
}

pub fn estimate_join_rows(
    left_rows: f64,
    right_rows: f64,
    condition: Option<&BoundExpr>,
    stats: &StatisticsProvider,
) -> f64 {
    if left_rows <= 0.0 || right_rows <= 0.0 {
        return 0.0;
    }
    let upper = left_rows * right_rows;
    let estimated = if let Some(condition) = condition {
        if let Some((left_col, right_col)) = equality_join_columns(condition) {
            let left_ndv = column_ndv(&left_col, stats);
            let right_ndv = column_ndv(&right_col, stats);
            let ndv = left_ndv.max(right_ndv).max(1.0);
            left_rows * right_rows / ndv
        } else {
            left_rows * right_rows * DEFAULT_FALLBACK_SELECTIVITY
        }
    } else {
        left_rows * right_rows
    };
    clamp_rows(estimated, upper)
}

pub fn estimate_aggregate_rows(
    input_rows: f64,
    group_by: &[BoundExpr],
    stats: &StatisticsProvider,
) -> f64 {
    if input_rows <= 0.0 {
        return 0.0;
    }
    if group_by.is_empty() {
        return 1.0;
    }
    let mut groups = 1.0f64;
    for expr in group_by {
        let ndv = expr_ndv(expr, stats, input_rows);
        groups *= ndv.max(1.0);
    }
    clamp_rows(groups, input_rows)
}

pub fn estimate_sort_rows(input_rows: f64) -> f64 {
    input_rows.max(0.0)
}

pub fn estimate_limit_rows(input_rows: f64, limit: u64, offset: u64) -> f64 {
    if input_rows <= 0.0 {
        return 0.0;
    }
    let after_offset = (input_rows - offset as f64).max(0.0);
    after_offset.min(limit as f64)
}

fn column_ndv(col: &BoundColumnRef, stats: &StatisticsProvider) -> f64 {
    stats
        .column_stats(col.table_id, col.column_id)
        .map(|c| c.ndv.max(1) as f64)
        .unwrap_or(FALLBACK_NDV)
}

fn expr_ndv(expr: &BoundExpr, stats: &StatisticsProvider, input_rows: f64) -> f64 {
    match expr {
        BoundExpr::Column(col) => column_ndv(col, stats),
        _ => input_rows.min(FALLBACK_NDV),
    }
}

fn equality_join_columns(condition: &BoundExpr) -> Option<(BoundColumnRef, BoundColumnRef)> {
    match condition {
        BoundExpr::Binary {
            op: BinaryOp::Eq,
            left,
            right,
            ..
        } => match (left.as_ref(), right.as_ref()) {
            (BoundExpr::Column(l), BoundExpr::Column(r)) if l.table_id != r.table_id => {
                Some((l.clone(), r.clone()))
            }
            _ => None,
        },
        BoundExpr::Binary {
            op: BinaryOp::And,
            left,
            right,
            ..
        } => equality_join_columns(left).or_else(|| equality_join_columns(right)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmc_model::{ColumnStatistics, StatValue};
    use dmc_sql_bind::BoundValue;
    use dmc_sql_front::SqlValue;

    fn sample_stats(row_count: u64, ndv: u64) -> StatisticsProvider {
        let table_id = TableId::new(1);
        let col_a = ColumnId::new(1);
        let col_b = ColumnId::new(2);
        let mut columns = std::collections::BTreeMap::new();
        columns.insert(
            col_a,
            ColumnStatistics {
                null_fraction: 0.0,
                ndv,
                min: Some(StatValue::Int64(1)),
                max: Some(StatValue::Int64(row_count as i64)),
            },
        );
        columns.insert(
            col_b,
            ColumnStatistics {
                null_fraction: 0.0,
                ndv,
                min: Some(StatValue::Int64(1)),
                max: Some(StatValue::Int64(100)),
            },
        );
        StatisticsProvider::from_tables([TableStatistics {
            table_id,
            row_count,
            columns,
        }])
    }

    fn col(table: u64, column: u64) -> BoundExpr {
        BoundExpr::Column(BoundColumnRef {
            table_id: TableId::new(table),
            column_id: ColumnId::new(column),
            data_type: dmc_model::SqlDataType::BigInt,
            nullable: false,
            span: Default::default(),
        })
    }

    #[test]
    fn scan_uses_table_row_count() {
        let stats = sample_stats(500, 50);
        assert_eq!(
            estimate_scan_rows(stats.get(TableId::new(1))),
            500.0
        );
    }

    #[test]
    fn scan_missing_statistics_uses_fallback() {
        assert_eq!(estimate_scan_rows(None), FALLBACK_TABLE_ROW_COUNT);
    }

    #[test]
    fn empty_table_scan_is_zero() {
        let stats = StatisticsProvider::from_tables([TableStatistics::empty(TableId::new(1))]);
        assert_eq!(estimate_scan_rows(stats.get(TableId::new(1))), 0.0);
    }

    #[test]
    fn filter_respects_input_bounds() {
        let stats = sample_stats(100, 10);
        let pred = BoundExpr::Binary {
            left: Box::new(col(1, 1)),
            op: BinaryOp::Eq,
            right: Box::new(BoundExpr::Literal {
                value: BoundValue {
                    value: SqlValue::Integer(1),
                    data_type: dmc_model::SqlDataType::BigInt,
                },
                span: Default::default(),
            }),
            data_type: dmc_model::SqlDataType::Boolean,
            span: Default::default(),
        };
        let rows = estimate_filter_rows(100.0, &pred, &stats);
        assert!(rows >= 0.0 && rows <= 100.0);
        assert!((rows - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn join_equality_uses_ndv_formula() {
        let left_id = TableId::new(1);
        let right_id = TableId::new(2);
        let mut left_cols = std::collections::BTreeMap::new();
        left_cols.insert(
            ColumnId::new(1),
            ColumnStatistics {
                null_fraction: 0.0,
                ndv: 100,
                min: Some(StatValue::Int64(1)),
                max: Some(StatValue::Int64(10_000)),
            },
        );
        let mut right_cols = std::collections::BTreeMap::new();
        right_cols.insert(
            ColumnId::new(2),
            ColumnStatistics {
                null_fraction: 0.0,
                ndv: 100,
                min: Some(StatValue::Int64(1)),
                max: Some(StatValue::Int64(100)),
            },
        );
        let stats = StatisticsProvider::from_tables([
            TableStatistics {
                table_id: left_id,
                row_count: 10_000,
                columns: left_cols,
            },
            TableStatistics {
                table_id: right_id,
                row_count: 100,
                columns: right_cols,
            },
        ]);
        let cond = BoundExpr::Binary {
            left: Box::new(col(1, 1)),
            op: BinaryOp::Eq,
            right: Box::new(col(2, 2)),
            data_type: dmc_model::SqlDataType::Boolean,
            span: Default::default(),
        };
        let rows = estimate_join_rows(10_000.0, 100.0, Some(&cond), &stats);
        assert!((rows - 10_000.0).abs() < f64::EPSILON);
    }

    #[test]
    fn aggregate_without_group_returns_one() {
        assert_eq!(estimate_aggregate_rows(100.0, &[], &StatisticsProvider::new()), 1.0);
    }

    #[test]
    fn sort_preserves_cardinality() {
        assert_eq!(estimate_sort_rows(42.0), 42.0);
    }

    #[test]
    fn limit_caps_rows() {
        assert_eq!(estimate_limit_rows(100.0, 10, 0), 10.0);
        assert_eq!(estimate_limit_rows(5.0, 10, 0), 5.0);
    }

    #[test]
    fn empty_input_stays_zero() {
        assert_eq!(estimate_filter_rows(0.0, &col(1, 1), &StatisticsProvider::new()), 0.0);
        assert_eq!(estimate_limit_rows(0.0, 10, 0), 0.0);
    }
}
