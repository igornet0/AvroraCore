//! Predicate selectivity estimation (Phase 6.15.4).

use dmc_model::{ColumnStatistics, StatValue};
use dmc_sql_bind::{BoundColumnRef, BoundExpr, BoundValue};
use dmc_sql_front::{BinaryOp, SqlValue};

use super::StatisticsProvider;

/// Default selectivity when statistics or expression shape are unknown.
pub const DEFAULT_FALLBACK_SELECTIVITY: f64 = 0.5;

pub fn clamp_selectivity(value: f64) -> f64 {
    if value.is_nan() {
        return DEFAULT_FALLBACK_SELECTIVITY;
    }
    value.clamp(0.0, 1.0)
}

pub fn combine_and_selectivity(left: f64, right: f64) -> f64 {
    clamp_selectivity(clamp_selectivity(left) * clamp_selectivity(right))
}

pub fn combine_or_selectivity(left: f64, right: f64) -> f64 {
    let a = clamp_selectivity(left);
    let b = clamp_selectivity(right);
    clamp_selectivity(a + b - a * b)
}

pub fn estimate_predicate_selectivity(predicate: &BoundExpr, stats: &StatisticsProvider) -> f64 {
    match predicate {
        BoundExpr::Binary { op: BinaryOp::And, left, right, .. } => combine_and_selectivity(
            estimate_predicate_selectivity(left, stats),
            estimate_predicate_selectivity(right, stats),
        ),
        BoundExpr::Binary { op: BinaryOp::Or, left, right, .. } => combine_or_selectivity(
            estimate_predicate_selectivity(left, stats),
            estimate_predicate_selectivity(right, stats),
        ),
        BoundExpr::Binary { op, left, right, .. } => {
            estimate_comparison_selectivity(op, left, right, stats)
        }
        BoundExpr::IsNull { expr, negated, .. } => {
            estimate_is_null_selectivity(expr, *negated, stats)
        }
        BoundExpr::Unary { op: dmc_sql_front::UnaryOp::Not, expr, .. } => {
            clamp_selectivity(1.0 - estimate_predicate_selectivity(expr, stats))
        }
        _ => DEFAULT_FALLBACK_SELECTIVITY,
    }
}

fn estimate_comparison_selectivity(
    op: &BinaryOp,
    left: &BoundExpr,
    right: &BoundExpr,
    stats: &StatisticsProvider,
) -> f64 {
    if let Some((col, lit)) = column_literal_pair(left, right) {
        return estimate_column_literal_selectivity(*op, col, lit, stats);
    }
    if let Some((col, lit)) = column_literal_pair(right, left) {
        return estimate_column_literal_selectivity(reverse_op(*op), col, lit, stats);
    }
    DEFAULT_FALLBACK_SELECTIVITY
}

fn estimate_column_literal_selectivity(
    op: BinaryOp,
    col: &BoundColumnRef,
    lit: &BoundValue,
    stats: &StatisticsProvider,
) -> f64 {
    let Some(column) = stats.column_stats(col.table_id, col.column_id) else {
        return DEFAULT_FALLBACK_SELECTIVITY;
    };

    match op {
        BinaryOp::Eq => equality_selectivity(column),
        BinaryOp::Ne => clamp_selectivity(1.0 - equality_selectivity(column)),
        BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
            range_selectivity(op, column, lit)
        }
        _ => DEFAULT_FALLBACK_SELECTIVITY,
    }
}

fn equality_selectivity(column: &ColumnStatistics) -> f64 {
    if column.ndv == 0 {
        return DEFAULT_FALLBACK_SELECTIVITY;
    }
    clamp_selectivity(1.0 / column.ndv.max(1) as f64)
}

fn range_selectivity(op: BinaryOp, column: &ColumnStatistics, lit: &BoundValue) -> f64 {
    let (Some(min), Some(max)) = (column.min.as_ref(), column.max.as_ref()) else {
        return DEFAULT_FALLBACK_SELECTIVITY;
    };
    if compare_stat_to_literal(min, lit).is_none() || compare_stat_to_literal(max, lit).is_none() {
        return DEFAULT_FALLBACK_SELECTIVITY;
    }

    let min_cmp = compare_stat_to_literal(min, lit);
    let max_cmp = compare_stat_to_literal(max, lit);
    let position = match (min_cmp, max_cmp) {
        (Some(std::cmp::Ordering::Greater), _) | (_, Some(std::cmp::Ordering::Less)) => 0.0,
        (Some(std::cmp::Ordering::Equal), Some(std::cmp::Ordering::Equal)) => 0.5,
        (Some(std::cmp::Ordering::Less), Some(std::cmp::Ordering::Greater)) => {
            let min_key = stat_sort_key(min);
            let max_key = stat_sort_key(max);
            let lit_key = literal_sort_key(lit);
            if (max_key - min_key).abs() < f64::EPSILON {
                0.5
            } else {
                ((lit_key - min_key) / (max_key - min_key)).clamp(0.0, 1.0)
            }
        }
        (Some(std::cmp::Ordering::Less), Some(std::cmp::Ordering::Equal)) => 1.0,
        (Some(std::cmp::Ordering::Equal), Some(std::cmp::Ordering::Greater)) => 0.0,
        _ => return DEFAULT_FALLBACK_SELECTIVITY,
    };

    let fraction = match op {
        BinaryOp::Lt | BinaryOp::Le => position,
        BinaryOp::Gt | BinaryOp::Ge => 1.0 - position,
        _ => return DEFAULT_FALLBACK_SELECTIVITY,
    };
    clamp_selectivity(fraction)
}

fn estimate_is_null_selectivity(expr: &BoundExpr, negated: bool, stats: &StatisticsProvider) -> f64 {
    let fraction = if let BoundExpr::Column(col) = expr {
        stats
            .column_stats(col.table_id, col.column_id)
            .map(|c| c.null_fraction)
            .unwrap_or(DEFAULT_FALLBACK_SELECTIVITY)
    } else {
        DEFAULT_FALLBACK_SELECTIVITY
    };
    clamp_selectivity(if negated { 1.0 - fraction } else { fraction })
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

fn reverse_op(op: BinaryOp) -> BinaryOp {
    match op {
        BinaryOp::Lt => BinaryOp::Gt,
        BinaryOp::Le => BinaryOp::Ge,
        BinaryOp::Gt => BinaryOp::Lt,
        BinaryOp::Ge => BinaryOp::Le,
        other => other,
    }
}

fn compare_stat_to_literal(stat: &StatValue, lit: &BoundValue) -> Option<std::cmp::Ordering> {
    match (stat, &lit.value) {
        (StatValue::Int64(a), SqlValue::Integer(b)) => Some(a.cmp(b)),
        (StatValue::Float64(a), SqlValue::Double(b)) => Some(a.total_cmp(b)),
        (StatValue::Float64(a), SqlValue::Integer(b)) => Some(a.total_cmp(&(*b as f64))),
        (StatValue::Int64(a), SqlValue::Double(b)) => Some((*a as f64).total_cmp(b)),
        (StatValue::String(a), SqlValue::Text(b)) => Some(a.cmp(b)),
        (StatValue::Date(a), SqlValue::Integer(b)) => Some(a.cmp(&(*b as i32))),
        (StatValue::Timestamp(a), SqlValue::Integer(b)) => Some(a.cmp(b)),
        _ => None,
    }
}

fn stat_sort_key(stat: &StatValue) -> f64 {
    match stat {
        StatValue::Int64(v) => *v as f64,
        StatValue::Float64(v) => *v,
        StatValue::String(v) => string_sort_key(v),
        StatValue::Date(v) => *v as f64,
        StatValue::Timestamp(v) => *v as f64,
    }
}

fn literal_sort_key(lit: &BoundValue) -> f64 {
    match &lit.value {
        SqlValue::Integer(v) => *v as f64,
        SqlValue::Double(v) => *v,
        SqlValue::Text(v) => string_sort_key(v),
        _ => 0.0,
    }
}

fn string_sort_key(value: &str) -> f64 {
    let mut key = 0.0f64;
    for (idx, byte) in value.as_bytes().iter().take(8).enumerate() {
        key += (*byte as f64) * 256f64.powi(-(idx as i32 + 1));
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmc_model::{ColumnId, TableId};

    fn col_stats(ndv: u64, null_fraction: f64, min: i64, max: i64) -> ColumnStatistics {
        ColumnStatistics {
            null_fraction,
            ndv,
            min: Some(StatValue::Int64(min)),
            max: Some(StatValue::Int64(max)),
        }
    }

    fn stats_with_column(ndv: u64, null_fraction: f64, min: i64, max: i64) -> StatisticsProvider {
        let table_id = TableId::new(1);
        let column_id = ColumnId::new(1);
        let mut columns = std::collections::BTreeMap::new();
        columns.insert(column_id, col_stats(ndv, null_fraction, min, max));
        StatisticsProvider::from_tables([dmc_model::TableStatistics {
            table_id,
            row_count: 10_000,
            columns,
        }])
    }

    fn col_expr() -> BoundExpr {
        BoundExpr::Column(BoundColumnRef {
            table_id: TableId::new(1),
            column_id: ColumnId::new(1),
            data_type: dmc_model::SqlDataType::BigInt,
            nullable: true,
            span: Default::default(),
        })
    }

    fn lit_int(v: i64) -> BoundExpr {
        BoundExpr::Literal {
            value: BoundValue {
                value: SqlValue::Integer(v),
                data_type: dmc_model::SqlDataType::BigInt,
            },
            span: Default::default(),
        }
    }

    #[test]
    fn equality_selectivity_uses_ndv() {
        let stats = stats_with_column(100, 0.0, 0, 100);
        let pred = BoundExpr::Binary {
            left: Box::new(col_expr()),
            op: BinaryOp::Eq,
            right: Box::new(lit_int(42)),
            data_type: dmc_model::SqlDataType::Boolean,
            span: Default::default(),
        };
        assert!((estimate_predicate_selectivity(&pred, &stats) - 0.01).abs() < f64::EPSILON);
    }

    #[test]
    fn equality_without_ndv_uses_fallback() {
        let stats = stats_with_column(0, 0.0, 0, 100);
        let pred = BoundExpr::Binary {
            left: Box::new(col_expr()),
            op: BinaryOp::Eq,
            right: Box::new(lit_int(1)),
            data_type: dmc_model::SqlDataType::Boolean,
            span: Default::default(),
        };
        assert_eq!(
            estimate_predicate_selectivity(&pred, &stats),
            DEFAULT_FALLBACK_SELECTIVITY
        );
    }

    #[test]
    fn range_lt_linear_fraction() {
        let stats = stats_with_column(100, 0.0, 0, 100);
        let pred = BoundExpr::Binary {
            left: Box::new(col_expr()),
            op: BinaryOp::Lt,
            right: Box::new(lit_int(20)),
            data_type: dmc_model::SqlDataType::Boolean,
            span: Default::default(),
        };
        assert!((estimate_predicate_selectivity(&pred, &stats) - 0.2).abs() < f64::EPSILON);
    }

    #[test]
    fn range_outside_min_is_zero() {
        let stats = stats_with_column(100, 0.0, 10, 100);
        let pred = BoundExpr::Binary {
            left: Box::new(col_expr()),
            op: BinaryOp::Lt,
            right: Box::new(lit_int(5)),
            data_type: dmc_model::SqlDataType::Boolean,
            span: Default::default(),
        };
        assert!((estimate_predicate_selectivity(&pred, &stats)).abs() < f64::EPSILON);
    }

    #[test]
    fn is_null_uses_null_fraction() {
        let stats = stats_with_column(10, 0.25, 0, 10);
        let pred = BoundExpr::IsNull {
            expr: Box::new(col_expr()),
            negated: false,
            data_type: dmc_model::SqlDataType::Boolean,
            span: Default::default(),
        };
        assert!((estimate_predicate_selectivity(&pred, &stats) - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn is_not_null_complement() {
        let stats = stats_with_column(10, 0.25, 0, 10);
        let pred = BoundExpr::IsNull {
            expr: Box::new(col_expr()),
            negated: true,
            data_type: dmc_model::SqlDataType::Boolean,
            span: Default::default(),
        };
        assert!((estimate_predicate_selectivity(&pred, &stats) - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn and_multiplies_selectivities() {
        assert!((combine_and_selectivity(0.5, 0.4) - 0.2).abs() < f64::EPSILON);
    }

    #[test]
    fn or_uses_inclusion_exclusion() {
        assert!((combine_or_selectivity(0.5, 0.5) - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn selectivity_is_clamped() {
        assert_eq!(clamp_selectivity(1.5), 1.0);
        assert_eq!(clamp_selectivity(-0.1), 0.0);
    }

    #[test]
    fn unknown_expression_uses_fallback_constant() {
        let stats = StatisticsProvider::new();
        let pred = BoundExpr::Literal {
            value: BoundValue {
                value: SqlValue::Boolean(true),
                data_type: dmc_model::SqlDataType::Boolean,
            },
            span: Default::default(),
        };
        assert_eq!(
            estimate_predicate_selectivity(&pred, &stats),
            DEFAULT_FALLBACK_SELECTIVITY
        );
    }
}
