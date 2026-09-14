//! Hash join build-side decisions (Phase 6.15.5).

use std::collections::BTreeSet;

use dmc_model::TableId;

use crate::plan::LogicalPlan;

use super::{estimate_plan, StatisticsProvider, CostModel};
use super::decisions::JoinBuildSide;

pub fn choose_join_build_side(
    left: &LogicalPlan,
    right: &LogicalPlan,
    stats: &StatisticsProvider,
    model: &CostModel,
) -> JoinBuildSide {
    let left_rows = estimate_plan(left, stats, model).output_rows;
    let right_rows = estimate_plan(right, stats, model).output_rows;
    if left_rows < right_rows {
        JoinBuildSide::Left
    } else if right_rows < left_rows {
        JoinBuildSide::Right
    } else {
        let left_table = min_table_id(left);
        let right_table = min_table_id(right);
        if left_table.raw() <= right_table.raw() {
            JoinBuildSide::Left
        } else {
            JoinBuildSide::Right
        }
    }
}

pub fn min_table_id(plan: &LogicalPlan) -> TableId {
    let mut tables = BTreeSet::new();
    collect_scan_tables(plan, &mut tables);
    tables
        .into_iter()
        .next()
        .unwrap_or_else(|| TableId::new(0))
}

fn collect_scan_tables(plan: &LogicalPlan, out: &mut BTreeSet<TableId>) {
    match plan {
        LogicalPlan::Scan(scan) => {
            out.insert(scan.table_id);
        }
        LogicalPlan::Filter { input, .. }
        | LogicalPlan::Project { input, .. }
        | LogicalPlan::Having { input, .. }
        | LogicalPlan::Sort { input, .. }
        | LogicalPlan::Limit { input, .. }
        | LogicalPlan::Aggregate { input, .. } => collect_scan_tables(input, out),
        LogicalPlan::Join { left, right, .. } => {
            collect_scan_tables(left, out);
            collect_scan_tables(right, out);
        }
        LogicalPlan::Empty
        | LogicalPlan::Insert(_)
        | LogicalPlan::Update(_)
        | LogicalPlan::Delete(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmc_model::{ColumnId, ColumnStatistics, StatValue, TableId, TableStatistics};
    use dmc_sql_bind::{BoundColumnRef, BoundExpr};
    use crate::plan::{LogicalPlan, LogicalScan};

    fn scan(table: u64) -> LogicalPlan {
        LogicalPlan::Scan(LogicalScan {
            table_id: TableId::new(table),
            alias: None,
            columns: vec![ColumnId::new(1)],
            all_columns: false,
        })
    }

    fn stats_for(tables: &[(u64, u64)]) -> StatisticsProvider {
        StatisticsProvider::from_tables(tables.iter().map(|(table, rows)| {
            TableStatistics {
                table_id: TableId::new(*table),
                row_count: *rows,
                columns: std::collections::BTreeMap::from([(
                    ColumnId::new(1),
                    ColumnStatistics {
                        null_fraction: 0.0,
                        ndv: (*rows).max(1),
                        min: Some(StatValue::Int64(1)),
                        max: Some(StatValue::Int64(*rows as i64)),
                    },
                )]),
            }
        }))
    }

    #[test]
    fn smaller_left_is_build_side() {
        let stats = stats_for(&[(1, 10), (2, 1000)]);
        let side = choose_join_build_side(&scan(1), &scan(2), &stats, &CostModel::default());
        assert_eq!(side, JoinBuildSide::Left);
    }

    #[test]
    fn smaller_right_is_build_side() {
        let stats = stats_for(&[(1, 1000), (2, 10)]);
        let side = choose_join_build_side(&scan(1), &scan(2), &stats, &CostModel::default());
        assert_eq!(side, JoinBuildSide::Right);
    }

    #[test]
    fn equal_cardinality_uses_lower_table_id_as_build_side() {
        let stats = stats_for(&[(1, 100), (2, 100)]);
        let side = choose_join_build_side(&scan(2), &scan(1), &stats, &CostModel::default());
        assert_eq!(side, JoinBuildSide::Right);
    }

    #[test]
    fn missing_stats_use_fallback_without_panic() {
        let side = choose_join_build_side(
            &scan(5),
            &scan(9),
            &StatisticsProvider::new(),
            &CostModel::default(),
        );
        assert!(matches!(side, JoinBuildSide::Left | JoinBuildSide::Right));
    }
}
