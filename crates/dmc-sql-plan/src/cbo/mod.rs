//! Phase 6.15.4–6.15.5 — cardinality/cost estimation and CBO decisions.

mod apply;
mod cardinality;
mod cost;
mod decisions;
mod index_choice;
mod join_choice;
mod selectivity;

pub use cardinality::{
    estimate_aggregate_rows, estimate_filter_rows, estimate_join_rows, estimate_limit_rows,
    estimate_scan_rows, estimate_sort_rows, clamp_rows,
};
pub use cost::{
    cost_aggregate, cost_filter, cost_hash_join, cost_index_scan, cost_limit, cost_project,
    cost_seq_scan, cost_sort, CostModel, PlanCost,
};
pub use apply::plan_cbo_decisions;
pub use decisions::{
    CboDecisionCursor, CboDecisions, JoinBuildSide, ScanAccessChoice,
};
pub use index_choice::{
    choose_scan_access, index_column_type, is_indexable_comparison, is_scan_chain,
    peel_scan_chain,
};
pub use join_choice::{choose_join_build_side, min_table_id};
pub use selectivity::{
    combine_and_selectivity, combine_or_selectivity, estimate_predicate_selectivity,
    clamp_selectivity, DEFAULT_FALLBACK_SELECTIVITY,
};

/// Row count assumed for a table with no statistics (conservative, deterministic).
pub const FALLBACK_TABLE_ROW_COUNT: f64 = 1_000.0;

/// NDV assumed when column statistics are missing (join/selectivity fallback).
pub const FALLBACK_NDV: f64 = 100.0;

use std::collections::BTreeMap;

use dmc_model::{ColumnId, ColumnStatistics, TableId, TableStatistics};

use crate::plan::LogicalPlan;

/// Read-only statistics lookup for cost estimation.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct StatisticsProvider {
    tables: BTreeMap<TableId, TableStatistics>,
}

impl StatisticsProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_tables(tables: impl IntoIterator<Item = TableStatistics>) -> Self {
        let mut provider = Self::new();
        for table in tables {
            provider.upsert(table);
        }
        provider
    }

    pub fn upsert(&mut self, stats: TableStatistics) {
        self.tables.insert(stats.table_id, stats);
    }

    pub fn get(&self, table_id: TableId) -> Option<&TableStatistics> {
        self.tables.get(&table_id)
    }

    pub fn table_row_count(&self, table_id: TableId) -> f64 {
        self.get(table_id)
            .map(|t| t.row_count as f64)
            .unwrap_or(FALLBACK_TABLE_ROW_COUNT)
    }

    pub fn column_stats(&self, table_id: TableId, column_id: ColumnId) -> Option<&ColumnStatistics> {
        self.get(table_id)?.columns.get(&column_id)
    }
}

/// Cardinality + cost for one logical operator subtree.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PlanEstimate {
    pub output_rows: f64,
    pub cost: PlanCost,
}

impl PlanEstimate {
    pub fn empty() -> Self {
        Self {
            output_rows: 0.0,
            cost: PlanCost::zero(),
        }
    }
}

/// Estimate output cardinality and scalar cost for a logical plan (read-only).
pub fn estimate_plan(
    plan: &LogicalPlan,
    stats: &StatisticsProvider,
    model: &CostModel,
) -> PlanEstimate {
    match plan {
        LogicalPlan::Empty => PlanEstimate::empty(),
        LogicalPlan::Scan(scan) => {
            let rows = estimate_scan_rows(stats.get(scan.table_id));
            PlanEstimate {
                output_rows: rows,
                cost: cost_seq_scan(model, rows),
            }
        }
        LogicalPlan::Filter { input, predicate } => {
            let child = estimate_plan(input, stats, model);
            let rows = estimate_filter_rows(child.output_rows, predicate, stats);
            PlanEstimate {
                output_rows: rows,
                cost: cost_filter(model, child.cost, child.output_rows, rows),
            }
        }
        LogicalPlan::Project { input, expressions } => {
            let child = estimate_plan(input, stats, model);
            PlanEstimate {
                output_rows: child.output_rows,
                cost: cost_project(model, child.cost, child.output_rows, expressions.len()),
            }
        }
        LogicalPlan::Having { input, predicate } => {
            let child = estimate_plan(input, stats, model);
            let rows = estimate_filter_rows(child.output_rows, predicate, stats);
            PlanEstimate {
                output_rows: rows,
                cost: cost_filter(model, child.cost, child.output_rows, rows),
            }
        }
        LogicalPlan::Sort { input, .. } => {
            let child = estimate_plan(input, stats, model);
            PlanEstimate {
                output_rows: child.output_rows,
                cost: cost_sort(model, child.cost, child.output_rows),
            }
        }
        LogicalPlan::Limit { input, limit, offset } => {
            let child = estimate_plan(input, stats, model);
            let rows = estimate_limit_rows(child.output_rows, *limit, *offset);
            PlanEstimate {
                output_rows: rows,
                cost: cost_limit(model, child.cost, child.output_rows, rows),
            }
        }
        LogicalPlan::Aggregate {
            input,
            group_by,
            ..
        } => {
            let child = estimate_plan(input, stats, model);
            let rows = estimate_aggregate_rows(child.output_rows, group_by, stats);
            PlanEstimate {
                output_rows: rows,
                cost: cost_aggregate(model, child.cost, child.output_rows),
            }
        }
        LogicalPlan::Join {
            left,
            right,
            condition,
            ..
        } => {
            let left_est = estimate_plan(left, stats, model);
            let right_est = estimate_plan(right, stats, model);
            let rows = estimate_join_rows(
                left_est.output_rows,
                right_est.output_rows,
                condition.as_ref(),
                stats,
            );
            PlanEstimate {
                output_rows: rows,
                cost: cost_hash_join(
                    model,
                    left_est.cost,
                    right_est.cost,
                    left_est.output_rows,
                    right_est.output_rows,
                ),
            }
        }
        LogicalPlan::Insert(_) | LogicalPlan::Update(_) | LogicalPlan::Delete(_) => {
            PlanEstimate {
                output_rows: 0.0,
                cost: PlanCost {
                    startup: model.dml_startup,
                    total: model.dml_startup,
                },
            }
        }
    }
}

/// Index-scan cost helper for 6.15.5+ (plan node arrives in 6.15.6).
pub fn estimate_index_scan(
    stats: &StatisticsProvider,
    table_id: TableId,
    estimated_rows: f64,
    model: &CostModel,
) -> PlanEstimate {
    let table_rows = stats.table_row_count(table_id);
    let rows = clamp_rows(estimated_rows, table_rows);
    PlanEstimate {
        output_rows: rows,
        cost: cost_index_scan(model, rows),
    }
}
