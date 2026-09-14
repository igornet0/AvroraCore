//! Phase 6.5–6.6 — SQL logical plan and rule-based optimizer.
//!
//! Transforms [`BoundStatement`] into [`LogicalPlan`]. **No execution, no journal.**

mod cbo;
mod error;
mod explain;
mod fingerprint;
mod optimizer;
mod plan;
mod planner;

pub use cbo::{
    choose_join_build_side, choose_scan_access, clamp_rows, clamp_selectivity,
    combine_and_selectivity, combine_or_selectivity, cost_aggregate, cost_filter, cost_hash_join,
    cost_index_scan, cost_limit, cost_project, cost_seq_scan, cost_sort, estimate_aggregate_rows,
    estimate_filter_rows, estimate_index_scan, estimate_join_rows, estimate_limit_rows,
    estimate_plan, estimate_predicate_selectivity, estimate_scan_rows, estimate_sort_rows,
    index_column_type, is_indexable_comparison, is_scan_chain, min_table_id, peel_scan_chain,
    plan_cbo_decisions, CboDecisionCursor, CboDecisions, CostModel, JoinBuildSide, PlanCost,
    PlanEstimate, ScanAccessChoice, StatisticsProvider, DEFAULT_FALLBACK_SELECTIVITY, FALLBACK_NDV,
    FALLBACK_TABLE_ROW_COUNT,
};
pub use error::{OptimizeError, OptimizeResult, PlanError, Result};
pub use explain::explain;
pub use fingerprint::{
    fingerprint, fingerprint_explain, has_pushed_filter, scan_is_pruned, table_scan_columns,
    top_filter_is_join_only, PlanFingerprint,
};
pub use optimizer::{optimize_plan, LogicalOptimizer, DEFAULT_MAX_ITERATIONS};
pub use plan::*;
pub use planner::{collect_column_ids, plan_statement, LogicalPlanner};
