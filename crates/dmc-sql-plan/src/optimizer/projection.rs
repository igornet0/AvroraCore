use std::collections::{BTreeMap, BTreeSet};

use dmc_model::{ColumnId, TableId};
use dmc_sql_bind::BoundExpr;

use crate::optimizer::expr::columns_in_expr;
use crate::plan::{LogicalAggregate, LogicalPlan, LogicalProjection, LogicalScan};

pub fn prune_projections(plan: LogicalPlan) -> LogicalPlan {
    let wildcards = wildcard_tables(&plan);
    let required = required_columns(&plan);
    rewrite_plan(plan, &required, &wildcards)
}

fn wildcard_tables(plan: &LogicalPlan) -> BTreeSet<TableId> {
    let mut out = BTreeSet::new();
    collect_wildcards(plan, &mut out);
    out
}

fn collect_wildcards(plan: &LogicalPlan, out: &mut BTreeSet<TableId>) {
    match plan {
        LogicalPlan::Project { expressions, input } => {
            for expr in expressions {
                if let LogicalProjection::Wildcard { table_id: None } = expr {
                    for table in tables_in_plan(input) {
                        out.insert(table);
                    }
                } else if let LogicalProjection::Wildcard {
                    table_id: Some(t),
                    ..
                } = expr
                {
                    out.insert(*t);
                }
            }
            collect_wildcards(input, out);
        }
        LogicalPlan::Filter { input, .. }
        | LogicalPlan::Having { input, .. }
        | LogicalPlan::Sort { input, .. }
        | LogicalPlan::Limit { input, .. }
        | LogicalPlan::Aggregate { input, .. } => collect_wildcards(input, out),
        LogicalPlan::Join { left, right, .. } => {
            collect_wildcards(left, out);
            collect_wildcards(right, out);
        }
        _ => {}
    }
}

fn required_columns(plan: &LogicalPlan) -> BTreeMap<TableId, BTreeSet<ColumnId>> {
    let mut required = BTreeMap::new();
    collect_required(plan, &mut required);
    required
}

fn collect_required(plan: &LogicalPlan, out: &mut BTreeMap<TableId, BTreeSet<ColumnId>>) {
    match plan {
        LogicalPlan::Project { expressions, input } => {
            for item in expressions {
                if let LogicalProjection::Expr { expr, .. } = item {
                    add_expr_columns(expr, out);
                }
            }
            collect_required(input, out);
        }
        LogicalPlan::Filter { input, predicate } => {
            add_expr_columns(predicate, out);
            collect_required(input, out);
        }
        LogicalPlan::Having { input, predicate } => {
            add_expr_columns(predicate, out);
            collect_required(input, out);
        }
        LogicalPlan::Sort { input, keys } => {
            for key in keys {
                add_expr_columns(&key.expr, out);
            }
            collect_required(input, out);
        }
        LogicalPlan::Limit { input, .. } => collect_required(input, out),
        LogicalPlan::Aggregate {
            input,
            group_by,
            aggregates,
        } => {
            for expr in group_by {
                add_expr_columns(expr, out);
            }
            for agg in aggregates {
                add_aggregate_columns(agg, out);
            }
            collect_required(input, out);
        }
        LogicalPlan::Join { left, right, condition, .. } => {
            if let Some(cond) = condition {
                add_expr_columns(cond, out);
            }
            collect_required(left, out);
            collect_required(right, out);
        }
        LogicalPlan::Update(upd) => {
            for (col, expr) in &upd.assignments {
                out.entry(table_for_update(upd.table_id))
                    .or_default()
                    .insert(*col);
                add_expr_columns(expr, out);
            }
            if let Some(filter) = &upd.filter {
                add_expr_columns(filter, out);
            }
        }
        LogicalPlan::Delete(del) => {
            if let Some(filter) = &del.filter {
                add_expr_columns(filter, out);
            }
        }
        LogicalPlan::Insert(ins) => {
            for col in &ins.columns {
                out.entry(ins.table_id).or_default().insert(*col);
            }
            for row in &ins.values {
                for expr in row {
                    add_expr_columns(expr, out);
                }
            }
        }
        LogicalPlan::Scan(_) | LogicalPlan::Empty => {}
    }
}

fn table_for_update(table_id: TableId) -> TableId {
    table_id
}

fn add_aggregate_columns(agg: &LogicalAggregate, out: &mut BTreeMap<TableId, BTreeSet<ColumnId>>) {
    if let Some(expr) = &agg.expr {
        add_expr_columns(expr, out);
    }
}

fn add_expr_columns(expr: &BoundExpr, out: &mut BTreeMap<TableId, BTreeSet<ColumnId>>) {
    for (table, col) in columns_in_expr(expr) {
        out.entry(table).or_default().insert(col);
    }
}

fn rewrite_plan(
    plan: LogicalPlan,
    required: &BTreeMap<TableId, BTreeSet<ColumnId>>,
    wildcards: &BTreeSet<TableId>,
) -> LogicalPlan {
    match plan {
        LogicalPlan::Scan(mut scan) => {
            if scan.all_columns && !wildcards.contains(&scan.table_id) {
                if let Some(cols) = required.get(&scan.table_id) {
                    if !cols.is_empty() {
                        scan.all_columns = false;
                        scan.columns = cols.iter().copied().collect();
                        scan.columns.sort_by_key(|c| c.raw());
                    }
                }
            }
            LogicalPlan::Scan(scan)
        }
        LogicalPlan::Filter { input, predicate } => LogicalPlan::Filter {
            input: Box::new(rewrite_plan(*input, required, wildcards)),
            predicate,
        },
        LogicalPlan::Project { input, expressions } => LogicalPlan::Project {
            input: Box::new(rewrite_plan(*input, required, wildcards)),
            expressions,
        },
        LogicalPlan::Having { input, predicate } => LogicalPlan::Having {
            input: Box::new(rewrite_plan(*input, required, wildcards)),
            predicate,
        },
        LogicalPlan::Sort { input, keys } => LogicalPlan::Sort {
            input: Box::new(rewrite_plan(*input, required, wildcards)),
            keys,
        },
        LogicalPlan::Limit { input, limit, offset } => LogicalPlan::Limit {
            input: Box::new(rewrite_plan(*input, required, wildcards)),
            limit,
            offset,
        },
        LogicalPlan::Aggregate {
            input,
            group_by,
            aggregates,
        } => LogicalPlan::Aggregate {
            input: Box::new(rewrite_plan(*input, required, wildcards)),
            group_by,
            aggregates,
        },
        LogicalPlan::Join {
            left,
            right,
            kind,
            condition,
        } => LogicalPlan::Join {
            left: Box::new(rewrite_plan(*left, required, wildcards)),
            right: Box::new(rewrite_plan(*right, required, wildcards)),
            kind,
            condition,
        },
        other => other,
    }
}

fn tables_in_plan(plan: &LogicalPlan) -> BTreeSet<TableId> {
    let mut out = BTreeSet::new();
    collect_plan_tables(plan, &mut out);
    out
}

fn collect_plan_tables(plan: &LogicalPlan, out: &mut BTreeSet<TableId>) {
    match plan {
        LogicalPlan::Scan(scan) => {
            out.insert(scan.table_id);
        }
        LogicalPlan::Filter { input, .. }
        | LogicalPlan::Project { input, .. }
        | LogicalPlan::Having { input, .. }
        | LogicalPlan::Sort { input, .. }
        | LogicalPlan::Limit { input, .. }
        | LogicalPlan::Aggregate { input, .. } => collect_plan_tables(input, out),
        LogicalPlan::Join { left, right, .. } => {
            collect_plan_tables(left, out);
            collect_plan_tables(right, out);
        }
        _ => {}
    }
}

fn find_scan<'a>(plan: &'a LogicalPlan, table_id: TableId) -> Option<&'a LogicalScan> {
    match plan {
        LogicalPlan::Scan(scan) if scan.table_id == table_id => Some(scan),
        LogicalPlan::Filter { input, .. }
        | LogicalPlan::Project { input, .. }
        | LogicalPlan::Having { input, .. }
        | LogicalPlan::Sort { input, .. }
        | LogicalPlan::Limit { input, .. }
        | LogicalPlan::Aggregate { input, .. } => find_scan(input, table_id),
        LogicalPlan::Join { left, right, .. } => {
            find_scan(left, table_id).or_else(|| find_scan(right, table_id))
        }
        _ => None,
    }
}
