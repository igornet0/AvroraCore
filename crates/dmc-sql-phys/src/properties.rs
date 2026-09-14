use dmc_model::ColumnId;
use dmc_sql_bind::BoundExpr;
use dmc_sql_plan::{collect_column_ids, LogicalPlan, LogicalProjection};

use crate::plan::PhysicalPlan;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhysicalPlanProperties {
    pub output_columns: Vec<ColumnId>,
}

impl PhysicalPlanProperties {
    pub fn from_logical(logical: &LogicalPlan) -> Self {
        Self {
            output_columns: collect_column_ids(logical),
        }
    }

    pub fn from_physical(plan: &PhysicalPlan) -> Self {
        Self {
            output_columns: collect_physical_column_ids(plan),
        }
    }
}

fn collect_physical_column_ids(plan: &PhysicalPlan) -> Vec<ColumnId> {
    let mut cols = Vec::new();
    collect_physical_column_ids_inner(plan, &mut cols);
    cols.sort_by_key(|c| c.raw());
    cols.dedup_by_key(|c| c.raw());
    cols
}

fn collect_physical_column_ids_inner(plan: &PhysicalPlan, out: &mut Vec<ColumnId>) {
    match plan {
        PhysicalPlan::Empty => {}
        PhysicalPlan::Scan(scan) => out.extend(scan.columns.iter().copied()),
        PhysicalPlan::IndexScan(scan) => {
            out.extend(scan.columns.iter().copied());
            collect_bound_expr_columns(&scan.index_predicate, out);
            collect_bound_expr_columns(&scan.filter_predicate, out);
        }
        PhysicalPlan::Filter(filter) => {
            collect_bound_expr_columns(&filter.predicate, out);
            collect_physical_column_ids_inner(&filter.input, out);
        }
        PhysicalPlan::Project(project) => {
            for expr in &project.expressions {
                if let LogicalProjection::Expr { expr, .. } = expr {
                    collect_bound_expr_columns(expr, out);
                }
            }
            collect_physical_column_ids_inner(&project.input, out);
        }
        PhysicalPlan::HashJoin(join) => {
            if let Some(cond) = &join.condition {
                collect_bound_expr_columns(cond, out);
            }
            collect_physical_column_ids_inner(&join.left, out);
            collect_physical_column_ids_inner(&join.right, out);
        }
        PhysicalPlan::Aggregate(agg) => {
            for expr in &agg.group_exprs {
                collect_bound_expr_columns(expr, out);
            }
            for item in &agg.aggregates {
                if let Some(expr) = &item.expr {
                    collect_bound_expr_columns(expr, out);
                }
            }
            collect_physical_column_ids_inner(&agg.input, out);
        }
        PhysicalPlan::Sort(sort) => {
            for key in &sort.keys {
                collect_bound_expr_columns(&key.expr, out);
            }
            collect_physical_column_ids_inner(&sort.input, out);
        }
        PhysicalPlan::Limit(limit) => collect_physical_column_ids_inner(&limit.input, out),
        PhysicalPlan::Insert(ins) => {
            out.extend(ins.columns.iter().copied());
            for row in &ins.values {
                for expr in row {
                    collect_bound_expr_columns(expr, out);
                }
            }
        }
        PhysicalPlan::Update(upd) => {
            for (col, expr) in &upd.assignments {
                out.push(*col);
                collect_bound_expr_columns(expr, out);
            }
            if let Some(filter) = &upd.filter {
                collect_bound_expr_columns(filter, out);
            }
        }
        PhysicalPlan::Delete(del) => {
            if let Some(filter) = &del.filter {
                collect_bound_expr_columns(filter, out);
            }
        }
    }
}

fn collect_bound_expr_columns(expr: &BoundExpr, out: &mut Vec<ColumnId>) {
    match expr {
        BoundExpr::Column(col) => out.push(col.column_id),
        BoundExpr::Literal { .. } => {}
        BoundExpr::Binary { left, right, .. } => {
            collect_bound_expr_columns(left, out);
            collect_bound_expr_columns(right, out);
        }
        BoundExpr::Unary { expr, .. } => collect_bound_expr_columns(expr, out),
        BoundExpr::Function { args, .. } => {
            for arg in args {
                if let dmc_sql_bind::BoundFunctionArg::Expr(e) = arg {
                    collect_bound_expr_columns(e, out);
                }
            }
        }
        BoundExpr::IsNull { expr, .. } => collect_bound_expr_columns(expr, out),
        BoundExpr::In { expr, values, .. } => {
            collect_bound_expr_columns(expr, out);
            for v in values {
                collect_bound_expr_columns(v, out);
            }
        }
    }
}
