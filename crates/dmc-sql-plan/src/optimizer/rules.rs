use dmc_sql_bind::BoundExpr;

use crate::optimizer::expr::{fold_constants, map_expr, simplify_boolean};
use crate::optimizer::predicate::push_predicates;
use crate::optimizer::projection::prune_projections;
use crate::plan::LogicalPlan;

pub trait OptimizerRule {
    fn apply(&self, plan: LogicalPlan) -> LogicalPlan;
}

pub struct ConstantFoldingRule;

impl OptimizerRule for ConstantFoldingRule {
    fn apply(&self, plan: LogicalPlan) -> LogicalPlan {
        map_plan_exprs(plan, fold_constants)
    }
}

pub struct BooleanSimplificationRule;

impl OptimizerRule for BooleanSimplificationRule {
    fn apply(&self, plan: LogicalPlan) -> LogicalPlan {
        map_plan_exprs(plan, simplify_boolean)
    }
}

pub struct PredicatePushdownRule;

impl OptimizerRule for PredicatePushdownRule {
    fn apply(&self, plan: LogicalPlan) -> LogicalPlan {
        push_predicates(plan)
    }
}

pub struct ProjectionPruningRule;

impl OptimizerRule for ProjectionPruningRule {
    fn apply(&self, plan: LogicalPlan) -> LogicalPlan {
        prune_projections(plan)
    }
}

pub fn default_rules() -> Vec<Box<dyn OptimizerRule>> {
    vec![
        Box::new(ConstantFoldingRule),
        Box::new(BooleanSimplificationRule),
        Box::new(PredicatePushdownRule),
        Box::new(ProjectionPruningRule),
    ]
}

fn map_plan_exprs(plan: LogicalPlan, mutator: fn(BoundExpr) -> BoundExpr) -> LogicalPlan {
    match plan {
        LogicalPlan::Filter { input, predicate } => LogicalPlan::Filter {
            input: Box::new(map_plan_exprs(*input, mutator)),
            predicate: mutator(predicate),
        },
        LogicalPlan::Project { input, expressions } => LogicalPlan::Project {
            input: Box::new(map_plan_exprs(*input, mutator)),
            expressions: expressions
                .into_iter()
                .map(|item| match item {
                    crate::plan::LogicalProjection::Expr { expr, output_name } => {
                        crate::plan::LogicalProjection::Expr {
                            expr: mutator(expr),
                            output_name,
                        }
                    }
                    other => other,
                })
                .collect(),
        },
        LogicalPlan::Having { input, predicate } => LogicalPlan::Having {
            input: Box::new(map_plan_exprs(*input, mutator)),
            predicate: mutator(predicate),
        },
        LogicalPlan::Sort { input, keys } => LogicalPlan::Sort {
            input: Box::new(map_plan_exprs(*input, mutator)),
            keys: keys
                .into_iter()
                .map(|mut key| {
                    key.expr = mutator(key.expr);
                    key
                })
                .collect(),
        },
        LogicalPlan::Limit { input, limit, offset } => LogicalPlan::Limit {
            input: Box::new(map_plan_exprs(*input, mutator)),
            limit,
            offset,
        },
        LogicalPlan::Aggregate {
            input,
            group_by,
            aggregates,
        } => LogicalPlan::Aggregate {
            input: Box::new(map_plan_exprs(*input, mutator)),
            group_by: group_by.into_iter().map(mutator).collect(),
            aggregates: aggregates
                .into_iter()
                .map(|mut agg| {
                    if let Some(expr) = agg.expr.take() {
                        agg.expr = Some(mutator(expr));
                    }
                    agg
                })
                .collect(),
        },
        LogicalPlan::Join {
            left,
            right,
            kind,
            condition,
        } => LogicalPlan::Join {
            left: Box::new(map_plan_exprs(*left, mutator)),
            right: Box::new(map_plan_exprs(*right, mutator)),
            kind,
            condition: condition.map(mutator),
        },
        LogicalPlan::Update(mut upd) => {
            if let Some(filter) = upd.filter.take() {
                upd.filter = Some(mutator(filter));
            }
            upd.assignments = upd
                .assignments
                .into_iter()
                .map(|(col, expr)| (col, mutator(expr)))
                .collect();
            LogicalPlan::Update(upd)
        }
        LogicalPlan::Delete(mut del) => {
            if let Some(filter) = del.filter.take() {
                del.filter = Some(mutator(filter));
            }
            LogicalPlan::Delete(del)
        }
        LogicalPlan::Insert(mut ins) => {
            ins.values = ins
                .values
                .into_iter()
                .map(|row| row.into_iter().map(mutator).collect())
                .collect();
            LogicalPlan::Insert(ins)
        }
        other => other,
    }
}

#[allow(dead_code)]
fn map_plan_exprs_with(expr: &BoundExpr, f: &mut dyn FnMut(BoundExpr) -> BoundExpr) -> BoundExpr {
    map_expr(expr, f)
}
