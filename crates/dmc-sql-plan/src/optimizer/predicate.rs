use dmc_sql_bind::BoundExpr;

use crate::optimizer::expr::{combine_conjunction, split_conjunction, tables_in_expr};
use crate::plan::{JoinType, LogicalPlan};

pub fn push_predicates(plan: LogicalPlan) -> LogicalPlan {
    match plan {
        LogicalPlan::Filter { input, predicate } => {
            let input = push_predicates(*input);
            push_filter(input, predicate)
        }
        LogicalPlan::Join { left, right, kind, condition } => LogicalPlan::Join {
            left: Box::new(push_predicates(*left)),
            right: Box::new(push_predicates(*right)),
            kind,
            condition,
        },
        LogicalPlan::Project { input, expressions } => LogicalPlan::Project {
            input: Box::new(push_predicates(*input)),
            expressions,
        },
        LogicalPlan::Having { input, predicate } => LogicalPlan::Having {
            input: Box::new(push_predicates(*input)),
            predicate,
        },
        LogicalPlan::Sort { input, keys } => LogicalPlan::Sort {
            input: Box::new(push_predicates(*input)),
            keys,
        },
        LogicalPlan::Limit { input, limit, offset } => LogicalPlan::Limit {
            input: Box::new(push_predicates(*input)),
            limit,
            offset,
        },
        LogicalPlan::Aggregate {
            input,
            group_by,
            aggregates,
        } => LogicalPlan::Aggregate {
            input: Box::new(push_predicates(*input)),
            group_by,
            aggregates,
        },
        other => other,
    }
}

fn push_filter(input: LogicalPlan, predicate: BoundExpr) -> LogicalPlan {
    match input {
        LogicalPlan::Join {
            left,
            right,
            kind,
            condition,
        } => partition_join_filter(*left, *right, kind, condition, predicate),
        LogicalPlan::Filter { input, predicate: inner } => {
            let merged = combine_conjunction(split_conjunction(&inner))
                .into_iter()
                .chain(split_conjunction(&predicate))
                .collect::<Vec<_>>();
            push_filter(*input, combine_conjunction(merged).unwrap_or(predicate))
        }
        other => wrap_filter(other, predicate),
    }
}

fn partition_join_filter(
    left: LogicalPlan,
    right: LogicalPlan,
    kind: JoinType,
    condition: Option<BoundExpr>,
    predicate: BoundExpr,
) -> LogicalPlan {
    let left_tables = tables_in_subplan(&left);
    let right_tables = tables_in_subplan(&right);

    let mut left_preds = Vec::new();
    let mut right_preds = Vec::new();
    let mut remain = Vec::new();

    for part in split_conjunction(&predicate) {
        let refs = tables_in_expr(&part);
        if refs.is_empty() {
            remain.push(part);
            continue;
        }
        let only_left = refs.iter().all(|t| left_tables.contains(t));
        let only_right = refs.iter().all(|t| right_tables.contains(t));
        match (only_left, only_right, kind) {
            (true, false, _) => left_preds.push(part),
            (false, true, JoinType::Inner) => right_preds.push(part),
            (false, true, JoinType::Right) => right_preds.push(part),
            (false, true, JoinType::Left | JoinType::Full) => remain.push(part),
            _ => remain.push(part),
        }
    }

    let left = apply_preds(left, left_preds);
    let right = apply_preds(right, right_preds);

    let mut plan = LogicalPlan::Join {
        left: Box::new(left),
        right: Box::new(right),
        kind,
        condition,
    };

    if let Some(rest) = combine_conjunction(remain) {
        plan = wrap_filter(plan, rest);
    }

    plan
}

fn apply_preds(input: LogicalPlan, preds: Vec<BoundExpr>) -> LogicalPlan {
    if preds.is_empty() {
        return input;
    }
    wrap_filter(input, combine_conjunction(preds).expect("non-empty preds"))
}

fn wrap_filter(input: LogicalPlan, predicate: BoundExpr) -> LogicalPlan {
    if crate::optimizer::expr::is_true_literal(&predicate) {
        return input;
    }
    LogicalPlan::Filter {
        input: Box::new(input),
        predicate,
    }
}

fn tables_in_subplan(plan: &LogicalPlan) -> std::collections::BTreeSet<dmc_model::TableId> {
    let mut out = std::collections::BTreeSet::new();
    collect_subplan_tables(plan, &mut out);
    out
}

fn collect_subplan_tables(plan: &LogicalPlan, out: &mut std::collections::BTreeSet<dmc_model::TableId>) {
    match plan {
        LogicalPlan::Scan(scan) => {
            out.insert(scan.table_id);
        }
        LogicalPlan::Filter { input, .. }
        | LogicalPlan::Project { input, .. }
        | LogicalPlan::Having { input, .. }
        | LogicalPlan::Sort { input, .. }
        | LogicalPlan::Limit { input, .. }
        | LogicalPlan::Aggregate { input, .. } => collect_subplan_tables(input, out),
        LogicalPlan::Join { left, right, .. } => {
            collect_subplan_tables(left, out);
            collect_subplan_tables(right, out);
        }
        _ => {}
    }
}
