use dmc_model::{ColumnId, TableId};
use dmc_sql_bind::BoundExpr;

use crate::explain::explain;
use crate::plan::{
    AggregateFunction, LogicalAggregate, LogicalPlan, LogicalProjection, LogicalScan,
    SortDirection,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PlanFingerprint(pub String);

impl PlanFingerprint {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn fingerprint(plan: &LogicalPlan) -> PlanFingerprint {
    PlanFingerprint(canonicalize(plan))
}

pub fn fingerprint_explain(plan: &LogicalPlan) -> PlanFingerprint {
    PlanFingerprint(explain(plan))
}

fn canonicalize(plan: &LogicalPlan) -> String {
    let mut out = String::new();
    write_node(plan, 0, &mut out);
    out
}

fn write_node(plan: &LogicalPlan, depth: usize, out: &mut String) {
    let pad = " ".repeat(depth * 2);
    match plan {
        LogicalPlan::Empty => out.push_str(&format!("{pad}Empty\n")),
        LogicalPlan::Scan(scan) => out.push_str(&format!("{pad}{}\n", scan_canonical(scan))),
        LogicalPlan::Filter { input, predicate } => {
            out.push_str(&format!("{pad}Filter({})\n", expr_tag(predicate)));
            write_node(input, depth + 1, out);
        }
        LogicalPlan::Project { input, expressions } => {
            out.push_str(&format!("{pad}Project\n"));
            for expr in expressions {
                out.push_str(&format!("{pad}  {}\n", projection_tag(expr)));
            }
            write_node(input, depth + 1, out);
        }
        LogicalPlan::Having { input, predicate } => {
            out.push_str(&format!("{pad}Having({})\n", expr_tag(predicate)));
            write_node(input, depth + 1, out);
        }
        LogicalPlan::Sort { input, keys } => {
            out.push_str(&format!("{pad}Sort\n"));
            for key in keys {
                let dir = match key.direction {
                    SortDirection::Asc => "ASC",
                    SortDirection::Desc => "DESC",
                };
                out.push_str(&format!("{pad}  {} {dir}\n", expr_tag(&key.expr)));
            }
            write_node(input, depth + 1, out);
        }
        LogicalPlan::Limit { input, limit, offset } => {
            out.push_str(&format!("{pad}Limit({limit},{offset})\n"));
            write_node(input, depth + 1, out);
        }
        LogicalPlan::Aggregate {
            input,
            group_by,
            aggregates,
        } => {
            out.push_str(&format!("{pad}Aggregate\n"));
            for expr in group_by {
                out.push_str(&format!("{pad}  group:{}\n", expr_tag(expr)));
            }
            for agg in aggregates {
                out.push_str(&format!("{pad}  {}\n", aggregate_tag(agg)));
            }
            write_node(input, depth + 1, out);
        }
        LogicalPlan::Join {
            left,
            right,
            kind,
            condition,
        } => {
            out.push_str(&format!("{pad}Join({kind:?})\n"));
            if let Some(cond) = condition {
                out.push_str(&format!("{pad}  ON:{}\n", expr_tag(cond)));
            }
            write_node(left, depth + 1, out);
            write_node(right, depth + 1, out);
        }
        LogicalPlan::Insert(ins) => {
            out.push_str(&format!(
                "{pad}Insert(table={},cols={},rows={})\n",
                ins.table_id.raw(),
                ins.columns.len(),
                ins.values.len()
            ));
        }
        LogicalPlan::Update(upd) => {
            out.push_str(&format!(
                "{pad}Update(table={},assignments={})\n",
                upd.table_id.raw(),
                upd.assignments.len()
            ));
        }
        LogicalPlan::Delete(del) => {
            out.push_str(&format!("{pad}Delete(table={})\n", del.table_id.raw()));
        }
    }
}

fn scan_canonical(scan: &LogicalScan) -> String {
    let alias = scan.alias.as_deref().unwrap_or("");
    let cols = if scan.all_columns {
        "*".to_string()
    } else {
        let mut ids: Vec<_> = scan.columns.iter().map(|c| c.raw()).collect();
        ids.sort_unstable();
        ids.iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",")
    };
    format!("Scan(t={},a={},c=[{cols}])", scan.table_id.raw(), alias)
}

fn projection_tag(item: &LogicalProjection) -> String {
    match item {
        LogicalProjection::Expr { expr, output_name } => {
            format!(
                "expr:{}:{}",
                expr_tag(expr),
                output_name.as_deref().unwrap_or("")
            )
        }
        LogicalProjection::Wildcard { table_id } => format!(
            "wildcard:{}",
            table_id.map(|t| t.raw().to_string()).unwrap_or_else(|| "*".into())
        ),
    }
}

fn aggregate_tag(agg: &LogicalAggregate) -> String {
    let name = match agg.function {
        AggregateFunction::Count => "COUNT",
        AggregateFunction::Sum => "SUM",
        AggregateFunction::Avg => "AVG",
        AggregateFunction::Min => "MIN",
        AggregateFunction::Max => "MAX",
    };
    let arg = agg
        .expr
        .as_ref()
        .map(expr_tag)
        .unwrap_or_else(|| "*".into());
    format!("{name}({arg})")
}

fn expr_tag(expr: &BoundExpr) -> String {
    match expr {
        BoundExpr::Column(col) => format!("c:{}@{}", col.column_id.raw(), col.table_id.raw()),
        BoundExpr::Literal { value, .. } => format!("lit:{:?}", value.value),
        BoundExpr::Binary { op, .. } => format!("{op:?}"),
        BoundExpr::Unary { op, .. } => format!("{op:?}"),
        BoundExpr::Function { name, .. } => name.clone(),
        BoundExpr::IsNull { negated, .. } => {
            if *negated {
                "IS NOT NULL".into()
            } else {
                "IS NULL".into()
            }
        }
        BoundExpr::In { negated, .. } => {
            if *negated {
                "NOT IN".into()
            } else {
                "IN".into()
            }
        }
    }
}

pub fn table_scan_columns(plan: &LogicalPlan, table_id: TableId) -> Option<Vec<ColumnId>> {
    find_scan(plan, table_id).map(|scan| {
        if scan.all_columns {
            Vec::new()
        } else {
            let mut cols: Vec<_> = scan.columns.iter().copied().collect();
            cols.sort_by_key(|c| c.raw());
            cols
        }
    })
}

pub fn scan_is_pruned(plan: &LogicalPlan, table_id: TableId) -> bool {
    matches!(
        find_scan(plan, table_id),
        Some(scan) if !scan.all_columns
    )
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

fn find_filter_over_scan<'a>(plan: &'a LogicalPlan, table_id: TableId) -> Option<&'a BoundExpr> {
    match plan {
        LogicalPlan::Filter { input, predicate } => match input.as_ref() {
            LogicalPlan::Scan(scan) if scan.table_id == table_id => Some(predicate),
            _ => find_filter_over_scan(input, table_id),
        },
        LogicalPlan::Join { left, right, .. } => {
            find_filter_over_scan(left, table_id).or_else(|| find_filter_over_scan(right, table_id))
        }
        LogicalPlan::Project { input, .. }
        | LogicalPlan::Having { input, .. }
        | LogicalPlan::Sort { input, .. }
        | LogicalPlan::Limit { input, .. }
        | LogicalPlan::Aggregate { input, .. } => find_filter_over_scan(input, table_id),
        _ => None,
    }
}

pub fn has_pushed_filter(plan: &LogicalPlan, table_id: TableId) -> bool {
    find_filter_over_scan(plan, table_id).is_some()
}

pub fn top_filter_is_join_only(plan: &LogicalPlan) -> bool {
    match plan {
        LogicalPlan::Project { input, .. }
        | LogicalPlan::Having { input, .. }
        | LogicalPlan::Sort { input, .. }
        | LogicalPlan::Limit { input, .. }
        | LogicalPlan::Aggregate { input, .. } => top_filter_is_join_only(input),
        LogicalPlan::Filter { input, .. } => !matches!(input.as_ref(), LogicalPlan::Join { .. }),
        LogicalPlan::Join { .. } => true,
        _ => false,
    }
}
