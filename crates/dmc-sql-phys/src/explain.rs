use dmc_sql_bind::BoundExpr;
use dmc_sql_plan::{AggregateFunction, JoinType, LogicalProjection, SortDirection};

use crate::plan::{
    PhysicalAggregateExpr, PhysicalPlan,
};

pub fn explain_physical(plan: &PhysicalPlan) -> String {
    let mut out = String::new();
    explain_node(plan, 0, &mut out);
    out
}

fn explain_node(plan: &PhysicalPlan, indent: usize, out: &mut String) {
    let pad = "  ".repeat(indent);
    match plan {
        PhysicalPlan::Empty => out.push_str(&format!("{pad}Empty\n")),
        PhysicalPlan::Scan(scan) => {
            let cols = if scan.columns.is_empty() {
                "*".to_string()
            } else {
                scan.columns
                    .iter()
                    .map(|c| c.raw().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            out.push_str(&format!("{pad}SeqScan\n"));
            out.push_str(&format!("{pad}  table: {}\n", scan.table_id.raw()));
            out.push_str(&format!("{pad}  columns: [{cols}]\n"));
            if let Some(note) = &scan.access_note {
                out.push_str(&format!("{pad}  reason: {note}\n"));
            }
        }
        PhysicalPlan::IndexScan(scan) => {
            let cols = if scan.columns.is_empty() {
                "*".to_string()
            } else {
                scan.columns
                    .iter()
                    .map(|c| c.raw().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            out.push_str(&format!("{pad}IndexScan\n"));
            out.push_str(&format!("{pad}  table: {}\n", scan.table_id.raw()));
            out.push_str(&format!("{pad}  index: {}\n", scan.index_id.raw()));
            out.push_str(&format!("{pad}  columns: [{cols}]\n"));
            out.push_str(&format!(
                "{pad}  index_predicate: {}\n",
                fmt_expr(&scan.index_predicate)
            ));
            if scan.filter_predicate != scan.index_predicate {
                out.push_str(&format!(
                    "{pad}  filter_predicate: {}\n",
                    fmt_expr(&scan.filter_predicate)
                ));
            }
            out.push_str(&format!("{pad}  snapshot: MVCC via RowStore\n"));
            if let Some(note) = &scan.access_note {
                out.push_str(&format!("{pad}  note: {note}\n"));
            }
        }
        PhysicalPlan::Filter(filter) => {
            out.push_str(&format!("{pad}Filter {}\n", fmt_expr(&filter.predicate)));
            explain_node(&filter.input, indent + 1, out);
        }
        PhysicalPlan::Project(project) => {
            out.push_str(&format!("{pad}Project\n"));
            for expr in &project.expressions {
                match expr {
                    LogicalProjection::Expr { expr, output_name } => {
                        let alias = output_name
                            .as_deref()
                            .map(|n| format!(" AS {n}"))
                            .unwrap_or_default();
                        out.push_str(&format!("{pad}  ├─ {}{alias}\n", fmt_expr(expr)));
                    }
                    LogicalProjection::Wildcard { table_id } => {
                        let target = table_id
                            .map(|t| t.raw().to_string())
                            .unwrap_or_else(|| "*".into());
                        out.push_str(&format!("{pad}  ├─ * ({target})\n"));
                    }
                }
            }
            explain_node(&project.input, indent + 1, out);
        }
        PhysicalPlan::HashJoin(join) => {
            out.push_str(&format!(
                "{pad}HashJoin {} build={:?}\n",
                fmt_join_kind(join.kind),
                join.build_side
            ));
            if let Some(cond) = &join.condition {
                out.push_str(&format!("{pad}  ON {}\n", fmt_expr(cond)));
            }
            explain_node(&join.left, indent + 1, out);
            explain_node(&join.right, indent + 1, out);
        }
        PhysicalPlan::Aggregate(agg) => {
            out.push_str(&format!("{pad}Aggregate\n"));
            for expr in &agg.group_exprs {
                out.push_str(&format!("{pad}  ├─ group {}\n", fmt_expr(expr)));
            }
            for item in &agg.aggregates {
                out.push_str(&format!("{pad}  ├─ {}\n", fmt_aggregate(item)));
            }
            explain_node(&agg.input, indent + 1, out);
        }
        PhysicalPlan::Sort(sort) => {
            out.push_str(&format!("{pad}Sort\n"));
            for key in &sort.keys {
                let dir = match key.direction {
                    SortDirection::Asc => "ASC",
                    SortDirection::Desc => "DESC",
                };
                out.push_str(&format!("{pad}  ├─ {} {dir}\n", fmt_expr(&key.expr)));
            }
            explain_node(&sort.input, indent + 1, out);
        }
        PhysicalPlan::Limit(limit) => {
            out.push_str(&format!("{pad}Limit {}\n", limit.limit));
            explain_node(&limit.input, indent + 1, out);
        }
        PhysicalPlan::Insert(ins) => {
            out.push_str(&format!(
                "{pad}Insert table={} columns={} rows={}\n",
                ins.table_id.raw(),
                ins.columns.len(),
                ins.values.len()
            ));
        }
        PhysicalPlan::Update(upd) => {
            out.push_str(&format!(
                "{pad}Update table={} assignments={}\n",
                upd.table_id.raw(),
                upd.assignments.len()
            ));
            if let Some(filter) = &upd.filter {
                out.push_str(&format!("{pad}  WHERE {}\n", fmt_expr(filter)));
            }
        }
        PhysicalPlan::Delete(del) => {
            out.push_str(&format!("{pad}Delete table={}\n", del.table_id.raw()));
            if let Some(filter) = &del.filter {
                out.push_str(&format!("{pad}  WHERE {}\n", fmt_expr(filter)));
            }
        }
    }
}

fn fmt_join_kind(kind: JoinType) -> &'static str {
    match kind {
        JoinType::Inner => "INNER",
        JoinType::Left => "LEFT",
        JoinType::Right => "RIGHT",
        JoinType::Full => "FULL",
    }
}

fn fmt_aggregate(agg: &PhysicalAggregateExpr) -> String {
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
        .map(fmt_expr)
        .unwrap_or_else(|| "*".into());
    let alias = agg
        .output_name
        .as_deref()
        .map(|n| format!(" AS {n}"))
        .unwrap_or_default();
    format!("{name}({arg}){alias}")
}

fn fmt_expr(expr: &BoundExpr) -> String {
    match expr {
        BoundExpr::Column(col) => {
            format!("col:{}@table:{}", col.column_id.raw(), col.table_id.raw())
        }
        BoundExpr::Literal { value, .. } => format!("{:?}", value.value),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::PhysicalScan;
    use dmc_model::{ColumnId, TableId};

    #[test]
    fn explain_scan() {
        let plan = PhysicalPlan::Scan(PhysicalScan {
            table_id: TableId::new(1),
            columns: vec![ColumnId::new(2)],
            access_note: None,
        });
        let text = explain_physical(&plan);
        assert!(text.contains("SeqScan"));
    }
}
