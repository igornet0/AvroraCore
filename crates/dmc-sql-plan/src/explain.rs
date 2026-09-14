use dmc_sql_bind::BoundExpr;

use crate::plan::{
    AggregateFunction, LogicalAggregate, LogicalPlan, LogicalProjection, SortDirection,
};

pub fn explain(plan: &LogicalPlan) -> String {
    let mut out = String::new();
    explain_node(plan, 0, &mut out);
    out
}

fn explain_node(plan: &LogicalPlan, indent: usize, out: &mut String) {
    let pad = "  ".repeat(indent);
    match plan {
        LogicalPlan::Empty => {
            out.push_str(&format!("{pad}Empty\n"));
        }
        LogicalPlan::Scan(scan) => {
            let alias = scan
                .alias
                .as_deref()
                .map(|a| format!(" ({a})"))
                .unwrap_or_default();
            let cols = if scan.all_columns {
                "*".to_string()
            } else {
                scan.columns
                    .iter()
                    .map(|c| c.raw().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            out.push_str(&format!(
                "{pad}Scan: table={}{alias} columns=[{cols}]\n",
                scan.table_id.raw()
            ));
        }
        LogicalPlan::Filter { input, predicate } => {
            out.push_str(&format!("{pad}Filter: {}\n", fmt_expr(predicate)));
            explain_node(input, indent + 1, out);
        }
        LogicalPlan::Project { input, expressions } => {
            out.push_str(&format!("{pad}Project:\n"));
            for expr in expressions {
                match expr {
                    LogicalProjection::Expr { expr, output_name } => {
                        let name = output_name
                            .as_deref()
                            .map(|n| format!(" AS {n}"))
                            .unwrap_or_default();
                        out.push_str(&format!(
                            "{pad}  ├─ {}{name}\n",
                            fmt_expr(expr)
                        ));
                    }
                    LogicalProjection::Wildcard { table_id } => {
                        let target = table_id
                            .map(|t| t.raw().to_string())
                            .unwrap_or_else(|| "*".into());
                        out.push_str(&format!("{pad}  ├─ * ({target})\n"));
                    }
                }
            }
            explain_node(input, indent + 1, out);
        }
        LogicalPlan::Having { input, predicate } => {
            out.push_str(&format!("{pad}Having: {}\n", fmt_expr(predicate)));
            explain_node(input, indent + 1, out);
        }
        LogicalPlan::Sort { input, keys } => {
            out.push_str(&format!("{pad}Sort:\n"));
            for key in keys {
                let dir = match key.direction {
                    SortDirection::Asc => "ASC",
                    SortDirection::Desc => "DESC",
                };
                out.push_str(&format!(
                    "{pad}  ├─ {} {dir}\n",
                    fmt_expr(&key.expr)
                ));
            }
            explain_node(input, indent + 1, out);
        }
        LogicalPlan::Limit { input, limit, offset } => {
            out.push_str(&format!("{pad}Limit: {limit} offset {offset}\n"));
            explain_node(input, indent + 1, out);
        }
        LogicalPlan::Aggregate {
            input,
            group_by,
            aggregates,
        } => {
            out.push_str(&format!("{pad}Aggregate:\n"));
            for key in group_by {
                out.push_str(&format!(
                    "{pad}  ├─ group: {}\n",
                    fmt_expr(key)
                ));
            }
            for agg in aggregates {
                out.push_str(&format!(
                    "{pad}  ├─ {}\n",
                    fmt_aggregate(agg)
                ));
            }
            explain_node(input, indent + 1, out);
        }
        LogicalPlan::Join {
            left,
            right,
            kind,
            condition,
        } => {
            out.push_str(&format!("{pad}Join: {kind:?}\n"));
            if let Some(cond) = condition {
                out.push_str(&format!("{pad}  ON: {}\n", fmt_expr(cond)));
            }
            explain_node(left, indent + 1, out);
            explain_node(right, indent + 1, out);
        }
        LogicalPlan::Insert(ins) => {
            out.push_str(&format!(
                "{pad}Insert: table={} columns={} rows={}\n",
                ins.table_id.raw(),
                ins.columns.len(),
                ins.values.len()
            ));
        }
        LogicalPlan::Update(upd) => {
            out.push_str(&format!(
                "{pad}Update: table={} assignments={}\n",
                upd.table_id.raw(),
                upd.assignments.len()
            ));
            if let Some(filter) = &upd.filter {
                out.push_str(&format!("{pad}  WHERE: {}\n", fmt_expr(filter)));
            }
        }
        LogicalPlan::Delete(del) => {
            out.push_str(&format!("{pad}Delete: table={}\n", del.table_id.raw()));
            if let Some(filter) = &del.filter {
                out.push_str(&format!("{pad}  WHERE: {}\n", fmt_expr(filter)));
            }
        }
    }
}

fn fmt_aggregate(agg: &LogicalAggregate) -> String {
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
        BoundExpr::Column(col) => format!("col:{}@table:{}", col.column_id.raw(), col.table_id.raw()),
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
    use dmc_model::{ColumnId, SqlDataType, TableId};
    use dmc_sql_bind::BoundColumnRef;
    use dmc_sql_front::SourceSpan;
    use crate::plan::LogicalScan;

    #[test]
    fn explain_scan_and_filter() {
        let plan = LogicalPlan::Filter {
            input: Box::new(LogicalPlan::Scan(LogicalScan {
                table_id: TableId::new(42),
                alias: Some("users".into()),
                columns: vec![ColumnId::new(1)],
                all_columns: true,
            })),
            predicate: BoundExpr::Column(BoundColumnRef {
                table_id: TableId::new(42),
                column_id: ColumnId::new(3),
                data_type: SqlDataType::Integer,
                nullable: true,
                span: SourceSpan::default(),
            }),
        };
        let text = explain(&plan);
        assert!(text.contains("Filter:"));
        assert!(text.contains("Scan: table=42"));
    }
}
