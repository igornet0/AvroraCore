use dmc_model::ColumnId;
use dmc_sql_bind::{
    BoundDelete, BoundExpr, BoundFunctionArg, BoundInsert, BoundSelect, BoundSelectItem,
    BoundStatement, BoundTableRef, BoundUpdate, BoundValue,
};
use dmc_sql_front::{JoinKind, SourceSpan};

use crate::error::{PlanError, Result};
use crate::plan::{
    AggregateFunction, JoinType, LogicalAggregate, LogicalDelete, LogicalInsert, LogicalPlan,
    LogicalProjection, LogicalScan, LogicalUpdate, NullOrder, SortDirection, SortKey,
};

pub struct LogicalPlanner;

impl LogicalPlanner {
    pub fn plan(statement: BoundStatement) -> Result<LogicalPlan> {
        plan_statement(statement)
    }
}

pub fn plan_statement(statement: BoundStatement) -> Result<LogicalPlan> {
    match statement {
        BoundStatement::Select(select) => plan_select(select),
        BoundStatement::Insert(insert) => plan_insert(insert),
        BoundStatement::Update(update) => plan_update(update),
        BoundStatement::Delete(delete) => plan_delete(delete),
        BoundStatement::Begin => Err(PlanError::NotAQueryPlan("BEGIN")),
        BoundStatement::Commit => Err(PlanError::NotAQueryPlan("COMMIT")),
        BoundStatement::Rollback => Err(PlanError::NotAQueryPlan("ROLLBACK")),
        BoundStatement::CreateDatabase(_)
        | BoundStatement::CreateSchema(_)
        | BoundStatement::CreateTable(_)
        | BoundStatement::DropTable(_)
        | BoundStatement::CreateIndex(_)
        | BoundStatement::DropIndex(_) => Err(PlanError::NotAQueryPlan("DDL")),
    }
}

fn plan_select(select: BoundSelect) -> Result<LogicalPlan> {
    if select.distinct {
        return Err(PlanError::Unsupported(
            "SELECT DISTINCT logical planning deferred".into(),
        ));
    }

    let mut plan = plan_from(&select.from)?;

    if let Some(predicate) = select.selection {
        plan = LogicalPlan::Filter {
            input: Box::new(plan),
            predicate,
        };
    }

    let aggregates = extract_aggregates(&select.projection)?;
    let has_aggregate = !aggregates.is_empty();
    let has_group_by = !select.group_by.is_empty();

    if has_group_by || has_aggregate {
        plan = LogicalPlan::Aggregate {
            input: Box::new(plan),
            group_by: select.group_by,
            aggregates,
        };
        if let Some(predicate) = select.having {
            plan = LogicalPlan::Having {
                input: Box::new(plan),
                predicate,
            };
        }
        plan = LogicalPlan::Project {
            input: Box::new(plan),
            expressions: plan_projection_items(&select.projection),
        };
    } else if needs_projection(&select.projection) {
        plan = LogicalPlan::Project {
            input: Box::new(plan),
            expressions: plan_projection_items(&select.projection),
        };
    }

    if !select.order_by.is_empty() {
        let keys = select
            .order_by
            .into_iter()
            .map(|item| SortKey {
                expr: item.expr,
                direction: if item.asc {
                    SortDirection::Asc
                } else {
                    SortDirection::Desc
                },
                nulls: NullOrder::Last,
            })
            .collect();
        plan = LogicalPlan::Sort {
            input: Box::new(plan),
            keys,
        };
    }

    if select.limit.is_some() || select.offset.is_some() {
        plan = LogicalPlan::Limit {
            input: Box::new(plan),
            limit: select.limit.unwrap_or(u64::MAX),
            offset: select.offset.unwrap_or(0),
        };
    }

    Ok(plan)
}

fn plan_from(from: &[BoundTableRef]) -> Result<LogicalPlan> {
    if from.is_empty() {
        return Err(PlanError::InvalidPlan(
            "SELECT requires at least one FROM table".into(),
        ));
    }

    let mut plan = scan_from_ref(&from[0])?;
    if let Some(join) = &from[0].join {
        plan = join_plan(plan, join)?;
    }

    for table_ref in from.iter().skip(1) {
        let right = scan_from_ref(table_ref)?;
        plan = LogicalPlan::Join {
            left: Box::new(plan),
            right: Box::new(if let Some(join) = &table_ref.join {
                join_plan(right, join)?
            } else {
                right
            }),
            kind: JoinType::Inner,
            condition: None,
        };
    }

    Ok(plan)
}

fn scan_from_ref(table_ref: &BoundTableRef) -> Result<LogicalPlan> {
    Ok(LogicalPlan::Scan(LogicalScan {
        table_id: table_ref.table_id,
        alias: table_ref.alias.clone(),
        columns: Vec::new(),
        all_columns: true,
    }))
}

fn join_plan(left: LogicalPlan, join: &dmc_sql_bind::BoundJoinClause) -> Result<LogicalPlan> {
    Ok(LogicalPlan::Join {
        left: Box::new(left),
        right: Box::new(LogicalPlan::Scan(LogicalScan {
            table_id: join.table_id,
            alias: join.alias.clone(),
            columns: Vec::new(),
            all_columns: true,
        })),
        kind: map_join_kind(join.kind),
        condition: Some(join.on.clone()),
    })
}

fn map_join_kind(kind: JoinKind) -> JoinType {
    match kind {
        JoinKind::Inner => JoinType::Inner,
        JoinKind::Left => JoinType::Left,
        JoinKind::Right => JoinType::Right,
    }
}

fn needs_projection(projection: &[BoundSelectItem]) -> bool {
    projection.len() != 1 || !matches!(projection[0], BoundSelectItem::Wildcard { .. })
}

fn plan_projection_items(projection: &[BoundSelectItem]) -> Vec<LogicalProjection> {
    projection
        .iter()
        .map(|item| match item {
            BoundSelectItem::Wildcard { table_id, .. } => LogicalProjection::Wildcard {
                table_id: *table_id,
            },
            BoundSelectItem::Expr { expr, alias, .. } => LogicalProjection::Expr {
                expr: expr.clone(),
                output_name: alias.clone(),
            },
        })
        .collect()
}

fn extract_aggregates(projection: &[BoundSelectItem]) -> Result<Vec<LogicalAggregate>> {
    let mut aggregates = Vec::new();
    for item in projection {
        if let BoundSelectItem::Expr { expr, alias, .. } = item {
            if let Some(agg) = expr_as_aggregate(expr, alias.clone())? {
                aggregates.push(agg);
            }
        }
    }
    Ok(aggregates)
}

fn expr_as_aggregate(
    expr: &BoundExpr,
    alias: Option<String>,
) -> Result<Option<LogicalAggregate>> {
    let BoundExpr::Function { name, args, .. } = expr else {
        return Ok(None);
    };
    let upper = name.to_ascii_uppercase();
    let function = match upper.as_str() {
        "COUNT" => AggregateFunction::Count,
        "SUM" => AggregateFunction::Sum,
        "AVG" => AggregateFunction::Avg,
        "MIN" => AggregateFunction::Min,
        "MAX" => AggregateFunction::Max,
        other => {
            return Err(PlanError::InvalidPlan(format!(
                "unsupported aggregate function '{other}'"
            )));
        }
    };
    let arg_expr = match args.as_slice() {
        [BoundFunctionArg::Star] => None,
        [BoundFunctionArg::Expr(inner)] => Some(inner.clone()),
        _ => {
            return Err(PlanError::InvalidPlan(format!(
                "invalid arguments for aggregate {upper}"
            )));
        }
    };
    Ok(Some(LogicalAggregate {
        function,
        expr: arg_expr,
        output_name: alias,
    }))
}

fn plan_insert(insert: BoundInsert) -> Result<LogicalPlan> {
    let values = insert
        .rows
        .into_iter()
        .map(|row| {
            row.into_iter()
                .map(value_to_expr)
                .collect::<Vec<_>>()
        })
        .collect();
    Ok(LogicalPlan::Insert(LogicalInsert {
        table_id: insert.table_id,
        columns: insert.columns,
        values,
    }))
}

fn plan_update(update: BoundUpdate) -> Result<LogicalPlan> {
    Ok(LogicalPlan::Update(LogicalUpdate {
        table_id: update.table_id,
        assignments: update
            .assignments
            .into_iter()
            .map(|(col, val)| (col, value_to_expr(val)))
            .collect(),
        filter: update.selection,
    }))
}

fn plan_delete(delete: BoundDelete) -> Result<LogicalPlan> {
    Ok(LogicalPlan::Delete(LogicalDelete {
        table_id: delete.table_id,
        filter: delete.selection,
    }))
}

fn value_to_expr(value: BoundValue) -> BoundExpr {
    BoundExpr::Literal {
        value,
        span: SourceSpan::default(),
    }
}

pub fn collect_column_ids(plan: &LogicalPlan) -> Vec<ColumnId> {
    let mut cols = Vec::new();
    collect_column_ids_inner(plan, &mut cols);
    cols.sort_by_key(|c| c.raw());
    cols.dedup_by_key(|c| c.raw());
    cols
}

fn collect_column_ids_inner(plan: &LogicalPlan, out: &mut Vec<ColumnId>) {
    match plan {
        LogicalPlan::Scan(scan) if !scan.all_columns => out.extend(scan.columns.iter().copied()),
        LogicalPlan::Filter { input, .. }
        | LogicalPlan::Project { input, .. }
        | LogicalPlan::Having { input, .. }
        | LogicalPlan::Sort { input, .. }
        | LogicalPlan::Limit { input, .. }
        | LogicalPlan::Aggregate { input, .. } => collect_column_ids_inner(input, out),
        LogicalPlan::Join { left, right, .. } => {
            collect_column_ids_inner(left, out);
            collect_column_ids_inner(right, out);
        }
        LogicalPlan::Insert(ins) => out.extend(ins.columns.iter().copied()),
        LogicalPlan::Update(upd) => {
            for (col, _) in &upd.assignments {
                out.push(*col);
            }
        }
        LogicalPlan::Delete(_) | LogicalPlan::Empty => {}
        LogicalPlan::Scan(_) => {}
    }
    collect_expr_columns(plan, out);
}

fn collect_expr_columns(plan: &LogicalPlan, out: &mut Vec<ColumnId>) {
    match plan {
        LogicalPlan::Filter { predicate, .. } => collect_bound_expr_columns(predicate, out),
        LogicalPlan::Having { predicate, .. } => collect_bound_expr_columns(predicate, out),
        LogicalPlan::Project { expressions, .. } => {
            for expr in expressions {
                if let LogicalProjection::Expr { expr, .. } = expr {
                    collect_bound_expr_columns(expr, out);
                }
            }
        }
        LogicalPlan::Sort { keys, .. } => {
            for key in keys {
                collect_bound_expr_columns(&key.expr, out);
            }
        }
        LogicalPlan::Aggregate { group_by, aggregates, .. } => {
            for expr in group_by {
                collect_bound_expr_columns(expr, out);
            }
            for agg in aggregates {
                if let Some(expr) = &agg.expr {
                    collect_bound_expr_columns(expr, out);
                }
            }
        }
        LogicalPlan::Join { condition: Some(cond), .. } => collect_bound_expr_columns(cond, out),
        LogicalPlan::Update(upd) => {
            if let Some(f) = &upd.filter {
                collect_bound_expr_columns(f, out);
            }
            for (_, expr) in &upd.assignments {
                collect_bound_expr_columns(expr, out);
            }
        }
        LogicalPlan::Delete(del) => {
            if let Some(f) = &del.filter {
                collect_bound_expr_columns(f, out);
            }
        }
        LogicalPlan::Insert(ins) => {
            for row in &ins.values {
                for expr in row {
                    collect_bound_expr_columns(expr, out);
                }
            }
        }
        _ => {}
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
                if let BoundFunctionArg::Expr(e) = arg {
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
