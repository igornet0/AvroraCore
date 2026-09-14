use dmc_model::Catalog;
use dmc_sql_front::{JoinClause, SelectItem, SelectStatement, TableRef};

use crate::bound::{
    BoundJoinClause, BoundOrderItem, BoundSelect, BoundSelectItem, BoundStatement, BoundTableRef,
};
use crate::error::Result;
use crate::expr::bind_expr;
use crate::scope::{BindScope, NameResolver};

pub fn bind_select(catalog: &Catalog, stmt: SelectStatement) -> Result<BoundStatement> {
    let span = stmt.span;
    let resolver = NameResolver::new(catalog);
    let mut scope = BindScope::new();
    let mut from = Vec::with_capacity(stmt.from.len());

    for table_ref in stmt.from {
        from.push(bind_table_ref(catalog, &resolver, &mut scope, table_ref)?);
    }

    let projection = stmt
        .projection
        .into_iter()
        .map(|item| bind_select_item(catalog, &scope, item))
        .collect::<Result<_>>()?;

    let selection = stmt
        .selection
        .as_ref()
        .map(|expr| bind_expr(catalog, &scope, &expr))
        .transpose()?;

    let group_by = stmt
        .group_by
        .into_iter()
        .map(|expr| bind_expr(catalog, &scope, &expr))
        .collect::<Result<_>>()?;

    let having = stmt
        .having
        .as_ref()
        .map(|expr| bind_expr(catalog, &scope, &expr))
        .transpose()?;

    let order_by = stmt
        .order_by
        .into_iter()
        .map(|item| {
            Ok(BoundOrderItem {
                expr: bind_expr(catalog, &scope, &item.expr)?,
                asc: item.asc,
                span: item.span,
            })
        })
        .collect::<Result<_>>()?;

    Ok(BoundStatement::Select(BoundSelect {
        distinct: stmt.distinct,
        projection,
        from,
        selection,
        group_by,
        having,
        order_by,
        limit: stmt.limit,
        offset: stmt.offset,
        span,
    }))
}

fn bind_table_ref(
    catalog: &Catalog,
    resolver: &NameResolver<'_>,
    scope: &mut BindScope,
    table_ref: TableRef,
) -> Result<BoundTableRef> {
    let (table_id, table) = resolver.resolve_table_ref(&table_ref.name, table_ref.span)?;
    scope.register_table(table.clone(), table_ref.alias.as_ref(), table_ref.span)?;
    let join = table_ref
        .join
        .as_ref()
        .map(|join| bind_join(catalog, resolver, scope, join))
        .transpose()?;
    Ok(BoundTableRef {
        table_id,
        alias: table_ref.alias.map(|a| a.name),
        join,
        span: table_ref.span,
    })
}

fn bind_join(
    catalog: &Catalog,
    resolver: &NameResolver<'_>,
    scope: &mut BindScope,
    join: &JoinClause,
) -> Result<BoundJoinClause> {
    let (table_id, table) = resolver.resolve_table_ref(&join.table, join.span)?;
    scope.register_table(table, join.alias.as_ref(), join.span)?;
    let on = bind_expr(catalog, scope, &join.on)?;
    Ok(BoundJoinClause {
        kind: join.kind,
        table_id,
        alias: join.alias.as_ref().map(|a| a.name.clone()),
        on,
        span: join.span,
    })
}

fn bind_select_item(
    catalog: &Catalog,
    scope: &BindScope,
    item: SelectItem,
) -> Result<BoundSelectItem> {
    match item {
        SelectItem::Wildcard { span } => Ok(BoundSelectItem::Wildcard {
            table_id: None,
            span,
        }),
        SelectItem::Expr { expr, alias, span } => Ok(BoundSelectItem::Expr {
            expr: bind_expr(catalog, scope, &expr)?,
            alias: alias.map(|a| a.name),
            span,
        }),
    }
}
