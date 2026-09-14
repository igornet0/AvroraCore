use dmc_model::Catalog;
use dmc_sql_front::{DeleteStatement, InsertStatement, UpdateStatement};

use crate::bound::{BoundDelete, BoundInsert, BoundStatement, BoundUpdate};
use crate::error::{BindError, Result};
use crate::expr::{bind_expr, bind_sql_value};
use crate::scope::{BindScope, NameResolver};
use crate::types::{check_value_fits_column, table_column_by_name};

pub fn bind_insert(catalog: &Catalog, stmt: InsertStatement) -> Result<BoundStatement> {
    let span = stmt.span;
    let resolver = NameResolver::new(catalog);
    let (table_id, table) = resolver.resolve_table_ref(&stmt.table, stmt.table.span)?;

    let columns = if stmt.columns.is_empty() {
        return Err(BindError::Catalog {
            message: "INSERT requires explicit column list in Phase 6.4".into(),
            span,
        });
    } else {
        resolve_insert_columns(&table, &stmt.columns)?
    };

    let mut rows = Vec::with_capacity(stmt.rows.len());
    for row in stmt.rows {
        if row.len() != columns.len() {
            return Err(BindError::Catalog {
                message: format!(
                    "VALUES row has {} expressions, expected {}",
                    row.len(),
                    columns.len()
                ),
                span,
            });
        }
        let mut bound_row = Vec::with_capacity(row.len());
        for (value, col_id) in row.into_iter().zip(columns.iter().copied()) {
            let col = table
                .columns
                .iter()
                .find(|c| c.id == col_id)
                .expect("resolved column id");
            let bound = bind_sql_value(&value, span)?;
            check_value_fits_column(col, &bound, span)?;
            bound_row.push(bound);
        }
        rows.push(bound_row);
    }

    Ok(BoundStatement::Insert(BoundInsert {
        table_id,
        columns,
        rows,
        span,
    }))
}

pub fn bind_update(catalog: &Catalog, stmt: UpdateStatement) -> Result<BoundStatement> {
    let span = stmt.span;
    let resolver = NameResolver::new(catalog);
    let (table_id, table) = resolver.resolve_table_ref(&stmt.table, stmt.table.span)?;
    let mut scope = BindScope::new();
    scope.register_table(table.clone(), None, span)?;

    let mut assignments = Vec::with_capacity(stmt.assignments.len());
    let mut seen = std::collections::HashSet::new();
    for (ident, value) in stmt.assignments {
        if !seen.insert(ident.name.clone()) {
            return Err(BindError::DuplicateColumn {
                name: ident.name.clone(),
                span: ident.span,
            });
        }
        let col = table_column_by_name(&table, &ident.name).ok_or(BindError::UnknownColumn {
            name: ident.name.clone(),
            span: ident.span,
        })?;
        let bound = bind_sql_value(&value, ident.span)?;
        check_value_fits_column(col, &bound, ident.span)?;
        assignments.push((col.id, bound));
    }

    let selection = stmt
        .selection
        .as_ref()
        .map(|expr| bind_expr(catalog, &scope, expr))
        .transpose()?;

    Ok(BoundStatement::Update(BoundUpdate {
        table_id,
        assignments,
        selection,
        span,
    }))
}

pub fn bind_delete(catalog: &Catalog, stmt: DeleteStatement) -> Result<BoundStatement> {
    let span = stmt.span;
    let resolver = NameResolver::new(catalog);
    let (table_id, table) = resolver.resolve_table_ref(&stmt.table, stmt.table.span)?;
    let mut scope = BindScope::new();
    scope.register_table(table, None, span)?;

    let selection = stmt
        .selection
        .as_ref()
        .map(|expr| bind_expr(catalog, &scope, expr))
        .transpose()?;

    Ok(BoundStatement::Delete(BoundDelete {
        table_id,
        selection,
        span,
    }))
}

fn resolve_insert_columns(
    table: &dmc_model::Table,
    columns: &[dmc_sql_front::Ident],
) -> Result<Vec<dmc_model::ColumnId>> {
    let mut ids = Vec::with_capacity(columns.len());
    let mut seen = std::collections::HashSet::new();
    for col in columns {
        if !seen.insert(col.name.clone()) {
            return Err(BindError::DuplicateColumn {
                name: col.name.clone(),
                span: col.span,
            });
        }
        let found = table_column_by_name(table, &col.name).ok_or(BindError::UnknownColumn {
            name: col.name.clone(),
            span: col.span,
        })?;
        ids.push(found.id);
    }
    Ok(ids)
}
