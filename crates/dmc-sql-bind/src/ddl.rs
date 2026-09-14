use dmc_model::{Catalog, ColumnDef, SqlDataType};
use dmc_sql_front::{
    CreateDatabase, CreateIndex, CreateSchema, CreateTable, DropIndex, DropTable, Statement,
};

use crate::bound::{BoundCatalogEvent, BoundStatement};
use crate::error::{BindError, Result};
use crate::scope::{map_catalog_error, NameResolver, DEFAULT_DATABASE};

pub fn bind_ddl(catalog: &mut Catalog, stmt: Statement) -> Result<BoundStatement> {
    match stmt {
        Statement::CreateDatabase(s) => bind_create_database(catalog, s),
        Statement::CreateSchema(s) => bind_create_schema(catalog, s),
        Statement::CreateTable(s) => bind_create_table(catalog, s),
        Statement::DropTable(s) => bind_drop_table(catalog, s),
        Statement::CreateIndex(s) => bind_create_index(catalog, s),
        Statement::DropIndex(s) => bind_drop_index(catalog, s),
        _ => Err(BindError::Catalog {
            message: "expected DDL statement".into(),
            span: dmc_sql_front::SourceSpan::default(),
        }),
    }
}

fn bind_create_database(catalog: &mut Catalog, stmt: CreateDatabase) -> Result<BoundStatement> {
    let span = stmt.span;
    let event = catalog
        .create_database_event(stmt.name.name)
        .map_err(|e| map_catalog_error(e, stmt.name.span))?;
    Ok(BoundStatement::CreateDatabase(BoundCatalogEvent { event, span }))
}

fn bind_create_schema(catalog: &mut Catalog, stmt: CreateSchema) -> Result<BoundStatement> {
    let span = stmt.span;
    let resolver = NameResolver::new(catalog);
    let database_id = resolver
        .database_by_name(DEFAULT_DATABASE, stmt.name.span)
        .map_err(|_| BindError::UnknownDatabase {
            name: DEFAULT_DATABASE.into(),
            span: stmt.name.span,
        })?;
    let event = catalog
        .create_schema_event(database_id, stmt.name.name)
        .map_err(|e| map_catalog_error(e, stmt.name.span))?;
    Ok(BoundStatement::CreateSchema(BoundCatalogEvent { event, span }))
}

fn bind_create_table(catalog: &mut Catalog, stmt: CreateTable) -> Result<BoundStatement> {
    let span = stmt.span;
    let resolver = NameResolver::new(catalog);
    let (schema_id, _) = resolve_create_table_target(&resolver, &stmt)?;
    validate_create_table_defs(&stmt)?;

    let mut columns = Vec::with_capacity(stmt.columns.len());
    let mut pk_names = Vec::new();
    for col in &stmt.columns {
        columns.push(ColumnDef {
            name: col.name.name.clone(),
            data_type: col.data_type.clone(),
            nullable: col.nullable,
            default: col.default.as_ref().map(sql_value_to_default_string),
        });
        if col.primary_key {
            pk_names.push(col.name.name.clone());
        }
    }
    let pk = if pk_names.is_empty() {
        None
    } else {
        Some(pk_names)
    };

    let event = catalog
        .create_table_event(schema_id, table_name(&stmt), columns, pk)
        .map_err(|e| map_catalog_error(e, stmt.name.span))?;
    Ok(BoundStatement::CreateTable(BoundCatalogEvent { event, span }))
}

fn bind_drop_table(catalog: &Catalog, stmt: DropTable) -> Result<BoundStatement> {
    let span = stmt.span;
    let resolver = NameResolver::new(catalog);
    let (table_id, _) = resolver.resolve_table_ref(&stmt.name, stmt.name.span)?;
    let event = catalog
        .drop_table_event(table_id)
        .map_err(|e| map_catalog_error(e, stmt.name.span))?;
    Ok(BoundStatement::DropTable(BoundCatalogEvent { event, span }))
}

fn bind_create_index(catalog: &mut Catalog, stmt: CreateIndex) -> Result<BoundStatement> {
    let span = stmt.span;
    let resolver = NameResolver::new(catalog);
    let (table_id, table) = resolver.resolve_table_ref(&stmt.table, stmt.table.span)?;
    let mut column_ids = Vec::with_capacity(stmt.columns.len());
    for col in &stmt.columns {
        let found = table
            .columns
            .iter()
            .find(|c| c.name == col.name)
            .ok_or(BindError::UnknownColumn {
                name: col.name.clone(),
                span: col.span,
            })?;
        column_ids.push(found.id);
    }
    let event = catalog
        .create_index_event(table_id, stmt.name.name, column_ids, stmt.unique)
        .map_err(|e| map_catalog_error(e, stmt.name.span))?;
    Ok(BoundStatement::CreateIndex(BoundCatalogEvent { event, span }))
}

fn bind_drop_index(catalog: &Catalog, stmt: DropIndex) -> Result<BoundStatement> {
    let span = stmt.span;
    let resolver = NameResolver::new(catalog);
    let (_, index_id) = resolver.find_index_by_name(&stmt.name.name, stmt.name.span)?;
    let event = catalog
        .drop_index_event(index_id)
        .map_err(|e| map_catalog_error(e, stmt.name.span))?;
    Ok(BoundStatement::DropIndex(BoundCatalogEvent { event, span }))
}

fn resolve_create_table_target(
    resolver: &NameResolver<'_>,
    stmt: &CreateTable,
) -> Result<(dmc_model::SchemaId, String)> {
    match stmt.name.parts.len() {
        1 => {
            let schema = resolver.default_schema()?;
            Ok((schema, stmt.name.parts[0].name.clone()))
        }
        2 => {
            let schema = resolver.schema_in_database(
                resolver.default_database()?,
                &stmt.name.parts[0].name,
                stmt.name.parts[0].span,
            )?;
            Ok((schema, stmt.name.parts[1].name.clone()))
        }
        _ => Err(BindError::UnknownTable {
            name: stmt
                .name
                .parts
                .iter()
                .map(|p| p.name.as_str())
                .collect::<Vec<_>>()
                .join("."),
            span: stmt.name.span,
        }),
    }
}

fn table_name(stmt: &CreateTable) -> String {
    stmt.name.parts.last().unwrap().name.clone()
}

fn validate_create_table_defs(stmt: &CreateTable) -> Result<()> {
    if stmt.columns.is_empty() {
        return Err(BindError::Catalog {
            message: "CREATE TABLE requires at least one column".into(),
            span: stmt.span,
        });
    }
    let mut seen = std::collections::HashSet::new();
    for col in &stmt.columns {
        if !seen.insert(col.name.name.clone()) {
            return Err(BindError::DuplicateColumn {
                name: col.name.name.clone(),
                span: col.name.span,
            });
        }
        if matches!(col.data_type, SqlDataType::Null) {
            return Err(BindError::TypeMismatch {
                message: "NULL is not a column type".into(),
                span: col.name.span,
            });
        }
    }
    let pk_cols: Vec<_> = stmt
        .columns
        .iter()
        .filter(|c| c.primary_key)
        .map(|c| c.name.name.as_str())
        .collect();
    if pk_cols.is_empty() {
        return Ok(());
    }
    for pk in pk_cols {
        if !stmt.columns.iter().any(|c| c.name.name == pk) {
            return Err(BindError::InvalidPrimaryKey {
                message: format!("unknown primary key column '{pk}'"),
                span: stmt.span,
            });
        }
    }
    Ok(())
}

fn sql_value_to_default_string(value: &dmc_sql_front::SqlValue) -> String {
    match value {
        dmc_sql_front::SqlValue::Null => "NULL".into(),
        dmc_sql_front::SqlValue::Boolean(v) => v.to_string(),
        dmc_sql_front::SqlValue::Integer(v) => v.to_string(),
        dmc_sql_front::SqlValue::Double(v) => v.to_string(),
        dmc_sql_front::SqlValue::Decimal(v) => v.clone(),
        dmc_sql_front::SqlValue::Text(v) => format!("'{v}'"),
        dmc_sql_front::SqlValue::Blob(_) => "BLOB".into(),
        dmc_sql_front::SqlValue::Date(v) => v.clone(),
        dmc_sql_front::SqlValue::Timestamp(v) => v.clone(),
    }
}
