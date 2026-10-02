use dmc_model::{Catalog, SqlDataType};

use crate::error::{CatalogError, Result};
use crate::page::{page_by_name, CatalogPage, PageQuery};
use crate::types::{
    CatalogColumn, CatalogConstraint, CatalogConstraintKind, CatalogDatabase, CatalogIndex,
    CatalogIndexType, CatalogObjectId, CatalogSchema, CatalogTable, CatalogTableKind, TableRef,
};

/// Backend-facing metadata source. SQL/`sys_*` or model catalog implementations plug in here.
pub trait CatalogProvider {
    fn list_databases(&self) -> Result<Vec<CatalogDatabase>>;
    fn list_schemas(&self, database: Option<&str>, page: &PageQuery) -> Result<CatalogPage<CatalogSchema>>;
    fn list_tables(
        &self,
        database: &str,
        schema: &str,
        page: &PageQuery,
    ) -> Result<CatalogPage<CatalogTable>>;
    fn get_table(&self, table: &TableRef) -> Result<CatalogTable>;
    fn list_columns(&self, table: &TableRef, page: &PageQuery) -> Result<CatalogPage<CatalogColumn>>;
    fn list_indexes(&self, table: &TableRef, page: &PageQuery) -> Result<CatalogPage<CatalogIndex>>;
    fn list_constraints(
        &self,
        table: &TableRef,
        page: &PageQuery,
    ) -> Result<CatalogPage<CatalogConstraint>>;
}

/// Provider over authoritative [`dmc_model::Catalog`] (journal / session catalog).
pub struct ModelCatalogProvider<'a> {
    catalog: &'a Catalog,
}

impl<'a> ModelCatalogProvider<'a> {
    pub fn new(catalog: &'a Catalog) -> Self {
        Self { catalog }
    }

    fn resolve_table(&self, table: &TableRef) -> Result<&dmc_model::Table> {
        if table.database.is_empty() || table.schema.is_empty() || table.table.is_empty() {
            return Err(CatalogError::InvalidIdentifier(
                "database, schema, and table are required".into(),
            ));
        }
        let db = self
            .catalog
            .database_by_name(&table.database)
            .ok_or_else(|| CatalogError::NotFound(format!("database '{}'", table.database)))?;
        let schema_id = self
            .catalog
            .schemas()
            .find(|s| s.database_id == db.id && s.name == table.schema)
            .map(|s| s.id)
            .ok_or_else(|| {
                CatalogError::NotFound(format!(
                    "schema '{}.{}'",
                    table.database, table.schema
                ))
            })?;
        self.catalog
            .table_by_name(schema_id, &table.table)
            .ok_or_else(|| {
                CatalogError::NotFound(format!(
                    "table '{}.{}.{}'",
                    table.database, table.schema, table.table
                ))
            })
    }
}

impl CatalogProvider for ModelCatalogProvider<'_> {
    fn list_databases(&self) -> Result<Vec<CatalogDatabase>> {
        let mut items: Vec<_> = self
            .catalog
            .databases()
            .map(|d| CatalogDatabase {
                id: CatalogObjectId::database(&d.name),
                name: d.name.clone(),
            })
            .collect();
        items.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(items)
    }

    fn list_schemas(
        &self,
        database: Option<&str>,
        page: &PageQuery,
    ) -> Result<CatalogPage<CatalogSchema>> {
        if let Some(db_name) = database {
            if self.catalog.database_by_name(db_name).is_none() {
                return Err(CatalogError::NotFound(format!("database '{db_name}'")));
            }
        }
        let items: Vec<_> = self
            .catalog
            .schemas()
            .filter_map(|s| {
                let db = self.catalog.database(s.database_id)?.name.clone();
                if let Some(want) = database {
                    if db != want {
                        return None;
                    }
                }
                Some(CatalogSchema {
                    id: CatalogObjectId::schema(&db, &s.name),
                    database: db,
                    name: s.name.clone(),
                })
            })
            .collect();
        Ok(page_by_name(items, page, |s| &s.name))
    }

    fn list_tables(
        &self,
        database: &str,
        schema: &str,
        page: &PageQuery,
    ) -> Result<CatalogPage<CatalogTable>> {
        let db = self
            .catalog
            .database_by_name(database)
            .ok_or_else(|| CatalogError::NotFound(format!("database '{database}'")))?;
        let schema_obj = self
            .catalog
            .schemas()
            .find(|s| s.database_id == db.id && s.name == schema)
            .ok_or_else(|| CatalogError::NotFound(format!("schema '{database}.{schema}'")))?;
        let items: Vec<_> = schema_obj
            .tables
            .iter()
            .filter_map(|tid| self.catalog.table(*tid))
            .map(|t| CatalogTable {
                id: CatalogObjectId::table(database, schema, &t.name),
                database: database.to_string(),
                schema: schema.to_string(),
                name: t.name.clone(),
                kind: CatalogTableKind::Table,
            })
            .collect();
        Ok(page_by_name(items, page, |t| &t.name))
    }

    fn get_table(&self, table: &TableRef) -> Result<CatalogTable> {
        let t = self.resolve_table(table)?;
        Ok(CatalogTable {
            id: CatalogObjectId::table(&table.database, &table.schema, &t.name),
            database: table.database.clone(),
            schema: table.schema.clone(),
            name: t.name.clone(),
            kind: CatalogTableKind::Table,
        })
    }

    fn list_columns(
        &self,
        table: &TableRef,
        page: &PageQuery,
    ) -> Result<CatalogPage<CatalogColumn>> {
        let t = self.resolve_table(table)?;
        let pk: Vec<_> = t
            .primary_key
            .as_ref()
            .map(|pk| pk.columns.clone())
            .unwrap_or_default();
        let mut items: Vec<_> = t
            .columns
            .iter()
            .map(|c| CatalogColumn {
                id: CatalogObjectId::column(
                    &table.database,
                    &table.schema,
                    &table.table,
                    &c.name,
                ),
                name: c.name.clone(),
                ordinal: c.ordinal,
                data_type: sql_type_name(&c.data_type),
                nullable: c.nullable,
                default: c.default.clone(),
                primary_key: pk.iter().any(|id| *id == c.id),
            })
            .collect();
        items.sort_by_key(|c| c.ordinal);
        // Column list uses ordinal order; pagination by name still applies for large tables.
        Ok(page_by_name(items, page, |c| &c.name))
    }

    fn list_indexes(
        &self,
        table: &TableRef,
        page: &PageQuery,
    ) -> Result<CatalogPage<CatalogIndex>> {
        let t = self.resolve_table(table)?;
        let items: Vec<_> = t
            .indexes
            .iter()
            .map(|idx| CatalogIndex {
                id: CatalogObjectId {
                    database: table.database.clone(),
                    schema: Some(table.schema.clone()),
                    object: Some(table.table.clone()),
                    child: Some(idx.name.clone()),
                },
                name: idx.name.clone(),
                index_type: CatalogIndexType::BTree,
                unique: idx.unique,
                columns: idx
                    .columns
                    .iter()
                    .filter_map(|cid| t.columns.iter().find(|c| c.id == *cid).map(|c| c.name.clone()))
                    .collect(),
            })
            .collect();
        Ok(page_by_name(items, page, |i| &i.name))
    }

    fn list_constraints(
        &self,
        table: &TableRef,
        page: &PageQuery,
    ) -> Result<CatalogPage<CatalogConstraint>> {
        let t = self.resolve_table(table)?;
        let mut items = Vec::new();
        if let Some(pk) = &t.primary_key {
            let columns: Vec<_> = pk
                .columns
                .iter()
                .filter_map(|cid| t.columns.iter().find(|c| c.id == *cid).map(|c| c.name.clone()))
                .collect();
            let name = format!("{}_pkey", t.name);
            items.push(CatalogConstraint {
                id: CatalogObjectId {
                    database: table.database.clone(),
                    schema: Some(table.schema.clone()),
                    object: Some(table.table.clone()),
                    child: Some(name.clone()),
                },
                name,
                kind: CatalogConstraintKind::PrimaryKey,
                columns,
                referenced_table: None,
                referenced_columns: None,
            });
        }
        for idx in &t.indexes {
            if !idx.unique {
                continue;
            }
            let columns: Vec<_> = idx
                .columns
                .iter()
                .filter_map(|cid| t.columns.iter().find(|c| c.id == *cid).map(|c| c.name.clone()))
                .collect();
            items.push(CatalogConstraint {
                id: CatalogObjectId {
                    database: table.database.clone(),
                    schema: Some(table.schema.clone()),
                    object: Some(table.table.clone()),
                    child: Some(idx.name.clone()),
                },
                name: idx.name.clone(),
                kind: CatalogConstraintKind::Unique,
                columns,
                referenced_table: None,
                referenced_columns: None,
            });
        }
        Ok(page_by_name(items, page, |c| &c.name))
    }
}

fn sql_type_name(ty: &SqlDataType) -> String {
    match ty {
        SqlDataType::Null => "NULL".into(),
        SqlDataType::Boolean => "BOOLEAN".into(),
        SqlDataType::Integer => "INTEGER".into(),
        SqlDataType::BigInt => "BIGINT".into(),
        SqlDataType::Double => "DOUBLE".into(),
        SqlDataType::Decimal { precision, scale } => format!("DECIMAL({precision},{scale})"),
        SqlDataType::Text => "TEXT".into(),
        SqlDataType::Blob => "BLOB".into(),
        SqlDataType::Timestamp => "TIMESTAMP".into(),
        SqlDataType::Date => "DATE".into(),
    }
}
