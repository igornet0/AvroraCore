use std::collections::HashMap;

use dmc_model::{Catalog, Column, ColumnId, DatabaseId, SchemaId, Table, TableId};
use dmc_sql_front::{Ident, QualifiedName, SourceSpan};

use crate::error::{BindError, Result};

pub const DEFAULT_DATABASE: &str = "avrora";
pub const DEFAULT_SCHEMA: &str = "public";

#[derive(Clone, Debug)]
pub struct ResolvedTable {
    pub table_id: TableId,
    pub table: Table,
    #[allow(dead_code)]
    pub alias: String,
}

#[derive(Clone, Debug, Default)]
pub struct BindScope {
    tables: Vec<ResolvedTable>,
    alias_to_table: HashMap<String, TableId>,
}

impl BindScope {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_table(
        &mut self,
        table: Table,
        alias: Option<&Ident>,
        span: SourceSpan,
    ) -> Result<()> {
        let alias_name = alias
            .map(|a| a.name.clone())
            .unwrap_or_else(|| table.name.clone());
        if self.alias_to_table.contains_key(&alias_name) {
            return Err(BindError::DuplicateAlias {
                name: alias_name,
                span: alias.map(|a| a.span).unwrap_or(span),
            });
        }
        let table_id = table.id;
        self.alias_to_table.insert(alias_name.clone(), table_id);
        self.tables.push(ResolvedTable {
            table_id,
            table,
            alias: alias_name,
        });
        Ok(())
    }

    pub fn resolve_table_alias(&self, name: &str, span: SourceSpan) -> Result<TableId> {
        self.alias_to_table
            .get(name)
            .copied()
            .ok_or(BindError::UnknownAlias {
                name: name.into(),
                span,
            })
    }

    pub fn table_by_id(&self, table_id: TableId) -> Option<&ResolvedTable> {
        self.tables.iter().find(|t| t.table_id == table_id)
    }

    pub fn resolve_column(
        &self,
        _catalog: &Catalog,
        qualifier: Option<&str>,
        name: &str,
        span: SourceSpan,
    ) -> Result<(TableId, ColumnId, Column)> {
        if let Some(q) = qualifier {
            let table_id = self.resolve_table_alias(q, span)?;
            let resolved = self
                .table_by_id(table_id)
                .expect("alias maps to registered table");
            let col = resolved
                .table
                .columns
                .iter()
                .find(|c| c.name == name)
                .cloned()
                .ok_or(BindError::UnknownColumn {
                    name: name.into(),
                    span,
                })?;
            return Ok((table_id, col.id, col));
        }

        let mut matches = Vec::new();
        for resolved in &self.tables {
            if let Some(col) = resolved.table.columns.iter().find(|c| c.name == name) {
                matches.push((resolved.table_id, col.clone()));
            }
        }
        match matches.len() {
            0 => Err(BindError::UnknownColumn {
                name: name.into(),
                span,
            }),
            1 => Ok((matches[0].0, matches[0].1.id, matches[0].1.clone())),
            _ => Err(BindError::AmbiguousColumn {
                name: name.into(),
                span,
            }),
        }
    }
}

pub struct NameResolver<'a> {
    catalog: &'a Catalog,
}

impl<'a> NameResolver<'a> {
    pub fn new(catalog: &'a Catalog) -> Self {
        Self { catalog }
    }

    pub fn default_database(&self) -> Result<DatabaseId> {
        self.database_by_name(DEFAULT_DATABASE, SourceSpan::default())
    }

    pub fn database_by_name(&self, name: &str, span: SourceSpan) -> Result<DatabaseId> {
        self.catalog
            .database_by_name(name)
            .map(|db| db.id)
            .ok_or(BindError::UnknownDatabase {
                name: name.into(),
                span,
            })
    }

    pub fn schema_in_database(
        &self,
        database_id: DatabaseId,
        name: &str,
        span: SourceSpan,
    ) -> Result<SchemaId> {
        self.catalog
            .schemas()
            .find(|s| s.database_id == database_id && s.name == name)
            .map(|s| s.id)
            .ok_or(BindError::UnknownSchema {
                name: name.into(),
                span,
            })
    }

    pub fn default_schema(&self) -> Result<SchemaId> {
        let db = self.default_database()?;
        self.schema_in_database(db, DEFAULT_SCHEMA, SourceSpan::default())
    }

    pub fn resolve_table_ref(
        &self,
        name: &QualifiedName,
        span: SourceSpan,
    ) -> Result<(TableId, Table)> {
        let parts: Vec<_> = name.parts.iter().map(|p| p.name.as_str()).collect();
        let (schema_id, table_name, table_span) = match parts.as_slice() {
            [table] => {
                let schema = self.default_schema()?;
                (schema, table.to_string(), name.parts[0].span)
            }
            [schema, table] => {
                let schema_id = self.schema_in_database(
                    self.default_database()?,
                    schema,
                    name.parts[0].span,
                )?;
                (schema_id, (*table).to_string(), name.parts[1].span)
            }
            [db, schema, table] => {
                let db_id = self.database_by_name(db, name.parts[0].span)?;
                let schema_id = self.schema_in_database(db_id, schema, name.parts[1].span)?;
                (schema_id, (*table).to_string(), name.parts[2].span)
            }
            _ => {
                return Err(BindError::UnknownTable {
                    name: parts.join("."),
                    span,
                });
            }
        };
        let table = self
            .catalog
            .table_by_name(schema_id, &table_name)
            .cloned()
            .ok_or(BindError::UnknownTable {
                name: table_name.clone(),
                span: table_span,
            })?;
        Ok((table.id, table))
    }

    pub fn find_index_by_name(&self, name: &str, span: SourceSpan) -> Result<(TableId, dmc_model::IndexId)> {
        let mut matches = Vec::new();
        for table in self.catalog.tables() {
            for idx in &table.indexes {
                if idx.name == name {
                    matches.push((table.id, idx.id));
                }
            }
        }
        match matches.len() {
            0 => Err(BindError::UnknownIndex {
                name: name.into(),
                span,
            }),
            1 => Ok(matches[0]),
            _ => Err(BindError::AmbiguousColumn {
                name: name.into(),
                span,
            }),
        }
    }
}

pub fn map_catalog_error(err: dmc_model::Error, span: SourceSpan) -> BindError {
    match err {
        dmc_model::Error::AlreadyExists(msg) => {
            if msg.contains("table") {
                BindError::TableAlreadyExists {
                    name: msg,
                    span,
                }
            } else if msg.contains("column") {
                BindError::ColumnAlreadyExists {
                    name: msg,
                    span,
                }
            } else if msg.contains("index") {
                BindError::IndexAlreadyExists {
                    name: msg,
                    span,
                }
            } else {
                BindError::Catalog { message: msg, span }
            }
        }
        dmc_model::Error::NotFound(msg) => BindError::Catalog { message: msg, span },
        other => BindError::Catalog {
            message: other.to_string(),
            span,
        },
    }
}
