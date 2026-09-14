use serde::{Deserialize, Serialize};

use crate::ids::{ColumnId, DatabaseId, IndexId, SchemaId, TableId};
use crate::model::{ColumnDef, ColumnSnapshot, PrimaryKey, SqlDataType};

/// Durable catalog mutation — not SQL AST. Produced by DDL planner / admin API / tests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CatalogEvent {
    CreateDatabase {
        id: DatabaseId,
        name: String,
    },
    CreateSchema {
        id: SchemaId,
        database_id: DatabaseId,
        name: String,
    },
    CreateTable {
        id: TableId,
        schema_id: SchemaId,
        name: String,
        columns: Vec<ColumnSnapshot>,
        primary_key: Option<PrimaryKey>,
    },
    DropTable {
        table_id: TableId,
    },
    AddColumn {
        table_id: TableId,
        column: ColumnDef,
        column_id: ColumnId,
    },
    DropColumn {
        table_id: TableId,
        column_id: ColumnId,
    },
    CreateIndex {
        id: IndexId,
        table_id: TableId,
        name: String,
        columns: Vec<ColumnId>,
        unique: bool,
    },
    DropIndex {
        index_id: IndexId,
    },
}

impl CatalogEvent {
    pub fn validate(&self) -> crate::Result<()> {
        match self {
            CatalogEvent::CreateDatabase { name, .. } => validate_name(name),
            CatalogEvent::CreateSchema { name, .. } => validate_name(name),
            CatalogEvent::CreateTable {
                name,
                columns,
                primary_key,
                ..
            } => {
                validate_name(name)?;
                if columns.is_empty() {
                    return Err(crate::Error::InvalidEvent(
                        "CreateTable requires at least one column".into(),
                    ));
                }
                for col in columns {
                    validate_name(&col.name)?;
                    if matches!(col.data_type, SqlDataType::Null) {
                        return Err(crate::Error::InvalidEvent(format!(
                            "column '{}' cannot use NULL type",
                            col.name
                        )));
                    }
                }
                if let Some(pk) = primary_key {
                    if pk.columns.is_empty() {
                        return Err(crate::Error::InvalidEvent(
                            "PRIMARY KEY requires at least one column".into(),
                        ));
                    }
                    for col_id in &pk.columns {
                        if !columns.iter().any(|c| c.id == *col_id) {
                            return Err(crate::Error::InvalidEvent(format!(
                                "PRIMARY KEY column {} not in CREATE TABLE column list",
                                col_id.raw()
                            )));
                        }
                    }
                }
                Ok(())
            }
            CatalogEvent::AddColumn { column, .. } => validate_columns(std::slice::from_ref(column)),
            CatalogEvent::CreateIndex { name, columns, .. } => {
                validate_name(name)?;
                if columns.is_empty() {
                    return Err(crate::Error::InvalidEvent(
                        "CREATE INDEX requires at least one column".into(),
                    ));
                }
                Ok(())
            }
            CatalogEvent::DropTable { .. }
            | CatalogEvent::DropColumn { .. }
            | CatalogEvent::DropIndex { .. } => Ok(()),
        }
    }
}

fn validate_name(name: &str) -> crate::Result<()> {
    if name.is_empty() {
        return Err(crate::Error::InvalidEvent("empty name".into()));
    }
    if name.chars().any(|c| c.is_whitespace()) {
        return Err(crate::Error::InvalidEvent(format!(
            "invalid name '{name}'"
        )));
    }
    Ok(())
}

fn validate_columns(columns: &[ColumnDef]) -> crate::Result<()> {
    for col in columns {
        validate_name(&col.name)?;
        if matches!(col.data_type, SqlDataType::Null) {
            return Err(crate::Error::InvalidEvent(format!(
                "column '{}' cannot use NULL type",
                col.name
            )));
        }
    }
    Ok(())
}
