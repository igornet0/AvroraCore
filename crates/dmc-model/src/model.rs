use serde::{Deserialize, Serialize};

use crate::ids::{ColumnId, DatabaseId, IndexId, RowId, SchemaId, TableId};

/// SQL data types for Phase 6 MVP ([ADR-016](https://github.com/) §Decision 3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SqlDataType {
    Null,
    Boolean,
    Integer,
    BigInt,
    Double,
    Decimal { precision: u32, scale: u32 },
    Text,
    Blob,
    Timestamp,
    Date,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnSnapshot {
    pub id: ColumnId,
    pub name: String,
    pub data_type: SqlDataType,
    pub nullable: bool,
    pub default: Option<String>,
    pub ordinal: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnDef {
    pub name: String,
    pub data_type: SqlDataType,
    pub nullable: bool,
    pub default: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Column {
    pub id: ColumnId,
    pub name: String,
    pub data_type: SqlDataType,
    pub nullable: bool,
    pub default: Option<String>,
    pub ordinal: u32,
}

/// Logical row identity / uniqueness constraint — distinct from physical [`RowId`](crate::RowId).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimaryKey {
    pub columns: Vec<ColumnId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Index {
    pub id: IndexId,
    pub name: String,
    pub table_id: TableId,
    pub columns: Vec<ColumnId>,
    pub unique: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Table {
    pub id: TableId,
    pub schema_id: SchemaId,
    pub name: String,
    pub columns: Vec<Column>,
    pub primary_key: Option<PrimaryKey>,
    pub indexes: Vec<Index>,
    /// Next physical row id to assign on INSERT (Phase 6.8+). Not journal-derived.
    pub next_row_id: RowId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schema {
    pub id: SchemaId,
    pub database_id: DatabaseId,
    pub name: String,
    pub tables: Vec<TableId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Database {
    pub id: DatabaseId,
    pub name: String,
    pub schemas: Vec<SchemaId>,
}
