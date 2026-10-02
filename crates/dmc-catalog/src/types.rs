/// Stable identity for catalog objects (namespace model of Avrora).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CatalogObjectId {
    pub database: String,
    pub schema: Option<String>,
    pub object: Option<String>,
    pub child: Option<String>,
}

impl CatalogObjectId {
    pub fn database(name: impl Into<String>) -> Self {
        Self {
            database: name.into(),
            schema: None,
            object: None,
            child: None,
        }
    }

    pub fn schema(database: impl Into<String>, schema: impl Into<String>) -> Self {
        Self {
            database: database.into(),
            schema: Some(schema.into()),
            object: None,
            child: None,
        }
    }

    pub fn table(
        database: impl Into<String>,
        schema: impl Into<String>,
        table: impl Into<String>,
    ) -> Self {
        Self {
            database: database.into(),
            schema: Some(schema.into()),
            object: Some(table.into()),
            child: None,
        }
    }

    pub fn column(
        database: impl Into<String>,
        schema: impl Into<String>,
        table: impl Into<String>,
        column: impl Into<String>,
    ) -> Self {
        Self {
            database: database.into(),
            schema: Some(schema.into()),
            object: Some(table.into()),
            child: Some(column.into()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableRef {
    pub database: String,
    pub schema: String,
    pub table: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogTableKind {
    Table,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogDatabase {
    pub id: CatalogObjectId,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogSchema {
    pub id: CatalogObjectId,
    pub database: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogTable {
    pub id: CatalogObjectId,
    pub database: String,
    pub schema: String,
    pub name: String,
    pub kind: CatalogTableKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogColumn {
    pub id: CatalogObjectId,
    pub name: String,
    pub ordinal: u32,
    pub data_type: String,
    pub nullable: bool,
    pub default: Option<String>,
    pub primary_key: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogIndexType {
    BTree,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogIndex {
    pub id: CatalogObjectId,
    pub name: String,
    pub index_type: CatalogIndexType,
    pub unique: bool,
    pub columns: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogConstraintKind {
    PrimaryKey,
    Unique,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogConstraint {
    pub id: CatalogObjectId,
    pub name: String,
    pub kind: CatalogConstraintKind,
    pub columns: Vec<String>,
    pub referenced_table: Option<String>,
    pub referenced_columns: Option<Vec<String>>,
}
