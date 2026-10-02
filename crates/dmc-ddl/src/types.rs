use dmc_catalog::TableRef;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColumnDefinition {
    pub name: String,
    pub data_type: String,
    pub nullable: bool,
    pub default: Option<String>,
    pub primary_key: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateTableRequest {
    pub database: String,
    pub schema: String,
    pub name: String,
    pub columns: Vec<ColumnDefinition>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DropTableRequest {
    pub table: TableRef,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenameTableRequest {
    pub table: TableRef,
    pub new_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddColumnRequest {
    pub table: TableRef,
    pub column: ColumnDefinition,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlterColumnRequest {
    pub table: TableRef,
    pub column: String,
    pub nullable: Option<bool>,
    pub data_type: Option<String>,
    pub default: Option<Option<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DropColumnRequest {
    pub table: TableRef,
    pub column: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenameColumnRequest {
    pub table: TableRef,
    pub column: String,
    pub new_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateIndexRequest {
    pub table: TableRef,
    pub name: String,
    pub columns: Vec<String>,
    pub unique: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DropIndexRequest {
    pub table: TableRef,
    pub name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    Database,
    Schema,
    Table,
    Column,
    Index,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogInvalidation {
    DatabaseList,
    SchemaList,
    TableList,
    TableGet,
    ColumnList,
    IndexList,
    ConstraintList,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaMutationResult {
    pub operation_id: String,
    pub operation: String,
    pub database: String,
    pub schema: String,
    pub object: String,
    pub object_kind: ObjectKind,
    pub invalidations: Vec<CatalogInvalidation>,
    /// Informational only — never the execution source of truth.
    pub generated_sql: Option<String>,
}

/// Ops that plan → journal → storage today (Create/Drop Table/Index).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupportedDdlOps {
    pub create_table: bool,
    pub drop_table: bool,
    pub create_index: bool,
    pub drop_index: bool,
    pub add_column: bool,
    pub drop_column: bool,
    pub alter_column: bool,
    pub rename_column: bool,
    pub rename_table: bool,
}

impl SupportedDdlOps {
    /// Matches live `dmc-sql-exec` + `StateMaterializer::apply_catalog_side_effects`.
    pub fn engine_v1() -> Self {
        Self {
            create_table: true,
            drop_table: true,
            create_index: true,
            drop_index: true,
            // CatalogEvent exists but row-store schema is not updated (`_ => {}`).
            add_column: false,
            drop_column: false,
            alter_column: false,
            rename_column: false,
            rename_table: false,
        }
    }
}
