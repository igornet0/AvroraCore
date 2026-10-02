use dmc_catalog::TableRef;
use dmc_model::{Catalog, CatalogEvent, ColumnDef, SqlDataType};

use crate::error::{DdlError, Result};
use crate::types::{
    AddColumnRequest, AlterColumnRequest, CatalogInvalidation, CreateIndexRequest,
    CreateTableRequest, DropColumnRequest, DropIndexRequest, DropTableRequest, ObjectKind,
    RenameColumnRequest, RenameTableRequest, SchemaMutationResult, SupportedDdlOps,
};

/// Plans typed DDL into [`CatalogEvent`]s using the authoritative catalog.
pub struct DdlService;

impl DdlService {
    pub fn supported_ops() -> SupportedDdlOps {
        SupportedDdlOps::engine_v1()
    }

    pub fn plan_create_table(
        catalog: &mut Catalog,
        req: &CreateTableRequest,
    ) -> Result<(CatalogEvent, SchemaMutationResult)> {
        if !Self::supported_ops().create_table {
            return Err(DdlError::Unsupported("create_table".into()));
        }
        validate_ident(&req.database)?;
        validate_ident(&req.schema)?;
        validate_ident(&req.name)?;
        if req.columns.is_empty() {
            return Err(DdlError::InvalidDefinition(
                "CREATE TABLE requires at least one column".into(),
            ));
        }
        let db = catalog
            .database_by_name(&req.database)
            .ok_or_else(|| DdlError::NotFound(format!("database '{}'", req.database)))?;
        let schema_id = catalog
            .schemas()
            .find(|s| s.database_id == db.id && s.name == req.schema)
            .map(|s| s.id)
            .ok_or_else(|| {
                DdlError::NotFound(format!("schema '{}.{}'", req.database, req.schema))
            })?;

        let mut columns = Vec::with_capacity(req.columns.len());
        let mut pk = Vec::new();
        for col in &req.columns {
            validate_ident(&col.name)?;
            columns.push(ColumnDef {
                name: col.name.clone(),
                data_type: parse_sql_type(&col.data_type)?,
                nullable: col.nullable,
                default: col.default.clone(),
            });
            if col.primary_key {
                pk.push(col.name.clone());
            }
        }
        let pk = if pk.is_empty() { None } else { Some(pk) };
        let event = catalog.create_table_event(schema_id, &req.name, columns, pk)?;
        let result = SchemaMutationResult {
            operation_id: new_operation_id(),
            operation: "create_table".into(),
            database: req.database.clone(),
            schema: req.schema.clone(),
            object: req.name.clone(),
            object_kind: ObjectKind::Table,
            invalidations: vec![
                CatalogInvalidation::TableList,
                CatalogInvalidation::TableGet,
                CatalogInvalidation::ColumnList,
                CatalogInvalidation::IndexList,
                CatalogInvalidation::ConstraintList,
            ],
            generated_sql: None,
        };
        Ok((event, result))
    }

    pub fn plan_drop_table(
        catalog: &Catalog,
        req: &DropTableRequest,
    ) -> Result<(CatalogEvent, SchemaMutationResult)> {
        if !Self::supported_ops().drop_table {
            return Err(DdlError::Unsupported("drop_table".into()));
        }
        let table = resolve_table(catalog, &req.table)?;
        let event = catalog.drop_table_event(table.id)?;
        let result = SchemaMutationResult {
            operation_id: new_operation_id(),
            operation: "drop_table".into(),
            database: req.table.database.clone(),
            schema: req.table.schema.clone(),
            object: req.table.table.clone(),
            object_kind: ObjectKind::Table,
            invalidations: vec![
                CatalogInvalidation::TableList,
                CatalogInvalidation::TableGet,
                CatalogInvalidation::ColumnList,
                CatalogInvalidation::IndexList,
                CatalogInvalidation::ConstraintList,
            ],
            generated_sql: None,
        };
        Ok((event, result))
    }

    pub fn plan_create_index(
        catalog: &mut Catalog,
        req: &CreateIndexRequest,
    ) -> Result<(CatalogEvent, SchemaMutationResult)> {
        if !Self::supported_ops().create_index {
            return Err(DdlError::Unsupported("create_index".into()));
        }
        validate_ident(&req.name)?;
        if req.columns.is_empty() {
            return Err(DdlError::InvalidDefinition(
                "CREATE INDEX requires at least one column".into(),
            ));
        }
        let table = resolve_table(catalog, &req.table)?;
        let mut col_ids = Vec::new();
        for name in &req.columns {
            let col = table
                .columns
                .iter()
                .find(|c| c.name == *name)
                .ok_or_else(|| {
                    DdlError::NotFound(format!(
                        "column '{}' on '{}.{}.{}'",
                        name, req.table.database, req.table.schema, req.table.table
                    ))
                })?;
            col_ids.push(col.id);
        }
        let event = catalog.create_index_event(table.id, &req.name, col_ids, req.unique)?;
        let result = SchemaMutationResult {
            operation_id: new_operation_id(),
            operation: "create_index".into(),
            database: req.table.database.clone(),
            schema: req.table.schema.clone(),
            object: req.name.clone(),
            object_kind: ObjectKind::Index,
            invalidations: vec![
                CatalogInvalidation::IndexList,
                CatalogInvalidation::TableGet,
                CatalogInvalidation::ConstraintList,
            ],
            generated_sql: None,
        };
        Ok((event, result))
    }

    pub fn plan_drop_index(
        catalog: &Catalog,
        req: &DropIndexRequest,
    ) -> Result<(CatalogEvent, SchemaMutationResult)> {
        if !Self::supported_ops().drop_index {
            return Err(DdlError::Unsupported("drop_index".into()));
        }
        validate_ident(&req.name)?;
        let table = resolve_table(catalog, &req.table)?;
        let index = table
            .indexes
            .iter()
            .find(|i| i.name == req.name)
            .ok_or_else(|| {
                DdlError::NotFound(format!(
                    "index '{}' on '{}.{}.{}'",
                    req.name, req.table.database, req.table.schema, req.table.table
                ))
            })?;
        let event = catalog.drop_index_event(index.id)?;
        let result = SchemaMutationResult {
            operation_id: new_operation_id(),
            operation: "drop_index".into(),
            database: req.table.database.clone(),
            schema: req.table.schema.clone(),
            object: req.name.clone(),
            object_kind: ObjectKind::Index,
            invalidations: vec![
                CatalogInvalidation::IndexList,
                CatalogInvalidation::TableGet,
                CatalogInvalidation::ConstraintList,
            ],
            generated_sql: None,
        };
        Ok((event, result))
    }

    pub fn plan_add_column(
        _catalog: &mut Catalog,
        _req: &AddColumnRequest,
    ) -> Result<(CatalogEvent, SchemaMutationResult)> {
        Err(DdlError::Unsupported(
            "add_column: CatalogEvent exists but row-store schema is not updated yet".into(),
        ))
    }

    pub fn plan_drop_column(
        _catalog: &Catalog,
        _req: &DropColumnRequest,
    ) -> Result<(CatalogEvent, SchemaMutationResult)> {
        Err(DdlError::Unsupported(
            "drop_column: CatalogEvent exists but row-store schema is not updated yet".into(),
        ))
    }

    pub fn plan_alter_column(
        _catalog: &Catalog,
        _req: &AlterColumnRequest,
    ) -> Result<(CatalogEvent, SchemaMutationResult)> {
        Err(DdlError::Unsupported(
            "alter_column: no CatalogEvent / SQL ALTER TABLE in engine".into(),
        ))
    }

    pub fn plan_rename_column(
        _catalog: &Catalog,
        _req: &RenameColumnRequest,
    ) -> Result<(CatalogEvent, SchemaMutationResult)> {
        Err(DdlError::Unsupported(
            "rename_column: no CatalogEvent in engine".into(),
        ))
    }

    pub fn plan_rename_table(
        _catalog: &Catalog,
        _req: &RenameTableRequest,
    ) -> Result<(CatalogEvent, SchemaMutationResult)> {
        Err(DdlError::Unsupported(
            "rename_table: no CatalogEvent in engine".into(),
        ))
    }

    /// Informational SQL for UI (not the execution source of truth).
    pub fn describe_sql(operation: &str, result: &SchemaMutationResult) -> Option<String> {
        let qual = format!("{}.{}", result.schema, result.object);
        match operation {
            "create_table" => Some(format!("-- planned CREATE TABLE {qual}")),
            "drop_table" => Some(format!("DROP TABLE {qual}")),
            "create_index" => Some(format!("-- planned CREATE INDEX {} ON {qual}", result.object)),
            "drop_index" => Some(format!("DROP INDEX {}", result.object)),
            _ => None,
        }
    }
}

fn resolve_table<'a>(
    catalog: &'a Catalog,
    table: &TableRef,
) -> Result<&'a dmc_model::Table> {
    validate_ident(&table.database)?;
    validate_ident(&table.schema)?;
    validate_ident(&table.table)?;
    let db = catalog
        .database_by_name(&table.database)
        .ok_or_else(|| DdlError::NotFound(format!("database '{}'", table.database)))?;
    let schema_id = catalog
        .schemas()
        .find(|s| s.database_id == db.id && s.name == table.schema)
        .map(|s| s.id)
        .ok_or_else(|| {
            DdlError::NotFound(format!("schema '{}.{}'", table.database, table.schema))
        })?;
    catalog
        .table_by_name(schema_id, &table.table)
        .ok_or_else(|| {
            DdlError::NotFound(format!(
                "table '{}.{}.{}'",
                table.database, table.schema, table.table
            ))
        })
}

fn validate_ident(name: &str) -> Result<()> {
    if name.is_empty() || name.chars().any(|c| c.is_whitespace()) {
        return Err(DdlError::InvalidIdentifier(name.into()));
    }
    Ok(())
}

fn new_operation_id() -> String {
    format!("ddl-{}", uuid::Uuid::new_v4())
}

pub fn parse_sql_type(raw: &str) -> Result<SqlDataType> {
    let s = raw.trim().to_ascii_uppercase();
    let base = s.split('(').next().unwrap_or(&s).trim();
    match base {
        "NULL" => Ok(SqlDataType::Null),
        "BOOLEAN" | "BOOL" => Ok(SqlDataType::Boolean),
        "INTEGER" | "INT" => Ok(SqlDataType::Integer),
        "BIGINT" => Ok(SqlDataType::BigInt),
        "DOUBLE" | "FLOAT" | "REAL" => Ok(SqlDataType::Double),
        "TEXT" | "VARCHAR" | "STRING" => Ok(SqlDataType::Text),
        "BLOB" | "BYTEA" => Ok(SqlDataType::Blob),
        "TIMESTAMP" => Ok(SqlDataType::Timestamp),
        "DATE" => Ok(SqlDataType::Date),
        "DECIMAL" | "NUMERIC" => {
            // DECIMAL(p,s) or DECIMAL
            if let Some(inside) = s.strip_prefix("DECIMAL(").or_else(|| s.strip_prefix("NUMERIC("))
            {
                let inside = inside.trim_end_matches(')');
                let mut parts = inside.split(',');
                let precision = parts
                    .next()
                    .and_then(|p| p.trim().parse().ok())
                    .unwrap_or(18);
                let scale = parts
                    .next()
                    .and_then(|p| p.trim().parse().ok())
                    .unwrap_or(0);
                Ok(SqlDataType::Decimal { precision, scale })
            } else {
                Ok(SqlDataType::Decimal {
                    precision: 18,
                    scale: 0,
                })
            }
        }
        _ => Err(DdlError::InvalidDefinition(format!(
            "unsupported data type '{raw}'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use dmc_model::{ApplyMode, Catalog, CatalogApplier, ColumnDef, SqlDataType};

    use super::*;
    use crate::types::ColumnDefinition;

    fn seeded() -> Catalog {
        let mut catalog = Catalog::new();
        let _ = catalog.bootstrap_default().unwrap();
        catalog
    }

    #[test]
    fn create_and_drop_table_plan() {
        let mut catalog = seeded();
        let (ev, res) = DdlService::plan_create_table(
            &mut catalog,
            &CreateTableRequest {
                database: "avrora".into(),
                schema: "public".into(),
                name: "orders".into(),
                columns: vec![
                    ColumnDefinition {
                        name: "id".into(),
                        data_type: "BIGINT".into(),
                        nullable: false,
                        default: None,
                        primary_key: true,
                    },
                    ColumnDefinition {
                        name: "note".into(),
                        data_type: "TEXT".into(),
                        nullable: true,
                        default: None,
                        primary_key: false,
                    },
                ],
            },
        )
        .unwrap();
        catalog.apply(&ev, ApplyMode::Live).unwrap();
        assert_eq!(res.operation, "create_table");
        assert!(catalog
            .tables()
            .any(|t| t.name == "orders"));

        let (drop, _) = DdlService::plan_drop_table(
            &catalog,
            &DropTableRequest {
                table: TableRef {
                    database: "avrora".into(),
                    schema: "public".into(),
                    table: "orders".into(),
                },
            },
        )
        .unwrap();
        catalog.apply(&drop, ApplyMode::Live).unwrap();
        assert!(!catalog.tables().any(|t| t.name == "orders"));
    }

    #[test]
    fn create_drop_index_plan() {
        let mut catalog = seeded();
        let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
        let create = catalog
            .create_table_event(
                schema,
                "t1",
                vec![ColumnDef {
                    name: "id".into(),
                    data_type: SqlDataType::BigInt,
                    nullable: false,
                    default: None,
                }],
                Some(vec!["id".into()]),
            )
            .unwrap();
        catalog.apply(&create, ApplyMode::Live).unwrap();

        let (idx, _) = DdlService::plan_create_index(
            &mut catalog,
            &CreateIndexRequest {
                table: TableRef {
                    database: "avrora".into(),
                    schema: "public".into(),
                    table: "t1".into(),
                },
                name: "t1_id_uq".into(),
                columns: vec!["id".into()],
                unique: true,
            },
        )
        .unwrap();
        catalog.apply(&idx, ApplyMode::Live).unwrap();
        let (drop, _) = DdlService::plan_drop_index(
            &catalog,
            &DropIndexRequest {
                table: TableRef {
                    database: "avrora".into(),
                    schema: "public".into(),
                    table: "t1".into(),
                },
                name: "t1_id_uq".into(),
            },
        )
        .unwrap();
        catalog.apply(&drop, ApplyMode::Live).unwrap();
    }

    #[test]
    fn unsupported_ops() {
        let mut catalog = seeded();
        let table = TableRef {
            database: "avrora".into(),
            schema: "public".into(),
            table: "users".into(),
        };
        assert!(matches!(
            DdlService::plan_add_column(
                &mut catalog,
                &AddColumnRequest {
                    table: table.clone(),
                    column: ColumnDefinition {
                        name: "x".into(),
                        data_type: "INT".into(),
                        nullable: true,
                        default: None,
                        primary_key: false,
                    },
                },
            ),
            Err(DdlError::Unsupported(_))
        ));
        assert!(matches!(
            DdlService::plan_rename_table(
                &catalog,
                &RenameTableRequest {
                    table,
                    new_name: "u2".into(),
                },
            ),
            Err(DdlError::Unsupported(_))
        ));
    }
}
