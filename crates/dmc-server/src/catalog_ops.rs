//! Typed Catalog RPC handlers (P7.2) — thin adapter over `dmc_catalog::CatalogService`.

use dmc_catalog::{
    CatalogConstraintKind, CatalogError, CatalogService, ModelCatalogProvider, PageQuery, TableRef,
};
use dmc_protocol::{
    CatalogColumnWire, CatalogConstraintKindWire, CatalogConstraintWire, CatalogDatabaseWire,
    CatalogIndexWire, CatalogSchemaWire, CatalogSnapshotWire,
    CatalogTableSummaryWire, CatalogTableWire, ControlRequest, ControlResponse, ProtocolErrorCode,
    ResponseEnvelope,
};

use crate::state::CoreServerState;

pub fn handle_catalog(
    state: &mut CoreServerState,
    request_id: u64,
    req: ControlRequest,
) -> ResponseEnvelope<ControlResponse> {
    if !dmc_protocol::ServerCapabilities::core_v1().sql_catalog {
        return ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::Unsupported,
            "sql catalog unsupported",
        );
    }
    if state.storage_sealed() {
        return ResponseEnvelope::err(request_id, ProtocolErrorCode::VaultLocked, "vault is locked");
    }
    let catalog = match state.ctx.session_catalog() {
        Ok(c) => c,
        Err(e) => {
            return ResponseEnvelope::err(
                request_id,
                ProtocolErrorCode::ResourceNotFound,
                e.to_string(),
            );
        }
    };
    let service = CatalogService::new(ModelCatalogProvider::new(catalog));

    match req {
        ControlRequest::CatalogList { .. } => {
            match snapshot_via_service(&service) {
                Ok(snap) => ResponseEnvelope::ok(request_id, ControlResponse::CatalogList(snap)),
                Err(err) => map_catalog_err(request_id, err),
            }
        }
        ControlRequest::DatabaseList { .. } => match service.list_databases() {
            Ok(items) => ResponseEnvelope::ok(
                request_id,
                ControlResponse::DatabaseList {
                    items: items
                        .into_iter()
                        .map(|d| CatalogDatabaseWire { name: d.name })
                        .collect(),
                },
            ),
            Err(err) => map_catalog_err(request_id, err),
        },
        ControlRequest::SchemaList {
            database,
            cursor,
            limit,
            name_filter,
            ..
        } => {
            let page = PageQuery {
                cursor,
                limit: Some(limit),
                name_filter,
            };
            match service.list_schemas(database.as_deref(), &page) {
                Ok(page) => ResponseEnvelope::ok(
                    request_id,
                    ControlResponse::SchemaList {
                        items: page
                            .items
                            .into_iter()
                            .map(|s| CatalogSchemaWire {
                                database: s.database,
                                name: s.name,
                            })
                            .collect(),
                        next_cursor: page.next_cursor.clone(),
                        truncated: page.truncated,
                    },
                ),
                Err(err) => map_catalog_err(request_id, err),
            }
        }
        ControlRequest::TableList {
            database,
            schema,
            cursor,
            limit,
            name_filter,
            ..
        } => {
            let page = PageQuery {
                cursor,
                limit: Some(limit),
                name_filter,
            };
            match service.list_tables(&database, &schema, &page) {
                Ok(page) => ResponseEnvelope::ok(
                    request_id,
                    ControlResponse::TableList {
                        items: page
                            .items
                            .into_iter()
                            .map(|t| CatalogTableSummaryWire {
                                database: t.database,
                                schema: t.schema,
                                name: t.name,
                                kind: "table".into(),
                            })
                            .collect(),
                        next_cursor: page.next_cursor.clone(),
                        truncated: page.truncated,
                    },
                ),
                Err(err) => map_catalog_err(request_id, err),
            }
        }
        ControlRequest::TableGet {
            database,
            schema,
            table,
            ..
        } => {
            let table = TableRef {
                database,
                schema,
                table,
            };
            match service.get_table(&table) {
                Ok(t) => ResponseEnvelope::ok(
                    request_id,
                    ControlResponse::TableGet(CatalogTableSummaryWire {
                        database: t.database,
                        schema: t.schema,
                        name: t.name,
                        kind: "table".into(),
                    }),
                ),
                Err(err) => map_catalog_err(request_id, err),
            }
        }
        ControlRequest::ColumnList {
            database,
            schema,
            table,
            cursor,
            limit,
            name_filter,
            ..
        } => {
            let table = TableRef {
                database,
                schema,
                table,
            };
            let page = PageQuery {
                cursor,
                limit: Some(limit),
                name_filter,
            };
            match service.list_columns(&table, &page) {
                Ok(page) => ResponseEnvelope::ok(
                    request_id,
                    ControlResponse::ColumnList {
                        items: page
                            .items
                            .into_iter()
                            .map(|c| CatalogColumnWire {
                                id: c
                                    .id
                                    .child
                                    .clone()
                                    .unwrap_or_else(|| c.name.clone()),
                                name: c.name,
                                data_type: c.data_type,
                                nullable: c.nullable,
                                default: c.default,
                                primary_key: c.primary_key,
                                ordinal: c.ordinal,
                            })
                            .collect(),
                        next_cursor: page.next_cursor.clone(),
                        truncated: page.truncated,
                    },
                ),
                Err(err) => map_catalog_err(request_id, err),
            }
        }
        ControlRequest::IndexList {
            database,
            schema,
            table,
            cursor,
            limit,
            name_filter,
            ..
        } => {
            let table = TableRef {
                database,
                schema,
                table,
            };
            let page = PageQuery {
                cursor,
                limit: Some(limit),
                name_filter,
            };
            match service.list_indexes(&table, &page) {
                Ok(page) => ResponseEnvelope::ok(
                    request_id,
                    ControlResponse::IndexList {
                        items: page
                            .items
                            .into_iter()
                            .map(|i| CatalogIndexWire {
                                id: i.name.clone(),
                                name: i.name,
                                columns: i.columns,
                                unique: i.unique,
                                index_type: "btree".into(),
                            })
                            .collect(),
                        next_cursor: page.next_cursor.clone(),
                        truncated: page.truncated,
                    },
                ),
                Err(err) => map_catalog_err(request_id, err),
            }
        }
        ControlRequest::ConstraintList {
            database,
            schema,
            table,
            cursor,
            limit,
            name_filter,
            ..
        } => {
            let table = TableRef {
                database,
                schema,
                table,
            };
            let page = PageQuery {
                cursor,
                limit: Some(limit),
                name_filter,
            };
            match service.list_constraints(&table, &page) {
                Ok(page) => ResponseEnvelope::ok(
                    request_id,
                    ControlResponse::ConstraintList {
                        items: page
                            .items
                            .into_iter()
                            .map(|c| CatalogConstraintWire {
                                id: c.name.clone(),
                                name: c.name,
                                kind: match c.kind {
                                    CatalogConstraintKind::PrimaryKey => {
                                        CatalogConstraintKindWire::PrimaryKey
                                    }
                                    CatalogConstraintKind::Unique => {
                                        CatalogConstraintKindWire::Unique
                                    }
                                },
                                columns: c.columns,
                                referenced_table: c.referenced_table,
                                referenced_columns: c.referenced_columns,
                            })
                            .collect(),
                        next_cursor: page.next_cursor.clone(),
                        truncated: page.truncated,
                    },
                ),
                Err(err) => map_catalog_err(request_id, err),
            }
        }
        other => ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::InvalidRequest,
            format!("not a catalog request: {other:?}"),
        ),
    }
}

fn snapshot_via_service(
    service: &CatalogService<ModelCatalogProvider<'_>>,
) -> Result<CatalogSnapshotWire, CatalogError> {
    let databases = service.list_databases()?;
    let schemas = service.list_schemas(None, &PageQuery {
        cursor: None,
        limit: Some(dmc_catalog::MAX_PAGE_LIMIT),
        name_filter: None,
    })?;
    let mut tables = Vec::new();
    for schema in &schemas.items {
        let mut cursor = None;
        loop {
            let page = service.list_tables(
                &schema.database,
                &schema.name,
                &PageQuery {
                    cursor: cursor.clone(),
                    limit: Some(dmc_catalog::MAX_PAGE_LIMIT),
                    name_filter: None,
                },
            )?;
            for t in &page.items {
                let table = TableRef {
                    database: t.database.clone(),
                    schema: t.schema.clone(),
                    table: t.name.clone(),
                };
                let columns = service.list_columns(&table, &PageQuery {
                    cursor: None,
                    limit: Some(dmc_catalog::MAX_PAGE_LIMIT),
                    name_filter: None,
                })?;
                let indexes = service.list_indexes(&table, &PageQuery {
                    cursor: None,
                    limit: Some(dmc_catalog::MAX_PAGE_LIMIT),
                    name_filter: None,
                })?;
                tables.push(CatalogTableWire {
                    database: t.database.clone(),
                    schema: t.schema.clone(),
                    name: t.name.clone(),
                    kind: "table".into(),
                    columns: columns
                        .items
                        .into_iter()
                        .map(|c| CatalogColumnWire {
                            id: c.name.clone(),
                            name: c.name,
                            data_type: c.data_type,
                            nullable: c.nullable,
                            default: c.default,
                            primary_key: c.primary_key,
                            ordinal: c.ordinal,
                        })
                        .collect(),
                    indexes: indexes
                        .items
                        .into_iter()
                        .map(|i| CatalogIndexWire {
                            id: i.name.clone(),
                            name: i.name,
                            columns: i.columns,
                            unique: i.unique,
                            index_type: "btree".into(),
                        })
                        .collect(),
                });
            }
            if !page.truncated {
                break;
            }
            cursor = page.next_cursor;
        }
    }
    Ok(CatalogSnapshotWire {
        databases: databases
            .into_iter()
            .map(|d| CatalogDatabaseWire { name: d.name })
            .collect(),
        schemas: schemas
            .items
            .into_iter()
            .map(|s| CatalogSchemaWire {
                database: s.database,
                name: s.name,
            })
            .collect(),
        tables,
    })
}


fn map_catalog_err(request_id: u64, err: CatalogError) -> ResponseEnvelope<ControlResponse> {
    let (code, msg) = match &err {
        CatalogError::NotFound(m) => (ProtocolErrorCode::ResourceNotFound, m.clone()),
        CatalogError::PermissionDenied(m) => (ProtocolErrorCode::AuthorizationDenied, m.clone()),
        CatalogError::Unsupported(m) => (ProtocolErrorCode::Unsupported, m.clone()),
        CatalogError::InvalidIdentifier(m) => (ProtocolErrorCode::InvalidRequest, m.clone()),
        CatalogError::DatabaseError(m) | CatalogError::Internal(m) => {
            (ProtocolErrorCode::InternalError, m.clone())
        }
    };
    ResponseEnvelope::err(request_id, code, msg)
}
