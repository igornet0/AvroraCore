//! Typed DDL Control handlers (P7.3).

use dmc_catalog::TableRef;
use dmc_ddl::{
    AddColumnRequest, AlterColumnRequest, CatalogInvalidation, ColumnDefinition, CreateIndexRequest,
    CreateTableRequest, DdlError, DdlService, DropColumnRequest, DropIndexRequest, DropTableRequest,
    ObjectKind, RenameColumnRequest, RenameTableRequest, SchemaMutationResult,
};
use dmc_protocol::{
    ColumnDefWire, ControlRequest, ControlResponse, ProtocolErrorCode, ResponseEnvelope,
    SchemaMutationResultWire, ServerCapabilities,
};
use dmc_security::auth::{Action, Authorizer, Resource, SessionManager};
use dmc_sql_bind::BoundCatalogEvent;
use dmc_sql_exec::execute_catalog_statement;
use dmc_sql_front::SourceSpan;

use crate::state::CoreServerState;

pub fn is_ddl_request(req: &ControlRequest) -> bool {
    matches!(
        req,
        ControlRequest::CreateTable { .. }
            | ControlRequest::DropTable { .. }
            | ControlRequest::RenameTable { .. }
            | ControlRequest::AddColumn { .. }
            | ControlRequest::AlterColumn { .. }
            | ControlRequest::DropColumn { .. }
            | ControlRequest::RenameColumn { .. }
            | ControlRequest::CreateIndex { .. }
            | ControlRequest::DropIndex { .. }
    )
}

pub fn handle_ddl(
    state: &mut CoreServerState,
    request_id: u64,
    req: ControlRequest,
) -> ResponseEnvelope<ControlResponse> {
    if !ServerCapabilities::core_v1().schema_mutation {
        return ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::Unsupported,
            "schema_mutation capability disabled",
        );
    }
    if let Err(err) = state.unlock_gate.require_unlocked() {
        return match err {
            dmc_protocol::ProtocolError::Wire { code, message } => {
                ResponseEnvelope::err(request_id, code, message)
            }
            other => ResponseEnvelope::err(
                request_id,
                ProtocolErrorCode::VaultLocked,
                other.to_string(),
            ),
        };
    }

    let session_id = ddl_session_id(&req).to_string();
    let principal = match state.auth.principal_for(&session_id.as_str().into()) {
        Ok(p) => p,
        Err(_) => {
            return ResponseEnvelope::err(
                request_id,
                ProtocolErrorCode::SessionInvalid,
                "invalid session",
            );
        }
    };

    if let Err(resp) = authorize_ddl(state, request_id, &req, &principal) {
        return resp;
    }

    let planned = match &req {
        ControlRequest::CreateTable {
            database,
            schema,
            name,
            columns,
            ..
        } => {
            let catalog = match state.ctx.session_catalog_mut() {
                Ok(c) => c,
                Err(e) => {
                    return ResponseEnvelope::err(
                        request_id,
                        ProtocolErrorCode::ResourceNotFound,
                        e.to_string(),
                    );
                }
            };
            DdlService::plan_create_table(
                catalog,
                &CreateTableRequest {
                    database: database.clone(),
                    schema: schema.clone(),
                    name: name.clone(),
                    columns: columns.iter().map(wire_column).collect(),
                },
            )
        }
        ControlRequest::DropTable {
            database,
            schema,
            table,
            ..
        } => {
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
            DdlService::plan_drop_table(
                catalog,
                &DropTableRequest {
                    table: TableRef {
                        database: database.clone(),
                        schema: schema.clone(),
                        table: table.clone(),
                    },
                },
            )
        }
        ControlRequest::CreateIndex {
            database,
            schema,
            table,
            name,
            columns,
            unique,
            ..
        } => {
            let catalog = match state.ctx.session_catalog_mut() {
                Ok(c) => c,
                Err(e) => {
                    return ResponseEnvelope::err(
                        request_id,
                        ProtocolErrorCode::ResourceNotFound,
                        e.to_string(),
                    );
                }
            };
            DdlService::plan_create_index(
                catalog,
                &CreateIndexRequest {
                    table: TableRef {
                        database: database.clone(),
                        schema: schema.clone(),
                        table: table.clone(),
                    },
                    name: name.clone(),
                    columns: columns.clone(),
                    unique: *unique,
                },
            )
        }
        ControlRequest::DropIndex {
            database,
            schema,
            table,
            name,
            ..
        } => {
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
            DdlService::plan_drop_index(
                catalog,
                &DropIndexRequest {
                    table: TableRef {
                        database: database.clone(),
                        schema: schema.clone(),
                        table: table.clone(),
                    },
                    name: name.clone(),
                },
            )
        }
        ControlRequest::AddColumn {
            database,
            schema,
            table,
            column,
            ..
        } => {
            let catalog = match state.ctx.session_catalog_mut() {
                Ok(c) => c,
                Err(e) => {
                    return ResponseEnvelope::err(
                        request_id,
                        ProtocolErrorCode::ResourceNotFound,
                        e.to_string(),
                    );
                }
            };
            DdlService::plan_add_column(
                catalog,
                &AddColumnRequest {
                    table: TableRef {
                        database: database.clone(),
                        schema: schema.clone(),
                        table: table.clone(),
                    },
                    column: wire_column(column),
                },
            )
        }
        ControlRequest::DropColumn {
            database,
            schema,
            table,
            column,
            ..
        } => {
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
            DdlService::plan_drop_column(
                catalog,
                &DropColumnRequest {
                    table: TableRef {
                        database: database.clone(),
                        schema: schema.clone(),
                        table: table.clone(),
                    },
                    column: column.clone(),
                },
            )
        }
        ControlRequest::AlterColumn {
            database,
            schema,
            table,
            column,
            nullable,
            data_type,
            default,
            ..
        } => {
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
            DdlService::plan_alter_column(
                catalog,
                &AlterColumnRequest {
                    table: TableRef {
                        database: database.clone(),
                        schema: schema.clone(),
                        table: table.clone(),
                    },
                    column: column.clone(),
                    nullable: *nullable,
                    data_type: data_type.clone(),
                    default: default.clone(),
                },
            )
        }
        ControlRequest::RenameColumn {
            database,
            schema,
            table,
            column,
            new_name,
            ..
        } => {
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
            DdlService::plan_rename_column(
                catalog,
                &RenameColumnRequest {
                    table: TableRef {
                        database: database.clone(),
                        schema: schema.clone(),
                        table: table.clone(),
                    },
                    column: column.clone(),
                    new_name: new_name.clone(),
                },
            )
        }
        ControlRequest::RenameTable {
            database,
            schema,
            table,
            new_name,
            ..
        } => {
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
            DdlService::plan_rename_table(
                catalog,
                &RenameTableRequest {
                    table: TableRef {
                        database: database.clone(),
                        schema: schema.clone(),
                        table: table.clone(),
                    },
                    new_name: new_name.clone(),
                },
            )
        }
        other => {
            return ResponseEnvelope::err(
                request_id,
                ProtocolErrorCode::InvalidRequest,
                format!("not a ddl request: {other:?}"),
            );
        }
    };

    let (event, mut result) = match planned {
        Ok(v) => v,
        Err(err) => return map_ddl_err(request_id, err),
    };
    result.generated_sql = DdlService::describe_sql(&result.operation, &result);
    result.operation_id = format!("ddl-{request_id}-{}", result.operation_id);

    // Ownership grants so the creator can index/drop the new table.
    if matches!(req, ControlRequest::CreateTable { .. }) {
        let id = principal.identity_id.clone();
        let grants = state.auth.grants_mut();
        for action in [
            Action::Select,
            Action::Insert,
            Action::Update,
            Action::Delete,
            Action::Create,
            Action::Drop,
        ] {
            grants.grant(
                id.clone(),
                Resource::table(&result.database, &result.schema, &result.object),
                action,
            );
        }
    }

    match execute_catalog_statement(
        BoundCatalogEvent {
            event,
            span: SourceSpan::default(),
        },
        &mut state.ctx,
    ) {
        Ok(_) => ResponseEnvelope::ok(
            request_id,
            ControlResponse::SchemaMutation(to_wire(result)),
        ),
        Err(err) => ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::ExecutionError,
            err.to_string(),
        ),
    }
}

fn authorize_ddl(
    state: &CoreServerState,
    request_id: u64,
    req: &ControlRequest,
    principal: &dmc_security::AuthPrincipal,
) -> Result<(), ResponseEnvelope<ControlResponse>> {
    let authorizer = state.auth.authorizer();
    match req {
        ControlRequest::CreateTable {
            database, schema, ..
        } => {
            authorizer
                .authorize_create_schema_on_database(principal, database)
                .map_err(|e| map_auth_err(request_id, e))?;
            authorizer
                .authorize_schema_create(principal, database, schema)
                .map_err(|e| map_auth_err(request_id, e))?;
        }
        ControlRequest::DropTable {
            database,
            schema,
            table,
            ..
        } => {
            authorizer
                .authorize_table(principal, database, schema, table, Action::Drop)
                .map_err(|e| map_auth_err(request_id, e))?;
        }
        ControlRequest::CreateIndex {
            database,
            schema,
            table,
            ..
        } => {
            authorizer
                .authorize_table(principal, database, schema, table, Action::Create)
                .map_err(|e| map_auth_err(request_id, e))?;
        }
        ControlRequest::DropIndex {
            database, schema, ..
        } => {
            // Mirror SQL auth_gate: schema-level Drop for DROP INDEX.
            authorizer
                .authorize(principal, &Resource::schema(database, schema), Action::Drop)
                .map_err(|e| map_auth_err(request_id, e))?;
        }
        // Unsupported ops still go through session/capability; typed Unsupported from DdlService.
        ControlRequest::AddColumn { .. }
        | ControlRequest::DropColumn { .. }
        | ControlRequest::AlterColumn { .. }
        | ControlRequest::RenameColumn { .. }
        | ControlRequest::RenameTable { .. } => {}
        _ => {}
    }
    Ok(())
}

fn wire_column(c: &ColumnDefWire) -> ColumnDefinition {
    ColumnDefinition {
        name: c.name.clone(),
        data_type: c.data_type.clone(),
        nullable: c.nullable,
        default: c.default.clone(),
        primary_key: c.primary_key,
    }
}

fn to_wire(r: SchemaMutationResult) -> SchemaMutationResultWire {
    SchemaMutationResultWire {
        operation_id: r.operation_id,
        operation: r.operation,
        database: r.database,
        schema: r.schema,
        object: r.object,
        object_kind: match r.object_kind {
            ObjectKind::Database => "database",
            ObjectKind::Schema => "schema",
            ObjectKind::Table => "table",
            ObjectKind::Column => "column",
            ObjectKind::Index => "index",
        }
        .into(),
        invalidations: r
            .invalidations
            .into_iter()
            .map(|i| {
                match i {
                    CatalogInvalidation::DatabaseList => "database_list",
                    CatalogInvalidation::SchemaList => "schema_list",
                    CatalogInvalidation::TableList => "table_list",
                    CatalogInvalidation::TableGet => "table_get",
                    CatalogInvalidation::ColumnList => "column_list",
                    CatalogInvalidation::IndexList => "index_list",
                    CatalogInvalidation::ConstraintList => "constraint_list",
                }
                .into()
            })
            .collect(),
        generated_sql: r.generated_sql,
    }
}

fn ddl_session_id(req: &ControlRequest) -> &str {
    match req {
        ControlRequest::CreateTable { session_id, .. }
        | ControlRequest::DropTable { session_id, .. }
        | ControlRequest::RenameTable { session_id, .. }
        | ControlRequest::AddColumn { session_id, .. }
        | ControlRequest::AlterColumn { session_id, .. }
        | ControlRequest::DropColumn { session_id, .. }
        | ControlRequest::RenameColumn { session_id, .. }
        | ControlRequest::CreateIndex { session_id, .. }
        | ControlRequest::DropIndex { session_id, .. } => session_id,
        _ => "",
    }
}

fn map_ddl_err(request_id: u64, err: DdlError) -> ResponseEnvelope<ControlResponse> {
    let (code, msg) = match &err {
        DdlError::NotFound(m) => (ProtocolErrorCode::ResourceNotFound, m.clone()),
        DdlError::AlreadyExists(m) | DdlError::Conflict(m) => {
            (ProtocolErrorCode::InvalidRequest, m.clone())
        }
        DdlError::InvalidIdentifier(m) | DdlError::InvalidDefinition(m) => {
            (ProtocolErrorCode::InvalidRequest, m.clone())
        }
        DdlError::Unsupported(m) => (ProtocolErrorCode::Unsupported, m.clone()),
        DdlError::PermissionDenied(m) => (ProtocolErrorCode::AuthorizationDenied, m.clone()),
        DdlError::UnsafeOperation(m) => (ProtocolErrorCode::InvalidRequest, m.clone()),
        DdlError::DatabaseError(m) | DdlError::Internal(m) => {
            (ProtocolErrorCode::InternalError, m.clone())
        }
    };
    ResponseEnvelope::err(request_id, code, msg)
}

fn map_auth_err(
    request_id: u64,
    err: dmc_security::Error,
) -> ResponseEnvelope<ControlResponse> {
    ResponseEnvelope::err(
        request_id,
        ProtocolErrorCode::AuthorizationDenied,
        err.to_string(),
    )
}
