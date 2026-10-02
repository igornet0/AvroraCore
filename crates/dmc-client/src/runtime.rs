use dmc_protocol::{
    CatalogColumnWire, CatalogConstraintWire, CatalogDatabaseWire, CatalogIndexWire,
    CatalogSchemaWire, CatalogSnapshotWire, CatalogTableSummaryWire, ChannelInfoWire,
    ChannelSpecWire, ColumnDefWire, ControlRequest, ControlResponse, ProtocolError,
    ProtocolErrorCode, ResponseStatus, RuntimeEventWire, SchemaMutationResultWire,
    SchemaSnapshotWire, ServerCapabilities, StreamSpecWire, TriggerDefWire,
};
use dmc_server::expect_ok_control;

use crate::client::Client;
use crate::error::{ClientError, Result};
use crate::transport::{Request, Response};

fn control(client: &mut Client, body: ControlRequest) -> Result<dmc_protocol::ResponseEnvelope<ControlResponse>> {
    match client.request(Request::Control(body))? {
        Response::Control(env) => {
            if env.status != ResponseStatus::Ok {
                return Err(ProtocolError::wire(
                    env.error_code.unwrap_or(ProtocolErrorCode::InternalError),
                    env.error_message.unwrap_or_else(|| "control error".into()),
                )
                .into());
            }
            Ok(env)
        }
        Response::Data(_) => Err(ClientError::UnexpectedData),
    }
}

#[derive(Clone, Debug, Default)]
pub struct CatalogListOptions {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    pub name_filter: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CatalogPage<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
    pub truncated: bool,
}

pub struct CatalogClient<'a> {
    pub(crate) client: &'a mut Client,
}

impl CatalogClient<'_> {
    pub fn snapshot(&mut self) -> Result<CatalogSnapshotWire> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::CatalogList { session_id },
        )?)?;
        match body {
            ControlResponse::CatalogList(snap) => Ok(snap),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn list_databases(&mut self) -> Result<Vec<CatalogDatabaseWire>> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::DatabaseList { session_id },
        )?)?;
        match body {
            ControlResponse::DatabaseList { items } => Ok(items),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn list_schemas(
        &mut self,
        database: Option<&str>,
        opts: CatalogListOptions,
    ) -> Result<CatalogPage<CatalogSchemaWire>> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::SchemaList {
                session_id,
                database: database.map(str::to_string),
                cursor: opts.cursor,
                limit: opts.limit.unwrap_or(500),
                name_filter: opts.name_filter,
            },
        )?)?;
        match body {
            ControlResponse::SchemaList { items, next_cursor, truncated } => Ok(CatalogPage {
                items,
                next_cursor,
                truncated,
            }),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn list_tables(
        &mut self,
        database: &str,
        schema: &str,
        opts: CatalogListOptions,
    ) -> Result<CatalogPage<CatalogTableSummaryWire>> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::TableList {
                session_id,
                database: database.into(),
                schema: schema.into(),
                cursor: opts.cursor,
                limit: opts.limit.unwrap_or(500),
                name_filter: opts.name_filter,
            },
        )?)?;
        match body {
            ControlResponse::TableList { items, next_cursor, truncated } => Ok(CatalogPage {
                items,
                next_cursor,
                truncated,
            }),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn get_table(
        &mut self,
        database: &str,
        schema: &str,
        table: &str,
    ) -> Result<CatalogTableSummaryWire> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::TableGet {
                session_id,
                database: database.into(),
                schema: schema.into(),
                table: table.into(),
            },
        )?)?;
        match body {
            ControlResponse::TableGet(t) => Ok(t),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn list_columns(
        &mut self,
        database: &str,
        schema: &str,
        table: &str,
        opts: CatalogListOptions,
    ) -> Result<CatalogPage<CatalogColumnWire>> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::ColumnList {
                session_id,
                database: database.into(),
                schema: schema.into(),
                table: table.into(),
                cursor: opts.cursor,
                limit: opts.limit.unwrap_or(500),
                name_filter: opts.name_filter,
            },
        )?)?;
        match body {
            ControlResponse::ColumnList { items, next_cursor, truncated } => Ok(CatalogPage {
                items,
                next_cursor,
                truncated,
            }),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn list_indexes(
        &mut self,
        database: &str,
        schema: &str,
        table: &str,
        opts: CatalogListOptions,
    ) -> Result<CatalogPage<CatalogIndexWire>> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::IndexList {
                session_id,
                database: database.into(),
                schema: schema.into(),
                table: table.into(),
                cursor: opts.cursor,
                limit: opts.limit.unwrap_or(500),
                name_filter: opts.name_filter,
            },
        )?)?;
        match body {
            ControlResponse::IndexList { items, next_cursor, truncated } => Ok(CatalogPage {
                items,
                next_cursor,
                truncated,
            }),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn list_constraints(
        &mut self,
        database: &str,
        schema: &str,
        table: &str,
        opts: CatalogListOptions,
    ) -> Result<CatalogPage<CatalogConstraintWire>> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::ConstraintList {
                session_id,
                database: database.into(),
                schema: schema.into(),
                table: table.into(),
                cursor: opts.cursor,
                limit: opts.limit.unwrap_or(500),
                name_filter: opts.name_filter,
            },
        )?)?;
        match body {
            ControlResponse::ConstraintList { items, next_cursor, truncated } => Ok(CatalogPage {
                items,
                next_cursor,
                truncated,
            }),
            _ => Err(ClientError::UnexpectedControl),
        }
    }
}

pub struct DdlClient<'a> {
    pub(crate) client: &'a mut Client,
}

impl DdlClient<'_> {
    pub fn create_table(
        &mut self,
        database: &str,
        schema: &str,
        name: &str,
        columns: Vec<ColumnDefWire>,
    ) -> Result<SchemaMutationResultWire> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::CreateTable {
                session_id,
                database: database.into(),
                schema: schema.into(),
                name: name.into(),
                columns,
            },
        )?)?;
        match body {
            ControlResponse::SchemaMutation(r) => Ok(r),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn drop_table(
        &mut self,
        database: &str,
        schema: &str,
        table: &str,
    ) -> Result<SchemaMutationResultWire> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::DropTable {
                session_id,
                database: database.into(),
                schema: schema.into(),
                table: table.into(),
            },
        )?)?;
        match body {
            ControlResponse::SchemaMutation(r) => Ok(r),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn rename_table(
        &mut self,
        database: &str,
        schema: &str,
        table: &str,
        new_name: &str,
    ) -> Result<SchemaMutationResultWire> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::RenameTable {
                session_id,
                database: database.into(),
                schema: schema.into(),
                table: table.into(),
                new_name: new_name.into(),
            },
        )?)?;
        match body {
            ControlResponse::SchemaMutation(r) => Ok(r),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn add_column(
        &mut self,
        database: &str,
        schema: &str,
        table: &str,
        column: ColumnDefWire,
    ) -> Result<SchemaMutationResultWire> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::AddColumn {
                session_id,
                database: database.into(),
                schema: schema.into(),
                table: table.into(),
                column,
            },
        )?)?;
        match body {
            ControlResponse::SchemaMutation(r) => Ok(r),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn alter_column(
        &mut self,
        database: &str,
        schema: &str,
        table: &str,
        column: &str,
        nullable: Option<bool>,
        data_type: Option<String>,
        default: Option<Option<String>>,
    ) -> Result<SchemaMutationResultWire> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::AlterColumn {
                session_id,
                database: database.into(),
                schema: schema.into(),
                table: table.into(),
                column: column.into(),
                nullable,
                data_type,
                default,
            },
        )?)?;
        match body {
            ControlResponse::SchemaMutation(r) => Ok(r),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn drop_column(
        &mut self,
        database: &str,
        schema: &str,
        table: &str,
        column: &str,
    ) -> Result<SchemaMutationResultWire> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::DropColumn {
                session_id,
                database: database.into(),
                schema: schema.into(),
                table: table.into(),
                column: column.into(),
            },
        )?)?;
        match body {
            ControlResponse::SchemaMutation(r) => Ok(r),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn rename_column(
        &mut self,
        database: &str,
        schema: &str,
        table: &str,
        column: &str,
        new_name: &str,
    ) -> Result<SchemaMutationResultWire> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::RenameColumn {
                session_id,
                database: database.into(),
                schema: schema.into(),
                table: table.into(),
                column: column.into(),
                new_name: new_name.into(),
            },
        )?)?;
        match body {
            ControlResponse::SchemaMutation(r) => Ok(r),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn create_index(
        &mut self,
        database: &str,
        schema: &str,
        table: &str,
        name: &str,
        columns: Vec<String>,
        unique: bool,
    ) -> Result<SchemaMutationResultWire> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::CreateIndex {
                session_id,
                database: database.into(),
                schema: schema.into(),
                table: table.into(),
                name: name.into(),
                columns,
                unique,
            },
        )?)?;
        match body {
            ControlResponse::SchemaMutation(r) => Ok(r),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn drop_index(
        &mut self,
        database: &str,
        schema: &str,
        table: &str,
        name: &str,
    ) -> Result<SchemaMutationResultWire> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::DropIndex {
                session_id,
                database: database.into(),
                schema: schema.into(),
                table: table.into(),
                name: name.into(),
            },
        )?)?;
        match body {
            ControlResponse::SchemaMutation(r) => Ok(r),
            _ => Err(ClientError::UnexpectedControl),
        }
    }
}

pub struct ChannelClient<'a> {
    pub(crate) client: &'a mut Client,
}

impl ChannelClient<'_> {
    pub fn list(&mut self) -> Result<Vec<ChannelInfoWire>> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(self.client, ControlRequest::ChannelList { session_id })?)?;
        match body {
            ControlResponse::ChannelList { items } => Ok(items),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn get(&mut self, id: &str) -> Result<ChannelInfoWire> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::ChannelGet {
                session_id,
                id: id.into(),
            },
        )?)?;
        match body {
            ControlResponse::ChannelInfo(info) => Ok(info),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn configure(&mut self, spec: ChannelSpecWire) -> Result<String> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::ChannelConfigure { session_id, spec },
        )?)?;
        match body {
            ControlResponse::ChannelConfigured { id } => Ok(id),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn start(&mut self, id: &str) -> Result<()> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::ChannelStart {
                session_id,
                id: id.into(),
            },
        )?)?;
        match body {
            ControlResponse::RuntimeOk => Ok(()),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn stop(&mut self, id: &str) -> Result<()> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::ChannelStop {
                session_id,
                id: id.into(),
            },
        )?)?;
        match body {
            ControlResponse::RuntimeOk => Ok(()),
            _ => Err(ClientError::UnexpectedControl),
        }
    }
}

pub struct StreamClient<'a> {
    pub(crate) client: &'a mut Client,
}

impl StreamClient<'_> {
    pub fn list(&mut self) -> Result<Vec<StreamSpecWire>> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(self.client, ControlRequest::StreamList { session_id })?)?;
        match body {
            ControlResponse::StreamList { items } => Ok(items),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn get(&mut self, id: &str) -> Result<StreamSpecWire> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::StreamGet {
                session_id,
                id: id.into(),
            },
        )?)?;
        match body {
            ControlResponse::StreamInfo(spec) => Ok(spec),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn create(&mut self, spec: StreamSpecWire) -> Result<String> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::StreamCreate { session_id, spec },
        )?)?;
        match body {
            ControlResponse::StreamCreated { id } => Ok(id),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn ingest(&mut self, stream_id: &str, path: &str, payload: &str) -> Result<()> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::StreamIngest {
                session_id,
                stream_id: stream_id.into(),
                path: path.into(),
                payload: payload.into(),
            },
        )?)?;
        match body {
            ControlResponse::RuntimeOk => Ok(()),
            _ => Err(ClientError::UnexpectedControl),
        }
    }
}

pub struct TriggerClient<'a> {
    pub(crate) client: &'a mut Client,
}

impl TriggerClient<'_> {
    pub fn list(&mut self) -> Result<Vec<TriggerDefWire>> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(self.client, ControlRequest::TriggerList { session_id })?)?;
        match body {
            ControlResponse::TriggerList { items } => Ok(items),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn get(&mut self, id: &str) -> Result<TriggerDefWire> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::TriggerGet {
                session_id,
                id: id.into(),
            },
        )?)?;
        match body {
            ControlResponse::TriggerInfo(def) => Ok(def),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn create(&mut self, def: TriggerDefWire) -> Result<String> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::TriggerCreate { session_id, def },
        )?)?;
        match body {
            ControlResponse::TriggerCreated { id } => Ok(id),
            _ => Err(ClientError::UnexpectedControl),
        }
    }
}

pub struct EventClient<'a> {
    pub(crate) client: &'a mut Client,
}

impl EventClient<'_> {
    pub fn list(&mut self, limit: u32) -> Result<Vec<RuntimeEventWire>> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::EventList { session_id, limit },
        )?)?;
        match body {
            ControlResponse::EventList { items } => Ok(items),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn runtime_schema(&mut self) -> Result<SchemaSnapshotWire> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::RuntimeSchema { session_id },
        )?)?;
        match body {
            ControlResponse::RuntimeSchema(snap) => Ok(snap),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn catalog(&mut self) -> Result<CatalogSnapshotWire> {
        let session_id = self.client.session.require_session()?.to_string();
        let body = expect_ok_control(control(
            self.client,
            ControlRequest::CatalogList { session_id },
        )?)?;
        match body {
            ControlResponse::CatalogList(snap) => Ok(snap),
            _ => Err(ClientError::UnexpectedControl),
        }
    }
}

impl Client {
    pub fn capabilities(&mut self) -> Result<ServerCapabilities> {
        let body = expect_ok_control(control(self, ControlRequest::GetCapabilities)?)?;
        match body {
            ControlResponse::Capabilities(caps) => Ok(caps),
            _ => Err(ClientError::UnexpectedControl),
        }
    }

    pub fn channels(&mut self) -> ChannelClient<'_> {
        ChannelClient { client: self }
    }

    pub fn streams(&mut self) -> StreamClient<'_> {
        StreamClient { client: self }
    }

    pub fn triggers(&mut self) -> TriggerClient<'_> {
        TriggerClient { client: self }
    }

    pub fn events(&mut self) -> EventClient<'_> {
        EventClient { client: self }
    }

    pub fn catalog(&mut self) -> CatalogClient<'_> {
        CatalogClient { client: self }
    }

    pub fn ddl(&mut self) -> DdlClient<'_> {
        DdlClient { client: self }
    }
}
