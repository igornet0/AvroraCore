use dmc_protocol::{
    DataRequest, DataResponse, ProtocolError, ProtocolErrorCode, ResponseStatus, SqlParam,
    SqlResult,
};
use dmc_server::expect_ok_data;

use crate::client::Client;
use crate::error::{ClientError, Result};
use crate::transport::{Request, Response};
use crate::types::ExecuteOutcome;

/// SQL-plane API. Sends SQL text only — no AST, no RowStore.
pub struct SqlClient<'a> {
    pub(crate) client: &'a mut Client,
}

impl SqlClient<'_> {
    pub fn execute(&mut self, sql: &str) -> Result<ExecuteOutcome> {
        self.execute_with_params(sql, Vec::new())
    }

    pub fn execute_with_params(
        &mut self,
        sql: &str,
        params: Vec<SqlParam>,
    ) -> Result<ExecuteOutcome> {
        let body = self.execute_raw(sql, params)?;
        match body {
            DataResponse::Ok => Ok(ExecuteOutcome::Ok),
            DataResponse::SqlResult(rows) if rows.columns.is_empty() && rows.rows.is_empty() => {
                Ok(ExecuteOutcome::Ok)
            }
            DataResponse::SqlResult(rows) => Ok(ExecuteOutcome::Rows(rows)),
        }
    }

    pub fn query(&mut self, sql: &str) -> Result<SqlResult> {
        self.query_with_params(sql, Vec::new())
    }

    pub fn query_with_params(&mut self, sql: &str, params: Vec<SqlParam>) -> Result<SqlResult> {
        match self.execute_raw(sql, params)? {
            DataResponse::SqlResult(rows) => Ok(rows),
            DataResponse::Ok => Err(ClientError::UnexpectedData),
        }
    }

    fn execute_raw(&mut self, sql: &str, params: Vec<SqlParam>) -> Result<DataResponse> {
        let session_id = self.client.session.require_session()?.to_string();
        let resp = match self.client.request(Request::Data(DataRequest::ExecuteSql {
            session_id,
            sql: sql.into(),
            params,
        }))? {
            Response::Data(env) => env,
            Response::Control(_) => return Err(ClientError::UnexpectedControl),
        };
        if resp.status != ResponseStatus::Ok {
            return Err(ProtocolError::wire(
                resp.error_code.unwrap_or(ProtocolErrorCode::InternalError),
                resp.error_message.unwrap_or_else(|| "data error".into()),
            )
            .into());
        }
        expect_ok_data(resp).map_err(Into::into)
    }
}
