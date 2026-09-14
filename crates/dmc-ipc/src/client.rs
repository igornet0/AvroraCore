use std::path::Path;

use dmc_protocol::{RemoteLimits, Result};
use dmc_server::ProtocolClient;

use crate::transport::{LocalConnection, LocalTransport, UnixSocketTransport};

pub struct LocalClient<C: LocalConnection> {
    inner: ProtocolClient<C>,
}

impl LocalClient<crate::transport::unix::UnixConnection> {
    pub fn connect(path: impl AsRef<Path>) -> Result<Self> {
        let conn = UnixSocketTransport::connect(path.as_ref())?;
        Ok(Self {
            inner: ProtocolClient::new(conn, RemoteLimits::default()),
        })
    }
}

impl<C: LocalConnection> LocalClient<C> {
    pub fn from_connection(conn: C) -> Self {
        Self {
            inner: ProtocolClient::with_protocol_limits(conn, Default::default()),
        }
    }

    pub fn handshake(
        &mut self,
        client_id: &str,
    ) -> Result<dmc_protocol::HandshakeResponse> {
        self.inner.handshake(client_id)
    }

    pub fn control(
        &mut self,
        body: dmc_protocol::ControlRequest,
    ) -> Result<dmc_protocol::ResponseEnvelope<dmc_protocol::ControlResponse>> {
        self.inner.control(body)
    }

    pub fn data(
        &mut self,
        body: dmc_protocol::DataRequest,
    ) -> Result<dmc_protocol::ResponseEnvelope<dmc_protocol::DataResponse>> {
        self.inner.data(body)
    }

    pub fn authenticate(
        &mut self,
        identity_name: &str,
        password: &str,
    ) -> Result<dmc_protocol::ResponseEnvelope<dmc_protocol::ControlResponse>> {
        self.inner.authenticate(identity_name, password)
    }

    pub fn execute_sql(
        &mut self,
        session_id: &str,
        sql: &str,
    ) -> Result<dmc_protocol::ResponseEnvelope<dmc_protocol::DataResponse>> {
        self.inner.execute_sql(session_id, sql)
    }

    pub fn close(self) -> Result<()> {
        self.inner.into_inner().shutdown().map_err(Into::into)
    }
}

pub use dmc_server::{expect_ok_control, expect_ok_data};
