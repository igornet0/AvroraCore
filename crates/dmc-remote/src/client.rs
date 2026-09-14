use std::net::SocketAddr;

use dmc_protocol::{RemoteLimits, Result};
use dmc_server::ProtocolClient;

use crate::mode::{RemoteConnectConfig, RemoteTransportPolicy};
use crate::tcp::TcpTransport;

pub struct RemoteClient {
    inner: ProtocolClient<crate::tcp::TcpConnection>,
}

impl RemoteClient {
    pub fn connect(addr: SocketAddr) -> Result<Self> {
        Self::connect_with_policy(addr, RemoteLimits::default(), RemoteTransportPolicy::development_plain_tcp())
    }

    pub fn connect_with_limits(addr: SocketAddr, limits: RemoteLimits) -> Result<Self> {
        Self::connect_with_policy(addr, limits, RemoteTransportPolicy::development_plain_tcp())
    }

    fn connect_with_policy(
        addr: SocketAddr,
        limits: RemoteLimits,
        policy: RemoteTransportPolicy,
    ) -> Result<Self> {
        RemoteConnectConfig {
            policy,
            server_hostname: "plain-tcp-dev".into(),
        }
        .ensure_allowed()?;
        let conn = TcpTransport::connect(addr)?;
        Ok(Self {
            inner: ProtocolClient::new(conn, limits),
        })
    }

    pub fn handshake(
        &mut self,
        client_id: &str,
    ) -> Result<dmc_protocol::HandshakeResponse> {
        self.inner.handshake(client_id)
    }

    pub fn authenticate(
        &mut self,
        identity_name: &str,
        password: &str,
    ) -> Result<dmc_protocol::ResponseEnvelope<dmc_protocol::ControlResponse>> {
        self.inner.authenticate(identity_name, password)
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
