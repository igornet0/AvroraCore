use std::net::SocketAddr;

use dmc_protocol::{FramedConnection, RemoteLimits, Result};
use dmc_server::{serve_connection, ConnectionLimits, CoreServerState, ServeOptions};

use crate::mode::{RemoteBindConfig, RemoteTransportPolicy};
use crate::tcp::{track_connection_start, TcpListener, TcpTransport};

pub struct RemoteServer {
    listener: TcpListener,
    options: ServeOptions,
}

impl RemoteServer {
    pub fn bind(addr: std::net::SocketAddr) -> Result<Self> {
        Self::bind_with_policy(
            addr,
            RemoteLimits::default(),
            RemoteTransportPolicy::development_plain_tcp(),
        )
    }

    pub fn bind_with_limits(addr: std::net::SocketAddr, limits: RemoteLimits) -> Result<Self> {
        Self::bind_with_policy(addr, limits, RemoteTransportPolicy::development_plain_tcp())
    }

    pub fn bind_with_policy(
        addr: std::net::SocketAddr,
        limits: RemoteLimits,
        policy: RemoteTransportPolicy,
    ) -> Result<Self> {
        RemoteBindConfig { policy }.ensure_allowed()?;
        let listener = TcpTransport::bind(addr, limits.frame.max_connections)?;
        Ok(Self {
            listener,
            options: ServeOptions {
                limits,
                max_requests_per_connection: limits.max_requests_per_connection,
                metrics_transport: Some(dmc_observability::MetricTransport::Remote),
                request_timeout_ms: limits.frame.read_timeout_ms,
            },
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.listener.local_addr()
    }

    pub fn with_options(mut self, options: ServeOptions) -> Self {
        self.options = options;
        self
    }

    pub fn accept_and_serve_one(&self, state: &mut CoreServerState) -> Result<()> {
        let _guard = track_connection_start(self.options.limits.frame.max_connections)?;
        let conn = self.listener.accept()?;
        let mut framed = FramedConnection::new(conn, self.options.limits.frame);
        let mut conn_limits = ConnectionLimits::default();
        serve_connection(&mut framed, state, &self.options, &mut conn_limits)
    }
}
