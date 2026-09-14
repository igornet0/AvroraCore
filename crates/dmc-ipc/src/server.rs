use std::path::{Path, PathBuf};

use dmc_protocol::{ProtocolLimits, Result};
use dmc_server::{serve_connection, ConnectionLimits, CoreServerState, ServeOptions};

use crate::path::{prepare_socket_dir, SocketPathOptions};
use crate::transport::{
    FramedConnection, LocalConnection, LocalListener, LocalTransport, UnixSocketTransport,
};

pub struct CoreServer {
    listener: <UnixSocketTransport as LocalTransport>::Listener,
    options: ServeOptions,
    socket_path: PathBuf,
}

impl CoreServer {
    pub fn bind(path: impl AsRef<Path>, options: &SocketPathOptions) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        prepare_socket_dir(&path, options)?;
        let listener = UnixSocketTransport::bind(&path)?;
        Ok(Self {
            listener,
            options: ServeOptions::default(),
            socket_path: path,
        })
    }

    pub fn with_limits(mut self, limits: ProtocolLimits) -> Self {
        self.options.limits.frame = limits;
        self
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn accept_and_serve_one(&self, state: &mut CoreServerState) -> Result<()> {
        let conn = self.listener.accept()?;
        let mut framed = FramedConnection::new(conn, self.options.limits.frame);
        let mut conn_limits = ConnectionLimits::default();
        serve_connection(&mut framed, state, &self.options, &mut conn_limits)
    }

    pub fn serve_one_connection<C: LocalConnection>(
        connection: C,
        state: &mut CoreServerState,
    ) -> Result<()> {
        let mut framed = FramedConnection::new(connection, ProtocolLimits::default());
        let mut conn_limits = ConnectionLimits::default();
        serve_connection(
            &mut framed,
            state,
            &ServeOptions::default(),
            &mut conn_limits,
        )
    }
}
