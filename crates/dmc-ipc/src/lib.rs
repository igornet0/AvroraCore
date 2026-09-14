//! Phase 7.3 — local IPC transport (Unix socket / Named Pipe).

mod client;
mod path;
mod server;
mod transport;

pub use client::LocalClient;
pub use dmc_protocol::{build_frame, read_frame, write_frame, FramedConnection};
pub use dmc_server::{
    bootstrap_core_state, bootstrap_core_state_unlocked_for_test, expect_ok_control, expect_ok_data,
    map_security_to_protocol, ConnectionLimits, CoreServerState, ProtocolClient, ServeOptions,
};
pub use path::{default_socket_path, prepare_socket_dir, SocketPathOptions};
pub use server::CoreServer;
pub use transport::{
    LocalConnection, LocalListener, LocalTransport, NamedPipeTransport, UnixSocketTransport,
};

#[cfg(unix)]
pub use transport::unix::UnixConnection;

pub use dmc_protocol as protocol;
