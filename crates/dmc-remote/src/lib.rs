//! Phase 7.4/7.5 — remote transport (plain TCP dev-only + TLS 1.3 production).

mod client;
mod mode;
mod server;
mod tcp;
mod tls;

pub use client::RemoteClient;
pub use dmc_server::{
    authenticate_with_binding, bootstrap_core_state, bootstrap_core_state_locked,
    bootstrap_core_state_unlocked_for_test, create_unlock_blob, expect_ok_control, expect_ok_data,
    expect_vault_unlocked, vault_lock, vault_status, vault_unlock, CoreServerState,
    MockKeyPassProvider, PasswordKeyPassProvider, ProtocolClient, ServeOptions, UnlockGate,
    UnlockMaterial, VaultState,
};
pub use mode::{
    DeploymentProfile, RemoteBindConfig, RemoteConnectConfig, RemoteMode, RemoteTransportPolicy,
};
pub use server::RemoteServer;
pub use tcp::{TcpConnection, TcpListener, TcpTransport};
pub use tls::{
    load_pem_certs, load_pem_key, map_rustls_error, map_tls_error, map_tls_io_error, tls_connect,
    TlsClientConfig, TlsConnection, TlsListener, TlsMaterial, TlsRemoteClient, TlsRemoteServer,
    TlsServerConfig,
};

pub use dmc_protocol as protocol;
