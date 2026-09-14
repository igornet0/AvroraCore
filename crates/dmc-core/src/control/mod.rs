//! Avrora Control Plane: TLS 1.3 listener, bootstrap, device registry, unlock RPC.

pub mod backup_config;
pub mod capability_rotation_config;
mod commands;
mod data;
mod devo_init;
mod devices;
mod handler;
mod init;
mod invite;
mod paths;
pub mod sessions;
mod server_config;
mod tls;
mod unlock_blob;

pub use backup_config::{
    load as load_backup_config, save as save_backup_config, BackupConfig, CONFIG_FILE as BACKUP_CONFIG_FILE,
};
pub use capability_rotation_config::{
    CapabilityRotationConfig, config_path, load as load_capability_rotation,
    save as save_capability_rotation, write_default as write_capability_rotation_default,
};
pub use commands::{
    format_auth_init, format_devo_init, format_status, format_status_for, format_ui_auth_reset,
    format_ui_login_hint, run_init,
};
pub use devo_init::{
    clear_ui_auth, load_dev_master_hex, read_dev_ui_credentials, reset_ui_auth, resolve_ui_access_key,
    run_auth_init, run_devo_init, DevoInitResult, UiAuthResetResult, DEV_MASTER_FILE,
    DEV_UI_CREDENTIALS_FILE, DEFAULT_UI_ACCESS_KEY,
};
pub use init::{InitResult, control_dir, init_control, init_control_for_host};
pub use invite::{export_invite, write_invite_file};
pub use paths::{AvroraPaths, control_port_from_env, default_control_addr, default_http_addr, reset_server_data};
pub use server_config::{
    display_http_url, load as load_server_config, resolve_ui_dist, save as save_server_config,
    ServerConfig, CONFIG_FILE as SERVER_CONFIG_FILE,
};
pub use tls::fingerprint_der;

use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::control::devices::DeviceRegistry;
use crate::control::handler::handle_connection;
use crate::control::sessions::ControlSessions;
use crate::control::tls::load_server_tls;
use crate::runtime::Runtime;
use dmc_security::AuthManager;

#[derive(Clone)]
pub struct ControlState {
    pub data_dir: PathBuf,
    pub runtime: Runtime,
    pub auth: AuthManager,
    pub devices: DeviceRegistry,
    pub sessions: ControlSessions,
}

pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub async fn serve(
    addr: SocketAddr,
    data_dir: PathBuf,
    runtime: Runtime,
    auth: AuthManager,
    sessions: ControlSessions,
) -> std::io::Result<()> {
    install_crypto_provider();
    let tls = load_server_tls(&data_dir)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let state = ControlState {
        devices: DeviceRegistry::open(data_dir.join("devices.json"))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?,
        data_dir,
        runtime,
        auth,
        sessions,
    };

    let listener = TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    println!("Avrora control plane on tls://{bound}");
    serve_listener(listener, acceptor, state).await
}

pub async fn serve_listener(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    state: ControlState,
) -> std::io::Result<()> {
    loop {
        let (sock, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = accept_one(acceptor, sock, state).await {
                eprintln!("control {peer}: {e}");
            }
        });
    }
}

/// Bind and serve; returns the bound address after spawn-ready bind.
pub async fn bind(
    addr: SocketAddr,
    data_dir: PathBuf,
    runtime: Runtime,
    auth: AuthManager,
    sessions: ControlSessions,
) -> std::io::Result<(SocketAddr, impl Future<Output = std::io::Result<()>>)> {
    install_crypto_provider();
    let tls = load_server_tls(&data_dir)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let state = ControlState {
        devices: DeviceRegistry::open(data_dir.join("devices.json"))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?,
        data_dir,
        runtime,
        auth,
        sessions,
    };
    let listener = TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    Ok((bound, serve_listener(listener, acceptor, state)))
}

async fn accept_one(
    acceptor: TlsAcceptor,
    sock: tokio::net::TcpStream,
    state: ControlState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut tls = acceptor.accept(sock).await?;
    let cert_fp = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .map(|c| fingerprint_der(c.as_ref()));
    handle_connection(&mut tls, state, cert_fp).await?;
    Ok(())
}

pub fn require_inited(data_dir: &Path) -> Result<(), String> {
    if !data_dir.join("tls/server.crt").is_file() {
        return Err(format!(
            "control plane not initialized; run `avrora init --data-dir {}`",
            data_dir.display()
        ));
    }
    Ok(())
}
