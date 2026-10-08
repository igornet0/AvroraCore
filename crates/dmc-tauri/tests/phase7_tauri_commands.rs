//! Phase 7.7.7 — Tauri adapter acceptance (bridge API; no UI).

#[path = "common/tls_support.rs"]
mod tls_support;

use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use dmc_client::{KeyPassHandle, UnlockMaterial};
use dmc_protocol::RemoteLimits;
use dmc_remote::{bootstrap_core_state_locked, CoreServerState, TlsRemoteServer};
use dmc_tauri::{
    ClientUiState, ConnectRequest, ConnectionUi, DmcBridge, FrontendErrorCode, VaultStatusUi,
};
use serde_json::Value;
use tempfile::tempdir;

#[cfg(unix)]
mod local_support {
    use super::*;
    use dmc_ipc::{CoreServer, SocketPathOptions};
    use dmc_server::bootstrap_core_state_locked as boot_locked;

    pub fn socket_options() -> SocketPathOptions {
        SocketPathOptions {
            allow_custom_path: true,
        }
    }

    pub fn spawn_locked_ipc(
        data_root: &Path,
        socket_path: PathBuf,
    ) -> (UnlockMaterial, thread::JoinHandle<()>) {
        let (state, master) = boot_locked(data_root, false);
        let state = Arc::new(Mutex::new(state));
        let handle = thread::spawn(move || {
            let server = CoreServer::bind(&socket_path, &socket_options()).unwrap();
            loop {
                let mut guard = state.lock().unwrap();
                if server.accept_and_serve_one(&mut guard).is_err() {
                    break;
                }
            }
        });
        thread::sleep(Duration::from_millis(25));
        (master, handle)
    }
}

fn pick_ephemeral_addr() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn spawn_locked_tls(
    addr: SocketAddr,
    tls: dmc_remote::TlsServerConfig,
    state: Arc<Mutex<CoreServerState>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let server = TlsRemoteServer::bind_dev(addr, tls, RemoteLimits::default()).unwrap();
        loop {
            let mut guard = state.lock().unwrap();
            if server.accept_and_serve_one(&mut guard).is_err() {
                break;
            }
        }
    })
}

const CREATE: &str = "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)";
const INSERT: &str = "INSERT INTO items (id, name) VALUES (1, 'a')";
const SELECT: &str = "SELECT id FROM items WHERE id = 1";

async fn run_full_lifecycle(bridge: &DmcBridge, master: UnlockMaterial, password: &str) {
    // Password KeyPass on Rust side — UI only ever sends `password`.
    let handle = KeyPassHandle::password_wrap(&master, password, "test-db").unwrap();
    bridge.install_keypass(handle).await;

    bridge
        .authenticate("analyst".into(), "pw".into())
        .await
        .unwrap();
    assert_eq!(
        bridge.vault_status().await.unwrap(),
        VaultStatusUi::Locked
    );
    assert_eq!(
        bridge.vault_unlock(password.into()).await.unwrap(),
        VaultStatusUi::Unlocked
    );

    bridge.sql_execute(CREATE.into()).await.unwrap();
    bridge.sql_execute(INSERT.into()).await.unwrap();
    assert_eq!(bridge.sql_query(SELECT.into()).await.unwrap().rows.len(), 1);

    assert_eq!(
        bridge.vault_lock().await.unwrap(),
        VaultStatusUi::Locked
    );
    let locked = bridge.sql_query(SELECT.into()).await.unwrap_err();
    assert_eq!(locked.code, FrontendErrorCode::VaultLocked);

    bridge.vault_unlock(password.into()).await.unwrap();
    assert_eq!(bridge.sql_query(SELECT.into()).await.unwrap().rows.len(), 1);

    bridge.logout().await.unwrap();
    let after = bridge.sql_query(SELECT.into()).await.unwrap_err();
    assert_eq!(after.code, FrontendErrorCode::SessionInvalid);
}

fn assert_no_secrets(json: &Value) {
    let text = json.to_string().to_lowercase();
    for needle in [
        "master_key",
        "unlockmaterial",
        "unlock_binding",
        "binding_key",
        "\"dek\"",
        "\"kek\"",
        "/tmp/",
        "keytree",
    ] {
        assert!(
            !text.contains(needle),
            "frontend payload leaked {needle}: {text}"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn tauri_local_e2e_lifecycle() {
    let dir = tempdir().unwrap();
    let socket = dir.path().join("dmc-tauri.sock");
    let (master, _handle) = local_support::spawn_locked_ipc(dir.path(), socket.clone());

    let bridge = DmcBridge::new();
    let state = bridge
        .connect(ConnectRequest::Local {
            socket: socket.to_string_lossy().into(),
        })
        .await
        .unwrap();
    assert_eq!(state.connection, ConnectionUi::Connected);
    assert!(!state.authenticated);

    run_full_lifecycle(&bridge, master, "ui-password").await;
}

#[tokio::test]
async fn tauri_tls_e2e_same_commands() {
    let stack = tls_support::dev_tls_stack("127.0.0.1");
    let dir = tempdir().unwrap();
    let (state_inner, master) = bootstrap_core_state_locked(dir.path(), false);
    let state = Arc::new(Mutex::new(state_inner));
    let addr = pick_ephemeral_addr();
    let _handle = spawn_locked_tls(addr, stack.server.clone(), Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));

    let ca_pem = String::from_utf8(stack.material.ca_cert_pem.clone()).unwrap();
    let bridge = DmcBridge::new();
    bridge
        .connect(ConnectRequest::Remote {
            host: "127.0.0.1".into(),
            port: addr.port(),
            ca_pem,
            server_name: Some("127.0.0.1".into()),
            development: true,
        })
        .await
        .unwrap();

    run_full_lifecycle(&bridge, master, "ui-password").await;
}

#[cfg(unix)]
#[tokio::test]
async fn tauri_disconnect_reconnect_resyncs_from_core() {
    let dir = tempdir().unwrap();
    let socket = dir.path().join("reconn.sock");
    let (master, _handle) = local_support::spawn_locked_ipc(dir.path(), socket.clone());

    let bridge = DmcBridge::new();
    bridge
        .connect(ConnectRequest::Local {
            socket: socket.to_string_lossy().into(),
        })
        .await
        .unwrap();
    let kp = KeyPassHandle::password_wrap(&master, "ui-password", "test-db").unwrap();
    bridge.install_keypass(kp).await;
    bridge
        .authenticate("analyst".into(), "pw".into())
        .await
        .unwrap();
    bridge.vault_unlock("ui-password".into()).await.unwrap();
    bridge.sql_execute(CREATE.into()).await.unwrap();
    bridge.sql_execute(INSERT.into()).await.unwrap();

    let disconnected = bridge.disconnect().await.unwrap();
    assert_eq!(disconnected, ClientUiState::default());

    // Reconnect clears local UI auth flags; Core vault may still be unlocked.
    let re = bridge.reconnect().await.unwrap();
    assert_eq!(re.connection, ConnectionUi::Connected);
    assert!(!re.authenticated);
    assert!(re.vault.is_none());

    bridge
        .authenticate("analyst".into(), "pw".into())
        .await
        .unwrap();
    assert_eq!(
        bridge.vault_status().await.unwrap(),
        VaultStatusUi::Unlocked
    );
    assert_eq!(bridge.sql_query(SELECT.into()).await.unwrap().rows.len(), 1);
}

#[cfg(unix)]
#[tokio::test]
async fn tauri_frontend_payloads_never_expose_secrets() {
    let dir = tempdir().unwrap();
    let socket = dir.path().join("sec.sock");
    let (master, _handle) = local_support::spawn_locked_ipc(dir.path(), socket.clone());
    let master_hex = hex::encode(master.0);

    let bridge = DmcBridge::new();
    let kp = KeyPassHandle::password_wrap(&master, "secret-pass", "db").unwrap();
    bridge.install_keypass(kp).await;

    let connected = bridge
        .connect(ConnectRequest::Local {
            socket: socket.to_string_lossy().into(),
        })
        .await
        .unwrap();
    let session = bridge
        .authenticate("analyst".into(), "pw".into())
        .await
        .unwrap();
    let unlocked = bridge.vault_unlock("secret-pass".into()).await.unwrap();
    bridge.sql_execute(CREATE.into()).await.unwrap();
    bridge.sql_execute(INSERT.into()).await.unwrap();
    let query = bridge.sql_query(SELECT.into()).await.unwrap();
    let locked_err = {
        bridge.vault_lock().await.unwrap();
        bridge.sql_query(SELECT.into()).await.unwrap_err()
    };
    let ui = bridge.client_state().await;

    for payload in [
        serde_json::to_value(&connected).unwrap(),
        serde_json::to_value(&session).unwrap(),
        serde_json::to_value(&unlocked).unwrap(),
        serde_json::to_value(&query).unwrap(),
        serde_json::to_value(&locked_err).unwrap(),
        serde_json::to_value(&ui).unwrap(),
    ] {
        assert_no_secrets(&payload);
        let text = payload.to_string();
        assert!(
            !text.contains(&master_hex),
            "master key hex leaked into frontend JSON"
        );
    }
}

#[test]
fn frontend_error_model_is_stable() {
    use dmc_client::ClientError;
    use dmc_tauri::FrontendError;

    let e = FrontendError::from_client(ClientError::NotConnected);
    assert_eq!(e.code, FrontendErrorCode::NotConnected);
    let json = serde_json::to_value(&e).unwrap();
    assert_eq!(json["code"], "NotConnected");
}

/// 7.7.8 UI command sequence (same React API surface for Local + TLS).
#[cfg(unix)]
#[tokio::test]
async fn tauri_ui_flow_local_with_keypass_dir_and_reconnect() {
    use dmc_client::PasswordKeyPassProvider;
    use dmc_vault::keypass;

    let dir = tempdir().unwrap();
    let socket = dir.path().join("ui-flow.sock");
    let (master, _handle) = local_support::spawn_locked_ipc(dir.path(), socket.clone());

    let keypass_dir = dir.path().join("db.keypass");
    let provider =
        PasswordKeyPassProvider::wrap_master(&master, "ui-password", "ui-db").unwrap();
    keypass::save(&keypass_dir, provider.bundle()).unwrap();

    let bridge = DmcBridge::new();
    bridge
        .install_keypass_dir(keypass_dir.to_string_lossy().into())
        .await
        .unwrap();
    bridge
        .connect(ConnectRequest::Local {
            socket: socket.to_string_lossy().into(),
        })
        .await
        .unwrap();

    bridge
        .authenticate("analyst".into(), "pw".into())
        .await
        .unwrap();
    assert_eq!(
        bridge.vault_status().await.unwrap(),
        VaultStatusUi::Locked
    );
    bridge.vault_unlock("ui-password".into()).await.unwrap();

    bridge.sql_execute(CREATE.into()).await.unwrap();
    bridge.sql_execute(INSERT.into()).await.unwrap();
    assert_eq!(bridge.sql_query(SELECT.into()).await.unwrap().rows.len(), 1);

    bridge.vault_lock().await.unwrap();
    assert_eq!(
        bridge.sql_query(SELECT.into()).await.unwrap_err().code,
        FrontendErrorCode::VaultLocked
    );

    bridge.vault_unlock("ui-password".into()).await.unwrap();
    assert_eq!(bridge.sql_query(SELECT.into()).await.unwrap().rows.len(), 1);

    bridge.logout().await.unwrap();
    assert_eq!(
        bridge.sql_query(SELECT.into()).await.unwrap_err().code,
        FrontendErrorCode::SessionInvalid
    );

    bridge.disconnect().await.unwrap();
    bridge.reconnect().await.unwrap();
    let reconciled = bridge.reconcile().await.unwrap();
    assert_eq!(reconciled.connection, ConnectionUi::Connected);
    assert!(!reconciled.authenticated);

    bridge
        .authenticate("analyst".into(), "pw".into())
        .await
        .unwrap();
    assert_eq!(
        bridge.vault_status().await.unwrap(),
        VaultStatusUi::Unlocked,
        "disconnect must not invent vault lock"
    );
}

#[tokio::test]
async fn tauri_ui_flow_tls_same_commands() {
    use dmc_client::PasswordKeyPassProvider;
    use dmc_vault::keypass;

    let stack = tls_support::dev_tls_stack("127.0.0.1");
    let dir = tempdir().unwrap();
    let (state_inner, master) = bootstrap_core_state_locked(dir.path(), false);
    let state = Arc::new(Mutex::new(state_inner));
    let addr = pick_ephemeral_addr();
    let _handle = spawn_locked_tls(addr, stack.server.clone(), Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));

    let keypass_dir = dir.path().join("db.keypass");
    let provider =
        PasswordKeyPassProvider::wrap_master(&master, "ui-password", "ui-db").unwrap();
    keypass::save(&keypass_dir, provider.bundle()).unwrap();

    let ca_pem = String::from_utf8(stack.material.ca_cert_pem.clone()).unwrap();
    let bridge = DmcBridge::new();
    bridge
        .install_keypass_dir(keypass_dir.to_string_lossy().into())
        .await
        .unwrap();
    bridge
        .connect(ConnectRequest::Remote {
            host: "127.0.0.1".into(),
            port: addr.port(),
            ca_pem,
            server_name: Some("127.0.0.1".into()),
            development: true,
        })
        .await
        .unwrap();

    bridge
        .authenticate("analyst".into(), "pw".into())
        .await
        .unwrap();
    assert_eq!(
        bridge.vault_status().await.unwrap(),
        VaultStatusUi::Locked
    );
    bridge.vault_unlock("ui-password".into()).await.unwrap();
    bridge.sql_execute(CREATE.into()).await.unwrap();
    bridge.sql_execute(INSERT.into()).await.unwrap();
    assert_eq!(bridge.sql_query(SELECT.into()).await.unwrap().rows.len(), 1);
    bridge.vault_lock().await.unwrap();
    assert_eq!(
        bridge.sql_query(SELECT.into()).await.unwrap_err().code,
        FrontendErrorCode::VaultLocked
    );
    bridge.vault_unlock("ui-password".into()).await.unwrap();
    assert_eq!(bridge.sql_query(SELECT.into()).await.unwrap().rows.len(), 1);
    bridge.logout().await.unwrap();
    assert_eq!(
        bridge.sql_query(SELECT.into()).await.unwrap_err().code,
        FrontendErrorCode::SessionInvalid
    );
    bridge.reconnect().await.unwrap();
    bridge
        .authenticate("analyst".into(), "pw".into())
        .await
        .unwrap();
    let _ = bridge.vault_status().await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn tauri_backup_create_verify_restore_recover() {
    let dir = tempdir().unwrap();
    let socket = dir.path().join("dmc-backup.sock");
    let (master, _handle) = local_support::spawn_locked_ipc(dir.path(), socket.clone());

    let bridge = DmcBridge::new();
    bridge
        .connect(ConnectRequest::Local {
            socket: socket.to_string_lossy().into(),
        })
        .await
        .unwrap();
    let handle = KeyPassHandle::password_wrap(&master, "ui-password", "test-db").unwrap();
    bridge.install_keypass(handle).await;
    bridge
        .authenticate("analyst".into(), "pw".into())
        .await
        .unwrap();
    // D4-F: storage (and so a backup) opens only after VaultUnlock
    bridge.vault_unlock("ui-password".into()).await.unwrap();

    let created = bridge
        .backup_create("ui1".into(), false)
        .await
        .unwrap();
    assert_eq!(created.backup_id, "ui1");
    let verified = bridge.backup_verify("ui1".into()).await.unwrap();
    assert!(verified.valid);
    let listed = bridge.backup_list().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].backup_id, "ui1");

    let restored = bridge
        .backup_restore("ui1".into(), "tgt1".into())
        .await
        .unwrap();
    assert!(restored.vault_locked);
    assert!(restored.sessions_invalid);

    let recovered = bridge.backup_recover("tgt1".into()).await.unwrap();
    assert_eq!(recovered.state, "ready");
    assert!(recovered.vault_locked);
    assert!(recovered.sessions_invalid);

    let status = bridge.backup_status("tgt1".into()).await.unwrap();
    assert_eq!(status.state, "ready");

    let payload = serde_json::to_value(&created).unwrap();
    assert_no_secrets(&payload);
}
