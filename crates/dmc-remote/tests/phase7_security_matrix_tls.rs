//! Phase 7.6.5 — Two-axis security matrix over TLS remote.

mod tls_support;

use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, ProtocolErrorCode, RemoteLimits, ResponseStatus,
    VaultStateWire,
};
use dmc_remote::{
    bootstrap_core_state_locked, create_unlock_blob, expect_ok_control, expect_ok_data,
    CoreServerState, MockKeyPassProvider, TlsRemoteClient, TlsRemoteServer,
};
use tempfile::tempdir;

use tls_support::dev_tls_stack;

fn pick_ephemeral_addr() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn spawn_locked_tls_server(
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

fn session_and_binding(
    auth: dmc_protocol::ResponseEnvelope<ControlResponse>,
) -> (String, [u8; 32]) {
    match expect_ok_control(auth).unwrap() {
        ControlResponse::Authenticate {
            session_id,
            unlock_binding_key,
            ..
        } => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&unlock_binding_key);
            (session_id, key)
        }
        other => panic!("{other:?}"),
    }
}

fn vault_unlock_tls(
    client: &mut TlsRemoteClient,
    session_id: &str,
    binding: &[u8; 32],
    master: &dmc_server::UnlockMaterial,
) {
    let blob = create_unlock_blob(session_id, binding, &MockKeyPassProvider::with_material(master.clone()))
        .unwrap();
    let resp = client
        .control(ControlRequest::VaultUnlock {
            session_id: session_id.into(),
            blob,
        })
        .unwrap();
    assert_eq!(resp.status, ResponseStatus::Ok);
}

const CREATE: &str = "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)";
const INSERT: &str = "INSERT INTO items (id, name) VALUES (1, 'a')";
const SELECT: &str = "SELECT id FROM items WHERE id = 1";

#[test]
fn tls_unauthenticated_sql_session_invalid() {
    let stack = dev_tls_stack("127.0.0.1");
    let dir = tempdir().unwrap();
    let (state_inner, _master) = bootstrap_core_state_locked(dir.path(), false);
    let state = Arc::new(Mutex::new(state_inner));
    let addr = pick_ephemeral_addr();
    let handle = spawn_locked_tls_server(addr, stack.server.clone(), Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));

    let mut client = TlsRemoteClient::connect_dev(addr, stack.client, RemoteLimits::default()).unwrap();
    client.handshake("sec-tls").unwrap();
    let resp = client
        .data(DataRequest::ExecuteSql {
            session_id: "ghost".into(),
            sql: SELECT.into(),
            params: Vec::new(),
        })
        .unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::SessionInvalid));
    client.close().unwrap();
    drop(handle);
}

#[test]
fn tls_authenticated_locked_vault_locked() {
    let stack = dev_tls_stack("127.0.0.1");
    let dir = tempdir().unwrap();
    let (state_inner, _master) = bootstrap_core_state_locked(dir.path(), false);
    let state = Arc::new(Mutex::new(state_inner));
    let addr = pick_ephemeral_addr();
    let handle = spawn_locked_tls_server(addr, stack.server.clone(), Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));

    let mut client = TlsRemoteClient::connect_dev(addr, stack.client, RemoteLimits::default()).unwrap();
    client.handshake("sec-tls").unwrap();
    let auth = client.authenticate("analyst", "pw").unwrap();
    let (session_id, _) = session_and_binding(auth);
    let resp = client.execute_sql(&session_id, CREATE).unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::VaultLocked));
    client.close().unwrap();
    drop(handle);
}

#[test]
fn tls_full_security_lifecycle_e2e() {
    let stack = dev_tls_stack("127.0.0.1");
    let dir = tempdir().unwrap();
    let (state_inner, master) = bootstrap_core_state_locked(dir.path(), false);
    let state = Arc::new(Mutex::new(state_inner));
    let addr = pick_ephemeral_addr();
    let handle = spawn_locked_tls_server(addr, stack.server.clone(), Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));

    let mut client = TlsRemoteClient::connect_dev(addr, stack.client, RemoteLimits::default()).unwrap();
    client.handshake("sec-e2e").unwrap();
    let auth = client.authenticate("analyst", "pw").unwrap();
    let (session_id, binding) = session_and_binding(auth);
    vault_unlock_tls(&mut client, &session_id, &binding, &master);

    assert_eq!(client.execute_sql(&session_id, CREATE).unwrap().status, ResponseStatus::Ok);
    assert_eq!(client.execute_sql(&session_id, INSERT).unwrap().status, ResponseStatus::Ok);
    expect_ok_data(client.execute_sql(&session_id, SELECT).unwrap()).unwrap();

    let lock = client
        .control(ControlRequest::VaultLock {
            session_id: session_id.clone(),
        })
        .unwrap();
    match expect_ok_control(lock).unwrap() {
        ControlResponse::VaultLock { state: st } => assert_eq!(st, VaultStateWire::Locked),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        client.execute_sql(&session_id, SELECT).unwrap().error_code,
        Some(ProtocolErrorCode::VaultLocked)
    );

    vault_unlock_tls(&mut client, &session_id, &binding, &master);
    assert_eq!(client.execute_sql(&session_id, SELECT).unwrap().status, ResponseStatus::Ok);
    client.close().unwrap();
    drop(handle);
}

#[test]
fn tls_unauthorized_after_unlock_authz_denied() {
    let stack = dev_tls_stack("127.0.0.1");
    let dir = tempdir().unwrap();
    let (state_inner, master) = bootstrap_core_state_locked(dir.path(), false);
    let state = Arc::new(Mutex::new(state_inner));
    let addr = pick_ephemeral_addr();
    let handle = spawn_locked_tls_server(addr, stack.server.clone(), Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));

    let mut client = TlsRemoteClient::connect_dev(addr, stack.client, RemoteLimits::default()).unwrap();
    client.handshake("sec-tls").unwrap();
    let auth = client.authenticate("analyst", "pw").unwrap();
    let (session_id, binding) = session_and_binding(auth);
    vault_unlock_tls(&mut client, &session_id, &binding, &master);
    let resp = client
        .execute_sql(&session_id, "SELECT id FROM secret_table")
        .unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::AuthorizationDenied));
    client.close().unwrap();
    drop(handle);
}
