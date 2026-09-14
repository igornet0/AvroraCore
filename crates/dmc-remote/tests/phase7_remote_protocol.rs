//! Phase 7.4 — remote TCP transport, auth boundary, SQL E2E.

use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, ProtocolError, ProtocolErrorCode,
    RemoteLimits, ResponseStatus,
};
use dmc_remote::{
    bootstrap_core_state_unlocked_for_test, expect_ok_control, expect_ok_data, CoreServerState, RemoteClient,
    RemoteServer,
};
use tempfile::tempdir;

fn pick_ephemeral_addr() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn spawn_remote_server(
    addr: SocketAddr,
    state: Arc<Mutex<CoreServerState>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let server = RemoteServer::bind(addr).unwrap();
        loop {
            let mut guard = state.lock().unwrap();
            let _ = server.accept_and_serve_one(&mut guard);
        }
    })
}

fn session_from_auth(resp: dmc_protocol::ResponseEnvelope<ControlResponse>) -> String {
    let body = expect_ok_control(resp).unwrap();
    match body {
        ControlResponse::Authenticate { session_id, .. } => session_id,
        other => panic!("expected authenticate response, got {other:?}"),
    }
}

#[test]
fn tcp_connect_handshake_authenticate() {
    let dir = tempdir().unwrap();
    let state = Arc::new(Mutex::new(bootstrap_core_state_unlocked_for_test(dir.path(), false)));
    let addr = pick_ephemeral_addr();
    let handle = spawn_remote_server(addr, Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));

    let mut client = RemoteClient::connect(addr).unwrap();
    client.handshake("remote-test").unwrap();
    let auth = client.authenticate("analyst", "pw").unwrap();
    assert_eq!(auth.status, ResponseStatus::Ok);
    client.close().unwrap();
    drop(handle);
}

#[test]
fn request_id_correlation_out_of_order_client_side() {
    let dir = tempdir().unwrap();
    let state = Arc::new(Mutex::new(bootstrap_core_state_unlocked_for_test(dir.path(), false)));
    let addr = pick_ephemeral_addr();
    let handle = spawn_remote_server(addr, Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));

    let mut client = RemoteClient::connect(addr).unwrap();
    client.handshake("remote-corr").unwrap();
    let auth = client.authenticate("analyst", "pw").unwrap();
    let session_id = session_from_auth(auth);

    let health = client.control(ControlRequest::Health).unwrap();
    assert_eq!(health.request_id, 2);

    let select = client
        .execute_sql(&session_id, "SELECT 1 WHERE 1=0")
        .unwrap();
    assert_eq!(select.request_id, 3);
    client.close().unwrap();
    drop(handle);
}

#[test]
fn invalid_credentials_rejected() {
    let dir = tempdir().unwrap();
    let state = Arc::new(Mutex::new(bootstrap_core_state_unlocked_for_test(dir.path(), false)));
    let addr = pick_ephemeral_addr();
    let handle = spawn_remote_server(addr, Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));

    let mut client = RemoteClient::connect(addr).unwrap();
    client.handshake("remote-bad-auth").unwrap();
    let resp = client.authenticate("analyst", "wrong").unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::AuthenticationFailed));
    drop(handle);
}

#[test]
fn unauthenticated_data_request_rejected() {
    let dir = tempdir().unwrap();
    let state = Arc::new(Mutex::new(bootstrap_core_state_unlocked_for_test(dir.path(), false)));
    let addr = pick_ephemeral_addr();
    let handle = spawn_remote_server(addr, Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));

    let mut client = RemoteClient::connect(addr).unwrap();
    client.handshake("remote-unauth").unwrap();
    let resp = client
        .data(DataRequest::ExecuteSql {
            session_id: "fake".into(),
            sql: "SELECT 1".into(),
            params: Vec::new(),
        })
        .unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::SessionInvalid));
    drop(handle);
}

#[test]
fn unauthorized_select_denied() {
    let dir = tempdir().unwrap();
    let state = Arc::new(Mutex::new(bootstrap_core_state_unlocked_for_test(dir.path(), false)));
    let addr = pick_ephemeral_addr();
    let handle = spawn_remote_server(addr, Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));

    let mut client = RemoteClient::connect(addr).unwrap();
    client.handshake("remote-authz").unwrap();
    let auth = client.authenticate("analyst", "pw").unwrap();
    let session_id = session_from_auth(auth);
    let resp = client
        .execute_sql(&session_id, "SELECT id FROM secret_table")
        .unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::AuthorizationDenied));
    drop(handle);
}

#[test]
fn remote_sql_e2e_create_insert_commit_select() {
    let dir = tempdir().unwrap();
    let state = Arc::new(Mutex::new(bootstrap_core_state_unlocked_for_test(dir.path(), false)));
    let addr = pick_ephemeral_addr();
    let handle = spawn_remote_server(addr, Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));

    let mut client = RemoteClient::connect(addr).unwrap();
    client.handshake("remote-e2e").unwrap();
    let auth = client.authenticate("analyst", "pw").unwrap();
    let session_id = session_from_auth(auth);

    assert_eq!(
        client
            .execute_sql(
                &session_id,
                "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)",
            )
            .unwrap()
            .status,
        ResponseStatus::Ok
    );

    client
        .data(DataRequest::Begin {
            session_id: session_id.clone(),
        })
        .unwrap();
    assert_eq!(
        client
            .execute_sql(&session_id, "INSERT INTO items (id, name) VALUES (1, 'alpha')")
            .unwrap()
            .status,
        ResponseStatus::Ok
    );
    client
        .data(DataRequest::Commit {
            session_id: session_id.clone(),
        })
        .unwrap();

    let select = client
        .execute_sql(&session_id, "SELECT id FROM items WHERE id = 1")
        .unwrap();
    let body = expect_ok_data(select).unwrap();
    match body {
        dmc_protocol::DataResponse::SqlResult(result) => assert_eq!(result.rows.len(), 1),
        other => panic!("unexpected {other:?}"),
    }
    client.close().unwrap();
    drop(handle);
}

#[test]
fn reconnect_preserves_session_and_transaction() {
    let dir = tempdir().unwrap();
    let state = Arc::new(Mutex::new(bootstrap_core_state_unlocked_for_test(dir.path(), false)));
    let addr = pick_ephemeral_addr();
    let handle = spawn_remote_server(addr, Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));

    let session_id = {
        let mut client = RemoteClient::connect(addr).unwrap();
        client.handshake("remote-txn-a").unwrap();
        let auth = client.authenticate("analyst", "pw").unwrap();
        let session_id = session_from_auth(auth);
        client
            .execute_sql(
                &session_id,
                "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)",
            )
            .unwrap();
        client
            .data(DataRequest::Begin {
                session_id: session_id.clone(),
            })
            .unwrap();
        client
            .execute_sql(&session_id, "INSERT INTO items (id, name) VALUES (2, 'beta')")
            .unwrap();
        client.close().unwrap();
        session_id
    };

    thread::sleep(Duration::from_millis(30));

    let mut client = RemoteClient::connect(addr).unwrap();
    client.handshake("remote-txn-b").unwrap();
    let info = client
        .control(ControlRequest::SessionInfo {
            session_id: session_id.clone(),
        })
        .unwrap();
    assert_eq!(info.status, ResponseStatus::Ok);

    client
        .data(DataRequest::Commit {
            session_id: session_id.clone(),
        })
        .unwrap();
    let select = client
        .execute_sql(&session_id, "SELECT id FROM items WHERE id = 2")
        .unwrap();
    assert_eq!(select.status, ResponseStatus::Ok);
    client.close().unwrap();
    drop(handle);
}

#[test]
fn disconnect_after_handshake_is_clean() {
    let dir = tempdir().unwrap();
    let state = Arc::new(Mutex::new(bootstrap_core_state_unlocked_for_test(dir.path(), false)));
    let addr = pick_ephemeral_addr();
    let handle = spawn_remote_server(addr, Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));

    let mut client = RemoteClient::connect(addr).unwrap();
    client.handshake("disconnect").unwrap();
    client.close().unwrap();
    drop(handle);
}

#[test]
fn sql_size_limit_enforced() {
    let limits = RemoteLimits {
        max_sql_size: 8,
        ..RemoteLimits::default()
    };
    let dir = tempdir().unwrap();
    let state = Arc::new(Mutex::new(bootstrap_core_state_unlocked_for_test(dir.path(), false)));
    let addr = pick_ephemeral_addr();
    let state_for_thread = Arc::clone(&state);
    let handle = thread::spawn(move || {
        let server = RemoteServer::bind_with_limits(addr, limits).unwrap();
        loop {
            let mut guard = state_for_thread.lock().unwrap();
            let _ = server.accept_and_serve_one(&mut guard);
        }
    });
    thread::sleep(Duration::from_millis(30));

    let mut client = RemoteClient::connect_with_limits(addr, limits).unwrap();
    client.handshake("sql-limit").unwrap();
    let auth = client.authenticate("analyst", "pw").unwrap();
    let session_id = session_from_auth(auth);
    let resp = client
        .execute_sql(&session_id, "SELECT very_long_sql")
        .unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::InvalidRequest));
    drop(handle);
}

#[test]
fn server_restart_invalidates_sessions() {
    let dir1 = tempdir().unwrap();
    let addr1 = pick_ephemeral_addr();

    let session_id = {
        let state = Arc::new(Mutex::new(bootstrap_core_state_unlocked_for_test(dir1.path(), false)));
        let handle = spawn_remote_server(addr1, Arc::clone(&state));
        thread::sleep(Duration::from_millis(30));
        let mut client = RemoteClient::connect(addr1).unwrap();
        client.handshake("restart-a").unwrap();
        let auth = client.authenticate("analyst", "pw").unwrap();
        let session_id = session_from_auth(auth);
        client.close().unwrap();
        drop(handle);
        session_id
    };

    let dir2 = tempdir().unwrap();
    let addr2 = pick_ephemeral_addr();
    let state = Arc::new(Mutex::new(bootstrap_core_state_unlocked_for_test(dir2.path(), false)));
    let handle = spawn_remote_server(addr2, Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));
    let mut client = RemoteClient::connect(addr2).unwrap();
    client.handshake("restart-b").unwrap();
    let resp = client
        .execute_sql(&session_id, "SELECT id FROM items WHERE 1 = 0")
        .unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::SessionInvalid));
    client.close().unwrap();
    drop(handle);
}
