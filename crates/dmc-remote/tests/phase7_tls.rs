//! Phase 7.5 — TLS 1.3 transport over remote TCP.

mod tls_support;

use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, ProtocolErrorCode, RemoteLimits, ResponseStatus,
};
use dmc_remote::{
    bootstrap_core_state_unlocked_for_test, expect_ok_control, expect_ok_data, map_tls_error, tls_connect,
    CoreServerState, DeploymentProfile, RemoteMode, RemoteServer, RemoteTransportPolicy,
    TlsClientConfig, TlsRemoteClient, TlsRemoteServer, TlsServerConfig,
};
use tempfile::tempdir;

use tls_support::{dev_tls_stack, expired_tls_stack, not_yet_valid_tls_stack, untrusted_ca_stack};

fn pick_ephemeral_addr() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn spawn_tls_server(
    addr: SocketAddr,
    tls: TlsServerConfig,
    state: Arc<Mutex<CoreServerState>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let server = TlsRemoteServer::bind_dev(addr, tls, RemoteLimits::default()).unwrap();
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
fn tls13_handshake_valid_certificate() {
    let stack = dev_tls_stack("127.0.0.1");
    let dir = tempdir().unwrap();
    let state = Arc::new(Mutex::new(bootstrap_core_state_unlocked_for_test(dir.path(), false)));
    let addr = pick_ephemeral_addr();
    let handle = spawn_tls_server(addr, stack.server.clone(), Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));

    let client = TlsRemoteClient::connect_dev(addr, stack.client, RemoteLimits::default()).unwrap();
    client.close().unwrap();
    drop(handle);
}

#[test]
fn tls13_rejects_tls12_client() {
    let stack = dev_tls_stack("127.0.0.1");
    let dir = tempdir().unwrap();
    let state = Arc::new(Mutex::new(bootstrap_core_state_unlocked_for_test(dir.path(), false)));
    let addr = pick_ephemeral_addr();
    let handle = spawn_tls_server(addr, stack.server.clone(), Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));

    let tls12_client =
        TlsClientConfig::from_ca_pem_tls12_only(&stack.material.ca_cert_pem, "127.0.0.1").unwrap();
    let err = match tls_connect(addr, &tls12_client) {
        Err(err) => err,
        Ok(_) => panic!("expected TLS 1.2 client to be rejected"),
    };
    assert_eq!(err.code(), Some(ProtocolErrorCode::TlsHandshakeFailed));
    drop(handle);
}

#[test]
fn tls_rejects_expired_certificate() {
    let stack = expired_tls_stack("127.0.0.1");
    let dir = tempdir().unwrap();
    let state = Arc::new(Mutex::new(bootstrap_core_state_unlocked_for_test(dir.path(), false)));
    let addr = pick_ephemeral_addr();
    let handle = spawn_tls_server(addr, stack.server.clone(), Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));

    let err = match tls_connect(addr, &stack.client) {
        Err(err) => err,
        Ok(_) => panic!("expected expired certificate rejection"),
    };
    assert_eq!(err.code(), Some(ProtocolErrorCode::CertificateExpired));
    drop(handle);
}

#[test]
fn tls_rejects_untrusted_ca() {
    let (stack, wrong_client) = untrusted_ca_stack("127.0.0.1");
    let dir = tempdir().unwrap();
    let state = Arc::new(Mutex::new(bootstrap_core_state_unlocked_for_test(dir.path(), false)));
    let addr = pick_ephemeral_addr();
    let handle = spawn_tls_server(addr, stack.server.clone(), Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));

    let err = match tls_connect(addr, &wrong_client) {
        Err(err) => err,
        Ok(_) => panic!("expected untrusted CA rejection"),
    };
    assert_eq!(err.code(), Some(ProtocolErrorCode::CertificateUntrusted));
    drop(handle);
}

#[test]
fn tls_rejects_hostname_mismatch() {
    let stack = dev_tls_stack("127.0.0.1");
    let dir = tempdir().unwrap();
    let state = Arc::new(Mutex::new(bootstrap_core_state_unlocked_for_test(dir.path(), false)));
    let addr = pick_ephemeral_addr();
    let handle = spawn_tls_server(addr, stack.server.clone(), Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));

    let bad_name = stack
        .client
        .clone()
        .with_hostname("wrong.example.com")
        .unwrap();
    let err = match tls_connect(addr, &bad_name) {
        Err(err) => err,
        Ok(_) => panic!("expected hostname mismatch rejection"),
    };
    assert_eq!(err.code(), Some(ProtocolErrorCode::HostnameMismatch));
    drop(handle);
}

#[test]
fn tls_rejects_not_yet_valid_certificate() {
    let stack = not_yet_valid_tls_stack("127.0.0.1");
    let dir = tempdir().unwrap();
    let state = Arc::new(Mutex::new(bootstrap_core_state_unlocked_for_test(dir.path(), false)));
    let addr = pick_ephemeral_addr();
    let handle = spawn_tls_server(addr, stack.server.clone(), Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));

    let err = match tls_connect(addr, &stack.client) {
        Err(err) => err,
        Ok(_) => panic!("expected not-yet-valid certificate rejection"),
    };
    assert_eq!(err.code(), Some(ProtocolErrorCode::CertificateInvalid));
    drop(handle);
}

#[test]
fn tls_framing_control_data_and_correlation() {
    let stack = dev_tls_stack("127.0.0.1");
    let dir = tempdir().unwrap();
    let state = Arc::new(Mutex::new(bootstrap_core_state_unlocked_for_test(dir.path(), false)));
    let addr = pick_ephemeral_addr();
    let handle = spawn_tls_server(addr, stack.server.clone(), Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));

    let mut client = TlsRemoteClient::connect_dev(addr, stack.client, RemoteLimits::default()).unwrap();
    client.handshake("tls-framing").unwrap();
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
fn tls_auth_success_and_failure_are_independent() {
    let stack = dev_tls_stack("127.0.0.1");
    let dir = tempdir().unwrap();
    let state = Arc::new(Mutex::new(bootstrap_core_state_unlocked_for_test(dir.path(), false)));
    let addr = pick_ephemeral_addr();
    let handle = spawn_tls_server(addr, stack.server.clone(), Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));

    let mut client = TlsRemoteClient::connect_dev(addr, stack.client.clone(), RemoteLimits::default())
        .unwrap();
    client.handshake("tls-auth-fail").unwrap();
    let bad = client.authenticate("analyst", "wrong").unwrap();
    assert_eq!(bad.error_code, Some(ProtocolErrorCode::AuthenticationFailed));
    client.close().unwrap();

    let mut client = TlsRemoteClient::connect_dev(addr, stack.client, RemoteLimits::default()).unwrap();
    client.handshake("tls-auth-ok").unwrap();
    let ok = client.authenticate("analyst", "pw").unwrap();
    assert_eq!(ok.status, ResponseStatus::Ok);
    drop(handle);
}

#[test]
fn tls_unauthenticated_data_and_authz_denied() {
    let stack = dev_tls_stack("127.0.0.1");
    let dir = tempdir().unwrap();
    let state = Arc::new(Mutex::new(bootstrap_core_state_unlocked_for_test(dir.path(), false)));
    let addr = pick_ephemeral_addr();
    let handle = spawn_tls_server(addr, stack.server.clone(), Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));

    let mut client = TlsRemoteClient::connect_dev(addr, stack.client, RemoteLimits::default()).unwrap();
    client.handshake("tls-authz").unwrap();
    let unauth = client
        .data(DataRequest::ExecuteSql {
            session_id: "fake".into(),
            sql: "SELECT 1".into(),
            params: Vec::new(),
        })
        .unwrap();
    assert_eq!(unauth.error_code, Some(ProtocolErrorCode::SessionInvalid));

    let auth = client.authenticate("analyst", "pw").unwrap();
    let session_id = session_from_auth(auth);
    let denied = client
        .execute_sql(&session_id, "SELECT id FROM secret_table")
        .unwrap();
    assert_eq!(denied.error_code, Some(ProtocolErrorCode::AuthorizationDenied));
    drop(handle);
}

#[test]
fn tls_sql_e2e_and_reconnect_requires_new_session() {
    let stack = dev_tls_stack("127.0.0.1");
    let dir = tempdir().unwrap();
    let state = Arc::new(Mutex::new(bootstrap_core_state_unlocked_for_test(dir.path(), false)));
    let addr = pick_ephemeral_addr();
    let handle = spawn_tls_server(addr, stack.server.clone(), Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));

    let session_id = {
        let mut client =
            TlsRemoteClient::connect_dev(addr, stack.client.clone(), RemoteLimits::default())
                .unwrap();
        client.handshake("tls-e2e-a").unwrap();
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
        client
            .execute_sql(&session_id, "INSERT INTO items (id, name) VALUES (3, 'gamma')")
            .unwrap();
        client.close().unwrap();
        session_id
    };

    thread::sleep(Duration::from_millis(30));

    let mut client =
        TlsRemoteClient::connect_dev(addr, stack.client, RemoteLimits::default()).unwrap();
    client.handshake("tls-e2e-b").unwrap();
    // D5 + F8: the old session died with its connection; its open transaction was
    // rolled back. The client re-authenticates and runs a new transaction.
    let commit = client
        .data(DataRequest::Commit {
            session_id: session_id.clone(),
        })
        .unwrap();
    assert_eq!(commit.error_code, Some(ProtocolErrorCode::SessionInvalid));
    let fresh = session_from_auth(client.authenticate("analyst", "pw").unwrap());
    let rows = |client: &mut TlsRemoteClient, sid: &str| match expect_ok_data(
        client.execute_sql(sid, "SELECT id FROM items WHERE id = 3").unwrap(),
    )
    .unwrap()
    {
        dmc_protocol::DataResponse::SqlResult(result) => result.rows.len(),
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(rows(&mut client, &fresh), 0, "orphan transaction rolled back");
    client.data(DataRequest::Begin { session_id: fresh.clone() }).unwrap();
    client
        .execute_sql(&fresh, "INSERT INTO items (id, name) VALUES (3, 'gamma')")
        .unwrap();
    client.data(DataRequest::Commit { session_id: fresh.clone() }).unwrap();
    assert_eq!(rows(&mut client, &fresh), 1);
    client.close().unwrap();
    drop(handle);
}

#[test]
fn production_plain_tcp_bind_rejected() {
    let addr = pick_ephemeral_addr();
    let policy = RemoteTransportPolicy {
        deployment: DeploymentProfile::Production,
        mode: RemoteMode::PlainTcpDev,
    };
    let err = match RemoteServer::bind_with_policy(addr, RemoteLimits::default(), policy) {
        Err(err) => err,
        Ok(_) => panic!("expected production plain TCP bind to be rejected"),
    };
    assert_eq!(err.code(), Some(ProtocolErrorCode::TransportError));
}

#[test]
fn tls_errors_sanitize_sensitive_paths() {
    let err = map_tls_error("/var/secrets/server.key unreadable".into());
    assert_eq!(err.code(), Some(ProtocolErrorCode::TlsHandshakeFailed));
    match err {
        dmc_protocol::ProtocolError::Wire { message, .. } => {
            assert_eq!(message, "request rejected");
        }
        other => panic!("unexpected {other:?}"),
    }
}
