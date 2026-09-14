//! Phase 7.6.2 — VaultUnlock over TLS (same UnlockBlob as IPC).

mod tls_support;

use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use dmc_protocol::{
    ControlRequest, ControlResponse, RemoteLimits,
};
use dmc_remote::{
    bootstrap_core_state_locked, create_unlock_blob, expect_ok_control, expect_vault_unlocked,
    CoreServerState, MockKeyPassProvider, TlsRemoteClient, TlsRemoteServer,
};
use tempfile::tempdir;

use tls_support::dev_tls_stack;

fn pick_ephemeral_addr() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn spawn_tls_server(
    addr: SocketAddr,
    tls: dmc_remote::TlsServerConfig,
    state: Arc<Mutex<CoreServerState>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let server = TlsRemoteServer::bind_dev(addr, tls, RemoteLimits::default()).unwrap();
        let mut guard = state.lock().unwrap();
        server.accept_and_serve_one(&mut guard).ok();
    })
}

#[test]
fn vault_unlock_over_tls_tcp() {
    let stack = dev_tls_stack("127.0.0.1");
    let dir = tempdir().unwrap();
    let (state_inner, master) = bootstrap_core_state_locked(dir.path(), false);
    let state = Arc::new(Mutex::new(state_inner));
    let addr = pick_ephemeral_addr();
    let handle = spawn_tls_server(addr, stack.server.clone(), Arc::clone(&state));
    thread::sleep(Duration::from_millis(30));

    let mut client =
        TlsRemoteClient::connect_dev(addr, stack.client, RemoteLimits::default()).unwrap();
    client.handshake("unlock-tls").unwrap();
    let auth = client.authenticate("analyst", "pw").unwrap();
    match expect_ok_control(auth).unwrap() {
        ControlResponse::Authenticate {
            session_id,
            unlock_binding_key,
            ..
        } => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&unlock_binding_key);
            let blob = create_unlock_blob(
                &session_id,
                &key,
                &MockKeyPassProvider::with_material(master),
            )
            .unwrap();
            let resp = client
                .control(ControlRequest::VaultUnlock {
                    session_id: session_id.clone(),
                    blob,
                })
                .unwrap();
            expect_vault_unlocked(resp).unwrap();
        }
        other => panic!("unexpected {other:?}"),
    }
    client.close().unwrap();
    drop(handle);
}
