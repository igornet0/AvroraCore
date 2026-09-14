//! Phase 7.6.5 — Two-axis security matrix over Unix IPC.

#[cfg(unix)]
mod unix_tests {
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use dmc_ipc::{expect_ok_control, expect_ok_data, CoreServer, CoreServerState, LocalClient, SocketPathOptions};
    use dmc_protocol::{
        ControlRequest, ControlResponse, DataRequest, ProtocolErrorCode, ResponseStatus, VaultStateWire,
    };
    use dmc_server::{
        bootstrap_core_state_locked, create_unlock_blob, MockKeyPassProvider, UnlockMaterial,
    };
    use tempfile::tempdir;

    fn socket_options() -> SocketPathOptions {
        SocketPathOptions {
            allow_custom_path: true,
        }
    }

    fn spawn_locked_server(
        data_root: &Path,
        socket_path: PathBuf,
    ) -> (Arc<Mutex<CoreServerState>>, UnlockMaterial, thread::JoinHandle<()>) {
        let (state, master) = bootstrap_core_state_locked(data_root, false);
        let state = Arc::new(Mutex::new(state));
        let state_t = Arc::clone(&state);
        let handle = thread::spawn(move || {
            let server = CoreServer::bind(&socket_path, &socket_options()).unwrap();
            loop {
                let mut guard = state_t.lock().unwrap();
                if server.accept_and_serve_one(&mut guard).is_err() {
                    break;
                }
            }
        });
        thread::sleep(Duration::from_millis(25));
        (state, master, handle)
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

    const CREATE: &str = "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)";
    const INSERT: &str = "INSERT INTO items (id, name) VALUES (1, 'a')";
    const SELECT: &str = "SELECT id FROM items WHERE id = 1";

    #[test]
    fn ipc_unauthenticated_sql_session_invalid() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("sec.sock");
        let (_state, _master, handle) = spawn_locked_server(dir.path(), socket.clone());
        let mut client = LocalClient::connect(&socket).unwrap();
        client.handshake("sec-ipc").unwrap();
        let resp = client
            .data(DataRequest::ExecuteSql {
                session_id: "ghost".into(),
                sql: SELECT.into(),
                params: Vec::new(),
            })
            .unwrap();
        assert_eq!(resp.error_code, Some(ProtocolErrorCode::SessionInvalid));
        drop(handle);
    }

    #[test]
    fn ipc_authenticated_locked_vault_locked() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("sec.sock");
        let (_state, _master, handle) = spawn_locked_server(dir.path(), socket.clone());
        let mut client = LocalClient::connect(&socket).unwrap();
        client.handshake("sec-ipc").unwrap();
        let auth = client.authenticate("analyst", "pw").unwrap();
        let (session_id, _) = session_and_binding(auth);
        let resp = client.execute_sql(&session_id, CREATE).unwrap();
        assert_eq!(resp.error_code, Some(ProtocolErrorCode::VaultLocked));
        drop(handle);
    }

    #[test]
    fn ipc_vault_lock_preserves_session() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("sec.sock");
        let (_state, master, handle) = spawn_locked_server(dir.path(), socket.clone());
        let mut client = LocalClient::connect(&socket).unwrap();
        client.handshake("sec-ipc").unwrap();
        let auth = client.authenticate("analyst", "pw").unwrap();
        let (session_id, binding) = session_and_binding(auth);
        let blob = create_unlock_blob(&session_id, &binding, &MockKeyPassProvider::with_material(master.clone()))
            .unwrap();
        assert_eq!(
            client
                .control(ControlRequest::VaultUnlock {
                    session_id: session_id.clone(),
                    blob,
                })
                .unwrap()
                .status,
            ResponseStatus::Ok
        );
        let lock = client
            .control(ControlRequest::VaultLock {
                session_id: session_id.clone(),
            })
            .unwrap();
        assert_eq!(lock.status, ResponseStatus::Ok);
        let info = client
            .control(ControlRequest::SessionInfo {
                session_id: session_id.clone(),
            })
            .unwrap();
        match expect_ok_control(info).unwrap() {
            ControlResponse::SessionInfo { active, .. } => assert!(active),
            other => panic!("{other:?}"),
        }
        drop(handle);
    }

    #[test]
    fn ipc_full_security_lifecycle_e2e() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("sec.sock");
        let (_state, master, handle) = spawn_locked_server(dir.path(), socket.clone());
        let mut client = LocalClient::connect(&socket).unwrap();
        client.handshake("sec-e2e").unwrap();

        let auth = client.authenticate("analyst", "pw").unwrap();
        let (session_id, binding) = session_and_binding(auth);
        let blob = create_unlock_blob(&session_id, &binding, &MockKeyPassProvider::with_material(master.clone()))
            .unwrap();
        assert_eq!(
            client
                .control(ControlRequest::VaultUnlock {
                    session_id: session_id.clone(),
                    blob,
                })
                .unwrap()
                .status,
            ResponseStatus::Ok
        );

        assert_eq!(client.execute_sql(&session_id, CREATE).unwrap().status, ResponseStatus::Ok);
        assert_eq!(client.execute_sql(&session_id, INSERT).unwrap().status, ResponseStatus::Ok);
        expect_ok_data(client.execute_sql(&session_id, SELECT).unwrap()).unwrap();

        let lock = client
            .control(ControlRequest::VaultLock {
                session_id: session_id.clone(),
            })
            .unwrap();
        match expect_ok_control(lock).unwrap() {
            ControlResponse::VaultLock { state } => assert_eq!(state, VaultStateWire::Locked),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            client.execute_sql(&session_id, SELECT).unwrap().error_code,
            Some(ProtocolErrorCode::VaultLocked)
        );

        let blob2 = create_unlock_blob(&session_id, &binding, &MockKeyPassProvider::with_material(master))
            .unwrap();
        assert_eq!(
            client
                .control(ControlRequest::VaultUnlock {
                    session_id: session_id.clone(),
                    blob: blob2,
                })
                .unwrap()
                .status,
            ResponseStatus::Ok
        );
        assert_eq!(client.execute_sql(&session_id, SELECT).unwrap().status, ResponseStatus::Ok);

        // logout: session gone, vault stays unlocked (server-side we can't logout via IPC client easily)
        // LocalClient has no logout — use SessionInfo then invalid session after server restart simulation
        // For transport test: verify post-lock re-unlock works; logout tested in-process.
        drop(handle);
    }

    #[test]
    fn ipc_unauthorized_after_unlock_authz_denied() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("sec.sock");
        let (_state, master, handle) = spawn_locked_server(dir.path(), socket.clone());
        let mut client = LocalClient::connect(&socket).unwrap();
        client.handshake("sec-ipc").unwrap();
        let auth = client.authenticate("analyst", "pw").unwrap();
        let (session_id, binding) = session_and_binding(auth);
        let blob = create_unlock_blob(&session_id, &binding, &MockKeyPassProvider::with_material(master))
            .unwrap();
        client
            .control(ControlRequest::VaultUnlock {
                session_id: session_id.clone(),
                blob,
            })
            .unwrap();
        let resp = client
            .execute_sql(&session_id, "SELECT id FROM secret_table")
            .unwrap();
        assert_eq!(resp.error_code, Some(ProtocolErrorCode::AuthorizationDenied));
        drop(handle);
    }
}
