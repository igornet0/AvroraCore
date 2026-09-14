//! Phase 7.7.1 — dmc-client SDK boundary (local IPC + TLS parity).

#[path = "common/tls_support.rs"]
mod tls_support;

#[cfg(unix)]
mod local_ipc {
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use dmc_client::{
        Client, ConnectionPhase, ConnectionTarget, ExecuteOutcome, MockKeyPassProvider,
        ProtocolErrorCode, UnlockMaterial, VaultState,
    };
    use dmc_ipc::{CoreServer, SocketPathOptions};
    use dmc_server::bootstrap_core_state_locked;
    use tempfile::tempdir;

    fn socket_options() -> SocketPathOptions {
        SocketPathOptions {
            allow_custom_path: true,
        }
    }

    fn spawn_locked_server(
        data_root: &Path,
        socket_path: PathBuf,
    ) -> (UnlockMaterial, thread::JoinHandle<()>) {
        let (state, master) = bootstrap_core_state_locked(data_root, false);
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

    const CREATE: &str = "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)";
    const INSERT: &str = "INSERT INTO items (id, name) VALUES (1, 'a')";
    const SELECT: &str = "SELECT id FROM items WHERE id = 1";

    #[test]
    fn client_sdk_local_e2e_auth_unlock_sql_lock_logout() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("client.sock");
        let (master, _handle) = spawn_locked_server(dir.path(), socket.clone());

        let mut client = Client::with_client_id(
            ConnectionTarget::Local {
                socket: socket.clone(),
            },
            "sdk-local",
        );
        client.connect().unwrap();
        assert_eq!(client.snapshot().phase, ConnectionPhase::Connected);

        client.control().authenticate("analyst", "pw").unwrap();
        assert_eq!(client.snapshot().phase, ConnectionPhase::Authenticated);
        assert_eq!(
            client.control().vault_status().unwrap(),
            VaultState::Locked
        );

        let provider = MockKeyPassProvider::with_material(master.clone());
        assert_eq!(
            client.control().vault_unlock(&provider).unwrap(),
            VaultState::Unlocked
        );

        let create_out = client.sql().execute(CREATE).unwrap();
        assert!(matches!(create_out, ExecuteOutcome::Ok));
        assert!(matches!(
            client.sql().execute(INSERT).unwrap(),
            ExecuteOutcome::Ok
        ));
        let rows = client.sql().query(SELECT).unwrap();
        assert_eq!(rows.rows.len(), 1);

        assert_eq!(client.control().vault_lock().unwrap(), VaultState::Locked);
        let locked = client.sql().execute(SELECT).unwrap_err();
        assert_eq!(locked.protocol_code(), Some(ProtocolErrorCode::VaultLocked));

        assert_eq!(
            client.control().vault_unlock(&provider).unwrap(),
            VaultState::Unlocked
        );
        let rows = client.sql().query(SELECT).unwrap();
        assert_eq!(rows.rows.len(), 1);

        client.control().logout().unwrap();
        assert_eq!(client.snapshot().phase, ConnectionPhase::Connected);
        let after_logout = client.sql().execute(SELECT).unwrap_err();
        assert_eq!(
            after_logout.protocol_code(),
            Some(ProtocolErrorCode::SessionInvalid)
        );
        assert_eq!(
            client.snapshot().vault,
            None,
            "logout clears local vault cache; server vault axis unchanged"
        );
    }

    #[test]
    fn client_sdk_disconnect_does_not_invent_core_semantics() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("reconn.sock");
        let (master, _handle) = spawn_locked_server(dir.path(), socket.clone());

        let mut client = Client::new(ConnectionTarget::Local {
            socket: socket.clone(),
        });
        client.connect().unwrap();
        client.control().authenticate("analyst", "pw").unwrap();
        let provider = MockKeyPassProvider::with_material(master);
        client.control().vault_unlock(&provider).unwrap();
        client.sql().execute(CREATE).unwrap();
        client.sql().execute(INSERT).unwrap();

        // Transport lost locally — must not claim vault locked / session destroyed.
        client.disconnect().unwrap();
        assert_eq!(client.snapshot().phase, ConnectionPhase::Disconnected);
        assert!(client.snapshot().session_id.is_none());

        client.connect().unwrap();
        // After reconnect: must re-auth; prior server session may still exist but
        // client must obtain a fresh session via authenticate.
        client.control().authenticate("analyst", "pw").unwrap();
        // Vault may still be unlocked server-side from before disconnect.
        let status = client.control().vault_status().unwrap();
        assert_eq!(status, VaultState::Unlocked);
        let rows = client.sql().query(SELECT).unwrap();
        assert_eq!(rows.rows.len(), 1);
    }
}

mod remote_tls {
    use std::net::{SocketAddr, TcpListener as StdTcpListener};
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use dmc_client::{
        Client, ConnectionPhase, ConnectionTarget, ExecuteOutcome, MockKeyPassProvider,
        ProtocolErrorCode, RemoteTlsConfig, UnlockMaterial, VaultState,
    };
    use dmc_protocol::RemoteLimits;
    use dmc_remote::{bootstrap_core_state_locked, CoreServerState, TlsRemoteServer};
    use tempfile::tempdir;

    use super::tls_support::dev_tls_stack;

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

    fn start_server(
        data_root: &Path,
    ) -> (
        SocketAddr,
        UnlockMaterial,
        dmc_remote::TlsClientConfig,
        thread::JoinHandle<()>,
    ) {
        let stack = dev_tls_stack("127.0.0.1");
        let (state_inner, master) = bootstrap_core_state_locked(data_root, false);
        let state = Arc::new(Mutex::new(state_inner));
        let addr = pick_ephemeral_addr();
        let handle = spawn_locked_tls_server(addr, stack.server.clone(), Arc::clone(&state));
        thread::sleep(Duration::from_millis(30));
        (addr, master, stack.client, handle)
    }

    const CREATE: &str = "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)";
    const INSERT: &str = "INSERT INTO items (id, name) VALUES (1, 'a')";
    const SELECT: &str = "SELECT id FROM items WHERE id = 1";

    #[test]
    fn client_sdk_tls_e2e_same_api_as_local() {
        let dir = tempdir().unwrap();
        let (addr, master, tls_client, _handle) = start_server(dir.path());

        let mut client = Client::with_client_id(
            ConnectionTarget::Remote {
                endpoint: addr,
                tls: RemoteTlsConfig {
                    client: tls_client,
                    development: true,
                },
            },
            "sdk-tls",
        );
        client.connect().unwrap();
        assert_eq!(client.snapshot().phase, ConnectionPhase::Connected);

        client.control().authenticate("analyst", "pw").unwrap();
        assert_eq!(
            client.control().vault_status().unwrap(),
            VaultState::Locked
        );

        let provider = MockKeyPassProvider::with_material(master);
        client.control().vault_unlock(&provider).unwrap();

        client.sql().execute(CREATE).unwrap();
        client.sql().execute(INSERT).unwrap();
        assert_eq!(client.sql().query(SELECT).unwrap().rows.len(), 1);

        client.control().vault_lock().unwrap();
        assert_eq!(
            client.sql().execute(SELECT).unwrap_err().protocol_code(),
            Some(ProtocolErrorCode::VaultLocked)
        );

        client.control().vault_unlock(&provider).unwrap();
        assert_eq!(client.sql().query(SELECT).unwrap().rows.len(), 1);

        client.control().logout().unwrap();
        assert_eq!(
            client.sql().execute(SELECT).unwrap_err().protocol_code(),
            Some(ProtocolErrorCode::SessionInvalid)
        );
        let _ = ExecuteOutcome::Ok;
    }
}
