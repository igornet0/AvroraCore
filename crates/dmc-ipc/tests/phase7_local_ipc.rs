//! Phase 7.3 — local IPC transport, protocol, auth boundary, SQL E2E.

#[cfg(unix)]
mod unix_tests {
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    use dmc_ipc::LocalConnection;
    use dmc_ipc::{
        bootstrap_core_state_unlocked_for_test, expect_ok_control, expect_ok_data, CoreServer, CoreServerState,
        FramedConnection, LocalClient, ServeOptions, SocketPathOptions,
    };
    use dmc_server::{serve_connection, ConnectionLimits};
    use dmc_protocol::{
        ControlRequest, ControlResponse, DataRequest, DataResponse, ProtocolError,
        ProtocolErrorCode, ProtocolLimits, ResponseStatus,
    };
    use tempfile::tempdir;

    fn socket_options() -> SocketPathOptions {
        SocketPathOptions {
            allow_custom_path: true,
        }
    }

    struct PairConn(UnixStream);

    impl Read for PairConn {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for PairConn {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush()
        }
    }

    impl LocalConnection for PairConn {
        fn shutdown(&mut self) -> std::io::Result<()> {
            self.0.shutdown(std::net::Shutdown::Both)
        }
    }

    fn spawn_server(
        data_root: &Path,
        socket_path: PathBuf,
    ) -> (Arc<Mutex<CoreServerState>>, thread::JoinHandle<()>) {
        let state = Arc::new(Mutex::new(bootstrap_core_state_unlocked_for_test(data_root, false)));
        let state_for_thread = Arc::clone(&state);
        let handle = thread::spawn(move || {
            let server = CoreServer::bind(&socket_path, &socket_options()).unwrap();
            loop {
                let mut guard = state_for_thread.lock().unwrap();
                let _ = server.accept_and_serve_one(&mut guard);
            }
        });
        thread::sleep(Duration::from_millis(20));
        (state, handle)
    }

    fn session_from_auth(resp: dmc_protocol::ResponseEnvelope<ControlResponse>) -> String {
        let body = expect_ok_control(resp).unwrap();
        match body {
            ControlResponse::Authenticate { session_id, .. } => session_id,
            other => panic!("expected authenticate response, got {other:?}"),
        }
    }

    #[test]
    fn in_process_pair_authenticate() {
        let (client_stream, server_stream) = UnixStream::pair().unwrap();
        let dir = tempdir().unwrap();
        let mut state = bootstrap_core_state_unlocked_for_test(dir.path(), false);
        let server_handle = thread::spawn(move || {
            let mut framed = FramedConnection::new(PairConn(server_stream), ProtocolLimits::default());
            let mut conn_limits = ConnectionLimits::default();
            serve_connection(
                &mut framed,
                &mut state,
                &ServeOptions::default(),
                &mut conn_limits,
            )
            .expect("serve_connection")
        });

        let mut client = LocalClient::from_connection(PairConn(client_stream));
        client.handshake("pair-test").unwrap();
        let auth = client.authenticate("analyst", "pw").unwrap();
        assert_eq!(auth.status, ResponseStatus::Ok);
        client.close().unwrap();
        server_handle.join().unwrap();
    }

    #[test]
    fn bind_and_connect() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("test.sock");
        let (_state, handle) = spawn_server(dir.path(), socket.clone());
        let mut client = LocalClient::connect(&socket).unwrap();
        let hs = client.handshake("phase7-test").unwrap();
        assert_eq!(hs.server_id, "avrora-core");
        client.close().unwrap();
        drop(handle);
    }

    #[test]
    fn handshake_required_before_control() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("test.sock");
        let (_state, handle) = spawn_server(dir.path(), socket.clone());
        let mut client = LocalClient::connect(&socket).unwrap();
        let err = client
            .control(ControlRequest::Health)
            .expect_err("health without handshake should fail");
        assert!(
            matches!(
                err,
                ProtocolError::Wire { .. } | ProtocolError::Io(_) | ProtocolError::InvalidFrame(_)
            ),
            "unexpected error: {err:?}"
        );
        drop(handle);
    }

    #[test]
    fn authenticate_and_health() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("test.sock");
        let (_state, handle) = spawn_server(dir.path(), socket.clone());
        let mut client = LocalClient::connect(&socket).unwrap();
        client.handshake("phase7-test").unwrap();
        let auth = client.authenticate("analyst", "pw").unwrap();
        assert_eq!(auth.status, ResponseStatus::Ok);
        let session_id = session_from_auth(auth);

        let info = client
            .control(ControlRequest::SessionInfo {
                session_id: session_id.clone(),
            })
            .unwrap();
        let info_body = expect_ok_control(info).unwrap();
        match info_body {
            ControlResponse::SessionInfo { active, .. } => assert!(active),
            other => panic!("unexpected {other:?}"),
        }

        let health = client.control(ControlRequest::Health).unwrap();
        assert_eq!(health.request_id, 3);
        client.close().unwrap();
        drop(handle);
    }

    #[test]
    fn request_id_preserved_in_responses() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("test.sock");
        let (_state, handle) = spawn_server(dir.path(), socket.clone());
        let mut client = LocalClient::connect(&socket).unwrap();
        client.handshake("phase7-test").unwrap();
        let resp = client.control(ControlRequest::Health).unwrap();
        assert_eq!(resp.request_id, 1);
        drop(handle);
    }

    #[test]
    fn unauthenticated_data_request_rejected() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("test.sock");
        let (_state, handle) = spawn_server(dir.path(), socket.clone());
        let mut client = LocalClient::connect(&socket).unwrap();
        client.handshake("phase7-test").unwrap();
        let resp = client
            .data(DataRequest::ExecuteSql {
                session_id: "fake-session".into(),
                sql: "SELECT 1".into(),
                params: Vec::new(),
            })
            .unwrap();
        assert_eq!(resp.status, ResponseStatus::Error);
        assert_eq!(resp.error_code, Some(ProtocolErrorCode::SessionInvalid));
        drop(handle);
    }

    #[test]
    fn invalid_session_rejected() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("test.sock");
        let (_state, handle) = spawn_server(dir.path(), socket.clone());
        let mut client = LocalClient::connect(&socket).unwrap();
        client.handshake("phase7-test").unwrap();
        client.authenticate("analyst", "pw").unwrap();
        let resp = client
            .execute_sql("not-a-real-session", "SELECT 1")
            .unwrap();
        assert_eq!(resp.error_code, Some(ProtocolErrorCode::SessionInvalid));
        drop(handle);
    }

    #[test]
    fn bad_password_authentication_failed() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("test.sock");
        let (_state, handle) = spawn_server(dir.path(), socket.clone());
        let mut client = LocalClient::connect(&socket).unwrap();
        client.handshake("phase7-test").unwrap();
        let resp = client.authenticate("analyst", "wrong").unwrap();
        assert_eq!(resp.status, ResponseStatus::Error);
        assert_eq!(resp.error_code, Some(ProtocolErrorCode::AuthenticationFailed));
        drop(handle);
    }

    #[test]
    fn unauthorized_sql_denied() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("test.sock");
        let (_state, handle) = spawn_server(dir.path(), socket.clone());
        let mut client = LocalClient::connect(&socket).unwrap();
        client.handshake("phase7-test").unwrap();
        let auth = client.authenticate("analyst", "pw").unwrap();
        let session_id = session_from_auth(auth);
        let resp = client
            .execute_sql(&session_id, "SELECT id FROM secret_table")
            .unwrap();
        assert_eq!(resp.error_code, Some(ProtocolErrorCode::AuthorizationDenied));
        drop(handle);
    }

    #[test]
    fn sql_e2e_create_insert_commit_select() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("test.sock");
        let (_state, handle) = spawn_server(dir.path(), socket.clone());
        let mut client = LocalClient::connect(&socket).unwrap();
        client.handshake("phase7-e2e").unwrap();
        let auth = client.authenticate("analyst", "pw").unwrap();
        let session_id = session_from_auth(auth);

        let create = client
            .execute_sql(
                &session_id,
                "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)",
            )
            .unwrap();
        assert!(
            create.status == ResponseStatus::Ok,
            "create failed: {:?} {:?}",
            create.error_code,
            create.error_message
        );

        client.data(DataRequest::Begin {
            session_id: session_id.clone(),
        })
        .unwrap();
        let insert = client
            .execute_sql(&session_id, "INSERT INTO items (id, name) VALUES (1, 'alpha')")
            .unwrap();
        assert_eq!(insert.status, ResponseStatus::Ok);
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
            DataResponse::SqlResult(result) => assert_eq!(result.rows.len(), 1),
            other => panic!("expected sql result, got {other:?}"),
        }

        client.close().unwrap();
        drop(handle);
    }

    #[test]
    fn reconnect_and_session_survives_disconnect() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("test.sock");
        let (_state, handle) = spawn_server(dir.path(), socket.clone());

        let session_id = {
            let mut client = LocalClient::connect(&socket).unwrap();
            client.handshake("phase7-reconnect").unwrap();
            let auth = client.authenticate("analyst", "pw").unwrap();
            let session_id = session_from_auth(auth);
            client
                .execute_sql(
                    &session_id,
                    "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)",
                )
                .unwrap();
            client.close().unwrap();
            session_id
        };

        thread::sleep(Duration::from_millis(20));

        let mut client = LocalClient::connect(&socket).unwrap();
        client.handshake("phase7-reconnect-2").unwrap();
        let info = client
            .control(ControlRequest::SessionInfo {
                session_id: session_id.clone(),
            })
            .unwrap();
        let info_body = expect_ok_control(info).unwrap();
        match info_body {
            ControlResponse::SessionInfo { active, .. } => assert!(active),
            other => panic!("unexpected {other:?}"),
        }

        let select = client
            .execute_sql(&session_id, "SELECT id FROM items")
            .unwrap();
        assert_eq!(select.status, ResponseStatus::Ok);
        client.close().unwrap();
        drop(handle);
    }

    #[test]
    fn stale_socket_removed_on_rebind() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("test.sock");
        {
            let _server = CoreServer::bind(&socket, &socket_options()).unwrap();
        }
        let rebind = CoreServer::bind(&socket, &socket_options());
        assert!(rebind.is_ok());
    }

    #[test]
    fn non_socket_path_rejected() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("test.sock");
        std::fs::write(&socket, b"stale").unwrap();
        assert!(CoreServer::bind(&socket, &socket_options()).is_err());
    }

    #[test]
    fn custom_socket_path_requires_opt_in() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("custom.sock");
        std::fs::create_dir_all(dir.path()).unwrap();
        assert!(CoreServer::bind(&socket, &SocketPathOptions::default()).is_err());
    }

    #[test]
    fn multiple_sequential_connections() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("test.sock");
        let (_state, handle) = spawn_server(dir.path(), socket.clone());

        for i in 0..3 {
            let mut client = LocalClient::connect(&socket).unwrap();
            client.handshake(&format!("client-{i}")).unwrap();
            let resp = client.control(ControlRequest::Health).unwrap();
            assert_eq!(resp.status, ResponseStatus::Ok);
            client.close().unwrap();
        }
        drop(handle);
    }
}
