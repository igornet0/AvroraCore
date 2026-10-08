//! Reliability regression: one failing client connection must not stop the IPC server.
//!
//! `CoreServer::serve_forever_shared` is the accept loop used by `dmc serve` (and the dev
//! co-hosted adapter). Previously `dmc serve` broke out of its loop on the first
//! connection error, so a single malformed frame took the server down.

#[cfg(unix)]
mod unix_tests {
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use dmc_ipc::{
        CoreServer, LocalClient, SocketPathOptions, bootstrap_core_state_unlocked_for_test,
        expect_ok_control,
    };
    use dmc_protocol::ControlResponse;
    use tempfile::tempdir;

    #[test]
    fn connection_errors_do_not_stop_the_accept_loop() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("serve.sock");
        let state = Arc::new(Mutex::new(bootstrap_core_state_unlocked_for_test(
            dir.path(),
            false,
        )));
        let errors = Arc::new(AtomicUsize::new(0));
        {
            let (state, errors, socket) = (state.clone(), errors.clone(), socket.clone());
            thread::spawn(move || {
                let server = CoreServer::bind(
                    &socket,
                    &SocketPathOptions {
                        allow_custom_path: true,
                    },
                )
                .unwrap();
                let _ = server.serve_forever_shared(&state, |_| {
                    errors.fetch_add(1, Ordering::SeqCst);
                });
            });
        }
        thread::sleep(Duration::from_millis(50));

        // 1. malformed frame: garbage header + body
        let mut bad = UnixStream::connect(&socket).unwrap();
        bad.write_all(&[0xFF; 64]).unwrap();
        drop(bad);
        // 2. client hangs up in the middle of a frame header
        let mut cut = UnixStream::connect(&socket).unwrap();
        cut.write_all(&[0x00, 0x01]).unwrap();
        drop(cut);
        thread::sleep(Duration::from_millis(100));
        assert!(
            errors.load(Ordering::SeqCst) >= 1,
            "the malformed connection was reported as an error"
        );

        // 3. a normal client is still served
        let mut client = LocalClient::connect(&socket).unwrap();
        client.handshake("after-errors").unwrap();
        let auth = client.authenticate("analyst", "pw").unwrap();
        assert!(matches!(
            expect_ok_control(auth).unwrap(),
            ControlResponse::Authenticate { .. }
        ));
        client.close().unwrap();
    }
}
