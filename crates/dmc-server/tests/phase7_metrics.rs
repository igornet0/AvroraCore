//! Phase 7.9.4 — Server lifecycle metrics wiring + failure isolation.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::thread;

use dmc_observability::{
    MemoryMetricsSink, Metric, MetricLabels, MetricOperation, MetricSample, MetricTransport,
    Metrics,
};
use dmc_protocol::{
    build_frame, decode_payload, encode_payload, ControlRequest, ControlResponse, DataRequest,
    FramedConnection, HandshakeRequest, HandshakeResponse, MessageType, ProtocolLimits,
    ProtocolErrorCode, RemoteLimits, RequestEnvelope, PROTOCOL_VERSION,
};
use dmc_server::{
    bootstrap_core_state_locked, create_unlock_blob, expect_ok_control, expect_ok_data,
    handle_control, handle_data, serve_connection, ConnectionLimits, CoreServerState,
    MockKeyPassProvider, ServeOptions, UnlockMaterial,
};
use tempfile::tempdir;

fn limits() -> RemoteLimits {
    RemoteLimits::default()
}

fn attach_metrics(state: &mut CoreServerState) -> MemoryMetricsSink {
    let sink = MemoryMetricsSink::new();
    state.set_metrics(Metrics::memory(sink.clone()));
    sink
}

fn auth_pair(
    state: &mut CoreServerState,
    req_id: u64,
) -> (String, [u8; 32]) {
    let resp = handle_control(
        state,
        RequestEnvelope {
            request_id: req_id,
            body: ControlRequest::Authenticate {
                identity_name: "analyst".into(),
                password: "pw".into(),
            },
        },
        &limits(),
        "conn-test",
    )
    .unwrap();
    match expect_ok_control(resp).unwrap() {
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

fn unlock(
    state: &mut CoreServerState,
    req_id: u64,
    sid: &str,
    binding: &[u8; 32],
    master: UnlockMaterial,
) {
    let blob =
        create_unlock_blob(sid, binding, &MockKeyPassProvider::with_material(master)).unwrap();
    expect_ok_control(
        handle_control(
            state,
            RequestEnvelope {
                request_id: req_id,
                body: ControlRequest::VaultUnlock {
                    session_id: sid.to_string(),
                    blob,
                },
            },
            &limits(),
            "conn-test",
        )
        .unwrap(),
    )
    .unwrap();
}

fn sql(state: &mut CoreServerState, req_id: u64, sid: &str, statement: &str) {
    expect_ok_data(
        handle_data(
            state,
            RequestEnvelope {
                request_id: req_id,
                body: DataRequest::ExecuteSql {
                    session_id: sid.to_string(),
                    sql: statement.into(),
                    params: vec![],
                },
            },
            &limits(),
            "conn-test",
        )
        .unwrap(),
    )
    .unwrap();
}

fn has_operation(sample: &MetricSample, op: MetricOperation) -> bool {
    match sample {
        MetricSample::Counter { labels, .. }
        | MetricSample::Observe { labels, .. }
        | MetricSample::Gauge { labels, .. } => labels.operation == Some(op),
    }
}

fn assert_no_forbidden_labels(sink: &MemoryMetricsSink) {
    for sample in sink.snapshot() {
        let labels = match &sample {
            MetricSample::Counter { labels, .. }
            | MetricSample::Observe { labels, .. }
            | MetricSample::Gauge { labels, .. } => labels,
        };
        for key in labels.as_map().keys() {
            assert!(
                !MetricLabels::is_forbidden_label_key(key),
                "forbidden label key leaked into metrics: {key}"
            );
        }
    }
}

#[test]
fn request_success_records_total_and_duration() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let sink = attach_metrics(&mut state);
    let _ = auth_pair(&mut state, 1);
    assert!(sink.counter_sum(Metric::RequestsTotal) >= 1);
    assert!(!sink.observe_values(Metric::RequestDurationMs).is_empty());
    assert_eq!(sink.counter_sum(Metric::RequestsFailedTotal), 0);
    assert_no_forbidden_labels(&sink);
}

#[test]
fn request_error_increments_failed() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let sink = attach_metrics(&mut state);
    let resp = handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 1,
            body: ControlRequest::Authenticate {
                identity_name: "analyst".into(),
                password: "wrong".into(),
            },
        },
        &limits(),
        "conn-test",
    )
    .unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::AuthenticationFailed));
    assert!(sink.counter_sum(Metric::RequestsFailedTotal) >= 1);
    assert!(sink.counter_sum(Metric::AuthFailureTotal) >= 1);
}

#[test]
fn auth_success_and_failure_metrics() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let sink = attach_metrics(&mut state);
    let _ = handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 1,
            body: ControlRequest::Authenticate {
                identity_name: "analyst".into(),
                password: "wrong".into(),
            },
        },
        &limits(),
        "conn-test",
    )
    .unwrap();
    assert_eq!(sink.counter_sum(Metric::AuthFailureTotal), 1);
    let _ = auth_pair(&mut state, 2);
    assert_eq!(sink.counter_sum(Metric::AuthSuccessTotal), 1);
}

#[test]
fn authz_deny_increments_authorization_denied() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), true);
    let sink = attach_metrics(&mut state);
    let (sid, binding) = auth_pair(&mut state, 1);
    unlock(&mut state, 2, &sid, &binding, master);
    sink.clear();
    let resp = handle_data(
        &mut state,
        RequestEnvelope {
            request_id: 3,
            body: DataRequest::ExecuteSql {
                session_id: sid,
                sql: "DELETE FROM users WHERE id = 1".into(),
                params: vec![],
            },
        },
        &limits(),
        "conn-test",
    )
    .unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::AuthorizationDenied));
    assert!(sink.counter_sum(Metric::AuthorizationDeniedTotal) >= 1);
    assert!(sink.counter_sum(Metric::SqlErrorsTotal) >= 1);
}

#[test]
fn vault_unlock_lock_and_locked_request_metrics() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), true);
    let sink = attach_metrics(&mut state);
    let (sid, binding) = auth_pair(&mut state, 1);
    unlock(&mut state, 2, &sid, &binding, master);
    assert!(sink.counter_sum(Metric::VaultUnlockSuccessTotal) >= 1);

    expect_ok_control(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 3,
                body: ControlRequest::VaultLock {
                    session_id: sid.clone(),
                },
            },
            &limits(),
            "conn-test",
        )
        .unwrap(),
    )
    .unwrap();
    assert!(sink.counter_sum(Metric::VaultLockTotal) >= 1);

    sink.clear();
    let resp = handle_data(
        &mut state,
        RequestEnvelope {
            request_id: 4,
            body: DataRequest::ExecuteSql {
                session_id: sid,
                sql: "SELECT 1".into(),
                params: vec![],
            },
        },
        &limits(),
        "conn-test",
    )
    .unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::VaultLocked));
    assert!(sink.counter_sum(Metric::VaultLockedRequestsTotal) >= 1);
}

#[test]
fn sql_success_and_txn_commit_rollback_metrics() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), true);
    let sink = attach_metrics(&mut state);
    let (sid, binding) = auth_pair(&mut state, 1);
    unlock(&mut state, 2, &sid, &binding, master);
    sql(
        &mut state,
        3,
        &sid,
        "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)",
    );
    sink.clear();

    expect_ok_data(
        handle_data(
            &mut state,
            RequestEnvelope {
                request_id: 4,
                body: DataRequest::Begin {
                    session_id: sid.clone(),
                },
            },
            &limits(),
            "conn-test",
        )
        .unwrap(),
    )
    .unwrap();
    sql(
        &mut state,
        5,
        &sid,
        "INSERT INTO items (id, name) VALUES (1, 'a')",
    );
    expect_ok_data(
        handle_data(
            &mut state,
            RequestEnvelope {
                request_id: 6,
                body: DataRequest::Commit {
                    session_id: sid.clone(),
                },
            },
            &limits(),
            "conn-test",
        )
        .unwrap(),
    )
    .unwrap();
    assert!(sink.counter_sum(Metric::SqlStatementsTotal) >= 3);
    assert!(sink.counter_sum(Metric::SqlTransactionsCommittedTotal) >= 1);
    assert!(sink
        .snapshot()
        .iter()
        .any(|s| has_operation(s, MetricOperation::Insert)));

    sink.clear();
    expect_ok_data(
        handle_data(
            &mut state,
            RequestEnvelope {
                request_id: 7,
                body: DataRequest::Begin {
                    session_id: sid.clone(),
                },
            },
            &limits(),
            "conn-test",
        )
        .unwrap(),
    )
    .unwrap();
    expect_ok_data(
        handle_data(
            &mut state,
            RequestEnvelope {
                request_id: 8,
                body: DataRequest::Rollback {
                    session_id: sid,
                },
            },
            &limits(),
            "conn-test",
        )
        .unwrap(),
    )
    .unwrap();
    assert!(sink.counter_sum(Metric::SqlTransactionsRolledBackTotal) >= 1);
}

#[test]
fn session_invalid_increments_metric() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let sink = attach_metrics(&mut state);
    let resp = handle_data(
        &mut state,
        RequestEnvelope {
            request_id: 1,
            body: DataRequest::ExecuteSql {
                session_id: "ghost-session".into(),
                sql: "SELECT 1".into(),
                params: vec![],
            },
        },
        &limits(),
        "conn-test",
    )
    .unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::SessionInvalid));
    assert!(sink.counter_sum(Metric::SessionInvalidTotal) >= 1);
    assert!(sink.counter_sum(Metric::RequestsFailedTotal) >= 1);
}

#[test]
fn failing_metrics_sink_does_not_change_sql_commit() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), true);
    state.set_metrics(Metrics::failing());
    let (sid, binding) = auth_pair(&mut state, 1);
    unlock(&mut state, 2, &sid, &binding, master);
    sql(
        &mut state,
        3,
        &sid,
        "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)",
    );
    expect_ok_data(
        handle_data(
            &mut state,
            RequestEnvelope {
                request_id: 4,
                body: DataRequest::Begin {
                    session_id: sid.clone(),
                },
            },
            &limits(),
            "conn-test",
        )
        .unwrap(),
    )
    .unwrap();
    sql(
        &mut state,
        5,
        &sid,
        "INSERT INTO items (id, name) VALUES (1, 'ok')",
    );
    expect_ok_data(
        handle_data(
            &mut state,
            RequestEnvelope {
                request_id: 6,
                body: DataRequest::Commit {
                    session_id: sid,
                },
            },
            &limits(),
            "conn-test",
        )
        .unwrap(),
    )
    .unwrap();
}

#[test]
fn failing_metrics_sink_does_not_change_auth_or_vault() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    state.set_metrics(Metrics::failing());
    let (sid, binding) = auth_pair(&mut state, 1);
    unlock(&mut state, 2, &sid, &binding, master);
    expect_ok_control(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 3,
                body: ControlRequest::VaultLock {
                    session_id: sid,
                },
            },
            &limits(),
            "conn-test",
        )
        .unwrap(),
    )
    .unwrap();
}

#[cfg(unix)]
mod connection_metrics {
    use super::*;

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

    #[test]
    fn accept_and_disconnect_update_connection_gauges() {
        let (client_stream, server_stream) = UnixStream::pair().unwrap();
        let dir = tempdir().unwrap();
        let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
        let sink = attach_metrics(&mut state);
        state.metrics_transport = Some(MetricTransport::Local);

        let server = thread::spawn(move || {
            let mut framed =
                FramedConnection::new(PairConn(server_stream), ProtocolLimits::default());
            let mut conn_limits = ConnectionLimits::default();
            let mut options = ServeOptions::default();
            options.metrics_transport = Some(MetricTransport::Local);
            serve_connection(&mut framed, &mut state, &options, &mut conn_limits)
                .expect("serve");
            sink
        });

        let mut client = FramedConnection::new(PairConn(client_stream), ProtocolLimits::default());
        let hs = HandshakeRequest {
            protocol_version: PROTOCOL_VERSION,
            client_id: "metrics-test".into(),
        };
        let payload = encode_payload(&hs, &ProtocolLimits::default()).unwrap();
        client
            .write_frame(&build_frame(MessageType::HandshakeRequest, payload))
            .unwrap();
        let frame = client.read_frame().unwrap();
        assert_eq!(frame.header.message_type, MessageType::HandshakeResponse);
        let _: HandshakeResponse = decode_payload(&frame.payload).unwrap();

        let auth = RequestEnvelope {
            request_id: 1,
            body: ControlRequest::Authenticate {
                identity_name: "analyst".into(),
                password: "pw".into(),
            },
        };
        let payload = encode_payload(&auth, &ProtocolLimits::default()).unwrap();
        client
            .write_frame(&build_frame(MessageType::ControlRequest, payload))
            .unwrap();
        let _ = client.read_frame().unwrap();
        drop(client);

        let sink = server.join().unwrap();
        assert!(sink.counter_sum(Metric::ConnectionsAcceptedTotal) >= 1);
        assert_eq!(sink.last_gauge(Metric::ConnectionsActive), Some(0));
        assert!(sink.counter_sum(Metric::AuthSuccessTotal) >= 1);
        assert_no_forbidden_labels(&sink);
    }
}
