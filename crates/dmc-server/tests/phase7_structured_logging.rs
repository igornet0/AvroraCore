//! Phase 7.9.2 — Dispatch emits structured events; observer failure does not change SQL outcome.

use dmc_observability::{EventKind, MemorySink, Observability};
use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, ProtocolErrorCode, RemoteLimits, RequestEnvelope,
    ResponseStatus,
};
use dmc_server::{
    bootstrap_core_state_locked, create_unlock_blob, expect_ok_control, expect_ok_data,
    handle_control, handle_data, CoreServerState, MockKeyPassProvider,
};
use tempfile::tempdir;

fn limits() -> RemoteLimits {
    RemoteLimits::default()
}

fn auth_pair(state: &mut CoreServerState, req_id: u64) -> (String, [u8; 32]) {
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

fn attach_memory(state: &mut CoreServerState) -> MemorySink {
    let sink = MemorySink::new();
    state.set_observability(Observability::memory(sink.clone()));
    sink
}

#[test]
fn successful_sql_emits_request_and_completed() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), true);
    let sink = attach_memory(&mut state);
    let (sid, binding) = auth_pair(&mut state, 1);
    let blob = create_unlock_blob(
        &sid,
        &binding,
        &MockKeyPassProvider::with_material(master),
    )
    .unwrap();
    expect_ok_control(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 2,
                body: ControlRequest::VaultUnlock {
                    session_id: sid.clone(),
                    blob,
                },
            },
            &limits(),
        "conn-test",
        )
        .unwrap(),
    )
    .unwrap();
    sink.clear();

    expect_ok_data(
        handle_data(
            &mut state,
            RequestEnvelope {
                request_id: 3,
                body: DataRequest::ExecuteSql {
                    session_id: sid,
                    sql: "SELECT id FROM users WHERE id = 0".into(),
                    params: vec![],
                },
            },
            &limits(),
        "conn-test",
        )
        .unwrap(),
    )
    .unwrap();

    let kinds: Vec<_> = sink.snapshot().iter().map(|e| e.kind).collect();
    assert!(kinds.contains(&EventKind::SqlRequest));
    assert!(kinds.contains(&EventKind::SqlCompleted));
    assert!(!kinds.iter().any(|k| matches!(k, EventKind::SqlFailed)));
}

#[test]
fn authentication_failure_emits_auth_failure() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let sink = attach_memory(&mut state);
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
    assert_eq!(resp.status, ResponseStatus::Error);
    assert_eq!(
        resp.error_code,
        Some(ProtocolErrorCode::AuthenticationFailed)
    );
    let kinds: Vec<_> = sink.snapshot().iter().map(|e| e.kind).collect();
    assert!(kinds.contains(&EventKind::AuthLoginFailure));
    let ev = sink
        .snapshot()
        .into_iter()
        .find(|e| e.kind == EventKind::AuthLoginFailure)
        .unwrap();
    assert_eq!(
        ev.fields.get("reason").map(String::as_str),
        Some("invalid_credential")
    );
}

#[test]
fn locked_vault_emits_sql_failed_with_vault_locked() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), true);
    let sink = attach_memory(&mut state);
    let (sid, _) = auth_pair(&mut state, 1);
    sink.clear();
    let resp = handle_data(
        &mut state,
        RequestEnvelope {
            request_id: 2,
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
    let kinds: Vec<_> = sink.snapshot().iter().map(|e| e.kind).collect();
    assert!(kinds.contains(&EventKind::SqlFailed));
}

#[test]
fn authz_denial_emits_authz_denied() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), true);
    let sink = attach_memory(&mut state);
    let (sid, binding) = auth_pair(&mut state, 1);
    let blob = create_unlock_blob(
        &sid,
        &binding,
        &MockKeyPassProvider::with_material(master),
    )
    .unwrap();
    expect_ok_control(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 2,
                body: ControlRequest::VaultUnlock {
                    session_id: sid.clone(),
                    blob,
                },
            },
            &limits(),
        "conn-test",
        )
        .unwrap(),
    )
    .unwrap();
    sink.clear();

    // analyst has Select on users, not Delete.
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
    let kinds: Vec<_> = sink.snapshot().iter().map(|e| e.kind).collect();
    assert!(kinds.contains(&EventKind::AuthzDenied));
}

#[test]
fn failing_observer_does_not_change_sql_success() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), true);
    state.set_observability(Observability::failing());
    let (sid, binding) = auth_pair(&mut state, 1);
    let blob = create_unlock_blob(
        &sid,
        &binding,
        &MockKeyPassProvider::with_material(master),
    )
    .unwrap();
    expect_ok_control(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 2,
                body: ControlRequest::VaultUnlock {
                    session_id: sid.clone(),
                    blob,
                },
            },
            &limits(),
        "conn-test",
        )
        .unwrap(),
    )
    .unwrap();

    // INSERT into items (granted) must succeed even if every emit fails.
    expect_ok_data(
        handle_data(
            &mut state,
            RequestEnvelope {
                request_id: 3,
                body: DataRequest::ExecuteSql {
                    session_id: sid.clone(),
                    sql: "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)".into(),
                    params: vec![],
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
                request_id: 4,
                body: DataRequest::ExecuteSql {
                    session_id: sid,
                    sql: "INSERT INTO items (id, name) VALUES (1, 'ok')".into(),
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
