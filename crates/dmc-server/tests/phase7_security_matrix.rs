//! Phase 7.6.5 — Two-axis security matrix (in-process).

use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, ProtocolErrorCode, RemoteLimits,
    RequestEnvelope, ResponseStatus, VaultStateWire,
};
use dmc_security::auth::{Action, Resource, SessionManager};
use dmc_server::{
    bootstrap_core_state_locked, bootstrap_core_state_unlocked_for_test, create_unlock_blob,
    expect_ok_control, expect_ok_data, handle_control, handle_data, CoreServerState,
    MockKeyPassProvider, SecurityState, UnlockMaterial, VaultState,
};
use tempfile::tempdir;

fn limits() -> RemoteLimits {
    RemoteLimits::default()
}

fn authenticate(state: &mut CoreServerState, req_id: u64) -> (String, [u8; 32]) {
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
    assert_eq!(resp.status, ResponseStatus::Ok);
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

fn vault_unlock_wire(
    state: &mut CoreServerState,
    req_id: u64,
    session_id: &str,
    binding: &[u8; 32],
    master: &UnlockMaterial,
) {
    let blob = create_unlock_blob(session_id, binding, &MockKeyPassProvider::with_material(master.clone()))
        .unwrap();
    let resp = handle_control(
        state,
        RequestEnvelope {
            request_id: req_id,
            body: ControlRequest::VaultUnlock {
                session_id: session_id.into(),
                blob,
            },
        },
        &limits(),
    "conn-test",
    )
    .unwrap();
    assert_eq!(resp.status, ResponseStatus::Ok);
}

fn execute_sql(
    state: &mut CoreServerState,
    req_id: u64,
    session_id: &str,
    sql: &str,
) -> dmc_protocol::ResponseEnvelope<dmc_protocol::DataResponse> {
    handle_data(
        state,
        RequestEnvelope {
            request_id: req_id,
            body: DataRequest::ExecuteSql {
                session_id: session_id.into(),
                sql: sql.into(),
                params: Vec::new(),
            },
        },
        &limits(),
    "conn-test",
    )
    .unwrap()
}

const CREATE: &str = "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)";
const INSERT: &str = "INSERT INTO items (id, name) VALUES (1, 'a')";
const SELECT: &str = "SELECT id FROM items WHERE id = 1";
const FORBIDDEN: &str = "SELECT id FROM secret_table";

// --- Control plane ---

#[test]
fn vault_status_requires_valid_session() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let resp = handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 1,
            body: ControlRequest::VaultStatus {
                session_id: "ghost".into(),
            },
        },
        &limits(),
    "conn-test",
    )
    .unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::SessionInvalid));
}

#[test]
fn vault_unlock_requires_valid_session_and_binding() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, binding) = authenticate(&mut state, 1);
    let blob = create_unlock_blob(&session_id, &binding, &MockKeyPassProvider::with_material(master))
        .unwrap();
    let bad_session = handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 2,
            body: ControlRequest::VaultUnlock {
                session_id: "ghost".into(),
                blob: blob.clone(),
            },
        },
        &limits(),
    "conn-test",
    )
    .unwrap();
    assert_eq!(
        bad_session.error_code,
        Some(ProtocolErrorCode::UnlockSessionMismatch)
    );
    let (s2, _b2) = authenticate(&mut state, 3);
    let wrong_binding = handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 4,
            body: ControlRequest::VaultUnlock {
                session_id: s2,
                blob,
            },
        },
        &limits(),
    "conn-test",
    )
    .unwrap();
    assert_eq!(
        wrong_binding.error_code,
        Some(ProtocolErrorCode::UnlockSessionMismatch)
    );
}

#[test]
fn vault_lock_preserves_auth_session() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, binding) = authenticate(&mut state, 1);
    vault_unlock_wire(&mut state, 2, &session_id, &binding, &master);
    handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 3,
            body: ControlRequest::VaultLock {
                session_id: session_id.clone(),
            },
        },
        &limits(),
    "conn-test",
    )
    .unwrap();
    assert!(state.auth.validate_session(&session_id.clone().into()).is_ok());
    assert_eq!(state.vault_state(), VaultState::Locked);
}

#[test]
fn logout_does_not_lock_vault() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, binding) = authenticate(&mut state, 1);
    vault_unlock_wire(&mut state, 2, &session_id, &binding, &master);
    state.auth.logout(&session_id.clone().into()).unwrap();
    assert_eq!(state.vault_state(), VaultState::Unlocked);
    assert!(state.root_dek_present());
}

#[test]
fn restart_invalidates_sessions_and_locks_vault() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, binding) = authenticate(&mut state, 1);
    vault_unlock_wire(&mut state, 2, &session_id, &binding, &master);
    state.simulate_restart();
    assert_eq!(state.vault_state(), VaultState::Locked);
    assert!(!state.root_dek_present());
    assert!(state.auth.validate_session(&session_id.into()).is_err());
}

#[test]
fn authenticate_does_not_unlock_vault() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, _) = authenticate(&mut state, 1);
    assert_eq!(state.vault_state(), VaultState::Locked);
    let sec = state.security_state(&session_id);
    assert!(sec.authenticated);
    assert!(!sec.vault_unlocked);
}

#[test]
fn vault_unlock_does_not_imply_authentication() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    state.apply_vault_unlock(&master).unwrap();
    assert_eq!(state.vault_state(), VaultState::Unlocked);
    let resp = execute_sql(&mut state, 1, "no-session", SELECT);
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::SessionInvalid));
}

// --- Data plane matrix ---

#[test]
fn matrix_unauthenticated_locked_session_invalid() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let resp = execute_sql(&mut state, 1, "ghost", SELECT);
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::SessionInvalid));
}

#[test]
fn matrix_unauthenticated_unlocked_session_invalid() {
    let dir = tempdir().unwrap();
    let mut state = bootstrap_core_state_unlocked_for_test(dir.path(), false);
    let resp = execute_sql(&mut state, 1, "ghost", SELECT);
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::SessionInvalid));
}

#[test]
fn matrix_authenticated_locked_vault_locked() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, _) = authenticate(&mut state, 1);
    let resp = execute_sql(&mut state, 2, &session_id, CREATE);
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::VaultLocked));
}

#[test]
fn matrix_authenticated_unlocked_unauthorized_authz_denied() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, binding) = authenticate(&mut state, 1);
    vault_unlock_wire(&mut state, 2, &session_id, &binding, &master);
    let resp = execute_sql(&mut state, 3, &session_id, FORBIDDEN);
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::AuthorizationDenied));
}

#[test]
fn matrix_authenticated_unlocked_authorized_sql_ok() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, binding) = authenticate(&mut state, 1);
    vault_unlock_wire(&mut state, 2, &session_id, &binding, &master);
    assert_eq!(execute_sql(&mut state, 3, &session_id, CREATE).status, ResponseStatus::Ok);
    assert_eq!(execute_sql(&mut state, 4, &session_id, INSERT).status, ResponseStatus::Ok);
    expect_ok_data(execute_sql(&mut state, 5, &session_id, SELECT)).unwrap();
}

#[test]
fn vault_locked_precedes_authz_not_masked_as_denied() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, _) = authenticate(&mut state, 1);
    let resp = execute_sql(&mut state, 2, &session_id, FORBIDDEN);
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::VaultLocked));
}

// --- Independence ---

#[test]
fn lock_then_unlock_same_session_continues() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, binding) = authenticate(&mut state, 1);
    vault_unlock_wire(&mut state, 2, &session_id, &binding, &master);
    assert_eq!(execute_sql(&mut state, 3, &session_id, CREATE).status, ResponseStatus::Ok);
    handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 4,
            body: ControlRequest::VaultLock {
                session_id: session_id.clone(),
            },
        },
        &limits(),
    "conn-test",
    )
    .unwrap();
    assert!(state.auth.validate_session(&session_id.clone().into()).is_ok());
    assert_eq!(
        execute_sql(&mut state, 5, &session_id, SELECT).error_code,
        Some(ProtocolErrorCode::VaultLocked)
    );
    vault_unlock_wire(&mut state, 6, &session_id, &binding, &master);
    assert_eq!(execute_sql(&mut state, 7, &session_id, SELECT).status, ResponseStatus::Ok);
}

#[test]
fn security_state_is_capability_only_no_secrets() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, binding) = authenticate(&mut state, 1);
    let locked = state.security_state(&session_id);
    assert_eq!(
        locked,
        SecurityState {
            authenticated: true,
            vault_unlocked: false,
        }
    );
    assert!(std::mem::size_of::<SecurityState>() <= 2);
    vault_unlock_wire(&mut state, 2, &session_id, &binding, &master);
    let unlocked = state.security_state(&session_id);
    assert!(unlocked.vault_unlocked);
    assert!(!format!("{unlocked:?}").to_lowercase().contains("key"));
    assert!(!format!("{unlocked:?}").to_lowercase().contains("dek"));
}

#[test]
fn full_control_data_lifecycle_in_process() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, binding) = authenticate(&mut state, 1);
    vault_unlock_wire(&mut state, 2, &session_id, &binding, &master);
    assert_eq!(execute_sql(&mut state, 3, &session_id, CREATE).status, ResponseStatus::Ok);
    assert_eq!(execute_sql(&mut state, 4, &session_id, INSERT).status, ResponseStatus::Ok);
    expect_ok_data(execute_sql(&mut state, 5, &session_id, SELECT)).unwrap();
    handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 6,
            body: ControlRequest::VaultLock {
                session_id: session_id.clone(),
            },
        },
        &limits(),
    "conn-test",
    )
    .unwrap();
    assert_eq!(
        execute_sql(&mut state, 7, &session_id, SELECT).error_code,
        Some(ProtocolErrorCode::VaultLocked)
    );
    vault_unlock_wire(&mut state, 8, &session_id, &binding, &master);
    assert_eq!(execute_sql(&mut state, 9, &session_id, SELECT).status, ResponseStatus::Ok);
    state.auth.logout(&session_id.clone().into()).unwrap();
    assert_eq!(
        execute_sql(&mut state, 10, &session_id, SELECT).error_code,
        Some(ProtocolErrorCode::SessionInvalid)
    );
    assert_eq!(state.vault_state(), VaultState::Unlocked);
}

#[test]
fn vault_status_reflects_runtime_state() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, binding) = authenticate(&mut state, 1);
    let status = handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 2,
            body: ControlRequest::VaultStatus {
                session_id: session_id.clone(),
            },
        },
        &limits(),
    "conn-test",
    )
    .unwrap();
    match expect_ok_control(status).unwrap() {
        ControlResponse::VaultStatus { state: st } => assert_eq!(st, VaultStateWire::Locked),
        other => panic!("{other:?}"),
    }
    vault_unlock_wire(&mut state, 3, &session_id, &binding, &master);
    let status = handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 4,
            body: ControlRequest::VaultStatus {
                session_id: session_id.clone(),
            },
        },
        &limits(),
    "conn-test",
    )
    .unwrap();
    match expect_ok_control(status).unwrap() {
        ControlResponse::VaultStatus { state: st } => assert_eq!(st, VaultStateWire::Unlocked),
        other => panic!("{other:?}"),
    }
}

#[test]
fn readonly_identity_still_needs_vault_unlock() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let id = state.auth.create_identity("readonly", "pw").unwrap();
    state.auth.grants_mut().grant(id, Resource::database("avrora"), Action::Connect);
    let resp = handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 1,
            body: ControlRequest::Authenticate {
                identity_name: "readonly".into(),
                password: "pw".into(),
            },
        },
        &limits(),
    "conn-test",
    )
    .unwrap();
    let session_id = match expect_ok_control(resp).unwrap() {
        ControlResponse::Authenticate { session_id, .. } => session_id,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        execute_sql(&mut state, 2, &session_id, "SELECT 1").error_code,
        Some(ProtocolErrorCode::VaultLocked)
    );
}
