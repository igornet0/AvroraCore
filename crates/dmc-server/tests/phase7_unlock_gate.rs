//! Phase 7.6.1 — UnlockGate + SecurityState (auth ≠ vault unlock).

use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, ProtocolErrorCode, RemoteLimits, RequestEnvelope,
    ResponseStatus,
};
use dmc_security::auth::SessionManager;
use dmc_server::{
    bootstrap_core_state_locked, expect_ok_control, expect_ok_data, handle_control, handle_data,
    CoreServerState, UnlockMaterial, VaultState,
};
use tempfile::tempdir;

fn limits() -> RemoteLimits {
    RemoteLimits::default()
}

fn authenticate(state: &mut CoreServerState) -> String {
    let resp = handle_control(
        state,
        RequestEnvelope {
            request_id: 1,
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
        ControlResponse::Authenticate { session_id, .. } => session_id,
        other => panic!("expected authenticate, got {other:?}"),
    }
}

fn execute_sql(
    state: &mut CoreServerState,
    request_id: u64,
    session_id: &str,
    sql: &str,
) -> dmc_protocol::ResponseEnvelope<dmc_protocol::DataResponse> {
    handle_data(
        state,
        RequestEnvelope {
            request_id,
            body: DataRequest::ExecuteSql {
                session_id: session_id.into(),
                sql: sql.into(),
                params: Vec::new(),
            },
        },
        &RemoteLimits::default(),
        "conn-test",
    )
    .unwrap()
}

fn unlock(state: &mut CoreServerState, master: &UnlockMaterial) {
    state.apply_vault_unlock(master).unwrap();
}

const CREATE_ITEMS: &str = "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)";
const SELECT_ITEMS: &str = "SELECT id FROM items WHERE id = 1";

#[test]
fn sql_while_locked_returns_vault_locked() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    assert_eq!(state.vault_state(), VaultState::Locked);
    assert!(!state.root_dek_present());

    let session_id = authenticate(&mut state);
    let sec = state.security_state(&session_id);
    assert!(sec.authenticated);
    assert!(!sec.vault_unlocked);

    let resp = execute_sql(&mut state, 2, &session_id, CREATE_ITEMS);
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::VaultLocked));
}

#[test]
fn unlock_allows_sql_then_lock_denies_again() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let session_id = authenticate(&mut state);

    assert_eq!(
        execute_sql(&mut state, 2, &session_id, CREATE_ITEMS).error_code,
        Some(ProtocolErrorCode::VaultLocked)
    );

    unlock(&mut state, &master);
    assert_eq!(state.vault_state(), VaultState::Unlocked);
    assert!(state.root_dek_present());

    assert_eq!(
        execute_sql(&mut state, 3, &session_id, CREATE_ITEMS).status,
        ResponseStatus::Ok
    );
    assert_eq!(
        execute_sql(
            &mut state,
            4,
            &session_id,
            "INSERT INTO items (id, name) VALUES (1, 'a')",
        )
        .status,
        ResponseStatus::Ok
    );
    let select = execute_sql(&mut state, 5, &session_id, SELECT_ITEMS);
    let body = expect_ok_data(select).unwrap();
    match body {
        dmc_protocol::DataResponse::SqlResult(result) => assert_eq!(result.rows.len(), 1),
        other => panic!("unexpected {other:?}"),
    }

    state.lock_vault();
    assert!(!state.root_dek_present());
    let session_ok = state.auth.validate_session(&session_id.clone().into());
    assert!(session_ok.is_ok());
    assert_eq!(
        execute_sql(&mut state, 6, &session_id, SELECT_ITEMS).error_code,
        Some(ProtocolErrorCode::VaultLocked)
    );
}

#[test]
fn logout_does_not_lock_vault() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let session_id = authenticate(&mut state);
    unlock(&mut state, &master);
    assert_eq!(
        execute_sql(&mut state, 2, &session_id, CREATE_ITEMS).status,
        ResponseStatus::Ok
    );

    state
        .auth
        .logout(&session_id.clone().into())
        .expect("logout");
    assert_eq!(state.vault_state(), VaultState::Unlocked);
    assert!(state.root_dek_present());

    let resp = execute_sql(&mut state, 3, &session_id, SELECT_ITEMS);
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::SessionInvalid));
    assert_eq!(state.vault_state(), VaultState::Unlocked);
}

#[test]
fn lock_does_not_logout() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let session_id = authenticate(&mut state);
    unlock(&mut state, &master);
    state.lock_vault();

    let info = handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 10,
            body: ControlRequest::SessionInfo {
                session_id: session_id.clone(),
            },
        },
        &limits(),
    "conn-test",
    )
    .unwrap();
    assert_eq!(info.status, ResponseStatus::Ok);
    match expect_ok_control(info).unwrap() {
        ControlResponse::SessionInfo { active, .. } => assert!(active),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn restart_locks_vault_and_invalidates_session() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let session_id = authenticate(&mut state);
    unlock(&mut state, &master);
    assert_eq!(
        execute_sql(&mut state, 2, &session_id, CREATE_ITEMS).status,
        ResponseStatus::Ok
    );

    state.simulate_restart();
    assert_eq!(state.vault_state(), VaultState::Locked);
    assert!(!state.root_dek_present());
    assert!(state.auth.validate_session(&session_id.clone().into()).is_err());

    let resp = execute_sql(&mut state, 3, &session_id, SELECT_ITEMS);
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::SessionInvalid));
}

#[test]
fn unlocked_without_auth_denied() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    unlock(&mut state, &master);

    let resp = execute_sql(&mut state, 1, "no-such-session", SELECT_ITEMS);
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::SessionInvalid));
}

#[test]
fn security_state_axes_independent() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let session_id = authenticate(&mut state);

    let locked_auth = state.security_state(&session_id);
    assert!(locked_auth.authenticated);
    assert!(!locked_auth.vault_unlocked);
    assert!(!locked_auth.sql_allowed_axes());

    unlock(&mut state, &master);
    let both = state.security_state(&session_id);
    assert!(both.authenticated);
    assert!(both.vault_unlocked);
    assert!(both.sql_allowed_axes());

    state.auth.logout(&session_id.clone().into()).unwrap();
    let unlocked_no_auth = state.security_state(&session_id);
    assert!(!unlocked_no_auth.authenticated);
    assert!(unlocked_no_auth.vault_unlocked);
    assert!(!unlocked_no_auth.sql_allowed_axes());
}
