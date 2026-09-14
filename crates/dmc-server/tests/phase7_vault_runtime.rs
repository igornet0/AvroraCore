//! Phase 7.6.3 — KeyPass + dmc-vault runtime integration lifecycle.

use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, ProtocolErrorCode, RemoteLimits, RequestEnvelope,
    ResponseStatus, VaultStateWire,
};
use dmc_security::auth::SessionManager;
use dmc_server::{
    bootstrap_core_state_locked, create_unlock_blob, expect_ok_control, expect_ok_data,
    handle_control, handle_data, CoreServerState, KeyPassProvider, MockKeyPassProvider,
    PasswordKeyPassProvider, UnlockMaterial, VaultState,
};
use tempfile::tempdir;

fn limits() -> RemoteLimits {
    RemoteLimits::default()
}

fn auth_pair(state: &mut CoreServerState) -> (String, [u8; 32]) {
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
        other => panic!("unexpected {other:?}"),
    }
}

fn vault_unlock(
    state: &mut CoreServerState,
    request_id: u64,
    session_id: &str,
    binding_key: &[u8; 32],
    provider: &dyn dmc_server::KeyPassProvider,
) -> dmc_protocol::ResponseEnvelope<ControlResponse> {
    let blob = create_unlock_blob(session_id, binding_key, provider).unwrap();
    handle_control(
        state,
        RequestEnvelope {
            request_id,
            body: ControlRequest::VaultUnlock {
                session_id: session_id.into(),
                blob,
            },
        },
        &limits(),
    "conn-test",
    )
    .unwrap()
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
        &limits(),
    "conn-test",
    )
    .unwrap()
}

const CREATE: &str = "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)";
const INSERT: &str = "INSERT INTO items (id, name) VALUES (1, 'a')";
const SELECT: &str = "SELECT id FROM items WHERE id = 1";

#[test]
fn full_keypass_vault_lifecycle() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    assert_eq!(state.vault_state(), VaultState::Locked);
    assert!(!state.root_dek_present());

    let (session_id, binding) = auth_pair(&mut state);
    let provider = PasswordKeyPassProvider::wrap_master(&master, "test-pass-ok", "db-test").unwrap();

    let unlock = vault_unlock(&mut state, 2, &session_id, &binding, &provider);
    assert_eq!(unlock.status, ResponseStatus::Ok);
    assert_eq!(state.vault_state(), VaultState::Unlocked);
    assert!(state.root_dek_present());

    assert_eq!(execute_sql(&mut state, 3, &session_id, CREATE).status, ResponseStatus::Ok);
    assert_eq!(execute_sql(&mut state, 4, &session_id, INSERT).status, ResponseStatus::Ok);
    let select = execute_sql(&mut state, 5, &session_id, SELECT);
    match expect_ok_data(select).unwrap() {
        dmc_protocol::DataResponse::SqlResult(r) => assert_eq!(r.rows.len(), 1),
        other => panic!("{other:?}"),
    }

    let lock = handle_control(
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
    match expect_ok_control(lock).unwrap() {
        ControlResponse::VaultLock { state: st } => assert_eq!(st, VaultStateWire::Locked),
        other => panic!("{other:?}"),
    }
    assert!(!state.root_dek_present());
    assert!(state.auth.validate_session(&session_id.clone().into()).is_ok());
    assert_eq!(
        execute_sql(&mut state, 7, &session_id, SELECT).error_code,
        Some(ProtocolErrorCode::VaultLocked)
    );

    let unlock2 = vault_unlock(&mut state, 8, &session_id, &binding, &provider);
    assert_eq!(unlock2.status, ResponseStatus::Ok);
    assert!(state.root_dek_present());
    assert_eq!(execute_sql(&mut state, 9, &session_id, SELECT).status, ResponseStatus::Ok);

    state.auth.logout(&session_id.clone().into()).unwrap();
    assert_eq!(state.vault_state(), VaultState::Unlocked);
    assert!(state.root_dek_present());

    state.simulate_restart();
    assert_eq!(state.vault_state(), VaultState::Locked);
    assert!(!state.root_dek_present());
    assert!(state.auth.validate_session(&session_id.clone().into()).is_err());
}

#[test]
fn wrong_keypass_keeps_vault_locked() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, binding) = auth_pair(&mut state);

    let wrong = MockKeyPassProvider::with_material(UnlockMaterial::random());
    let resp = vault_unlock(&mut state, 2, &session_id, &binding, &wrong);
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::UnlockFailed));
    assert_eq!(state.vault_state(), VaultState::Locked);
    assert!(!state.root_dek_present());

    // Correct material still works after failed attempt (nonce not burned on failure).
    let ok = vault_unlock(
        &mut state,
        3,
        &session_id,
        &binding,
        &MockKeyPassProvider::with_material(master),
    );
    assert_eq!(ok.status, ResponseStatus::Ok);
    assert!(state.root_dek_present());
}

#[test]
fn wrong_password_keypass_provider_fails_client_side() {
    let dir = tempdir().unwrap();
    let (_state, master) = bootstrap_core_state_locked(dir.path(), false);
    let bundle = dmc_vault::keypass::wrap(
        &dmc_vault::KeyMaterial::from_bytes(master.0),
        "correct-password",
        "db-1",
    )
    .unwrap();
    let bad = PasswordKeyPassProvider::new(bundle, "wrong-password");
    assert!(matches!(
        bad.unlock(),
        Err(dmc_server::KeyPassError::UnlockFailed)
    ));
}

#[test]
fn startup_invariant_locked_no_secrets() {
    let dir = tempdir().unwrap();
    let (state, _master) = bootstrap_core_state_locked(dir.path(), false);
    assert_eq!(state.vault_state(), VaultState::Locked);
    assert!(!state.root_dek_present());
}

#[test]
fn unlock_idempotent_when_already_unlocked() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, binding) = auth_pair(&mut state);
    let provider = MockKeyPassProvider::with_material(master.clone());
    assert_eq!(
        vault_unlock(&mut state, 2, &session_id, &binding, &provider).status,
        ResponseStatus::Ok
    );
    // Second blob (new nonce) while unlocked is ok / idempotent.
    let provider2 = MockKeyPassProvider::with_material(master);
    assert_eq!(
        vault_unlock(&mut state, 3, &session_id, &binding, &provider2).status,
        ResponseStatus::Ok
    );
    assert!(state.root_dek_present());
}
