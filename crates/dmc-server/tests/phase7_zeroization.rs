//! Phase 7.6.6 — Zeroization audit: secrets wiped after lock / failed unlock.

use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, ProtocolErrorCode, RemoteLimits, RequestEnvelope,
    ResponseStatus,
};
use dmc_security::auth::SessionManager;
use dmc_server::{
    bootstrap_core_state_locked, create_unlock_blob, expect_ok_control, handle_control, handle_data,
    open_unlock_blob, seal_unlock_blob, MockKeyPassProvider, UnlockGate, UnlockMaterial, VaultState,
};
use tempfile::tempdir;

fn limits() -> RemoteLimits {
    RemoteLimits::default()
}

fn auth_pair(state: &mut dmc_server::CoreServerState) -> (String, [u8; 32]) {
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
        other => panic!("{other:?}"),
    }
}

fn unlock(
    state: &mut dmc_server::CoreServerState,
    req: u64,
    session_id: &str,
    binding: &[u8; 32],
    master: &UnlockMaterial,
) {
    let blob = create_unlock_blob(session_id, binding, &MockKeyPassProvider::with_material(master.clone()))
        .unwrap();
    let resp = handle_control(
        state,
        RequestEnvelope {
            request_id: req,
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

#[test]
fn unlock_material_debug_is_redacted() {
    let m = UnlockMaterial([0xab; 32]);
    let dbg = format!("{m:?}");
    assert_eq!(dbg, "UnlockMaterial([REDACTED])");
    assert!(!dbg.contains("ab"));
    assert!(!dbg.contains("171"));
}

#[test]
fn unlock_gate_debug_has_no_key_bytes() {
    let (gate, master) = UnlockGate::create_locked().unwrap();
    let dbg = format!("{gate:?}");
    assert!(dbg.contains("Locked"));
    assert!(!dbg.contains("KeyTree"));
    let dbg_master = format!("{master:?}");
    assert_eq!(dbg_master, "UnlockMaterial([REDACTED])");
    assert!(!dbg_master.chars().any(|c| c.is_ascii_digit()));
}

#[test]
fn unlock_blob_debug_omits_ciphertext_bytes() {
    let blob = seal_unlock_blob("s", &[1u8; 32], &UnlockMaterial([9u8; 32])).unwrap();
    let dbg = format!("{blob:?}");
    assert!(dbg.contains("ciphertext_len"));
    assert!(!dbg.contains("ciphertext: ["));
    assert!(dbg.contains("nonce_len"));
}

#[test]
fn vault_lock_wipes_root_dek() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, binding) = auth_pair(&mut state);
    unlock(&mut state, 2, &session_id, &binding, &master);
    assert!(state.root_dek_present());
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
    assert_eq!(state.vault_state(), VaultState::Locked);
    assert!(!state.root_dek_present());
}

#[test]
fn wrong_unlock_leaves_vault_locked_no_dek() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, binding) = auth_pair(&mut state);
    let wrong = UnlockMaterial::random();
    let blob = create_unlock_blob(&session_id, &binding, &MockKeyPassProvider::with_material(wrong))
        .unwrap();
    let resp = handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 2,
            body: ControlRequest::VaultUnlock {
                session_id: session_id.clone(),
                blob,
            },
        },
        &limits(),
    "conn-test",
    )
    .unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::UnlockFailed));
    assert_eq!(state.vault_state(), VaultState::Locked);
    assert!(!state.root_dek_present());
    let msg = resp.error_message.unwrap_or_default().to_lowercase();
    assert!(!msg.contains("master"));
    assert!(!msg.contains("dek"));
    assert!(!msg.contains("key"));
}

#[test]
fn tampered_blob_error_sanitized_vault_locked() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, binding) = auth_pair(&mut state);
    let mut blob = seal_unlock_blob(&session_id, &binding, &master).unwrap();
    if let Some(b) = blob.ciphertext.first_mut() {
        *b ^= 0xff;
    }
    let resp = handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 2,
            body: ControlRequest::VaultUnlock {
                session_id: session_id.clone(),
                blob,
            },
        },
        &limits(),
    "conn-test",
    )
    .unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::UnlockBlobInvalid));
    assert!(!state.root_dek_present());
    let msg = resp.error_message.unwrap_or_default();
    assert!(!msg.contains('/'));
    assert!(!msg.to_lowercase().contains("ciphertext"));
}

#[test]
fn replay_error_sanitized() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, binding) = auth_pair(&mut state);
    let blob = create_unlock_blob(&session_id, &binding, &MockKeyPassProvider::with_material(master))
        .unwrap();
    assert_eq!(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 2,
                body: ControlRequest::VaultUnlock {
                    session_id: session_id.clone(),
                    blob: blob.clone(),
                },
            },
            &limits(),
        "conn-test",
        )
        .unwrap()
        .status,
        ResponseStatus::Ok
    );
    let replay = handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 3,
            body: ControlRequest::VaultUnlock { session_id, blob },
        },
        &limits(),
    "conn-test",
    )
    .unwrap();
    assert_eq!(replay.error_code, Some(ProtocolErrorCode::UnlockBlobReplay));
    assert_eq!(replay.error_message.as_deref(), Some("unlock blob replay"));
}

#[test]
fn restart_wipes_secrets_and_sessions() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, binding) = auth_pair(&mut state);
    unlock(&mut state, 2, &session_id, &binding, &master);
    assert!(state.root_dek_present());
    state.simulate_restart();
    assert!(!state.root_dek_present());
    assert_eq!(state.vault_state(), VaultState::Locked);
    assert!(state.auth.validate_session(&session_id.into()).is_err());
}

#[test]
fn open_unlock_blob_roundtrip_then_material_debug_safe() {
    let material = UnlockMaterial([7u8; 32]);
    let key = [3u8; 32];
    let blob = seal_unlock_blob("sess", &key, &material).unwrap();
    let opened = open_unlock_blob(&blob, &key).unwrap();
    assert_eq!(opened.0, material.0);
    assert_eq!(format!("{opened:?}"), "UnlockMaterial([REDACTED])");
}

#[test]
fn explicit_wipe_clears_material_bytes() {
    let mut m = UnlockMaterial([0x42; 32]);
    m.wipe();
    assert_eq!(m.0, [0u8; 32]);
}

#[test]
fn sql_after_lock_vault_locked_no_secret_in_error() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, binding) = auth_pair(&mut state);
    unlock(&mut state, 2, &session_id, &binding, &master);
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
    let resp = handle_data(
        &mut state,
        RequestEnvelope {
            request_id: 4,
            body: DataRequest::ExecuteSql {
                session_id,
                sql: "SELECT 1".into(),
                params: Vec::new(),
            },
        },
        &limits(),
    "conn-test",
    )
    .unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::VaultLocked));
    let msg = resp.error_message.unwrap_or_default().to_lowercase();
    assert!(!msg.contains("dek"));
    assert!(!msg.contains("master"));
    assert!(!msg.contains('/'));
}

#[test]
fn logout_does_not_wipe_vault_secrets() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, binding) = auth_pair(&mut state);
    unlock(&mut state, 2, &session_id, &binding, &master);
    state.auth.logout(&session_id.into()).unwrap();
    assert!(state.root_dek_present());
    assert_eq!(state.vault_state(), VaultState::Unlocked);
}
