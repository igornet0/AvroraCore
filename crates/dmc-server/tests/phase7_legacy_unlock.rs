//! Phase 7.6.4 — Legacy master_key_hex migration gate.

use dmc_protocol::{
    decode_payload, encode_payload, sanitize_client_message, ControlRequest, ProtocolErrorCode,
    ProtocolLimits, RemoteLimits, RequestEnvelope, ResponseStatus, VaultStateWire,
};
use dmc_server::{
    bootstrap_core_state_locked, create_unlock_blob, expect_ok_control, expect_ok_data,
    handle_control, handle_data, MockKeyPassProvider, VaultState,
};
use tempfile::tempdir;

fn limits() -> RemoteLimits {
    RemoteLimits::default()
}

#[test]
fn vault_unlock_wire_has_no_master_key_hex_field() {
    let blob = dmc_server::seal_unlock_blob("s", &[1u8; 32], &dmc_server::UnlockMaterial([2u8; 32]))
        .unwrap();
    let req = ControlRequest::VaultUnlock {
        session_id: "s".into(),
        blob,
    };
    let bytes = encode_payload(&req, &ProtocolLimits::default()).unwrap();
    let text = format!("{bytes:?}");
    assert!(
        !text.to_lowercase().contains("master_key"),
        "VaultUnlock payload must not carry master_key fields"
    );
    let decoded: ControlRequest = decode_payload(&bytes).unwrap();
    match decoded {
        ControlRequest::VaultUnlock { session_id, blob } => {
            assert_eq!(session_id, "s");
            assert!(!blob.ciphertext.is_empty());
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn sanitize_strips_key_material_hints() {
    assert_eq!(
        sanitize_client_message("master_key_hex leaked".into()),
        "request rejected"
    );
    assert_eq!(
        sanitize_client_message("UnlockMaterial present".into()),
        "request rejected"
    );
    assert_eq!(
        sanitize_client_message("DEK unwrap failed".into()),
        "request rejected"
    );
    assert_eq!(
        sanitize_client_message("LegacyUnlockDisabled".into()),
        "LegacyUnlockDisabled"
    );
}

#[test]
fn migration_gate_unlockblob_then_lock() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    assert_eq!(state.vault_state(), VaultState::Locked);
    assert!(!state.root_dek_present());

    let auth = handle_control(
        &mut state,
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
    let (session_id, binding) = match expect_ok_control(auth).unwrap() {
        dmc_protocol::ControlResponse::Authenticate {
            session_id,
            unlock_binding_key,
            ..
        } => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&unlock_binding_key);
            (session_id, key)
        }
        other => panic!("{other:?}"),
    };

    let provider = MockKeyPassProvider::with_material(master.clone());
    let blob = create_unlock_blob(&session_id, &binding, &provider).unwrap();
    let unlock = handle_control(
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
    assert_eq!(unlock.status, ResponseStatus::Ok);
    assert_eq!(state.vault_state(), VaultState::Unlocked);
    assert!(state.root_dek_present());

    assert_eq!(
        handle_data(
            &mut state,
            RequestEnvelope {
                request_id: 3,
                body: dmc_protocol::DataRequest::ExecuteSql {
                    session_id: session_id.clone(),
                    sql: "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)".into(),
                    params: Vec::new(),
                },
            },
            &limits(),
        "conn-test",
        )
        .unwrap()
        .status,
        ResponseStatus::Ok
    );

    let lock = handle_control(
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
    match expect_ok_control(lock).unwrap() {
        dmc_protocol::ControlResponse::VaultLock { state: st } => {
            assert_eq!(st, VaultStateWire::Locked)
        }
        other => panic!("{other:?}"),
    }
    assert!(!state.root_dek_present());
    assert_eq!(
        handle_data(
            &mut state,
            RequestEnvelope {
                request_id: 5,
                body: dmc_protocol::DataRequest::ExecuteSql {
                    session_id: session_id.clone(),
                    sql: "SELECT id FROM items WHERE id = 1".into(),
                    params: Vec::new(),
                },
            },
            &limits(),
        "conn-test",
        )
        .unwrap()
        .error_code,
        Some(ProtocolErrorCode::VaultLocked)
    );

    // After restart: still Locked; UnlockBlob path recovers.
    state.simulate_restart();
    assert_eq!(state.vault_state(), VaultState::Locked);
    assert!(!state.root_dek_present());

    let auth2 = handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 6,
            body: ControlRequest::Authenticate {
                identity_name: "analyst".into(),
                password: "pw".into(),
            },
        },
        &limits(),
    "conn-test",
    )
    .unwrap();
    let (session2, binding2) = match expect_ok_control(auth2).unwrap() {
        dmc_protocol::ControlResponse::Authenticate {
            session_id,
            unlock_binding_key,
            ..
        } => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&unlock_binding_key);
            (session_id, key)
        }
        other => panic!("{other:?}"),
    };
    let blob2 = create_unlock_blob(
        &session2,
        &binding2,
        &MockKeyPassProvider::with_material(master),
    )
    .unwrap();
    assert_eq!(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 7,
                body: ControlRequest::VaultUnlock {
                    session_id: session2.clone(),
                    blob: blob2,
                },
            },
            &limits(),
        "conn-test",
        )
        .unwrap()
        .status,
        ResponseStatus::Ok
    );
    let select = handle_data(
        &mut state,
        RequestEnvelope {
            request_id: 8,
            body: dmc_protocol::DataRequest::ExecuteSql {
                session_id: session2,
                sql: "SELECT id FROM items WHERE id = 1".into(),
                params: Vec::new(),
            },
        },
        &limits(),
    "conn-test",
    )
    .unwrap();
    expect_ok_data(select).unwrap();
}

#[test]
fn legacy_unlock_disabled_error_code_exists_for_audit() {
    assert_eq!(
        ProtocolErrorCode::LegacyUnlockDisabled.as_str(),
        "LegacyUnlockDisabled"
    );
    assert_eq!(ProtocolErrorCode::LegacyUnlockDisabled as u16, 27);
}
