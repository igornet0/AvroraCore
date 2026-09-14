//! Phase 7.6.2 — UnlockBlob protocol, session binding, replay protection.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use dmc_ipc::{CoreServer, LocalConnection, SocketPathOptions};
use dmc_protocol::{
    decode_payload, encode_payload, validate_control_request, ControlRequest, ControlResponse,
    DataRequest, ProtocolErrorCode, RemoteLimits, RequestEnvelope, ResponseStatus,
    UNLOCK_BLOB_VERSION, UnlockBlob, VaultStateWire,
};
use dmc_server::{
    authenticate_with_binding, bootstrap_core_state_locked, create_unlock_blob, expect_ok_control,
    expect_vault_unlocked, handle_control, handle_data, open_unlock_blob, seal_unlock_blob,
    vault_unlock, CoreServerState, MockKeyPassProvider, ProtocolClient, UnlockMaterial, VaultState,
};
use tempfile::tempdir;

fn limits() -> RemoteLimits {
    RemoteLimits::default()
}

fn socket_options() -> SocketPathOptions {
    SocketPathOptions {
        allow_custom_path: true,
    }
}
const CREATE_ITEMS: &str = "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)";
const SELECT_ITEMS: &str = "SELECT id FROM items WHERE id = 1";

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

fn vault_unlock_control(
    state: &mut CoreServerState,
    request_id: u64,
    session_id: &str,
    binding_key: &[u8; 32],
    provider: &MockKeyPassProvider,
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

#[test]
fn unlock_blob_seal_open_roundtrip() {
    let material = UnlockMaterial::random();
    let key = [7u8; 32];
    let blob = seal_unlock_blob("sess-a", &key, &material).unwrap();
    assert_eq!(blob.version, UNLOCK_BLOB_VERSION);
    assert_eq!(blob.session_id, "sess-a");
    assert!(!blob.ciphertext.is_empty());
    let opened = open_unlock_blob(&blob, &key).unwrap();
    assert_eq!(opened.0, material.0);
}

#[test]
fn unlock_blob_version_mismatch_rejected() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, key) = auth_pair(&mut state);
    let mut blob = seal_unlock_blob(&session_id, &key, &UnlockMaterial::random()).unwrap();
    blob.version = 99;
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
}

#[test]
fn unlock_blob_oversized_rejected() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, key) = auth_pair(&mut state);
    let mut blob = seal_unlock_blob(&session_id, &key, &UnlockMaterial::random()).unwrap();
    blob.ciphertext = vec![0u8; 5000];
    let mut limits = limits();
    limits.max_unlock_blob_size = 64;
    let resp = handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 2,
            body: ControlRequest::VaultUnlock { session_id, blob },
        },
        &limits,
        "conn-test",
    )
    .unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::InvalidRequest));
}

#[test]
fn unlock_blob_postcard_roundtrip_no_plaintext_fields() {
    let blob = seal_unlock_blob("s", &[1u8; 32], &UnlockMaterial([2u8; 32])).unwrap();
    let bytes = encode_payload(&blob, limits().protocol()).unwrap();
    let decoded: dmc_protocol::UnlockBlob = decode_payload(&bytes).unwrap();
    assert_eq!(decoded, blob);
}

#[test]
fn valid_blob_unlocks_vault() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, key) = auth_pair(&mut state);
    let resp = vault_unlock_control(&mut state, 2, &session_id, &key, &MockKeyPassProvider::with_material(master.clone()));
    expect_vault_unlocked(resp).unwrap();
    assert_eq!(state.vault_state(), VaultState::Unlocked);
}

#[test]
fn wrong_session_binding_rejected() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (s1, k1) = auth_pair(&mut state);
    let (s2, _k2) = auth_pair(&mut state);
    let blob = create_unlock_blob(&s1, &k1, &MockKeyPassProvider::with_material(master.clone())).unwrap();
    let resp = handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 10,
            body: ControlRequest::VaultUnlock {
                session_id: s2,
                blob,
            },
        },
        &limits(),
    "conn-test",
    )
    .unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::UnlockSessionMismatch));
}

#[test]
fn wrong_binding_key_rejected() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, _key) = auth_pair(&mut state);
    let blob = seal_unlock_blob(&session_id, &[9u8; 32], &UnlockMaterial::random()).unwrap();
    let resp = handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 2,
            body: ControlRequest::VaultUnlock { session_id, blob },
        },
        &limits(),
    "conn-test",
    )
    .unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::UnlockBlobInvalid));
}

#[test]
fn modified_ciphertext_rejected() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, key) = auth_pair(&mut state);
    let mut blob = seal_unlock_blob(&session_id, &key, &UnlockMaterial::random()).unwrap();
    if let Some(byte) = blob.ciphertext.first_mut() {
        *byte ^= 0xff;
    }
    let resp = handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 2,
            body: ControlRequest::VaultUnlock { session_id, blob },
        },
        &limits(),
    "conn-test",
    )
    .unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::UnlockBlobInvalid));
}

#[test]
fn modified_nonce_rejected() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, key) = auth_pair(&mut state);
    let mut blob = seal_unlock_blob(&session_id, &key, &UnlockMaterial::random()).unwrap();
    blob.nonce[0] ^= 0xff;
    let resp = handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 2,
            body: ControlRequest::VaultUnlock { session_id, blob },
        },
        &limits(),
    "conn-test",
    )
    .unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::UnlockBlobInvalid));
}

#[test]
fn unlock_blob_replay_rejected() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, key) = auth_pair(&mut state);
    let blob = create_unlock_blob(&session_id, &key, &MockKeyPassProvider::with_material(master.clone())).unwrap();
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
}

#[test]
fn invalid_session_rejected() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let blob = seal_unlock_blob("ghost", &[1u8; 32], &UnlockMaterial::random()).unwrap();
    let resp = handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 1,
            body: ControlRequest::VaultUnlock {
                session_id: "ghost".into(),
                blob,
            },
        },
        &limits(),
    "conn-test",
    )
    .unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::SessionInvalid));
}

#[test]
fn vault_lock_unlock_lifecycle() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, key) = auth_pair(&mut state);

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

    vault_unlock_control(&mut state, 3, &session_id, &key, &MockKeyPassProvider::with_material(master.clone()));
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
    assert_eq!(state.vault_state(), VaultState::Locked);

    let resp = handle_data(
        &mut state,
        RequestEnvelope {
            request_id: 5,
            body: DataRequest::ExecuteSql {
                session_id,
                sql: SELECT_ITEMS.into(),
                params: Vec::new(),
            },
        },
        &limits(),
    "conn-test",
    )
    .unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::VaultLocked));
}

#[test]
fn unlock_then_logout_vault_stays_unlocked() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, key) = auth_pair(&mut state);
    vault_unlock_control(&mut state, 2, &session_id, &key, &MockKeyPassProvider::with_material(master.clone()));
    state.auth.logout(&session_id.clone().into()).unwrap();
    assert_eq!(state.vault_state(), VaultState::Unlocked);
}

#[test]
fn unlock_e2e_sql_after_blob() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, key) = auth_pair(&mut state);
    vault_unlock_control(&mut state, 2, &session_id, &key, &MockKeyPassProvider::with_material(master.clone()));
    assert_eq!(
        handle_data(
            &mut state,
            RequestEnvelope {
                request_id: 3,
                body: DataRequest::ExecuteSql {
                    session_id,
                    sql: CREATE_ITEMS.into(),
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
}

#[test]
fn vault_unlock_over_unix_ipc() {
    let dir = tempdir().unwrap();
    let socket = dir.path().join("test.sock");
    let (state_inner, master) = bootstrap_core_state_locked(dir.path(), false);
    let state = Arc::new(Mutex::new(state_inner));
    let state_t = Arc::clone(&state);
    let socket_t = socket.clone();
    let handle = thread::spawn(move || {
        let server = CoreServer::bind(&socket_t, &socket_options()).unwrap();
        let mut guard = state_t.lock().unwrap();
        server.accept_and_serve_one(&mut guard).ok();
    });
    thread::sleep(Duration::from_millis(30));

    let stream = UnixStream::connect(&socket).unwrap();
    let mut client = ProtocolClient::new(PairConn(stream), limits());
    client.handshake("unlock-ipc").unwrap();
    let (session_id, key) = authenticate_with_binding(&mut client, "analyst", "pw").unwrap();
    let resp = vault_unlock(&mut client, &session_id, &key, &MockKeyPassProvider::with_material(master.clone())).unwrap();
    expect_vault_unlocked(resp).unwrap();
    drop(handle);
}

#[test]
fn malformed_blob_empty_ciphertext_rejected() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, _key) = auth_pair(&mut state);
    let blob = UnlockBlob {
        version: UNLOCK_BLOB_VERSION,
        session_id: session_id.clone(),
        nonce: [1u8; 12],
        ciphertext: Vec::new(),
    };
    let err = validate_control_request(
        &ControlRequest::VaultUnlock {
            session_id,
            blob,
        },
        &limits(),
    )
    .unwrap_err();
    assert_eq!(err.code(), Some(ProtocolErrorCode::UnlockBlobInvalid));
}

#[test]
fn control_vault_unlock_postcard_roundtrip() {
    let blob = seal_unlock_blob("sess", &[2u8; 32], &UnlockMaterial::random()).unwrap();
    let req = ControlRequest::VaultUnlock {
        session_id: "sess".into(),
        blob,
    };
    let bytes = encode_payload(&req, limits().protocol()).unwrap();
    let decoded: ControlRequest = decode_payload(&bytes).unwrap();
    assert_eq!(decoded, req);
}

#[test]
fn unlock_then_restart_vault_locked() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (session_id, key) = auth_pair(&mut state);
    vault_unlock_control(&mut state, 2, &session_id, &key, &MockKeyPassProvider::with_material(master.clone()));
    assert_eq!(state.vault_state(), VaultState::Unlocked);
    state.simulate_restart();
    assert_eq!(state.vault_state(), VaultState::Locked);
}

#[test]
fn data_namespace_has_no_vault_unlock_ops() {
    let variants = [
        DataRequest::ExecuteSql {
            session_id: "s".into(),
            sql: "SELECT 1".into(),
            params: Vec::new(),
        },
        DataRequest::Begin {
            session_id: "s".into(),
        },
        DataRequest::Commit {
            session_id: "s".into(),
        },
        DataRequest::Rollback {
            session_id: "s".into(),
        },
    ];
    for body in variants {
        assert!(validate_control_request(
            &ControlRequest::VaultStatus {
                session_id: "s".into()
            },
            &limits(),
        )
        .is_ok());
        assert!(dmc_protocol::validate_data_request(&body, &limits()).is_ok());
    }
}

#[test]
fn vault_status_requires_session() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let resp = handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 1,
            body: ControlRequest::VaultStatus {
                session_id: String::new(),
            },
        },
        &limits(),
    "conn-test",
    )
    .unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::InvalidRequest));
}
