//! Phase 7.8.7 — Control Plane backup/restore/recover adapter over dmc-backup.

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

fn control(
    state: &mut CoreServerState,
    req_id: u64,
    body: ControlRequest,
) -> dmc_protocol::ResponseEnvelope<ControlResponse> {
    handle_control(
        state,
        RequestEnvelope {
            request_id: req_id,
            body,
        },
        &limits(),
    "conn-test",
    )
    .unwrap()
}

/// D4-F: the bootstrap opens SQL storage only on `VaultUnlock` (as production does), so
/// backups — sealed with the storage keys — need an unlocked vault.
fn unlocked(root: &std::path::Path) -> (CoreServerState, String) {
    let (mut state, master) = bootstrap_core_state_locked(root, true);
    let (sid, binding) = auth_pair(&mut state);
    let blob = create_unlock_blob(&sid, &binding, &MockKeyPassProvider::with_material(master))
        .unwrap();
    expect_ok_control(control(
        &mut state,
        1,
        ControlRequest::VaultUnlock {
            session_id: sid.clone(),
            blob,
        },
    ))
    .unwrap();
    (state, sid)
}

#[test]
fn backup_needs_an_unlocked_vault() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), true);
    let (sid, _) = auth_pair(&mut state);
    let resp = control(
        &mut state,
        2,
        ControlRequest::BackupCreate {
            session_id: sid,
            backup_id: "locked".into(),
            include_rowstore: false,
        },
    );
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::VaultLocked));
    assert!(!dir.path().join("backups/backup-locked").exists());
}

#[test]
fn create_then_verify_and_list() {
    let dir = tempdir().unwrap();
    let (mut state, sid) = unlocked(dir.path());

    let created = expect_ok_control(control(
        &mut state,
        2,
        ControlRequest::BackupCreate {
            session_id: sid.clone(),
            backup_id: "cp1".into(),
            include_rowstore: false,
        },
    ))
    .unwrap();
    let ControlResponse::BackupCreate {
        backup_id,
        checkpoint_sequence,
        ..
    } = created
    else {
        panic!("create");
    };
    assert_eq!(backup_id, "cp1");
    assert!(checkpoint_sequence > 0);

    let verified = expect_ok_control(control(
        &mut state,
        3,
        ControlRequest::BackupVerify {
            session_id: sid.clone(),
            backup_id: "cp1".into(),
        },
    ))
    .unwrap();
    let ControlResponse::BackupVerify { valid, .. } = verified else {
        panic!("verify");
    };
    assert!(valid);

    let listed = expect_ok_control(control(
        &mut state,
        4,
        ControlRequest::BackupList {
            session_id: sid.clone(),
        },
    ))
    .unwrap();
    let ControlResponse::BackupList { items } = listed else {
        panic!("list");
    };
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].backup_id, "cp1");
    assert!(items[0].valid);
    assert_eq!(items[0].state, "published");
}

#[test]
fn backup_remains_valid_after_live_commits() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), true);
    let (sid, binding) = auth_pair(&mut state);

    let blob = create_unlock_blob(
        &sid,
        &binding,
        &MockKeyPassProvider::with_material(master.clone()),
    )
    .unwrap();
    expect_ok_control(control(
        &mut state,
        10,
        ControlRequest::VaultUnlock {
            session_id: sid.clone(),
            blob,
        },
    ))
    .unwrap();

    expect_ok_control(control(
        &mut state,
        11,
        ControlRequest::BackupCreate {
            session_id: sid.clone(),
            backup_id: "frozen".into(),
            include_rowstore: false,
        },
    ))
    .unwrap();

    expect_ok_data(
        handle_data(
            &mut state,
            RequestEnvelope {
                request_id: 12,
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
                request_id: 13,
                body: DataRequest::ExecuteSql {
                    session_id: sid.clone(),
                    sql: "INSERT INTO items (id, name) VALUES (1, 'x')".into(),
                    params: vec![],
                },
            },
            &limits(),
        "conn-test",
        )
        .unwrap(),
    )
    .unwrap();

    let verified = expect_ok_control(control(
        &mut state,
        14,
        ControlRequest::BackupVerify {
            session_id: sid.clone(),
            backup_id: "frozen".into(),
        },
    ))
    .unwrap();
    let ControlResponse::BackupVerify { valid, .. } = verified else {
        panic!("verify");
    };
    assert!(valid);
}

#[test]
fn restore_invalid_backup_rejected() {
    let dir = tempdir().unwrap();
    let (mut state, sid) = unlocked(dir.path());

    expect_ok_control(control(
        &mut state,
        2,
        ControlRequest::BackupCreate {
            session_id: sid.clone(),
            backup_id: "ok".into(),
            include_rowstore: false,
        },
    ))
    .unwrap();

    let manifest = dir.path().join("backups/backup-ok/manifest.json");
    std::fs::write(&manifest, b"{corrupt").unwrap();

    let resp = control(
        &mut state,
        3,
        ControlRequest::BackupRestore {
            session_id: sid.clone(),
            backup_id: "ok".into(),
            target_id: "t1".into(),
        },
    );
    assert_eq!(resp.status, ResponseStatus::Error);
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::BackupInvalid));
    assert!(!dir.path().join("restores/t1").exists());
}

#[test]
fn restore_non_empty_target_rejected() {
    let dir = tempdir().unwrap();
    let (mut state, sid) = unlocked(dir.path());

    expect_ok_control(control(
        &mut state,
        2,
        ControlRequest::BackupCreate {
            session_id: sid.clone(),
            backup_id: "b1".into(),
            include_rowstore: false,
        },
    ))
    .unwrap();

    expect_ok_control(control(
        &mut state,
        3,
        ControlRequest::BackupRestore {
            session_id: sid.clone(),
            backup_id: "b1".into(),
            target_id: "tgt".into(),
        },
    ))
    .unwrap();

    let resp = control(
        &mut state,
        4,
        ControlRequest::BackupRestore {
            session_id: sid.clone(),
            backup_id: "b1".into(),
            target_id: "tgt".into(),
        },
    );
    assert_eq!(resp.status, ResponseStatus::Error);
    assert_eq!(
        resp.error_code,
        Some(ProtocolErrorCode::BackupTargetNotEmpty)
    );
}

#[test]
fn restore_then_recover_ready_and_idempotent() {
    let dir = tempdir().unwrap();
    let (mut state, sid) = unlocked(dir.path());

    expect_ok_control(control(
        &mut state,
        2,
        ControlRequest::BackupCreate {
            session_id: sid.clone(),
            backup_id: "r1".into(),
            include_rowstore: false,
        },
    ))
    .unwrap();

    let restored = expect_ok_control(control(
        &mut state,
        3,
        ControlRequest::BackupRestore {
            session_id: sid.clone(),
            backup_id: "r1".into(),
            target_id: "rec".into(),
        },
    ))
    .unwrap();
    let ControlResponse::BackupRestore {
        vault_locked,
        sessions_invalid,
        ..
    } = restored
    else {
        panic!("restore");
    };
    assert!(vault_locked);
    assert!(sessions_invalid);

    let recovered = expect_ok_control(control(
        &mut state,
        4,
        ControlRequest::BackupRecover {
            session_id: sid.clone(),
            target_id: "rec".into(),
        },
    ))
    .unwrap();
    let ControlResponse::BackupRecover {
        state: rec_state,
        vault_locked,
        sessions_invalid,
        ..
    } = recovered
    else {
        panic!("recover");
    };
    assert_eq!(rec_state, "ready");
    assert!(vault_locked);
    assert!(sessions_invalid);

    let again = expect_ok_control(control(
        &mut state,
        5,
        ControlRequest::BackupRecover {
            session_id: sid.clone(),
            target_id: "rec".into(),
        },
    ))
    .unwrap();
    let ControlResponse::BackupRecover { state: s2, .. } = again else {
        panic!("recover2");
    };
    assert_eq!(s2, "ready");

    let status = expect_ok_control(control(
        &mut state,
        6,
        ControlRequest::BackupStatus {
            session_id: sid.clone(),
            target_id: "rec".into(),
        },
    ))
    .unwrap();
    let ControlResponse::BackupStatus {
        state: st,
        vault_locked,
        sessions_invalid,
        ..
    } = status
    else {
        panic!("status");
    };
    assert_eq!(st, "ready");
    assert!(vault_locked);
    assert!(sessions_invalid);
}

#[test]
fn backup_ops_require_session() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), true);
    let resp = control(
        &mut state,
        1,
        ControlRequest::BackupList {
            session_id: "missing".into(),
        },
    );
    assert_eq!(resp.status, ResponseStatus::Error);
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::SessionInvalid));
}

#[test]
fn backup_not_found() {
    let dir = tempdir().unwrap();
    let (mut state, sid) = unlocked(dir.path());
    let resp = control(
        &mut state,
        2,
        ControlRequest::BackupVerify {
            session_id: sid,
            backup_id: "nope".into(),
        },
    );
    assert_eq!(resp.status, ResponseStatus::Error);
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::BackupNotFound));
}
