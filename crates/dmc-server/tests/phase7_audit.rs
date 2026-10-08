//! Phase 7.9.5 — Audit wiring across Auth / Vault / SQL / Backup + failure isolation.

use dmc_observability::{
    assert_no_secrets_in_audit, Audit, AuditEventKind, AuditResult, MemoryAuditSink,
};
use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, ProtocolErrorCode, RemoteLimits, RequestEnvelope,
};
use dmc_server::{
    bootstrap_core_state_locked, create_unlock_blob, expect_ok_control, expect_ok_data,
    handle_control, handle_data, CoreServerState, MockKeyPassProvider, UnlockMaterial,
};
use tempfile::tempdir;

fn limits() -> RemoteLimits {
    RemoteLimits::default()
}

fn attach_audit(state: &mut CoreServerState) -> MemoryAuditSink {
    let sink = MemoryAuditSink::new();
    state.set_audit(Audit::memory(sink.clone()));
    sink
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

fn control(state: &mut CoreServerState, req_id: u64, body: ControlRequest) {
    expect_ok_control(
        handle_control(
            state,
            RequestEnvelope {
                request_id: req_id,
                body,
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

fn assert_audit_clean(sink: &MemoryAuditSink) {
    for ev in sink.snapshot() {
        assert_no_secrets_in_audit(&ev).unwrap();
        assert!(ev.operation.as_ref().map(|o| !o.contains(' ')).unwrap_or(true));
    }
}

#[test]
fn successful_login_emits_auth_and_session_created() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let sink = attach_audit(&mut state);
    let (sid, _) = auth_pair(&mut state, 1);
    assert!(sink.count_kind(AuditEventKind::AuthenticationSucceeded) >= 1);
    assert!(sink.count_kind(AuditEventKind::SessionCreated) >= 1);
    let ev = sink
        .snapshot()
        .into_iter()
        .find(|e| e.kind == AuditEventKind::AuthenticationSucceeded)
        .unwrap();
    assert_eq!(ev.result, AuditResult::Success);
    assert_eq!(ev.session_id.as_deref(), Some(sid.as_str()));
    assert!(ev.principal_id.is_some());
    assert_audit_clean(&sink);
}

#[test]
fn failed_login_emits_authentication_failed_without_session() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let sink = attach_audit(&mut state);
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
    assert_eq!(sink.count_kind(AuditEventKind::AuthenticationFailed), 1);
    let ev = sink.snapshot().into_iter().next().unwrap();
    assert!(ev.session_id.is_none());
    assert!(ev.principal_id.is_none());
    assert!(ev.request_id.is_some());
    assert!(ev.connection_id.is_some());
}

#[test]
fn logout_emits_session_invalidated() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let sink = attach_audit(&mut state);
    let (sid, _) = auth_pair(&mut state, 1);
    sink.clear();
    control(
        &mut state,
        2,
        ControlRequest::Logout {
            session_id: sid,
        },
    );
    assert!(sink.count_kind(AuditEventKind::SessionInvalidated) >= 1);
}

#[test]
fn invalid_session_does_not_emit_false_authz_denied() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), true);
    let sink = attach_audit(&mut state);
    let resp = handle_data(
        &mut state,
        RequestEnvelope {
            request_id: 1,
            body: DataRequest::ExecuteSql {
                session_id: "ghost".into(),
                sql: "SELECT 1".into(),
                params: vec![],
            },
        },
        &limits(),
        "conn-test",
    )
    .unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::SessionInvalid));
    assert_eq!(sink.count_kind(AuditEventKind::AuthorizationDenied), 0);
}

#[test]
fn authz_deny_emits_authorization_denied_not_full_sql() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), true);
    let sink = attach_audit(&mut state);
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
    assert_eq!(sink.count_kind(AuditEventKind::AuthorizationDenied), 1);
    let ev = sink.snapshot().into_iter().next().unwrap();
    assert_eq!(ev.operation.as_deref(), Some("DELETE"));
    assert_no_secrets_in_audit(&ev).unwrap();
    let json = serde_json::to_string(&ev).unwrap();
    assert!(!json.contains("DELETE FROM"));
}

#[test]
fn allowed_select_emits_sql_executed_not_denial() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), true);
    let sink = attach_audit(&mut state);
    let (sid, binding) = auth_pair(&mut state, 1);
    unlock(&mut state, 2, &sid, &binding, master);
    sink.clear();
    sql(
        &mut state,
        3,
        &sid,
        "SELECT id FROM users WHERE id = 0",
    );
    assert!(sink.count_kind(AuditEventKind::SqlExecuted) >= 1);
    assert_eq!(sink.count_kind(AuditEventKind::AuthorizationDenied), 0);
}

#[test]
fn vault_unlock_lock_and_failed_unlock_audited() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let sink = attach_audit(&mut state);
    let (sid, binding) = auth_pair(&mut state, 1);

    // Failed unlock with wrong material.
    let bad = UnlockMaterial::random();
    let blob = create_unlock_blob(&sid, &binding, &MockKeyPassProvider::with_material(bad)).unwrap();
    let _ = handle_control(
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
    .unwrap();
    assert!(sink.count_kind(AuditEventKind::VaultUnlockFailed) >= 1);

    unlock(&mut state, 3, &sid, &binding, master);
    assert!(sink.count_kind(AuditEventKind::VaultUnlocked) >= 1);

    control(
        &mut state,
        4,
        ControlRequest::VaultLock {
            session_id: sid,
        },
    );
    assert!(sink.count_kind(AuditEventKind::VaultLocked) >= 1);
}

#[test]
fn sql_commit_and_rollback_emit_transaction_events() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), true);
    let sink = attach_audit(&mut state);
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
    assert!(sink.count_kind(AuditEventKind::TransactionCommitted) >= 1);
    assert!(sink.count_kind(AuditEventKind::SqlExecuted) >= 1);

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
    assert!(sink.count_kind(AuditEventKind::TransactionRolledBack) >= 1);
}

#[test]
fn backup_create_verify_restore_recovery_audited() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), true);
    let sink = attach_audit(&mut state);
    let (sid, binding) = auth_pair(&mut state, 1);
    unlock(&mut state, 50, &sid, &binding, master); // D4-F: backups need open storage
    sink.clear();

    control(
        &mut state,
        2,
        ControlRequest::BackupCreate {
            session_id: sid.clone(),
            backup_id: "a1".into(),
            include_rowstore: false,
        },
    );
    assert!(sink.count_kind(AuditEventKind::BackupCreated) >= 1);

    control(
        &mut state,
        3,
        ControlRequest::BackupVerify {
            session_id: sid.clone(),
            backup_id: "a1".into(),
        },
    );
    assert!(sink.count_kind(AuditEventKind::BackupVerified) >= 1);

    control(
        &mut state,
        4,
        ControlRequest::BackupRestore {
            session_id: sid.clone(),
            backup_id: "a1".into(),
            target_id: "t1".into(),
        },
    );
    assert!(sink.count_kind(AuditEventKind::BackupRestoreStarted) >= 1);
    assert!(sink.count_kind(AuditEventKind::BackupRestored) >= 1);

    control(
        &mut state,
        5,
        ControlRequest::BackupRecover {
            session_id: sid,
            target_id: "t1".into(),
        },
    );
    assert!(sink.count_kind(AuditEventKind::RecoveryStarted) >= 1);
    assert!(sink.count_kind(AuditEventKind::RecoveryCompleted) >= 1);
    assert_audit_clean(&sink);
}

#[test]
fn failing_audit_sink_does_not_change_sql_commit() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), true);
    state.set_audit(Audit::failing());
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
fn failing_audit_sink_does_not_change_auth_vault_or_backup() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), true);
    state.set_audit(Audit::failing());
    let (sid, binding) = auth_pair(&mut state, 1);
    unlock(&mut state, 2, &sid, &binding, master);
    control(
        &mut state,
        3,
        ControlRequest::BackupCreate {
            session_id: sid.clone(),
            backup_id: "x".into(),
            include_rowstore: false,
        },
    );
    control(
        &mut state,
        4,
        ControlRequest::VaultLock {
            session_id: sid,
        },
    );
}
