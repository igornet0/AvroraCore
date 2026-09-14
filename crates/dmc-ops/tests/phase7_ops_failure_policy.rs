//! Phase 7.10.8 — Failure policy classifier (RejectOnly / NotReady / Fatal).

use dmc_observability::{Audit, Metrics, Observability};
use dmc_ops::{
    apply_failure_class, apply_failure_to_started, assert_started_invariants, classify_kind,
    classify_protocol, classify_shutdown, classify_startup, decision_for, failure_matrix,
    parse_config_json, start_core, CoreConfig, FailureClass, FailureKind, LifecycleState,
    ProcessLifecycle, ProjectedReadiness, ShutdownError, StartupError, StartupOptions,
};
use dmc_protocol::{
    ControlRequest, DataRequest, ProtocolErrorCode, RemoteLimits, RequestEnvelope, ResponseStatus,
};
use dmc_security::auth::{Action, Resource};
use dmc_server::{
    create_unlock_blob, expect_ok_control, expect_ok_data, handle_control, handle_data,
    CoreLifecycle, CoreServerState, MockKeyPassProvider, UnlockMaterial,
};
use tempfile::tempdir;

fn cfg_for(root: &std::path::Path) -> CoreConfig {
    parse_config_json(&format!(
        r#"{{ "data_root": "{}", "profile": "development" }}"#,
        root.display()
    ))
    .unwrap()
}

fn limits() -> RemoteLimits {
    RemoteLimits::default()
}

fn grant_analyst(state: &mut CoreServerState) {
    let identity = state.auth_mut().create_identity("analyst", "pw").unwrap();
    let grants = state.auth_mut().grants_mut();
    grants.grant(
        identity.clone(),
        Resource::database("avrora"),
        Action::Connect,
    );
    grants.grant(
        identity.clone(),
        Resource::schema("avrora", "public"),
        Action::Usage,
    );
    grants.grant(
        identity.clone(),
        Resource::schema("avrora", "public"),
        Action::Create,
    );
    grants.grant(
        identity.clone(),
        Resource::table("avrora", "public", "users"),
        Action::Select,
    );
    grants.grant(
        identity.clone(),
        Resource::table("avrora", "public", "users"),
        Action::Insert,
    );
    grants.grant(identity, Resource::database("avrora"), Action::Create);
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
        "conn",
    )
    .unwrap();
    match expect_ok_control(resp).unwrap() {
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
    }
}

fn unlock(
    state: &mut CoreServerState,
    req_id: u64,
    session_id: &str,
    binding: &[u8; 32],
    master: &UnlockMaterial,
) {
    let blob = create_unlock_blob(
        session_id,
        binding,
        &MockKeyPassProvider::with_material(master.clone()),
    )
    .unwrap();
    expect_ok_control(
        handle_control(
            state,
            RequestEnvelope {
                request_id: req_id,
                body: ControlRequest::VaultUnlock {
                    session_id: session_id.into(),
                    blob,
                },
            },
            &limits(),
            "conn",
        )
        .unwrap(),
    )
    .unwrap();
}

fn sql(
    state: &mut CoreServerState,
    req_id: u64,
    session_id: &str,
    statement: &str,
) -> dmc_protocol::ResponseEnvelope<dmc_protocol::DataResponse> {
    handle_data(
        state,
        RequestEnvelope {
            request_id: req_id,
            body: DataRequest::ExecuteSql {
                session_id: session_id.into(),
                sql: statement.into(),
                params: vec![],
            },
        },
        &limits(),
        "conn",
    )
    .unwrap()
}

// ─── Classification ─────────────────────────────────────────────────────────

#[test]
fn matrix_matches_classify_kind() {
    for &(kind, class) in failure_matrix() {
        assert_eq!(classify_kind(kind), class, "{kind:?}");
    }
}

#[test]
fn protocol_codes_are_reject_only() {
    for code in [
        ProtocolErrorCode::InvalidSql,
        ProtocolErrorCode::AuthenticationFailed,
        ProtocolErrorCode::AuthorizationDenied,
        ProtocolErrorCode::VaultLocked,
        ProtocolErrorCode::ConstraintViolation,
        ProtocolErrorCode::TransactionConflict,
        ProtocolErrorCode::InvalidRequest,
        ProtocolErrorCode::FrameTooLarge,
        ProtocolErrorCode::BackupInvalid,
        ProtocolErrorCode::SessionInvalid,
        ProtocolErrorCode::ExecutionError,
    ] {
        assert_eq!(
            classify_protocol(code),
            FailureClass::RejectOnly,
            "{code:?}"
        );
    }
}

#[test]
fn startup_and_shutdown_errors_are_fatal() {
    assert_eq!(
        classify_startup(&StartupError::Journal("corrupt".into())),
        FailureClass::Fatal
    );
    assert_eq!(
        classify_startup(&StartupError::Recovery("artifact".into())),
        FailureClass::Fatal
    );
    assert_eq!(
        classify_startup(&StartupError::Catalog("open".into())),
        FailureClass::Fatal
    );
    assert_eq!(
        classify_shutdown(&ShutdownError::Flush("fsync".into())),
        FailureClass::Fatal
    );
}

#[test]
fn temporary_dependency_is_not_ready() {
    assert_eq!(
        classify_kind(FailureKind::TemporaryOperationalDependency),
        FailureClass::NotReady
    );
}

#[test]
fn decision_ready_reject_stays_ready() {
    let d = decision_for(FailureClass::RejectOnly, LifecycleState::Ready);
    assert!(!d.terminal);
    assert!(d.accepts_new_work);
    assert_eq!(d.projected_readiness, ProjectedReadiness::Ready);
    assert!(!d.may_mark_failed);
}

#[test]
fn decision_ready_not_ready_overlay() {
    let d = decision_for(FailureClass::NotReady, LifecycleState::Ready);
    assert!(!d.terminal);
    assert!(!d.accepts_new_work);
    assert_eq!(d.projected_readiness, ProjectedReadiness::NotReady);
    assert!(d.may_note_not_ready);
}

#[test]
fn decision_ready_fatal_terminal() {
    let d = decision_for(FailureClass::Fatal, LifecycleState::Ready);
    assert!(d.terminal);
    assert!(!d.accepts_new_work);
    assert_eq!(d.projected_readiness, ProjectedReadiness::Failed);
    assert!(d.may_mark_failed);
}

// ─── Lifecycle apply ────────────────────────────────────────────────────────

#[test]
fn apply_reject_only_noop() {
    let mut lc = ProcessLifecycle::new();
    lc.mark_ready().unwrap();
    apply_failure_class(&mut lc, FailureClass::RejectOnly).unwrap();
    assert_eq!(lc.state(), LifecycleState::Ready);
    assert!(lc.accepts_new_work());
    assert_eq!(
        lc.snapshot().projected_readiness,
        ProjectedReadiness::Ready
    );
}

#[test]
fn apply_not_ready_overlay() {
    let mut lc = ProcessLifecycle::new();
    lc.mark_ready().unwrap();
    apply_failure_class(&mut lc, FailureClass::NotReady).unwrap();
    assert_eq!(lc.state(), LifecycleState::Ready);
    assert!(!lc.accepts_new_work());
    assert!(lc.operational_not_ready());
    assert_eq!(
        lc.snapshot().projected_readiness,
        ProjectedReadiness::NotReady
    );
    lc.clear_operational_not_ready().unwrap();
    assert!(lc.accepts_new_work());
}

#[test]
fn apply_fatal_from_ready() {
    let mut lc = ProcessLifecycle::new();
    lc.mark_ready().unwrap();
    apply_failure_class(&mut lc, FailureClass::Fatal).unwrap();
    assert_eq!(lc.state(), LifecycleState::Failed);
    assert!(!lc.accepts_new_work());
}

// ─── Security / correctness ─────────────────────────────────────────────────

#[test]
fn reject_only_does_not_touch_journal_vault_session() {
    let dir = tempdir().unwrap();
    let mut started = start_core(
        cfg_for(&dir.path().join("data")),
        StartupOptions::production(),
    )
    .unwrap();
    grant_analyst(&mut started.server);
    let master = started.unlock_material.clone();
    let (sid, binding) = auth_pair(&mut started.server, 1);
    unlock(&mut started.server, 2, &sid, &binding, &master);
    let tip = started.server.ctx.journal().unwrap().tip_sequence();

    apply_failure_to_started(&mut started, FailureClass::RejectOnly).unwrap();

    assert_eq!(started.lifecycle.state(), LifecycleState::Ready);
    assert!(started.server.root_dek_present());
    assert!(started.server.security_state(&sid).authenticated);
    assert_eq!(
        started.server.ctx.journal().unwrap().tip_sequence(),
        tip
    );
}

#[test]
fn not_ready_does_not_lock_or_unlock_vault() {
    let dir = tempdir().unwrap();
    let mut started = start_core(
        cfg_for(&dir.path().join("data")),
        StartupOptions::production(),
    )
    .unwrap();
    grant_analyst(&mut started.server);
    let master = started.unlock_material.clone();
    let (sid, binding) = auth_pair(&mut started.server, 1);
    unlock(&mut started.server, 2, &sid, &binding, &master);
    assert!(started.server.root_dek_present());

    apply_failure_to_started(&mut started, FailureClass::NotReady).unwrap();

    assert_eq!(started.lifecycle.state(), LifecycleState::Ready);
    assert!(!started.lifecycle.accepts_new_work());
    assert!(started.server.root_dek_present());
    assert!(started.server.security_state(&sid).authenticated);
}

#[test]
fn fatal_wipes_secrets_and_rejects_work() {
    let dir = tempdir().unwrap();
    let mut started = start_core(
        cfg_for(&dir.path().join("data")),
        StartupOptions::production(),
    )
    .unwrap();
    grant_analyst(&mut started.server);
    let master = started.unlock_material.clone();
    let (sid, binding) = auth_pair(&mut started.server, 1);
    unlock(&mut started.server, 2, &sid, &binding, &master);

    apply_failure_to_started(&mut started, FailureClass::Fatal).unwrap();

    assert_eq!(started.lifecycle.state(), LifecycleState::Failed);
    assert!(!started.lifecycle.accepts_new_work());
    assert!(!started.server.root_dek_present());
    assert!(!started.server.security_state(&sid).authenticated);
    assert_eq!(
        started.server.operational.lifecycle,
        CoreLifecycle::Failed
    );
    assert!(!started.server.accepts_new_work());
}

// ─── Observability isolation ────────────────────────────────────────────────

#[test]
fn failing_observability_does_not_change_classification() {
    let dir = tempdir().unwrap();
    let mut started = start_core(
        cfg_for(&dir.path().join("data")),
        StartupOptions::production(),
    )
    .unwrap();
    started
        .server
        .set_observability(Observability::failing());
    started.server.set_metrics(Metrics::failing());
    started.server.set_audit(Audit::failing());

    assert_eq!(
        classify_protocol(ProtocolErrorCode::ConstraintViolation),
        FailureClass::RejectOnly
    );
    apply_failure_to_started(&mut started, FailureClass::RejectOnly).unwrap();
    assert_eq!(started.lifecycle.state(), LifecycleState::Ready);

    apply_failure_to_started(&mut started, FailureClass::Fatal).unwrap();
    assert_eq!(started.lifecycle.state(), LifecycleState::Failed);
}

// ─── Acceptance ─────────────────────────────────────────────────────────────

#[test]
fn acceptance_reject_only_then_fatal() {
    let dir = tempdir().unwrap();
    let mut started = start_core(
        cfg_for(&dir.path().join("data")),
        StartupOptions::production(),
    )
    .unwrap();
    assert_started_invariants(&started);

    grant_analyst(&mut started.server);
    let master = started.unlock_material.clone();
    let (sid, binding) = auth_pair(&mut started.server, 1);
    unlock(&mut started.server, 2, &sid, &binding, &master);

    // Invalid SQL → wire error, classify RejectOnly, Core stays Ready.
    let bad = sql(&mut started.server, 3, &sid, "NOT A VALID STATEMENT !!!");
    assert_eq!(bad.status, ResponseStatus::Error);
    let code = bad.error_code.unwrap();
    assert_eq!(classify_protocol(code), FailureClass::RejectOnly);
    apply_failure_to_started(&mut started, FailureClass::RejectOnly).unwrap();
    assert_eq!(started.lifecycle.state(), LifecycleState::Ready);
    assert!(started.lifecycle.accepts_new_work());

    // Valid SQL still works.
    expect_ok_data(sql(
        &mut started.server,
        4,
        &sid,
        "CREATE TABLE users (id BIGINT NOT NULL, name TEXT)",
    ))
    .unwrap();
    expect_ok_data(sql(
        &mut started.server,
        5,
        &sid,
        "INSERT INTO users (id, name) VALUES (1, 'Alice')",
    ))
    .unwrap();

    // Simulate operational fatal.
    apply_failure_to_started(&mut started, FailureClass::Fatal).unwrap();
    assert_eq!(started.lifecycle.state(), LifecycleState::Failed);
    let denied = handle_control(
        &mut started.server,
        RequestEnvelope {
            request_id: 99,
            body: ControlRequest::Health,
        },
        &limits(),
        "conn",
    )
    .unwrap();
    // Health is allowed while stopping, but Failed rejects via accepts_new_work.
    // Health is in control_allowed_while_stopping — but Failed is not Stopping.
    // accepts_new_work is false → non-allowed control rejected.
    // Health is allowed_while_stopping only — for Failed, Health still allowed by that helper!
    // Check Data path instead.
    let sql_denied = sql(&mut started.server, 100, &sid, "SELECT 1");
    assert_eq!(sql_denied.status, ResponseStatus::Error);
    assert_eq!(
        sql_denied.error_code,
        Some(ProtocolErrorCode::ConnectionClosed)
    );
    let _ = denied;
}

#[test]
fn acceptance_startup_recovery_failure_is_failed() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("data");
    let started = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    let path = started.layout.recovery_state();
    drop(started);
    // Restored without artifact → recovery-on-startup fails.
    let file = dmc_backup::RecoveryStateFile {
        format_version: dmc_backup::RecoveryStateFile::FORMAT_VERSION,
        checkpoint_sequence: 1,
        state: dmc_backup::RecoveryState::Restored,
        indexes_rebuilt: false,
        statistics_rebuilt: false,
        live_relative: "live".into(),
    };
    std::fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();

    let err = start_core(cfg_for(&root), StartupOptions::production()).unwrap_err();
    assert_eq!(classify_startup(&err), FailureClass::Fatal);
    assert!(matches!(err, StartupError::Recovery(_)));
}
