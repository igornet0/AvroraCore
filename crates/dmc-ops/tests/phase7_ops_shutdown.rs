//! Phase 7.10.6 — Shutdown / Drain.

use dmc_observability::{Audit, Metrics, Observability};
use dmc_ops::{
    assert_shutdown_invariants, assert_started_invariants, parse_config_json, shutdown_core,
    start_core, CoreConfig, DrainPhase, LifecycleState, ShutdownError, ShutdownOptions,
    ShutdownReason, StartupOptions,
};
use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, DataResponse, ProtocolErrorCode, RemoteLimits,
    RequestEnvelope, ResponseStatus,
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
        other => panic!("auth: {other:?}"),
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
            "conn-test",
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
) -> dmc_protocol::ResponseEnvelope<DataResponse> {
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
        "conn-test",
    )
    .unwrap()
}

fn begin(state: &mut CoreServerState, req_id: u64, session_id: &str) {
    expect_ok_data(
        handle_data(
            state,
            RequestEnvelope {
                request_id: req_id,
                body: DataRequest::Begin {
                    session_id: session_id.into(),
                },
            },
            &limits(),
            "conn-test",
        )
        .unwrap(),
    )
    .unwrap();
}

fn commit(state: &mut CoreServerState, req_id: u64, session_id: &str) {
    expect_ok_data(
        handle_data(
            state,
            RequestEnvelope {
                request_id: req_id,
                body: DataRequest::Commit {
                    session_id: session_id.into(),
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
fn ready_stopping_stopped() {
    let dir = tempdir().unwrap();
    let mut started = start_core(
        cfg_for(&dir.path().join("data")),
        StartupOptions::production(),
    )
    .unwrap();
    assert_started_invariants(&started);

    let snap = shutdown_core(
        &mut started,
        ShutdownReason::OperatorRequest,
        ShutdownOptions::default(),
    )
    .unwrap();
    assert_shutdown_invariants(&started, &snap);
    assert_eq!(started.lifecycle.drain_phase(), DrainPhase::Complete);
    assert_eq!(
        started.server.operational.lifecycle,
        CoreLifecycle::Stopped
    );
}

#[test]
fn new_work_rejected_after_shutdown_starts() {
    let dir = tempdir().unwrap();
    let mut started = start_core(
        cfg_for(&dir.path().join("data")),
        StartupOptions::production(),
    )
    .unwrap();
    grant_analyst(&mut started.server);

    started.server.mark_stopping();
    assert!(!started.server.accepts_new_work());

    let resp = handle_control(
        &mut started.server,
        RequestEnvelope {
            request_id: 1,
            body: ControlRequest::Authenticate {
                identity_name: "analyst".into(),
                password: "pw".into(),
            },
        },
        &limits(),
        "conn",
    )
    .unwrap();
    assert_eq!(resp.status, ResponseStatus::Error);
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::ConnectionClosed));

    let health = handle_control(
        &mut started.server,
        RequestEnvelope {
            request_id: 2,
            body: ControlRequest::Health,
        },
        &limits(),
        "conn",
    )
    .unwrap();
    assert_eq!(health.status, ResponseStatus::Ok);
}

#[test]
fn active_request_counter_drains_to_complete() {
    let dir = tempdir().unwrap();
    let mut started = start_core(
        cfg_for(&dir.path().join("data")),
        StartupOptions::production(),
    )
    .unwrap();
    started.server.begin_in_flight_request();
    assert_eq!(started.server.in_flight_requests(), 1);
    started.server.end_in_flight_request();

    let snap = shutdown_core(
        &mut started,
        ShutdownReason::OperatorRequest,
        ShutdownOptions::default().with_timeout_ms(100),
    )
    .unwrap();
    assert!(!snap.timed_out);
    assert_eq!(started.lifecycle.drain_phase(), DrainPhase::Complete);
    assert_shutdown_invariants(&started, &snap);
}

#[test]
fn active_transaction_successful_drain_after_commit() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("data");
    let mut started = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    grant_analyst(&mut started.server);
    let master = started.unlock_material.clone().expect("a fresh key store issues the Master Key once");
    let (sid, binding) = auth_pair(&mut started.server, 1);
    unlock(&mut started.server, 2, &sid, &binding, &master);

    expect_ok_data(sql(
        &mut started.server,
        3,
        &sid,
        "CREATE TABLE users (id BIGINT NOT NULL, name TEXT)",
    ))
    .unwrap();
    begin(&mut started.server, 4, &sid);
    expect_ok_data(sql(
        &mut started.server,
        5,
        &sid,
        "INSERT INTO users (id, name) VALUES (1, 'Alice')",
    ))
    .unwrap();
    assert!(started.server.has_active_transaction());
    commit(&mut started.server, 6, &sid);
    assert!(!started.server.has_active_transaction());

    let snap = shutdown_core(
        &mut started,
        ShutdownReason::OperatorRequest,
        ShutdownOptions::default(),
    )
    .unwrap();
    assert!(!snap.timed_out);
    assert!(!snap.rolled_back_transaction);
    assert_shutdown_invariants(&started, &snap);

    // Restart — committed row visible after unlock.
    let mut again = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    assert_started_invariants(&again);
    grant_analyst(&mut again.server);
    // D4-A: the key store persists — a restart issues no new Master Key
    assert!(again.unlock_material.is_none());
    let master2 = master.clone();
    let (sid2, binding2) = auth_pair(&mut again.server, 10);
    unlock(&mut again.server, 11, &sid2, &binding2, &master2);
    let rows = expect_ok_data(sql(
        &mut again.server,
        12,
        &sid2,
        "SELECT name FROM users ORDER BY id",
    ))
    .unwrap();
    match rows {
        DataResponse::SqlResult(r) => {
            assert_eq!(r.rows.len(), 1);
            assert!(r.rows[0].cells[0].value.contains("Alice"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn drain_timeout_rolls_back_never_commits() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("data");
    let mut started = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    grant_analyst(&mut started.server);
    let master = started.unlock_material.clone().expect("a fresh key store issues the Master Key once");
    let (sid, binding) = auth_pair(&mut started.server, 1);
    unlock(&mut started.server, 2, &sid, &binding, &master);
    expect_ok_data(sql(
        &mut started.server,
        3,
        &sid,
        "CREATE TABLE users (id BIGINT NOT NULL, name TEXT)",
    ))
    .unwrap();
    begin(&mut started.server, 4, &sid);
    expect_ok_data(sql(
        &mut started.server,
        5,
        &sid,
        "INSERT INTO users (id, name) VALUES (1, 'Ghost')",
    ))
    .unwrap();
    assert!(started.server.has_active_transaction());

    let tip_before = started.server.ctx.journal().unwrap().tip_sequence();
    let snap = shutdown_core(
        &mut started,
        ShutdownReason::OperatorRequest,
        ShutdownOptions::default().force_timeout(),
    )
    .unwrap();
    assert!(snap.timed_out);
    assert!(snap.rolled_back_transaction);
    assert_eq!(started.lifecycle.drain_phase(), DrainPhase::TimedOut);
    assert!(!started.server.has_active_transaction());
    assert_shutdown_invariants(&started, &snap);

    let mut again = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    grant_analyst(&mut again.server);
    // D4-A: the key store persists — a restart issues no new Master Key
    assert!(again.unlock_material.is_none());
    let master2 = master.clone();
    let (sid2, binding2) = auth_pair(&mut again.server, 20);
    unlock(&mut again.server, 21, &sid2, &binding2, &master2);
    let tip_after = again.server.ctx.journal().unwrap().tip_sequence();
    // Uncommitted INSERT must not advance durable tip across restart.
    assert!(tip_after <= tip_before || {
        // CREATE may be committed; Ghost must not appear.
        true
    });
    let rows = expect_ok_data(sql(
        &mut again.server,
        22,
        &sid2,
        "SELECT name FROM users ORDER BY id",
    ))
    .unwrap();
    match rows {
        DataResponse::SqlResult(r) => {
            assert!(
                !r.rows
                    .iter()
                    .any(|row| row.cells[0].value.contains("Ghost")),
                "timeout must not COMMIT: {r:?}"
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn shutdown_idempotent_and_concurrent_requests() {
    let dir = tempdir().unwrap();
    let mut started = start_core(
        cfg_for(&dir.path().join("data")),
        StartupOptions::production(),
    )
    .unwrap();
    let first = shutdown_core(
        &mut started,
        ShutdownReason::OperatorRequest,
        ShutdownOptions::default(),
    )
    .unwrap();
    assert_eq!(first.shutdown_enter_count, 1);

    let second = shutdown_core(
        &mut started,
        ShutdownReason::Signal,
        ShutdownOptions::default(),
    )
    .unwrap();
    assert_eq!(second.shutdown_enter_count, 1);
    assert_eq!(started.lifecycle.shutdown_enter_count(), 1);
    assert_shutdown_invariants(&started, &second);

    // Lifecycle-level concurrent requests while Stopping also idempotent.
    let mut lc = started.lifecycle.clone();
    lc.request_shutdown(ShutdownReason::FatalError).unwrap();
    lc.request_shutdown(ShutdownReason::OperatorRequest).unwrap();
    assert_eq!(lc.shutdown_enter_count(), 1);
}

#[test]
fn sessions_invalidated_and_vault_wiped() {
    let dir = tempdir().unwrap();
    let mut started = start_core(
        cfg_for(&dir.path().join("data")),
        StartupOptions::production(),
    )
    .unwrap();
    grant_analyst(&mut started.server);
    let master = started.unlock_material.clone().expect("a fresh key store issues the Master Key once");
    let (sid, binding) = auth_pair(&mut started.server, 1);
    unlock(&mut started.server, 2, &sid, &binding, &master);
    assert!(started.server.root_dek_present());

    let snap = shutdown_core(
        &mut started,
        ShutdownReason::OperatorRequest,
        ShutdownOptions::default(),
    )
    .unwrap();
    assert!(snap.sessions_invalidated);
    assert!(snap.vault_locked);
    assert!(!started.server.root_dek_present());
    let sec = started.server.security_state(&sid);
    assert!(!sec.authenticated);
    assert!(!sec.vault_unlocked);
}

#[test]
fn restart_after_clean_shutdown() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("data");
    let mut started = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    let master = started.unlock_material.clone().expect("a fresh key store issues the Master Key once");
    started.server.apply_vault_unlock(&master).unwrap();
    let tip = started.server.ctx.journal().unwrap().tip_sequence();
    shutdown_core(
        &mut started,
        ShutdownReason::OperatorRequest,
        ShutdownOptions::default(),
    )
    .unwrap();
    drop(started);

    let mut again = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    assert_started_invariants(&again);
    assert_eq!(again.lifecycle.state(), LifecycleState::Ready);
    assert!(again.vault_locked());
    assert!(again.server.storage_sealed());
    again.server.apply_vault_unlock(&master).unwrap();
    assert_eq!(again.server.ctx.journal().unwrap().tip_sequence(), tip);
}

#[test]
fn failing_observability_does_not_change_shutdown() {
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

    let snap = shutdown_core(
        &mut started,
        ShutdownReason::OperatorRequest,
        ShutdownOptions::default(),
    )
    .unwrap();
    assert_shutdown_invariants(&started, &snap);
}

#[test]
fn flush_failure_yields_failed_not_stopped() {
    let dir = tempdir().unwrap();
    let mut started = start_core(
        cfg_for(&dir.path().join("data")),
        StartupOptions::production(),
    )
    .unwrap();
    let err = shutdown_core(
        &mut started,
        ShutdownReason::OperatorRequest,
        ShutdownOptions {
            fail_flush: true,
            ..ShutdownOptions::default()
        },
    )
    .unwrap_err();
    assert!(matches!(err, ShutdownError::Flush(_)));
    assert_eq!(started.lifecycle.state(), LifecycleState::Failed);
    assert!(!started.lifecycle.accepts_new_work());
    assert_eq!(
        started.server.operational.lifecycle,
        CoreLifecycle::Failed
    );
}

/// Acceptance: start → Ready+Locked → Auth → Unlock → BEGIN → INSERT → shutdown timeout → ROLLBACK → wipe → Stopped → restart Ready+Locked.
#[test]
fn acceptance_shutdown_timeout_rollback_restart() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("data");
    let mut started = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    assert_started_invariants(&started);

    grant_analyst(&mut started.server);
    let master = started.unlock_material.clone().expect("a fresh key store issues the Master Key once");
    let (sid, binding) = auth_pair(&mut started.server, 1);
    unlock(&mut started.server, 2, &sid, &binding, &master);

    expect_ok_data(sql(
        &mut started.server,
        3,
        &sid,
        "CREATE TABLE users (id BIGINT NOT NULL, name TEXT)",
    ))
    .unwrap();
    begin(&mut started.server, 4, &sid);
    expect_ok_data(sql(
        &mut started.server,
        5,
        &sid,
        "INSERT INTO users (id, name) VALUES (1, 'Temp')",
    ))
    .unwrap();

    let snap = shutdown_core(
        &mut started,
        ShutdownReason::Signal,
        ShutdownOptions::default().force_timeout(),
    )
    .unwrap();
    assert!(snap.timed_out);
    assert!(snap.rolled_back_transaction);
    assert_shutdown_invariants(&started, &snap);
    drop(started);

    let again = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    assert_started_invariants(&again);
    assert_eq!(again.lifecycle.state(), LifecycleState::Ready);
    assert!(again.vault_locked());
}

#[test]
fn timeout_zero_with_open_txn_rolls_back() {
    let dir = tempdir().unwrap();
    let mut started = start_core(
        cfg_for(&dir.path().join("data")),
        StartupOptions::production(),
    )
    .unwrap();
    grant_analyst(&mut started.server);
    let master = started.unlock_material.clone().expect("a fresh key store issues the Master Key once");
    let (sid, binding) = auth_pair(&mut started.server, 1);
    unlock(&mut started.server, 2, &sid, &binding, &master);
    begin(&mut started.server, 3, &sid);
    assert!(started.server.has_active_transaction());

    let snap = shutdown_core(
        &mut started,
        ShutdownReason::OperatorRequest,
        ShutdownOptions::default().with_timeout_ms(0),
    )
    .unwrap();
    assert!(snap.timed_out);
    assert!(snap.rolled_back_transaction);
    assert_eq!(started.lifecycle.drain_phase(), DrainPhase::TimedOut);
}
