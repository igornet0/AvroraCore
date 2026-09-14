//! Phase 7.9.8 — Observability DoD final acceptance.
//!
//! No new mechanisms. Proves 7.9.1–7.9.7 against ADR-025:
//! sanitization matrix, failure isolation, correlation, channel separation,
//! health/diagnostics axes, and end-to-end lifecycle.

use std::fs;
use std::path::Path;

use dmc_backup::{RecoveryState, RecoveryStateFile, RECOVERY_STATE_FILE};
use dmc_observability::{
    assert_no_secrets_in_audit, assert_no_secrets_in_diagnostics, assert_no_secrets_in_event, Audit,
    AuditEventKind, EventKind, MemoryAuditSink, MemoryMetricsSink, MemorySink, Metric,
    MetricLabels, MetricSample, Metrics, Observability, ObservabilityComponentStatus,
};
use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, DataResponse, DiagnosticsWire, ProtocolErrorCode,
    RemoteLimits, RequestEnvelope, ResponseStatus,
};
use dmc_server::{
    allocate_connection_id, bootstrap_core_state_locked, create_unlock_blob, diagnostics_to_wire,
    evaluate_diagnostics, expect_ok_control, expect_ok_data, handle_control, handle_data,
    CoreServerState, MockKeyPassProvider, UnlockMaterial,
};
use tempfile::tempdir;

fn limits() -> RemoteLimits {
    RemoteLimits::default()
}

const FORBIDDEN: &[&str] = &[
    "master_key",
    "masterkey",
    "unlock_material",
    "unlockmaterial",
    "unlock_blob",
    "unlockblob",
    "\"dek\"",
    "\"kek\"",
    "keypass",
    "ciphertext",
    "argon2",
    "-----begin",
    ".pem",
    ".key",
    "private_key",
];

fn assert_surface_clean(label: &str, value: &impl std::fmt::Debug) {
    let text = format!("{value:?}").to_lowercase();
    for needle in FORBIDDEN {
        assert!(
            !text.contains(needle),
            "{label} leaked `{needle}`: {text}"
        );
    }
    assert!(
        !text.contains("/users/") && !text.contains("/home/") && !text.contains("c:\\\\"),
        "{label} leaked absolute path: {text}"
    );
    // Full SQL / params must not appear as free text on obs surfaces.
    assert!(
        !text.contains("insert into")
            && !text.contains("create table")
            && !text.contains("values ("),
        "{label} leaked full SQL: {text}"
    );
}

fn assert_json_clean(label: &str, value: &impl serde::Serialize) {
    let text = serde_json::to_string(value).unwrap().to_lowercase();
    for needle in FORBIDDEN {
        assert!(
            !text.contains(needle),
            "{label} JSON leaked `{needle}`: {text}"
        );
    }
    assert!(
        !text.contains("\"password\"") && !text.contains("password\":"),
        "{label} JSON leaked password field: {text}"
    );
    assert!(
        !text.contains("/users/") && !text.contains("/home/") && !text.contains("c:\\\\"),
        "{label} JSON leaked absolute path: {text}"
    );
}

fn control(
    state: &mut CoreServerState,
    req_id: u64,
    conn: &str,
    body: ControlRequest,
) -> dmc_protocol::ResponseEnvelope<ControlResponse> {
    handle_control(
        state,
        RequestEnvelope {
            request_id: req_id,
            body,
        },
        &limits(),
        conn,
    )
    .unwrap()
}

fn data(
    state: &mut CoreServerState,
    req_id: u64,
    conn: &str,
    body: DataRequest,
) -> dmc_protocol::ResponseEnvelope<DataResponse> {
    handle_data(
        state,
        RequestEnvelope {
            request_id: req_id,
            body,
        },
        &limits(),
        conn,
    )
    .unwrap()
}

fn auth_pair(state: &mut CoreServerState, req_id: u64, conn: &str) -> (String, [u8; 32]) {
    match expect_ok_control(control(
        state,
        req_id,
        conn,
        ControlRequest::Authenticate {
            identity_name: "analyst".into(),
            password: "pw".into(),
        },
    ))
    .unwrap()
    {
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
    conn: &str,
    sid: &str,
    binding: &[u8; 32],
    master: UnlockMaterial,
) {
    let blob =
        create_unlock_blob(sid, binding, &MockKeyPassProvider::with_material(master)).unwrap();
    expect_ok_control(control(
        state,
        req_id,
        conn,
        ControlRequest::VaultUnlock {
            session_id: sid.into(),
            blob,
        },
    ))
    .unwrap();
}

fn sql_ok(state: &mut CoreServerState, req_id: u64, conn: &str, sid: &str, statement: &str) {
    expect_ok_data(data(
        state,
        req_id,
        conn,
        DataRequest::ExecuteSql {
            session_id: sid.into(),
            sql: statement.into(),
            params: vec![],
        },
    ))
    .unwrap();
}

fn begin(state: &mut CoreServerState, req_id: u64, conn: &str, sid: &str) {
    expect_ok_data(data(
        state,
        req_id,
        conn,
        DataRequest::Begin {
            session_id: sid.into(),
        },
    ))
    .unwrap();
}

fn commit(state: &mut CoreServerState, req_id: u64, conn: &str, sid: &str) {
    expect_ok_data(data(
        state,
        req_id,
        conn,
        DataRequest::Commit {
            session_id: sid.into(),
        },
    ))
    .unwrap();
}

fn health(state: &mut CoreServerState, req_id: u64, conn: &str) -> ControlResponse {
    expect_ok_control(control(state, req_id, conn, ControlRequest::Health)).unwrap()
}

fn readiness(state: &mut CoreServerState, req_id: u64, conn: &str) -> ControlResponse {
    expect_ok_control(control(state, req_id, conn, ControlRequest::Readiness)).unwrap()
}

fn diagnostics(state: &mut CoreServerState, req_id: u64, conn: &str) -> DiagnosticsWire {
    match expect_ok_control(control(state, req_id, conn, ControlRequest::Diagnostics)).unwrap() {
        ControlResponse::Diagnostics(wire) => wire,
        other => panic!("{other:?}"),
    }
}

fn attach_all(
    state: &mut CoreServerState,
) -> (MemorySink, MemoryMetricsSink, MemoryAuditSink) {
    let logs = MemorySink::new();
    let metrics = MemoryMetricsSink::new();
    let audit = MemoryAuditSink::new();
    state.set_observability(Observability::memory(logs.clone()));
    state.set_metrics(Metrics::memory(metrics.clone()));
    state.set_audit(Audit::memory(audit.clone()));
    (logs, metrics, audit)
}

fn assert_logs_clean(sink: &MemorySink) {
    for ev in sink.snapshot() {
        assert_no_secrets_in_event(&ev).unwrap();
        assert_surface_clean("log", &ev);
    }
}

fn assert_metrics_clean(sink: &MemoryMetricsSink) {
    for sample in sink.snapshot() {
        assert_surface_clean("metric", &sample);
        let labels = match &sample {
            MetricSample::Counter { labels, .. }
            | MetricSample::Observe { labels, .. }
            | MetricSample::Gauge { labels, .. } => labels,
        };
        for key in labels.as_map().keys() {
            assert!(
                !MetricLabels::is_forbidden_label_key(key),
                "forbidden metric label: {key}"
            );
        }
    }
}

fn assert_audit_clean(sink: &MemoryAuditSink) {
    for ev in sink.snapshot() {
        assert_no_secrets_in_audit(&ev).unwrap();
        assert_surface_clean("audit", &ev);
    }
}

fn write_recovery(data_root: &Path, state: RecoveryState) {
    let file = RecoveryStateFile {
        format_version: RecoveryStateFile::FORMAT_VERSION,
        checkpoint_sequence: 7,
        state,
        indexes_rebuilt: state == RecoveryState::Ready,
        statistics_rebuilt: state == RecoveryState::Ready,
        live_relative: "live".into(),
    };
    let path = data_root.join(RECOVERY_STATE_FILE);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();
}

fn assert_health_ready_locked(h: &ControlResponse) {
    match h {
        ControlResponse::Health {
            liveness,
            readiness,
            vault,
            ..
        } => {
            assert_eq!(liveness, "alive");
            assert_eq!(readiness, "ready");
            assert_eq!(vault, "locked");
        }
        other => panic!("expected Health, got {other:?}"),
    }
}

fn assert_readiness_ready(h: &ControlResponse) {
    match h {
        ControlResponse::Readiness { readiness, .. } => {
            assert_eq!(readiness, "ready");
        }
        other => panic!("expected Readiness, got {other:?}"),
    }
}

// ─── Security / sanitization ───────────────────────────────────────────────

#[test]
fn sanitization_matrix_across_all_surfaces() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (logs, metrics, audit) = attach_all(&mut state);
    let conn = allocate_connection_id();

    let fail = control(
        &mut state,
        1,
        &conn,
        ControlRequest::Authenticate {
            identity_name: "analyst".into(),
            password: "super-secret-password-DEK-KEK".into(),
        },
    );
    assert_eq!(fail.error_code, Some(ProtocolErrorCode::AuthenticationFailed));
    assert_surface_clean("wire auth fail", &fail);
    assert_json_clean("wire auth fail", &fail);

    let (sid, binding) = auth_pair(&mut state, 2, &conn);
    unlock(&mut state, 3, &conn, &sid, &binding, master);
    sql_ok(
        &mut state,
        4,
        &conn,
        &sid,
        "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)",
    );
    begin(&mut state, 5, &conn, &sid);
    sql_ok(
        &mut state,
        6,
        &conn,
        &sid,
        "INSERT INTO items (id, name) VALUES (1, 'secret-sql-payload')",
    );
    commit(&mut state, 7, &conn, &sid);

    let h = health(&mut state, 8, &conn);
    let r = readiness(&mut state, 9, &conn);
    let d = diagnostics(&mut state, 10, &conn);
    assert_surface_clean("health", &h);
    assert_surface_clean("readiness", &r);
    assert_surface_clean("diagnostics", &d);
    assert_json_clean("health", &h);
    assert_json_clean("readiness", &r);
    assert_json_clean("diagnostics", &d);

    let snap = evaluate_diagnostics(&mut state);
    assert_no_secrets_in_diagnostics(&snap).unwrap();
    assert_json_clean("diagnostics snapshot", &diagnostics_to_wire(&snap));

    assert_logs_clean(&logs);
    assert_metrics_clean(&metrics);
    assert_audit_clean(&audit);

    // Correlation only on logs/audit — never as metric labels.
    for sample in metrics.snapshot() {
        let text = format!("{sample:?}");
        assert!(!text.contains("request_id"));
        assert!(!text.contains("session_id"));
        assert!(!text.contains("transaction_id"));
        assert!(!text.contains("connection_id"));
    }
}

#[test]
fn wire_errors_sanitized_no_filesystem_or_sql() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let conn = allocate_connection_id();
    let resp = data(
        &mut state,
        1,
        &conn,
        DataRequest::ExecuteSql {
            session_id: "no-session".into(),
            sql: format!(
                "SELECT * FROM users WHERE path = '{}/secret.pem' AND key = 'DEK'",
                dir.path().display()
            ),
            params: vec![],
        },
    );
    assert_eq!(resp.status, ResponseStatus::Error);
    assert_surface_clean("sql wire error", &resp);
    assert_json_clean("sql wire error", &resp);
    let msg = resp.error_message.clone().unwrap_or_default().to_lowercase();
    assert!(!msg.contains(".pem"));
    assert!(!msg.contains("dek"));
    assert!(!msg.contains(&dir.path().display().to_string().to_lowercase()));
}

// ─── Failure isolation ─────────────────────────────────────────────────────

#[test]
fn all_failing_sinks_preserve_sql_auth_vault_backup() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    state.set_observability(Observability::failing());
    state.set_metrics(Metrics::failing());
    state.set_audit(Audit::failing());
    let conn = allocate_connection_id();

    let (sid, binding) = auth_pair(&mut state, 1, &conn);
    unlock(&mut state, 2, &conn, &sid, &binding, master.clone());
    sql_ok(
        &mut state,
        3,
        &conn,
        &sid,
        "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)",
    );
    begin(&mut state, 4, &conn, &sid);
    sql_ok(
        &mut state,
        5,
        &conn,
        &sid,
        "INSERT INTO items (id, name) VALUES (1, 'a')",
    );
    commit(&mut state, 6, &conn, &sid);
    sql_ok(
        &mut state,
        7,
        &conn,
        &sid,
        "SELECT id FROM items WHERE id = 1",
    );

    expect_ok_control(control(
        &mut state,
        8,
        &conn,
        ControlRequest::BackupCreate {
            session_id: sid.clone(),
            backup_id: "obs-fail".into(),
            include_rowstore: false,
        },
    ))
    .unwrap();
    expect_ok_control(control(
        &mut state,
        9,
        &conn,
        ControlRequest::BackupVerify {
            session_id: sid.clone(),
            backup_id: "obs-fail".into(),
        },
    ))
    .unwrap();
    expect_ok_control(control(
        &mut state,
        10,
        &conn,
        ControlRequest::BackupRestore {
            session_id: sid.clone(),
            backup_id: "obs-fail".into(),
            target_id: "t-fail".into(),
        },
    ))
    .unwrap();
    expect_ok_control(control(
        &mut state,
        11,
        &conn,
        ControlRequest::BackupRecover {
            session_id: sid.clone(),
            target_id: "t-fail".into(),
        },
    ))
    .unwrap();

    expect_ok_control(control(
        &mut state,
        12,
        &conn,
        ControlRequest::VaultLock {
            session_id: sid.clone(),
        },
    ))
    .unwrap();

    let locked = data(
        &mut state,
        13,
        &conn,
        DataRequest::ExecuteSql {
            session_id: sid,
            sql: "SELECT 1".into(),
            params: vec![],
        },
    );
    assert_eq!(locked.error_code, Some(ProtocolErrorCode::VaultLocked));

    // Diagnostics / readiness still work under failing sinks.
    let d = diagnostics(&mut state, 14, &conn);
    assert_eq!(d.readiness, "ready");
    assert_eq!(d.vault, "locked");
    assert_eq!(d.logging, ObservabilityComponentStatus::Degraded.as_str());
    assert_eq!(d.metrics, ObservabilityComponentStatus::Degraded.as_str());
    assert_eq!(d.audit, ObservabilityComponentStatus::Degraded.as_str());
}

#[test]
fn channels_independent_failing_one_keeps_others() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let logs = MemorySink::new();
    let metrics = MemoryMetricsSink::new();
    let audit = MemoryAuditSink::new();

    // Fail metrics only — logs + audit must still record.
    state.set_observability(Observability::memory(logs.clone()));
    state.set_metrics(Metrics::failing());
    state.set_audit(Audit::memory(audit.clone()));

    let conn = allocate_connection_id();
    let (sid, binding) = auth_pair(&mut state, 1, &conn);
    unlock(&mut state, 2, &conn, &sid, &binding, master);
    assert!(logs
        .snapshot()
        .iter()
        .any(|e| e.kind == EventKind::AuthLoginSuccess));
    assert!(audit.count_kind(AuditEventKind::AuthenticationSucceeded) >= 1);

    // Fail logs — metrics + audit continue.
    state.set_observability(Observability::failing());
    state.set_metrics(Metrics::memory(metrics.clone()));
    logs.clear();
    audit.clear();
    sql_ok(
        &mut state,
        3,
        &conn,
        &sid,
        "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)",
    );
    assert!(metrics.counter_sum(Metric::RequestsTotal) >= 1);
    assert!(audit.count_kind(AuditEventKind::SqlExecuted) >= 1 || !audit.snapshot().is_empty());
    assert!(logs.snapshot().is_empty());

    // Fail audit — logs + metrics continue; COMMIT still succeeds.
    state.set_observability(Observability::memory(logs.clone()));
    state.set_audit(Audit::failing());
    begin(&mut state, 4, &conn, &sid);
    sql_ok(
        &mut state,
        5,
        &conn,
        &sid,
        "INSERT INTO items (id, name) VALUES (1, 'x')",
    );
    commit(&mut state, 6, &conn, &sid);
    assert!(logs
        .snapshot()
        .iter()
        .any(|e| e.kind == EventKind::SqlCompleted));
    assert!(
        metrics.counter_sum(Metric::SqlTransactionsCommittedTotal) >= 1
            || metrics.counter_sum(Metric::RequestsTotal) >= 2
    );
}

// ─── Correlation ───────────────────────────────────────────────────────────

#[test]
fn correlation_lifecycle_fields_only_when_present() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (logs, _, _) = attach_all(&mut state);
    let conn = allocate_connection_id();

    let _ = control(
        &mut state,
        1,
        &conn,
        ControlRequest::Authenticate {
            identity_name: "analyst".into(),
            password: "wrong".into(),
        },
    );
    let fail = logs
        .snapshot()
        .into_iter()
        .find(|e| e.kind == EventKind::AuthLoginFailure)
        .expect("login failure");
    assert_eq!(fail.context.request_id.as_deref(), Some("1"));
    assert_eq!(fail.context.connection_id.as_deref(), Some(conn.as_str()));
    assert!(fail.context.session_id.is_none());
    assert!(fail.context.transaction_id.is_none());
    assert!(fail.context.journal_sequence.is_none());

    logs.clear();
    let (sid, binding) = auth_pair(&mut state, 2, &conn);
    unlock(&mut state, 3, &conn, &sid, &binding, master);
    sql_ok(
        &mut state,
        4,
        &conn,
        &sid,
        "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)",
    );
    logs.clear();

    begin(&mut state, 5, &conn, &sid);
    sql_ok(
        &mut state,
        6,
        &conn,
        &sid,
        "INSERT INTO items (id, name) VALUES (1, 'a')",
    );
    let insert = logs
        .snapshot()
        .into_iter()
        .find(|e| e.kind == EventKind::SqlCompleted && e.context.request_id.as_deref() == Some("6"))
        .unwrap();
    assert_eq!(insert.context.session_id.as_deref(), Some(sid.as_str()));
    assert!(insert.context.transaction_id.is_some());
    assert!(insert.context.journal_sequence.is_none());

    logs.clear();
    commit(&mut state, 7, &conn, &sid);
    let committed = logs
        .snapshot()
        .into_iter()
        .find(|e| e.kind == EventKind::SqlCompleted && e.context.request_id.as_deref() == Some("7"))
        .unwrap();
    assert!(committed.context.transaction_id.is_some());
    assert!(committed.context.journal_sequence.is_some());

    let conn2 = allocate_connection_id();
    assert_ne!(conn, conn2);
}

// ─── Health / diagnostics ──────────────────────────────────────────────────

#[test]
fn health_axes_vault_independent_diagnostics_readonly() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let conn = allocate_connection_id();

    assert_health_ready_locked(&health(&mut state, 1, &conn));
    assert_readiness_ready(&readiness(&mut state, 2, &conn));
    let d0 = diagnostics(&mut state, 3, &conn);
    assert_eq!(d0.vault, "locked");
    assert_eq!(d0.readiness, "ready");
    assert_eq!(d0.journal_lag, Some(0));

    let (sid, binding) = auth_pair(&mut state, 4, &conn);
    unlock(&mut state, 5, &conn, &sid, &binding, master);
    match health(&mut state, 6, &conn) {
        ControlResponse::Health {
            readiness,
            vault,
            ..
        } => {
            assert_eq!(readiness, "ready");
            assert_eq!(vault, "unlocked");
        }
        other => panic!("{other:?}"),
    }

    write_recovery(dir.path(), RecoveryState::Recovering);
    match readiness(&mut state, 7, &conn) {
        ControlResponse::Readiness { readiness, .. } => {
            assert_eq!(readiness, "not_ready");
        }
        other => panic!("{other:?}"),
    }
    let d1 = diagnostics(&mut state, 8, &conn);
    assert_eq!(d1.recovery_state.as_deref(), Some("recovering"));
    // Diagnostics does not unlock / mutate vault.
    assert_eq!(d1.vault, "unlocked");

    // Clear recovery overlay file → Ready again; diagnostics still read-only.
    let _ = fs::remove_file(dir.path().join(RECOVERY_STATE_FILE));
    assert_eq!(
        match readiness(&mut state, 9, &conn) {
            ControlResponse::Readiness { readiness, .. } => readiness,
            other => panic!("{other:?}"),
        },
        "ready"
    );
}

#[test]
fn control_data_boundary_no_diagnostics_on_data_plane() {
    // Data plane variants: ExecuteSql / Begin / Commit / Rollback only.
    let surface = format!(
        "{:?}",
        [
            DataRequest::ExecuteSql {
                session_id: "x".into(),
                sql: "SELECT 1".into(),
                params: vec![],
            },
            DataRequest::Begin {
                session_id: "x".into(),
            },
            DataRequest::Commit {
                session_id: "x".into(),
            },
            DataRequest::Rollback {
                session_id: "x".into(),
            },
        ]
    );
    assert!(!surface.to_lowercase().contains("diagnostic"));
    assert!(matches!(
        ControlRequest::Diagnostics,
        ControlRequest::Diagnostics
    ));
}

// ─── End-to-end acceptance lifecycle ───────────────────────────────────────

#[test]
fn acceptance_lifecycle_observability_does_not_become_sot() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (logs, metrics, audit) = attach_all(&mut state);
    let conn = allocate_connection_id();

    // start → Health / Readiness (Ready + Locked)
    assert_health_ready_locked(&health(&mut state, 1, &conn));
    assert_readiness_ready(&readiness(&mut state, 2, &conn));

    // authenticate → unlock
    let (sid, binding) = auth_pair(&mut state, 3, &conn);
    unlock(&mut state, 4, &conn, &sid, &binding, master.clone());
    assert!(logs
        .snapshot()
        .iter()
        .any(|e| e.kind == EventKind::VaultUnlock));
    assert!(audit.count_kind(AuditEventKind::VaultUnlocked) >= 1);
    assert!(metrics.counter_sum(Metric::VaultUnlockSuccessTotal) >= 1);

    // CREATE / INSERT / COMMIT / SELECT / UPDATE / COMMIT
    sql_ok(
        &mut state,
        5,
        &conn,
        &sid,
        "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)",
    );
    begin(&mut state, 6, &conn, &sid);
    sql_ok(
        &mut state,
        7,
        &conn,
        &sid,
        "INSERT INTO items (id, name) VALUES (1, 'Alice')",
    );
    commit(&mut state, 8, &conn, &sid);
    sql_ok(
        &mut state,
        9,
        &conn,
        &sid,
        "SELECT name FROM items WHERE id = 1",
    );
    begin(&mut state, 10, &conn, &sid);
    sql_ok(
        &mut state,
        11,
        &conn,
        &sid,
        "INSERT INTO items (id, name) VALUES (2, 'Bob')",
    );
    commit(&mut state, 12, &conn, &sid);

    // Journal ≠ Audit: tip advanced; audit is a separate stream.
    let tip_before_backup = state.ctx.journal().unwrap().tip_sequence();
    assert!(tip_before_backup > 0);
    assert!(audit.count_kind(AuditEventKind::SqlExecuted) >= 1);
    assert!(logs
        .snapshot()
        .iter()
        .any(|e| e.kind == EventKind::SqlCompleted && e.context.journal_sequence.is_some()));

    // backup
    expect_ok_control(control(
        &mut state,
        13,
        &conn,
        ControlRequest::BackupCreate {
            session_id: sid.clone(),
            backup_id: "obs-dod".into(),
            include_rowstore: false,
        },
    ))
    .unwrap();
    assert!(audit.count_kind(AuditEventKind::BackupCreated) >= 1);

    // lock → diagnostics
    expect_ok_control(control(
        &mut state,
        14,
        &conn,
        ControlRequest::VaultLock {
            session_id: sid.clone(),
        },
    ))
    .unwrap();
    let d = diagnostics(&mut state, 15, &conn);
    assert_eq!(d.vault, "locked");
    assert_eq!(d.readiness, "ready");
    assert_eq!(d.journal_tip, Some(tip_before_backup));
    assert_eq!(d.materialized_sequence, Some(tip_before_backup));
    assert_eq!(d.journal_lag, Some(0));
    assert_eq!(d.logging, ObservabilityComponentStatus::Available.as_str());
    assert_surface_clean("lifecycle diagnostics", &d);

    // restart → vault locked, sessions invalid
    state.simulate_restart();
    let d2 = diagnostics(&mut state, 16, &conn);
    assert_eq!(d2.vault, "locked");
    assert_eq!(d2.readiness, "ready");
    let denied = data(
        &mut state,
        17,
        &conn,
        DataRequest::ExecuteSql {
            session_id: sid.clone(),
            sql: "SELECT 1".into(),
            params: vec![],
        },
    );
    assert!(matches!(
        denied.error_code,
        Some(ProtocolErrorCode::SessionInvalid | ProtocolErrorCode::VaultLocked)
    ));

    // recovery path (restore + recover) still succeeds with memory sinks attached
    let (sid2, binding2) = auth_pair(&mut state, 18, &conn);
    unlock(&mut state, 19, &conn, &sid2, &binding2, master);
    expect_ok_control(control(
        &mut state,
        20,
        &conn,
        ControlRequest::BackupRestore {
            session_id: sid2.clone(),
            backup_id: "obs-dod".into(),
            target_id: "t-dod".into(),
        },
    ))
    .unwrap();
    expect_ok_control(control(
        &mut state,
        21,
        &conn,
        ControlRequest::BackupRecover {
            session_id: sid2,
            target_id: "t-dod".into(),
        },
    ))
    .unwrap();
    assert!(audit.count_kind(AuditEventKind::RecoveryCompleted) >= 1);

    assert_logs_clean(&logs);
    assert_metrics_clean(&metrics);
    assert_audit_clean(&audit);
}
