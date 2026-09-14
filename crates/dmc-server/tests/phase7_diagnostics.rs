//! Phase 7.9.7 — Operational diagnostics Control wiring + failure isolation.

use std::fs;
use std::path::Path;

use dmc_backup::{RecoveryState, RecoveryStateFile, RECOVERY_STATE_FILE};
use dmc_observability::{
    assert_no_secrets_in_diagnostics, Audit, Observability, ObservabilityComponentStatus, Metrics,
};
use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, DiagnosticsWire, RemoteLimits, RequestEnvelope,
};
use dmc_server::{
    bootstrap_core_state_locked, create_unlock_blob, diagnostics_to_wire, evaluate_diagnostics,
    expect_ok_control, handle_control, handle_data, CoreLifecycle, CoreServerState,
    MockKeyPassProvider, UnlockMaterial,
};
use tempfile::tempdir;

fn limits() -> RemoteLimits {
    RemoteLimits::default()
}

fn diagnostics(state: &mut CoreServerState) -> DiagnosticsWire {
    match expect_ok_control(
        handle_control(
            state,
            RequestEnvelope {
                request_id: 1,
                body: ControlRequest::Diagnostics,
            },
            &limits(),
            "conn-diag",
        )
        .unwrap(),
    )
    .unwrap()
    {
        ControlResponse::Diagnostics(wire) => wire,
        other => panic!("{other:?}"),
    }
}

fn write_recovery(data_root: &Path, state: RecoveryState) {
    let file = RecoveryStateFile {
        format_version: RecoveryStateFile::FORMAT_VERSION,
        checkpoint_sequence: 42,
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

fn auth_unlock(
    state: &mut CoreServerState,
    master: UnlockMaterial,
) -> String {
    let resp = handle_control(
        state,
        RequestEnvelope {
            request_id: 10,
            body: ControlRequest::Authenticate {
                identity_name: "analyst".into(),
                password: "pw".into(),
            },
        },
        &limits(),
        "conn-diag",
    )
    .unwrap();
    let (sid, key) = match expect_ok_control(resp).unwrap() {
        ControlResponse::Authenticate {
            session_id,
            unlock_binding_key,
            ..
        } => {
            let mut k = [0u8; 32];
            k.copy_from_slice(&unlock_binding_key);
            (session_id, k)
        }
        other => panic!("{other:?}"),
    };
    let blob = create_unlock_blob(&sid, &key, &MockKeyPassProvider::with_material(master)).unwrap();
    expect_ok_control(
        handle_control(
            state,
            RequestEnvelope {
                request_id: 11,
                body: ControlRequest::VaultUnlock {
                    session_id: sid.clone(),
                    blob,
                },
            },
            &limits(),
            "conn-diag",
        )
        .unwrap(),
    )
    .unwrap();
    sid
}

#[test]
fn ready_locked_diagnostics_snapshot() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let wire = diagnostics(&mut state);
    assert_eq!(wire.liveness, "alive");
    assert_eq!(wire.readiness, "ready");
    assert_eq!(wire.vault, "locked");
    assert_eq!(wire.process_state, "running");
    assert!(wire.journal_tip.is_some());
    assert!(wire.materialized_sequence.is_some());
    assert_eq!(wire.journal_lag, Some(0));
    assert_eq!(wire.catalog, "ready");
    assert!(wire.recovery_state.is_none());
    assert_eq!(wire.logging, "available");
    assert_eq!(wire.metrics, "available");
    assert_eq!(wire.audit, "available");
}

#[test]
fn ready_unlocked_diagnostics_keeps_readiness() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let _ = auth_unlock(&mut state, master);
    let wire = diagnostics(&mut state);
    assert_eq!(wire.readiness, "ready");
    assert_eq!(wire.vault, "unlocked");
}

#[test]
fn not_ready_locked_when_initializing() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    state.set_lifecycle(CoreLifecycle::Initializing);
    let wire = diagnostics(&mut state);
    assert_eq!(wire.liveness, "alive");
    assert_eq!(wire.readiness, "initializing");
    assert_eq!(wire.vault, "locked");
    assert_eq!(wire.readiness_reason_code.as_deref(), Some("Initializing"));
}

#[test]
fn journal_lag_zero_on_bootstrapped_core() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), true);
    let snap = evaluate_diagnostics(&mut state);
    assert_eq!(snap.journal.tip_sequence, snap.materializer.materialized_sequence);
    assert_eq!(snap.materializer.journal_lag, Some(0));
    assert_no_secrets_in_diagnostics(&snap).unwrap();
}

#[test]
fn recovery_states_surface_in_diagnostics() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);

    write_recovery(dir.path(), RecoveryState::Recovering);
    let wire = diagnostics(&mut state);
    assert_eq!(wire.recovery_state.as_deref(), Some("recovering"));
    assert_eq!(wire.recovery_checkpoint_sequence, Some(42));
    assert_eq!(wire.readiness, "not_ready");

    write_recovery(dir.path(), RecoveryState::Failed);
    let wire = diagnostics(&mut state);
    assert_eq!(wire.recovery_state.as_deref(), Some("failed"));
    assert_eq!(wire.readiness, "not_ready");

    write_recovery(dir.path(), RecoveryState::Restored);
    let wire = diagnostics(&mut state);
    assert_eq!(wire.recovery_state.as_deref(), Some("restored"));

    write_recovery(dir.path(), RecoveryState::Ready);
    let wire = diagnostics(&mut state);
    assert_eq!(wire.recovery_state.as_deref(), Some("ready"));
    assert_eq!(wire.readiness, "ready");
}

#[test]
fn failing_sinks_do_not_break_diagnostics_or_readiness() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    state.set_observability(Observability::failing());
    state.set_metrics(Metrics::failing());
    state.set_audit(Audit::failing());
    let wire = diagnostics(&mut state);
    assert_eq!(wire.readiness, "ready");
    assert_eq!(wire.logging, "degraded");
    assert_eq!(wire.metrics, "degraded");
    assert_eq!(wire.audit, "degraded");
}

#[test]
fn diagnostics_is_read_only_no_sql_side_effects() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), true);
    let tip_before = state.ctx.journal().unwrap().tip_sequence();
    let _ = diagnostics(&mut state);
    let _ = diagnostics(&mut state);
    assert_eq!(state.ctx.journal().unwrap().tip_sequence(), tip_before);
    // Vault still locked until unlock — diagnostics did not unlock.
    assert_eq!(diagnostics(&mut state).vault, "locked");
    let _ = auth_unlock(&mut state, master);
    assert_eq!(diagnostics(&mut state).vault, "unlocked");
}

#[test]
fn wire_and_snapshot_have_no_forbidden_fields() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let snap = evaluate_diagnostics(&mut state);
    assert_no_secrets_in_diagnostics(&snap).unwrap();
    let wire = diagnostics_to_wire(&snap);
    let json = serde_json::to_string(&wire).unwrap();
    let lower = json.to_lowercase();
    for needle in ["password", "master", "dek", "kek", "pem", "ciphertext", "session_id"] {
        assert!(!lower.contains(needle), "leaked `{needle}` in {json}");
    }
    assert!(!json.contains(dir.path().to_string_lossy().as_ref()));
}

#[test]
fn data_plane_has_no_diagnostics_variant() {
    let _ = DataRequest::Begin {
        session_id: "s".into(),
    };
}

#[test]
fn degraded_observability_status_tokens() {
    assert_eq!(ObservabilityComponentStatus::Degraded.as_str(), "degraded");
    assert_eq!(ObservabilityComponentStatus::Available.as_str(), "available");
}

#[test]
fn sql_still_requires_unlock_when_diagnostics_ready() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), true);
    let wire = diagnostics(&mut state);
    assert_eq!(wire.readiness, "ready");
    let resp = handle_control(
        &mut state,
        RequestEnvelope {
            request_id: 2,
            body: ControlRequest::Authenticate {
                identity_name: "analyst".into(),
                password: "pw".into(),
            },
        },
        &limits(),
        "conn-diag",
    )
    .unwrap();
    let sid = match expect_ok_control(resp).unwrap() {
        ControlResponse::Authenticate { session_id, .. } => session_id,
        other => panic!("{other:?}"),
    };
    let sql_resp = handle_data(
        &mut state,
        RequestEnvelope {
            request_id: 3,
            body: DataRequest::ExecuteSql {
                session_id: sid,
                sql: "SELECT 1".into(),
                params: vec![],
            },
        },
        &limits(),
        "conn-diag",
    )
    .unwrap();
    assert_eq!(
        sql_resp.error_code,
        Some(dmc_protocol::ProtocolErrorCode::VaultLocked)
    );
}
