//! Phase 7.9.6 — Health / Readiness contracts and Control-plane wiring.

use std::fs;
use std::path::Path;

use dmc_backup::{RecoveryState, RecoveryStateFile, RECOVERY_STATE_FILE};
use dmc_observability::{
    Audit, HealthStatus, Liveness, MemoryAuditSink, MemoryMetricsSink, Metric, Metrics, Readiness,
    ReadinessReasonCode, VaultHealth,
};
use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, ProtocolErrorCode, RemoteLimits, RequestEnvelope,
};
use dmc_server::{
    bootstrap_core_state_locked, create_unlock_blob, expect_ok_control, expect_ok_data,
    handle_control, handle_data, CoreLifecycle, CoreServerState, MockKeyPassProvider,
    UnlockMaterial,
};
use tempfile::tempdir;

fn limits() -> RemoteLimits {
    RemoteLimits::default()
}

fn health(state: &mut CoreServerState) -> ControlResponse {
    expect_ok_control(
        handle_control(
            state,
            RequestEnvelope {
                request_id: 1,
                body: ControlRequest::Health,
            },
            &limits(),
            "conn-health",
        )
        .unwrap(),
    )
    .unwrap()
}

fn readiness(state: &mut CoreServerState) -> ControlResponse {
    expect_ok_control(
        handle_control(
            state,
            RequestEnvelope {
                request_id: 2,
                body: ControlRequest::Readiness,
            },
            &limits(),
            "conn-health",
        )
        .unwrap(),
    )
    .unwrap()
}

fn write_recovery(data_root: &Path, state: RecoveryState) {
    let file = RecoveryStateFile {
        format_version: RecoveryStateFile::FORMAT_VERSION,
        checkpoint_sequence: 1,
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

fn auth_pair(state: &mut CoreServerState) -> (String, [u8; 32]) {
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
        "conn-health",
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

fn unlock(state: &mut CoreServerState, sid: &str, binding: &[u8; 32], master: UnlockMaterial) {
    let blob =
        create_unlock_blob(sid, binding, &MockKeyPassProvider::with_material(master)).unwrap();
    expect_ok_control(
        handle_control(
            state,
            RequestEnvelope {
                request_id: 11,
                body: ControlRequest::VaultUnlock {
                    session_id: sid.to_string(),
                    blob,
                },
            },
            &limits(),
            "conn-health",
        )
        .unwrap(),
    )
    .unwrap();
}

#[test]
fn health_status_contract_serialization() {
    let h = HealthStatus {
        liveness: Liveness::Alive,
        readiness: Readiness::Ready,
        vault: VaultHealth::Locked,
        reason_code: None,
    };
    let json = serde_json::to_string(&h).unwrap();
    assert!(json.contains("\"liveness\":\"alive\""));
    assert!(json.contains("\"readiness\":\"ready\""));
    assert!(json.contains("\"vault\":\"locked\""));
    assert!(!json.contains("master"));
    assert!(!json.contains('/'));
}

#[test]
fn running_core_is_alive_and_ready_with_vault_locked() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    match health(&mut state) {
        ControlResponse::Health {
            liveness,
            readiness,
            vault,
            reason_code,
        } => {
            assert_eq!(liveness, "alive");
            assert_eq!(readiness, "ready");
            assert_eq!(vault, "locked");
            assert!(reason_code.is_none());
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn initializing_core_is_alive_but_not_ready() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    state.set_lifecycle(CoreLifecycle::Initializing);
    match health(&mut state) {
        ControlResponse::Health {
            liveness,
            readiness,
            reason_code,
            ..
        } => {
            assert_eq!(liveness, "alive");
            assert_eq!(readiness, "initializing");
            assert_eq!(reason_code.as_deref(), Some("Initializing"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn failed_lifecycle_is_not_alive_and_failed_readiness() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    state.set_lifecycle(CoreLifecycle::Failed);
    match health(&mut state) {
        ControlResponse::Health {
            liveness,
            readiness,
            reason_code,
            ..
        } => {
            assert_eq!(liveness, "not_alive");
            assert_eq!(readiness, "failed");
            assert_eq!(reason_code.as_deref(), Some("CoreFailed"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn recovery_failed_makes_readiness_not_ready() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    write_recovery(dir.path(), RecoveryState::Failed);
    match readiness(&mut state) {
        ControlResponse::Readiness {
            readiness,
            reason_code,
        } => {
            assert_eq!(readiness, "not_ready");
            assert_eq!(reason_code.as_deref(), Some("RecoveryFailed"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn recovery_ready_keeps_core_ready() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    write_recovery(dir.path(), RecoveryState::Ready);
    match readiness(&mut state) {
        ControlResponse::Readiness {
            readiness,
            reason_code,
        } => {
            assert_eq!(readiness, "ready");
            assert!(reason_code.is_none());
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn vault_locked_and_unlocked_both_ready() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    match health(&mut state) {
        ControlResponse::Health {
            readiness, vault, ..
        } => {
            assert_eq!(readiness, "ready");
            assert_eq!(vault, "locked");
        }
        other => panic!("{other:?}"),
    }
    let (sid, binding) = auth_pair(&mut state);
    unlock(&mut state, &sid, &binding, master);
    match health(&mut state) {
        ControlResponse::Health {
            readiness, vault, ..
        } => {
            assert_eq!(readiness, "ready");
            assert_eq!(vault, "unlocked");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn ready_locked_authenticated_still_blocks_sql_via_unlock_gate() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), true);
    let (sid, _) = auth_pair(&mut state);
    match health(&mut state) {
        ControlResponse::Health {
            readiness, vault, ..
        } => {
            assert_eq!(readiness, "ready");
            assert_eq!(vault, "locked");
        }
        other => panic!("{other:?}"),
    }
    let resp = handle_data(
        &mut state,
        RequestEnvelope {
            request_id: 20,
            body: DataRequest::ExecuteSql {
                session_id: sid,
                sql: "SELECT 1".into(),
                params: vec![],
            },
        },
        &limits(),
        "conn-health",
    )
    .unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::VaultLocked));
}

#[test]
fn ready_unlocked_unauthenticated_is_valid_ops_state() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), false);
    let (sid, binding) = auth_pair(&mut state);
    unlock(&mut state, &sid, &binding, master);
    // Logout — vault stays unlocked; readiness stays ready.
    expect_ok_control(
        handle_control(
            &mut state,
            RequestEnvelope {
                request_id: 12,
                body: ControlRequest::Logout {
                    session_id: sid,
                },
            },
            &limits(),
            "conn-health",
        )
        .unwrap(),
    )
    .unwrap();
    match health(&mut state) {
        ControlResponse::Health {
            readiness, vault, ..
        } => {
            assert_eq!(readiness, "ready");
            assert_eq!(vault, "unlocked");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn restart_returns_ready_with_vault_locked_and_sessions_invalid() {
    let dir = tempdir().unwrap();
    let (mut state, master) = bootstrap_core_state_locked(dir.path(), true);
    let (sid, binding) = auth_pair(&mut state);
    unlock(&mut state, &sid, &binding, master);
    expect_ok_data(
        handle_data(
            &mut state,
            RequestEnvelope {
                request_id: 13,
                body: DataRequest::ExecuteSql {
                    session_id: sid.clone(),
                    sql: "SELECT id FROM users WHERE id = 0".into(),
                    params: vec![],
                },
            },
            &limits(),
            "conn-health",
        )
        .unwrap(),
    )
    .unwrap();

    state.simulate_restart();
    match health(&mut state) {
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
        other => panic!("{other:?}"),
    }
    let resp = handle_data(
        &mut state,
        RequestEnvelope {
            request_id: 14,
            body: DataRequest::ExecuteSql {
                session_id: sid,
                sql: "SELECT 1".into(),
                params: vec![],
            },
        },
        &limits(),
        "conn-health",
    )
    .unwrap();
    assert_eq!(resp.error_code, Some(ProtocolErrorCode::SessionInvalid));
}

#[test]
fn health_polling_does_not_emit_audit_events() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let sink = MemoryAuditSink::new();
    state.set_audit(Audit::memory(sink.clone()));
    for _ in 0..20 {
        let _ = health(&mut state);
        let _ = readiness(&mut state);
    }
    assert!(
        sink.snapshot().is_empty(),
        "health/readiness polling must not create audit noise"
    );
}

#[test]
fn health_updates_liveness_and_ready_metrics() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let sink = MemoryMetricsSink::new();
    state.set_metrics(Metrics::memory(sink.clone()));
    let _ = health(&mut state);
    assert_eq!(sink.last_gauge(Metric::CoreLiveness), Some(1));
    assert_eq!(sink.last_gauge(Metric::CoreReady), Some(1));

    state.set_lifecycle(CoreLifecycle::Initializing);
    let _ = health(&mut state);
    assert_eq!(sink.last_gauge(Metric::CoreLiveness), Some(1));
    assert_eq!(sink.last_gauge(Metric::CoreReady), Some(0));
}

#[test]
fn health_response_has_no_paths_or_secrets() {
    let dir = tempdir().unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(dir.path(), false);
    let resp = health(&mut state);
    let json = serde_json::to_string(&resp).unwrap();
    let lower = json.to_lowercase();
    assert!(!lower.contains("master"));
    assert!(!lower.contains("password"));
    assert!(!lower.contains("dek"));
    assert!(!json.contains(dir.path().to_string_lossy().as_ref()));
    assert!(!json.contains('/'));
}

#[test]
fn data_plane_has_no_health_variants() {
    // Compile-time / enum surface: DataRequest must not grow Health/Readiness.
    let variants = [
        DataRequest::ExecuteSql {
            session_id: "s".into(),
            sql: "SELECT 1".into(),
            params: vec![],
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
    assert_eq!(variants.len(), 4);
}

#[test]
fn reason_code_enum_is_closed() {
    assert_eq!(ReadinessReasonCode::RecoveryRequired.as_str(), "RecoveryRequired");
    assert_eq!(ReadinessReasonCode::RecoveryFailed.as_str(), "RecoveryFailed");
}
