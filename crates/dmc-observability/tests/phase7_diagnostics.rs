//! Phase 7.9.7 — DiagnosticsSnapshot contract unit tests.

use dmc_observability::{
    assert_no_secrets_in_diagnostics, ComponentReady, ConnectionDiagnostics, DiagnosticsSnapshot,
    HealthStatus, JournalDiagnostics, Liveness, MaterializerDiagnostics, ObservabilityComponentStatus,
    ObservabilityDiagnostics, Readiness, RecoveryDiagnostics, RuntimeDiagnostics, StorageDiagnostics,
    VaultHealth,
};

fn sample_snap() -> DiagnosticsSnapshot {
    DiagnosticsSnapshot {
        version: "0.1.0".into(),
        runtime: RuntimeDiagnostics {
            process_state: "running".into(),
            uptime_secs: 12,
            version: "0.1.0".into(),
        },
        health: HealthStatus {
            liveness: Liveness::Alive,
            readiness: Readiness::Ready,
            vault: VaultHealth::Locked,
            reason_code: None,
        },
        journal: JournalDiagnostics {
            tip_sequence: Some(1500),
        },
        materializer: MaterializerDiagnostics {
            materialized_sequence: Some(1500),
            journal_lag: Some(0),
        },
        storage: StorageDiagnostics {
            catalog: ComponentReady::Ready,
            rowstore: ComponentReady::Ready,
            indexes: ComponentReady::Ready,
            statistics: ComponentReady::Ready,
        },
        recovery: RecoveryDiagnostics {
            state: None,
            checkpoint_sequence: None,
        },
        connections: ConnectionDiagnostics {
            connections_active: 1,
            connections_accepted_total: 3,
        },
        observability: ObservabilityDiagnostics {
            logging: ObservabilityComponentStatus::Available,
            metrics: ObservabilityComponentStatus::Available,
            audit: ObservabilityComponentStatus::Available,
        },
    }
}

#[test]
fn deterministic_snapshot_shape() {
    let snap = sample_snap();
    let json = serde_json::to_string(&snap).unwrap();
    let back: DiagnosticsSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(back.journal.tip_sequence, Some(1500));
    assert_eq!(back.materializer.journal_lag, Some(0));
    assert_eq!(back.health.vault, VaultHealth::Locked);
}

#[test]
fn lag_zero_when_tip_equals_materialized() {
    let snap = sample_snap();
    assert_eq!(snap.journal.tip_sequence, snap.materializer.materialized_sequence);
    assert_eq!(snap.materializer.journal_lag, Some(0));
}

#[test]
fn positive_lag_when_journal_ahead() {
    let mut snap = sample_snap();
    snap.journal.tip_sequence = Some(1500);
    snap.materializer.materialized_sequence = Some(1497);
    snap.materializer.journal_lag = Some(3);
    assert_eq!(snap.materializer.journal_lag, Some(3));
    assert_no_secrets_in_diagnostics(&snap).unwrap();
}

#[test]
fn optional_recovery_absent_by_default() {
    let snap = sample_snap();
    assert!(snap.recovery.state.is_none());
    assert!(snap.recovery.checkpoint_sequence.is_none());
}

#[test]
fn no_secrets_or_paths_in_snapshot() {
    let snap = sample_snap();
    assert_no_secrets_in_diagnostics(&snap).unwrap();
}
