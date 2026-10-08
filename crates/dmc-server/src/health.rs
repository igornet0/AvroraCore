//! Phase 7.9.6 — Compute sanitized Health / Readiness from Core operational state.

use std::path::Path;

use dmc_backup::{RecoveryGate, RecoveryState, RECOVERY_STATE_FILE};
use dmc_observability::{
    HealthStatus, Liveness, Metric, MetricLabels, Readiness, ReadinessReasonCode, VaultHealth,
};

use crate::state::{CoreLifecycle, CoreServerState};
use crate::unlock_gate::VaultState;

/// Evaluate current health snapshot (Control plane). No secrets / paths.
pub fn evaluate_health(state: &mut CoreServerState) -> HealthStatus {
    let previous = state.operational.last_readiness;
    let status = compute_health(state);
    publish_health_side_effects(state, previous, &status);
    status
}

pub fn evaluate_readiness(state: &mut CoreServerState) -> (Readiness, Option<ReadinessReasonCode>) {
    let h = evaluate_health(state);
    (h.readiness, h.reason_code)
}

pub fn liveness(state: &CoreServerState) -> Liveness {
    match state.operational.lifecycle {
        CoreLifecycle::Failed | CoreLifecycle::Stopped => Liveness::NotAlive,
        CoreLifecycle::Initializing | CoreLifecycle::Ready | CoreLifecycle::Stopping => {
            Liveness::Alive
        }
    }
}

fn compute_health(state: &CoreServerState) -> HealthStatus {
    let vault = match state.vault_state() {
        VaultState::Locked => VaultHealth::Locked,
        VaultState::Unlocked => VaultHealth::Unlocked,
    };

    let live = liveness(state);

    let (readiness, reason_code) = match state.operational.lifecycle {
        CoreLifecycle::Initializing => (
            Readiness::Initializing,
            Some(ReadinessReasonCode::Initializing),
        ),
        CoreLifecycle::Failed => (Readiness::Failed, Some(ReadinessReasonCode::CoreFailed)),
        CoreLifecycle::Stopping | CoreLifecycle::Stopped => (Readiness::NotReady, None),
        CoreLifecycle::Ready => readiness_when_core_ready(state),
    };

    HealthStatus {
        liveness: live,
        readiness,
        vault,
        reason_code,
    }
}

fn readiness_when_core_ready(state: &CoreServerState) -> (Readiness, Option<ReadinessReasonCode>) {
    // Sealed storage (vault locked, D4-A) is a normal state: SQL is refused with
    // VaultLocked until unlock, the Core itself is ready.
    if state.ctx.journal().is_none() && !state.storage_sealed() {
        return (
            Readiness::NotReady,
            Some(ReadinessReasonCode::JournalUnavailable),
        );
    }
    if let Some(reason) = recovery_overlay(&state.data_root) {
        return (Readiness::NotReady, Some(reason));
    }
    (Readiness::Ready, None)
}

/// Only consult RecoveryGate when a recovery state file exists on this data root.
/// Absence means a normal live Core (not mid-restore) → no negative overlay.
fn recovery_overlay(data_root: &Path) -> Option<ReadinessReasonCode> {
    let path = data_root.join(RECOVERY_STATE_FILE);
    if !path.is_file() {
        return None;
    }
    match RecoveryGate::load(data_root) {
        Ok(gate) => match gate.state {
            RecoveryState::Ready => None,
            RecoveryState::Failed => Some(ReadinessReasonCode::RecoveryFailed),
            RecoveryState::Restored | RecoveryState::Recovering => {
                Some(ReadinessReasonCode::RecoveryRequired)
            }
        },
        Err(_) => Some(ReadinessReasonCode::RecoveryFailed),
    }
}

fn publish_health_side_effects(
    state: &mut CoreServerState,
    previous: Option<Readiness>,
    status: &HealthStatus,
) {
    state.metrics.set_gauge(
        Metric::CoreLiveness,
        if status.liveness == Liveness::Alive {
            1
        } else {
            0
        },
        MetricLabels::default(),
    );
    state.metrics.set_gauge(
        Metric::CoreReady,
        if status.readiness.is_ready() { 1 } else { 0 },
        MetricLabels::default(),
    );

    // Structured log only on readiness *change* — never AuditEvent on health polling.
    if previous != Some(status.readiness) {
        tracing::info!(
            event = "readiness.changed",
            from = previous.map(|r| r.as_str()).unwrap_or("none"),
            to = status.readiness.as_str(),
            reason = status
                .reason_code
                .map(|c| c.as_str())
                .unwrap_or(""),
            "readiness changed"
        );
    }
    state.operational.last_readiness = Some(status.readiness);
}

/// Wire-safe strings for ControlResponse (no internal dumps).
pub fn health_to_wire(status: &HealthStatus) -> (String, String, String, Option<String>) {
    (
        status.liveness.as_str().into(),
        status.readiness.as_str().into(),
        status.vault.as_str().into(),
        status.reason_code.map(|c| c.as_str().into()),
    )
}
