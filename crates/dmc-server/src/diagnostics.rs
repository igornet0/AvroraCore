//! Phase 7.9.7 — Read-only operational diagnostics (Control plane).

use std::path::Path;

use dmc_backup::{RecoveryGate, RecoveryState, RECOVERY_STATE_FILE};
use dmc_observability::{
    ComponentReady, ConnectionDiagnostics, DiagnosticsSnapshot, JournalDiagnostics,
    MaterializerDiagnostics, ObservabilityDiagnostics, RecoveryDiagnostics, RuntimeDiagnostics,
    StorageDiagnostics,
};
use dmc_protocol::DiagnosticsWire;

use crate::health;
use crate::state::{CoreLifecycle, CoreServerState};

const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Build a sanitized diagnostics snapshot. Read-only — never mutates vault/SQL/journal.
pub fn evaluate_diagnostics(state: &mut CoreServerState) -> DiagnosticsSnapshot {
    // Health evaluation may update readiness metrics / change log — observational only.
    let health_status = health::evaluate_health(state);

    let (tip, materialized) = match state.ctx.journal() {
        Some(j) => (Some(j.tip_sequence()), Some(j.watermark_sequence())),
        None => (None, None),
    };
    let lag = match (tip, materialized) {
        (Some(t), Some(m)) => Some(t.saturating_sub(m)),
        _ => None,
    };

    let storage = storage_diagnostics(state);
    let recovery = recovery_diagnostics(&state.data_root);
    let uptime_secs = state.operational.started_at.elapsed().as_secs();
    let process_state = match state.operational.lifecycle {
        CoreLifecycle::Ready => "running",
        CoreLifecycle::Initializing => "initializing",
        CoreLifecycle::Stopping => "stopping",
        CoreLifecycle::Stopped => "stopped",
        CoreLifecycle::Failed => "failed",
    };

    DiagnosticsSnapshot {
        version: CORE_VERSION.to_string(),
        runtime: RuntimeDiagnostics {
            process_state: process_state.into(),
            uptime_secs,
            version: CORE_VERSION.to_string(),
        },
        health: health_status,
        journal: JournalDiagnostics {
            tip_sequence: tip,
        },
        materializer: MaterializerDiagnostics {
            materialized_sequence: materialized,
            journal_lag: lag,
        },
        storage,
        recovery,
        connections: ConnectionDiagnostics {
            connections_active: state.metrics.connections_active().max(0) as u64,
            connections_accepted_total: state.metrics.connections_accepted_total(),
        },
        observability: ObservabilityDiagnostics {
            logging: state.observability.probe(),
            metrics: state.metrics.probe(),
            audit: state.audit.probe(),
        },
    }
}

fn storage_diagnostics(state: &CoreServerState) -> StorageDiagnostics {
    let journal_ok = state.ctx.journal().is_some();
    let catalog_ok = journal_ok && state.ctx.session_catalog().is_ok();
    let ready = |ok: bool| {
        if ok {
            ComponentReady::Ready
        } else {
            ComponentReady::NotReady
        }
    };
    // V1: journal attachment implies rowstore/index/statistics subsystems are initialized.
    StorageDiagnostics {
        catalog: ready(catalog_ok),
        rowstore: ready(journal_ok),
        indexes: ready(journal_ok),
        statistics: ready(journal_ok),
    }
}

fn recovery_diagnostics(data_root: &Path) -> RecoveryDiagnostics {
    let path = data_root.join(RECOVERY_STATE_FILE);
    if !path.is_file() {
        return RecoveryDiagnostics {
            state: None,
            checkpoint_sequence: None,
        };
    }
    match RecoveryGate::load(data_root) {
        Ok(gate) => RecoveryDiagnostics {
            state: Some(recovery_state_label(gate.state).into()),
            checkpoint_sequence: Some(gate.checkpoint_sequence),
        },
        Err(_) => RecoveryDiagnostics {
            state: Some("failed".into()),
            checkpoint_sequence: None,
        },
    }
}

fn recovery_state_label(state: RecoveryState) -> &'static str {
    match state {
        RecoveryState::Restored => "restored",
        RecoveryState::Recovering => "recovering",
        RecoveryState::Ready => "ready",
        RecoveryState::Failed => "failed",
    }
}

pub fn diagnostics_to_wire(snap: &DiagnosticsSnapshot) -> DiagnosticsWire {
    DiagnosticsWire {
        version: snap.version.clone(),
        process_state: snap.runtime.process_state.clone(),
        uptime_secs: snap.runtime.uptime_secs,
        liveness: snap.health.liveness.as_str().into(),
        readiness: snap.health.readiness.as_str().into(),
        vault: snap.health.vault.as_str().into(),
        readiness_reason_code: snap.health.reason_code.map(|c| c.as_str().into()),
        journal_tip: snap.journal.tip_sequence,
        materialized_sequence: snap.materializer.materialized_sequence,
        journal_lag: snap.materializer.journal_lag,
        catalog: snap.storage.catalog.as_str().into(),
        rowstore: snap.storage.rowstore.as_str().into(),
        indexes: snap.storage.indexes.as_str().into(),
        statistics: snap.storage.statistics.as_str().into(),
        recovery_state: snap.recovery.state.clone(),
        recovery_checkpoint_sequence: snap.recovery.checkpoint_sequence,
        connections_active: snap.connections.connections_active,
        connections_accepted_total: snap.connections.connections_accepted_total,
        logging: snap.observability.logging.as_str().into(),
        metrics: snap.observability.metrics.as_str().into(),
        audit: snap.observability.audit.as_str().into(),
    }
}
