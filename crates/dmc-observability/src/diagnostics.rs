//! Phase 7.9.7 — Read-only operational diagnostics snapshot (not a control/security API).

use serde::{Deserialize, Serialize};

use crate::health::{HealthStatus, Liveness, Readiness, ReadinessReasonCode, VaultHealth};

/// Closed component readiness token (no paths).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentReady {
    Ready,
    NotReady,
}

impl ComponentReady {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::NotReady => "not_ready",
        }
    }
}

/// Observability sink availability — degraded ≠ Core NotReady.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservabilityComponentStatus {
    Available,
    Degraded,
}

impl ObservabilityComponentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Degraded => "degraded",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeDiagnostics {
    pub process_state: String,
    pub uptime_secs: u64,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalDiagnostics {
    pub tip_sequence: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializerDiagnostics {
    pub materialized_sequence: Option<u64>,
    /// `tip - materialized` when both known; never negative.
    pub journal_lag: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageDiagnostics {
    pub catalog: ComponentReady,
    pub rowstore: ComponentReady,
    pub indexes: ComponentReady,
    pub statistics: ComponentReady,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryDiagnostics {
    pub state: Option<String>,
    pub checkpoint_sequence: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionDiagnostics {
    pub connections_active: u64,
    pub connections_accepted_total: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservabilityDiagnostics {
    pub logging: ObservabilityComponentStatus,
    pub metrics: ObservabilityComponentStatus,
    pub audit: ObservabilityComponentStatus,
}

/// V1 read-only operational snapshot for Control plane.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticsSnapshot {
    pub version: String,
    pub runtime: RuntimeDiagnostics,
    pub health: HealthStatus,
    pub journal: JournalDiagnostics,
    pub materializer: MaterializerDiagnostics,
    pub storage: StorageDiagnostics,
    pub recovery: RecoveryDiagnostics,
    pub connections: ConnectionDiagnostics,
    pub observability: ObservabilityDiagnostics,
}

impl DiagnosticsSnapshot {
    pub fn readiness(&self) -> Readiness {
        self.health.readiness
    }

    pub fn liveness(&self) -> Liveness {
        self.health.liveness
    }

    pub fn vault(&self) -> VaultHealth {
        self.health.vault
    }

    pub fn readiness_reason(&self) -> Option<ReadinessReasonCode> {
        self.health.reason_code
    }
}

/// Ensure diagnostics JSON cannot carry secret markers or absolute paths.
pub fn assert_no_secrets_in_diagnostics(snap: &DiagnosticsSnapshot) -> Result<(), String> {
    let json = serde_json::to_string(snap).map_err(|e| e.to_string())?;
    let lower = json.to_lowercase();
    for needle in [
        "master_key",
        "unlockmaterial",
        "unlock_material",
        "\"dek\"",
        "\"kek\"",
        "keypass",
        "private_key",
        "-----begin",
        "password",
        "ciphertext",
        ".pem",
        ".key",
    ] {
        if lower.contains(needle) {
            return Err(format!("secret marker `{needle}` in diagnostics JSON"));
        }
    }
    if lower.contains("\"sql\":")
        || lower.contains("\"statement\":")
        || lower.contains("\"query\":")
        || lower.contains("session_id")
        || lower.contains("principal_id")
    {
        return Err("forbidden identity/SQL field in diagnostics".into());
    }
    // Absolute path leakage (unix / windows drive).
    if json.contains(":\\") || json.contains("\\\\") {
        return Err("filesystem path-like value in diagnostics".into());
    }
    // Heuristic: long absolute unix paths with multiple segments.
    if json.contains("/Users/") || json.contains("/var/") || json.contains("/home/") {
        return Err("absolute path in diagnostics".into());
    }
    Ok(())
}
