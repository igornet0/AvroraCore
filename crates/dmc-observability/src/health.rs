//! Phase 7.9.6 — Liveness / Readiness / Vault (independent operational axes).
//!
//! `Liveness ≠ Readiness ≠ VaultUnlocked ≠ Authenticated`.

use serde::{Deserialize, Serialize};

/// Process / runtime can serve control requests?
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Liveness {
    Alive,
    NotAlive,
}

impl Liveness {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Alive => "alive",
            Self::NotAlive => "not_alive",
        }
    }
}

/// Core ready for production traffic (not the same as vault unlocked / SQL allowed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Readiness {
    Initializing,
    Ready,
    NotReady,
    Failed,
}

impl Readiness {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Initializing => "initializing",
            Self::Ready => "ready",
            Self::NotReady => "not_ready",
            Self::Failed => "failed",
        }
    }

    pub fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// Vault axis — independent of readiness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultHealth {
    Locked,
    Unlocked,
}

impl VaultHealth {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Locked => "locked",
            Self::Unlocked => "unlocked",
        }
    }
}

/// Closed reason codes for readiness (no free-form internal errors / paths).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessReasonCode {
    Initializing,
    CoreFailed,
    JournalUnavailable,
    RecoveryRequired,
    RecoveryFailed,
}

impl ReadinessReasonCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Initializing => "Initializing",
            Self::CoreFailed => "CoreFailed",
            Self::JournalUnavailable => "JournalUnavailable",
            Self::RecoveryRequired => "RecoveryRequired",
            Self::RecoveryFailed => "RecoveryFailed",
        }
    }
}

/// Sanitized operational snapshot for Control plane.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthStatus {
    pub liveness: Liveness,
    pub readiness: Readiness,
    pub vault: VaultHealth,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<ReadinessReasonCode>,
}

impl HealthStatus {
    pub fn alive_ready_locked() -> Self {
        Self {
            liveness: Liveness::Alive,
            readiness: Readiness::Ready,
            vault: VaultHealth::Locked,
            reason_code: None,
        }
    }
}
