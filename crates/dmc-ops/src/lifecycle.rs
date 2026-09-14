//! Phase 7.10.2 — Process lifecycle state machine (ADR-026).
//!
//! Owns **only** process state transitions and “may accept new work” gates.
//! Does **not** open Journal, run recovery, unlock vault, run SQL, or bind transports.

use serde::{Deserialize, Serialize};

use crate::error::{LifecycleError, LifecycleResult as Result};

/// Process instance lifecycle (independent of readiness / vault / recovery gate).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    Starting,
    Ready,
    Stopping,
    Stopped,
    /// Terminal for this process instance (startup/init failure).
    Failed,
}

impl LifecycleState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Ready => "ready",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }

    /// Whether Control/Data may accept **new** work in this process state.
    pub fn accepts_new_work(self) -> bool {
        matches!(self, Self::Ready)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShutdownReason {
    OperatorRequest,
    Signal,
    FatalError,
    StartupAborted,
}

impl ShutdownReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OperatorRequest => "operator_request",
            Self::Signal => "signal",
            Self::FatalError => "fatal_error",
            Self::StartupAborted => "startup_aborted",
        }
    }
}

/// Drain phase signals for future 7.10.6 — **not** transaction execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DrainPhase {
    #[default]
    Idle,
    Draining,
    /// Drain hit configured timeout. **MUST NOT** be interpreted as COMMIT.
    TimedOut,
    Complete,
}

impl DrainPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Draining => "draining",
            Self::TimedOut => "timed_out",
            Self::Complete => "complete",
        }
    }
}

/// Projected readiness token for Health wiring (7.9.6) — not ProcessState itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectedReadiness {
    Initializing,
    Ready,
    NotReady,
    Failed,
}

impl ProjectedReadiness {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Initializing => "initializing",
            Self::Ready => "ready",
            Self::NotReady => "not_ready",
            Self::Failed => "failed",
        }
    }
}

/// Read-only lifecycle view (no secrets / paths / SQL).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleSnapshot {
    pub state: LifecycleState,
    pub accepts_new_work: bool,
    pub projected_readiness: ProjectedReadiness,
    pub shutdown_reason: Option<ShutdownReason>,
    pub drain: DrainPhase,
    /// Lifecycle never unlocks vault; axis remains independent (always reported locked here).
    pub vault_axis_untouched: bool,
}

/// Pure process lifecycle controller.
#[derive(Clone, Debug)]
pub struct ProcessLifecycle {
    state: LifecycleState,
    shutdown_reason: Option<ShutdownReason>,
    drain: DrainPhase,
    /// Counts successful `request_shutdown` transitions into Stopping (not repeats).
    shutdown_enter_count: u32,
    /// Temporary operational NotReady overlay while process state remains Ready (7.10.8).
    /// Does **not** imply VaultLocked / Failed.
    not_ready_overlay: bool,
}

impl Default for ProcessLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessLifecycle {
    /// New process instance always starts in [`LifecycleState::Starting`].
    pub fn new() -> Self {
        Self {
            state: LifecycleState::Starting,
            shutdown_reason: None,
            drain: DrainPhase::Idle,
            shutdown_enter_count: 0,
            not_ready_overlay: false,
        }
    }

    pub fn state(&self) -> LifecycleState {
        self.state
    }

    pub fn accepts_new_work(&self) -> bool {
        self.state.accepts_new_work() && !self.not_ready_overlay
    }

    pub fn drain_phase(&self) -> DrainPhase {
        self.drain
    }

    pub fn shutdown_enter_count(&self) -> u32 {
        self.shutdown_enter_count
    }

    pub fn operational_not_ready(&self) -> bool {
        self.not_ready_overlay
    }

    pub fn snapshot(&self) -> LifecycleSnapshot {
        LifecycleSnapshot {
            state: self.state,
            accepts_new_work: self.accepts_new_work(),
            projected_readiness: project_readiness(self.state, self.not_ready_overlay),
            shutdown_reason: self.shutdown_reason,
            drain: self.drain,
            vault_axis_untouched: true,
        }
    }

    /// Starting → Ready. Rejects new work until this succeeds.
    pub fn mark_ready(&mut self) -> Result<()> {
        match self.state {
            LifecycleState::Starting => {
                self.state = LifecycleState::Ready;
                self.drain = DrainPhase::Idle;
                self.not_ready_overlay = false;
                Ok(())
            }
            other => Err(LifecycleError::invalid_transition(
                other,
                "mark_ready",
            )),
        }
    }

    /// Starting | Ready | Stopping → Failed (terminal). Idempotent if already Failed.
    pub fn mark_failed(&mut self) -> Result<()> {
        match self.state {
            LifecycleState::Starting | LifecycleState::Ready | LifecycleState::Stopping => {
                self.state = LifecycleState::Failed;
                self.drain = DrainPhase::Idle;
                self.not_ready_overlay = false;
                Ok(())
            }
            LifecycleState::Failed => Ok(()),
            other => Err(LifecycleError::invalid_transition(
                other,
                "mark_failed",
            )),
        }
    }

    /// Ready → readiness NotReady overlay (process stays Ready / alive).
    /// Clears only via [`Self::clear_operational_not_ready`].
    pub fn note_operational_not_ready(&mut self) -> Result<()> {
        match self.state {
            LifecycleState::Ready => {
                self.not_ready_overlay = true;
                Ok(())
            }
            other => Err(LifecycleError::invalid_transition(
                other,
                "note_operational_not_ready",
            )),
        }
    }

    /// Clear NotReady overlay — process Ready again for new work.
    pub fn clear_operational_not_ready(&mut self) -> Result<()> {
        match self.state {
            LifecycleState::Ready => {
                self.not_ready_overlay = false;
                Ok(())
            }
            other => Err(LifecycleError::invalid_transition(
                other,
                "clear_operational_not_ready",
            )),
        }
    }

    /// Request graceful shutdown. Idempotent once Stopping/Stopped/Failed.
    ///
    /// | From | Effect |
    /// |------|--------|
    /// | Starting | → Stopping (startup aborted); `accepts_new_work = false` |
    /// | Ready | → Stopping |
    /// | Stopping | no-op (idempotent) |
    /// | Stopped / Failed | no-op (idempotent) |
    pub fn request_shutdown(&mut self, reason: ShutdownReason) -> Result<()> {
        match self.state {
            LifecycleState::Starting => {
                self.state = LifecycleState::Stopping;
                self.shutdown_reason = Some(match reason {
                    ShutdownReason::OperatorRequest | ShutdownReason::Signal => {
                        ShutdownReason::StartupAborted
                    }
                    other => other,
                });
                self.shutdown_enter_count = self.shutdown_enter_count.saturating_add(1);
                self.drain = DrainPhase::Idle;
                Ok(())
            }
            LifecycleState::Ready => {
                self.state = LifecycleState::Stopping;
                self.shutdown_reason = Some(reason);
                self.shutdown_enter_count = self.shutdown_enter_count.saturating_add(1);
                self.drain = DrainPhase::Idle;
                self.not_ready_overlay = false;
                Ok(())
            }
            LifecycleState::Stopping | LifecycleState::Stopped | LifecycleState::Failed => Ok(()),
        }
    }

    /// Stopping → mark drain in progress. Idempotent while already Draining.
    pub fn begin_draining(&mut self) -> Result<()> {
        match self.state {
            LifecycleState::Stopping => {
                if matches!(self.drain, DrainPhase::Idle | DrainPhase::Draining) {
                    self.drain = DrainPhase::Draining;
                }
                Ok(())
            }
            other => Err(LifecycleError::invalid_transition(
                other,
                "begin_draining",
            )),
        }
    }

    /// Record drain timeout. Signals future 7.10.6 to ROLLBACK open txns —
    /// **never** means COMMIT.
    pub fn note_drain_timeout(&mut self) -> Result<()> {
        match self.state {
            LifecycleState::Stopping => {
                self.drain = DrainPhase::TimedOut;
                Ok(())
            }
            other => Err(LifecycleError::invalid_transition(
                other,
                "note_drain_timeout",
            )),
        }
    }

    /// Mark in-flight drain finished successfully (before or without timeout).
    pub fn note_drain_complete(&mut self) -> Result<()> {
        match self.state {
            LifecycleState::Stopping => {
                if self.drain != DrainPhase::TimedOut {
                    self.drain = DrainPhase::Complete;
                }
                Ok(())
            }
            other => Err(LifecycleError::invalid_transition(
                other,
                "note_drain_complete",
            )),
        }
    }

    /// Stopping → Stopped. Idempotent if already Stopped.
    /// Failed remains terminal (no transition to Stopped).
    pub fn finish_shutdown(&mut self) -> Result<()> {
        match self.state {
            LifecycleState::Stopping => {
                self.state = LifecycleState::Stopped;
                if matches!(self.drain, DrainPhase::Idle | DrainPhase::Draining) {
                    self.drain = DrainPhase::Complete;
                }
                Ok(())
            }
            LifecycleState::Stopped => Ok(()),
            other => Err(LifecycleError::invalid_transition(
                other,
                "finish_shutdown",
            )),
        }
    }
}

fn project_readiness(state: LifecycleState, not_ready_overlay: bool) -> ProjectedReadiness {
    match state {
        LifecycleState::Starting => ProjectedReadiness::Initializing,
        LifecycleState::Ready if not_ready_overlay => ProjectedReadiness::NotReady,
        LifecycleState::Ready => ProjectedReadiness::Ready,
        LifecycleState::Stopping | LifecycleState::Stopped => ProjectedReadiness::NotReady,
        LifecycleState::Failed => ProjectedReadiness::Failed,
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn new_is_starting_no_work() {
        let lc = ProcessLifecycle::new();
        assert_eq!(lc.state(), LifecycleState::Starting);
        assert!(!lc.accepts_new_work());
        assert_eq!(
            lc.snapshot().projected_readiness,
            ProjectedReadiness::Initializing
        );
    }
}
