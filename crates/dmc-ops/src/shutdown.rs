//! Phase 7.10.6 — Shutdown / Drain orchestration.
//!
//! Owns lifecycle + drain **semantics** only. Server executes txn rollback, flush,
//! vault wipe, and session invalidation. Never invents COMMIT on timeout.

use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::config::LifecycleConfig;
use crate::error::{ShutdownError, ShutdownResult as Result};
use crate::lifecycle::{DrainPhase, LifecycleState, ShutdownReason};
use crate::startup::StartedCore;

/// Drain timeout policy (ADR-026 §8). Timeout **MUST NOT** mean COMMIT.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainPolicy {
    pub timeout_ms: u64,
}

impl DrainPolicy {
    pub fn from_lifecycle_config(cfg: &LifecycleConfig) -> Self {
        Self {
            timeout_ms: cfg.shutdown_drain_timeout_ms,
        }
    }

    pub fn with_timeout_ms(timeout_ms: u64) -> Self {
        Self { timeout_ms }
    }
}

impl Default for DrainPolicy {
    fn default() -> Self {
        Self {
            timeout_ms: LifecycleConfig::default().shutdown_drain_timeout_ms,
        }
    }
}

/// Options for [`shutdown_core`].
#[derive(Clone, Debug, Default)]
pub struct ShutdownOptions {
    pub policy: DrainPolicy,
    /// Force TimedOut + ROLLBACK path (tests / operator abort). Never COMMIT.
    pub force_drain_timeout: bool,
    /// Test hook: fail durable flush → shutdown Failed.
    pub fail_flush: bool,
}

impl ShutdownOptions {
    pub fn from_config(cfg: &LifecycleConfig) -> Self {
        Self {
            policy: DrainPolicy::from_lifecycle_config(cfg),
            force_drain_timeout: false,
            fail_flush: false,
        }
    }

    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.policy.timeout_ms = timeout_ms;
        self
    }

    pub fn force_timeout(mut self) -> Self {
        self.force_drain_timeout = true;
        self
    }
}

/// Read-only shutdown outcome (no secrets).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShutdownSnapshot {
    pub state: String,
    pub accepts_new_work: bool,
    pub drain: String,
    pub shutdown_reason: Option<String>,
    pub shutdown_enter_count: u32,
    pub rolled_back_transaction: bool,
    pub vault_locked: bool,
    pub sessions_invalidated: bool,
    pub timed_out: bool,
}

/// Coordinates ProcessLifecycle drain transitions; delegates destructive work to server.
#[derive(Debug)]
pub struct ShutdownCoordinator {
    policy: DrainPolicy,
    force_drain_timeout: bool,
    fail_flush: bool,
    /// Whether destructive wipe/finish already ran (idempotency).
    completed: bool,
}

impl ShutdownCoordinator {
    pub fn new(options: ShutdownOptions) -> Self {
        Self {
            policy: options.policy,
            force_drain_timeout: options.force_drain_timeout,
            fail_flush: options.fail_flush,
            completed: false,
        }
    }

    pub fn from_started(started: &StartedCore, options: ShutdownOptions) -> Self {
        let mut c = Self::new(options);
        if started.lifecycle.state() == LifecycleState::Stopped {
            c.completed = true;
        }
        c
    }
}

/// Graceful shutdown: Ready → Stopping → (drain) → wipe → Stopped.
///
/// Idempotent: repeated calls on Stopped return the same exterior without
/// re-running wipe or incrementing `shutdown_enter_count`.
pub fn shutdown_core(
    started: &mut StartedCore,
    reason: ShutdownReason,
    options: ShutdownOptions,
) -> Result<ShutdownSnapshot> {
    let mut coordinator = ShutdownCoordinator::from_started(started, options);
    coordinator.run(started, reason)
}

impl ShutdownCoordinator {
    pub fn run(
        &mut self,
        started: &mut StartedCore,
        reason: ShutdownReason,
    ) -> Result<ShutdownSnapshot> {
        // Idempotent exterior: already Stopped → no second destructive pass.
        if started.lifecycle.state() == LifecycleState::Stopped || self.completed {
            return Ok(snapshot_of(started, false, true));
        }

        let enter_before = started.lifecycle.shutdown_enter_count();
        started
            .lifecycle
            .request_shutdown(reason)
            .map_err(|e| ShutdownError::Lifecycle(e.to_string()))?;
        // Idempotent request_shutdown must not bump count on repeats — enforced by lifecycle.
        debug_assert!(started.lifecycle.shutdown_enter_count() >= enter_before);
        debug_assert!(started.lifecycle.shutdown_enter_count() <= enter_before.saturating_add(1));

        started.server.mark_stopping();
        debug_assert!(!started.lifecycle.accepts_new_work());
        debug_assert!(!started.server.accepts_new_work());

        started
            .lifecycle
            .begin_draining()
            .map_err(|e| ShutdownError::Lifecycle(e.to_string()))?;

        let mut rolled_back = false;
        let timed_out = {
            let (timed_out, rb) = self.drain_until_idle_or_timeout(started)?;
            rolled_back |= rb;
            timed_out
        };

        // Safety net: never leave an open txn across Stopped (never COMMIT).
        if started.server.has_active_transaction() {
            started
                .server
                .force_rollback_transaction()
                .map_err(ShutdownError::Rollback)?;
            rolled_back = true;
        }

        if timed_out {
            started
                .lifecycle
                .note_drain_timeout()
                .map_err(|e| ShutdownError::Lifecycle(e.to_string()))?;
        } else {
            started
                .lifecycle
                .note_drain_complete()
                .map_err(|e| ShutdownError::Lifecycle(e.to_string()))?;
        }

        if self.fail_flush {
            let _ = started.lifecycle.mark_failed();
            started.server.set_lifecycle(dmc_server::CoreLifecycle::Failed);
            return Err(ShutdownError::Flush("forced flush failure".into()));
        }

        started
            .server
            .flush_for_shutdown()
            .map_err(ShutdownError::Flush)?;

        // Observability must not change outcome — emit best-effort, ignore sink errors.
        let _ = emit_shutdown_observability(started);

        started.server.wipe_for_shutdown();
        started.server.mark_stopped();

        started
            .lifecycle
            .finish_shutdown()
            .map_err(|e| ShutdownError::Lifecycle(e.to_string()))?;

        self.completed = true;

        if !matches!(
            started.server.vault_state(),
            dmc_server::VaultState::Locked
        ) || started.server.root_dek_present()
        {
            return Err(ShutdownError::Vault(
                "vault wipe invariant violated: secrets remain".into(),
            ));
        }

        Ok(snapshot_of(started, rolled_back, true))
    }

    /// Returns `(timed_out, rolled_back)`.
    fn drain_until_idle_or_timeout(
        &mut self,
        started: &mut StartedCore,
    ) -> Result<(bool, bool)> {
        if self.force_drain_timeout {
            let mut rolled = false;
            if started.server.has_active_transaction() {
                started
                    .server
                    .force_rollback_transaction()
                    .map_err(ShutdownError::Rollback)?;
                rolled = true;
            }
            return Ok((true, rolled));
        }

        let timeout = Duration::from_millis(self.policy.timeout_ms);
        let deadline = Instant::now() + timeout;

        // timeout_ms == 0 with residual work → immediate TimedOut path.
        if self.policy.timeout_ms == 0
            && (started.server.in_flight_requests() > 0
                || started.server.has_active_transaction())
        {
            let mut rolled = false;
            if started.server.has_active_transaction() {
                started
                    .server
                    .force_rollback_transaction()
                    .map_err(ShutdownError::Rollback)?;
                rolled = true;
            }
            return Ok((true, rolled));
        }

        loop {
            if started.server.in_flight_requests() == 0
                && !started.server.has_active_transaction()
            {
                return Ok((false, false));
            }
            if Instant::now() >= deadline {
                let mut rolled = false;
                if started.server.has_active_transaction() {
                    started
                        .server
                        .force_rollback_transaction()
                        .map_err(ShutdownError::Rollback)?;
                    rolled = true;
                }
                return Ok((true, rolled));
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
}

fn emit_shutdown_observability(started: &StartedCore) {
    // Purely observational — sink failure must not alter shutdown.
    let _ = &started.server.observability;
    let _ = &started.server.metrics;
    let _ = &started.server.audit;
}

fn snapshot_of(
    started: &StartedCore,
    rolled_back_transaction: bool,
    sessions_invalidated: bool,
) -> ShutdownSnapshot {
    let snap = started.lifecycle.snapshot();
    ShutdownSnapshot {
        state: snap.state.as_str().into(),
        accepts_new_work: snap.accepts_new_work,
        drain: snap.drain.as_str().into(),
        shutdown_reason: snap.shutdown_reason.map(|r| r.as_str().into()),
        shutdown_enter_count: started.lifecycle.shutdown_enter_count(),
        rolled_back_transaction,
        vault_locked: matches!(
            started.server.vault_state(),
            dmc_server::VaultState::Locked
        ),
        sessions_invalidated,
        timed_out: snap.drain == DrainPhase::TimedOut,
    }
}

/// Assert shutdown exterior invariants (tests).
pub fn assert_shutdown_invariants(started: &StartedCore, snap: &ShutdownSnapshot) {
    assert_eq!(started.lifecycle.state(), LifecycleState::Stopped);
    assert!(!started.lifecycle.accepts_new_work());
    assert!(!started.server.accepts_new_work());
    assert!(snap.vault_locked);
    assert!(!started.server.root_dek_present());
    assert!(matches!(
        started.server.vault_state(),
        dmc_server::VaultState::Locked
    ));
    assert!(!snap.accepts_new_work);
    assert_eq!(snap.state, "stopped");
}
