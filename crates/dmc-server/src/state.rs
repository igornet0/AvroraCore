use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use dmc_observability::{Audit, Metrics, Observability, Readiness};
use dmc_protocol::{ProtocolError, ProtocolErrorCode, RemoteLimits};
use dmc_runtime::RuntimeHub;
use dmc_security::auth::AuthService;
use dmc_sql_exec::ExecutionContext;

use crate::session_gate::SessionGateStore;
use crate::unlock_blob::UnlockMaterial;
use crate::unlock_gate::{SecurityState, UnlockGate, VaultState};

/// Core operational lifecycle (independent of vault / auth).
///
/// Extended in 7.10.6 for graceful shutdown mirroring `dmc_ops::ProcessLifecycle`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CoreLifecycle {
    #[default]
    Ready,
    Initializing,
    /// Graceful shutdown in progress — reject new work; NotReady.
    Stopping,
    /// Shutdown complete — secrets wiped; NotReady.
    Stopped,
    Failed,
}

#[derive(Clone, Debug)]
pub struct OperationalState {
    pub lifecycle: CoreLifecycle,
    /// Last published readiness (for change-only logging).
    pub last_readiness: Option<Readiness>,
    /// Process start instant for diagnostics uptime (not a security clock).
    pub started_at: Instant,
}

impl Default for OperationalState {
    fn default() -> Self {
        Self {
            lifecycle: CoreLifecycle::Ready,
            last_readiness: None,
            started_at: Instant::now(),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct ReplayGuard {
    accepted: HashSet<(String, [u8; 12])>,
}

impl ReplayGuard {
    fn contains(&self, session_id: &str, nonce: [u8; 12]) -> bool {
        self.accepted
            .contains(&(session_id.to_string(), nonce))
    }

    fn mark(&mut self, session_id: &str, nonce: [u8; 12]) {
        self.accepted.insert((session_id.to_string(), nonce));
    }

    fn clear(&mut self) {
        self.accepted.clear();
    }
}

pub struct CoreServerState {
    pub auth: AuthService,
    pub ctx: ExecutionContext,
    /// Opaque data root for backups/restores (never exposed to UI as a browseable tree).
    pub data_root: PathBuf,
    pub unlock_gate: UnlockGate,
    /// Shared channels/streams/triggers/events domain (HTTP + DMC).
    pub runtime: RuntimeHub,
    /// Structured logging facade (7.9.2) — observational only.
    pub observability: Observability,
    /// Metrics facade (7.9.4) — observational only.
    pub metrics: Metrics,
    /// Audit facade (7.9.5) — observational / accountability only; not Journal SoT.
    pub audit: Audit,
    /// Optional low-cardinality transport label for metrics (`local` / `remote`).
    pub metrics_transport: Option<dmc_observability::MetricTransport>,
    /// Operational lifecycle for Health / Readiness (7.9.6).
    pub operational: OperationalState,
    /// Production limits from CoreConfig (7.10.7) — not a second hardcoded table.
    pub limits: RemoteLimits,
    unlock_replay: ReplayGuard,
    session_gates: SessionGateStore,
    /// In-flight Control/Data requests (7.10.6 drain / 7.10.7 concurrent).
    in_flight_requests: u32,
    /// Active accepted connections (7.10.7 admission).
    active_connections: u32,
}

impl CoreServerState {
    /// Production-safe: vault Locked, no runtime secrets.
    /// `master` is one-time material for client KeyPass wrap — not stored in state.
    pub fn new_locked(
        auth: AuthService,
        ctx: ExecutionContext,
        data_root: PathBuf,
    ) -> Result<(Self, UnlockMaterial), dmc_protocol::ProtocolError> {
        Self::new_locked_with_hub(auth, ctx, data_root, RuntimeHub::new())
    }

    /// Same as [`Self::new_locked`], but inject a shared [`RuntimeHub`] (HTTP + DMC).
    pub fn new_locked_with_hub(
        auth: AuthService,
        ctx: ExecutionContext,
        data_root: PathBuf,
        runtime: RuntimeHub,
    ) -> Result<(Self, UnlockMaterial), dmc_protocol::ProtocolError> {
        let (unlock_gate, master) = UnlockGate::create_locked()?;
        Ok((
            Self {
                auth,
                ctx,
                data_root,
                unlock_gate,
                runtime,
                observability: Observability::tracing(),
                metrics: Metrics::tracing(),
                audit: Audit::tracing(),
                metrics_transport: None,
                operational: OperationalState {
                    lifecycle: CoreLifecycle::Ready,
                    last_readiness: None,
                    started_at: Instant::now(),
                },
                limits: RemoteLimits::default(),
                unlock_replay: ReplayGuard::default(),
                session_gates: SessionGateStore::new(),
                in_flight_requests: 0,
                active_connections: 0,
            },
            master,
        ))
    }

    /// Replace the runtime hub (composition / tests). Same Arc as HTTP adapter when shared.
    pub fn set_runtime_hub(&mut self, runtime: RuntimeHub) {
        self.runtime = runtime;
    }

    pub fn runtime_hub(&self) -> &RuntimeHub {
        &self.runtime
    }

    /// Install config-backed limits (called from `start_core` / tests).
    pub fn set_limits(&mut self, limits: RemoteLimits) {
        self.limits = limits;
    }

    /// Test / ops: force lifecycle without touching vault or auth.
    pub fn set_lifecycle(&mut self, lifecycle: CoreLifecycle) {
        self.operational.lifecycle = lifecycle;
    }

    /// Replace observability sink (tests / failure isolation). Does not affect security state.
    pub fn set_observability(&mut self, observability: Observability) {
        self.observability = observability;
    }

    /// Replace metrics sink (tests / failure isolation). Does not affect security state.
    pub fn set_metrics(&mut self, metrics: Metrics) {
        self.metrics = metrics;
    }

    /// Replace audit sink (tests / failure isolation). Does not affect security state.
    pub fn set_audit(&mut self, audit: Audit) {
        self.audit = audit;
    }

    pub fn auth_mut(&mut self) -> &mut AuthService {
        &mut self.auth
    }

    pub fn vault_state(&self) -> VaultState {
        self.unlock_gate.state()
    }

    /// Apply Master Key from UnlockBlob into dmc-vault. Idempotent if already unlocked.
    pub fn apply_vault_unlock(
        &mut self,
        material: &UnlockMaterial,
    ) -> Result<(), dmc_protocol::ProtocolError> {
        self.unlock_gate.apply_unlock(material)
    }

    /// Lock vault only — AuthSessions remain valid; DEK/KeyTree secrets wiped.
    pub fn lock_vault(&mut self) {
        self.unlock_gate.lock();
    }

    pub fn security_state(&self, session_id: &str) -> SecurityState {
        use dmc_security::auth::SessionManager;
        let authenticated = self.auth.validate_session(&session_id.into()).is_ok();
        SecurityState {
            authenticated,
            vault_unlocked: self.unlock_gate.is_unlocked(),
        }
    }

    /// Simulate process restart: vault locked (secrets wiped), all sessions cleared.
    /// Readiness returns to Ready with vault Locked (security gates still apply to SQL).
    pub fn simulate_restart(&mut self) {
        self.operational.lifecycle = CoreLifecycle::Initializing;
        self.unlock_gate.lock();
        self.unlock_replay.clear();
        self.auth.restart();
        self.session_gates = SessionGateStore::new();
        self.operational.lifecycle = CoreLifecycle::Ready;
        self.operational.last_readiness = None;
        self.in_flight_requests = 0;
        self.active_connections = 0;
    }

    pub fn root_dek_present(&self) -> bool {
        self.unlock_gate.root_dek_present()
    }

    /// Whether Control/Data may accept **new** work (7.10.6).
    pub fn accepts_new_work(&self) -> bool {
        matches!(self.operational.lifecycle, CoreLifecycle::Ready)
    }

    pub fn begin_in_flight_request(&mut self) {
        self.in_flight_requests = self.in_flight_requests.saturating_add(1);
    }

    pub fn end_in_flight_request(&mut self) {
        self.in_flight_requests = self.in_flight_requests.saturating_sub(1);
    }

    pub fn in_flight_requests(&self) -> u32 {
        self.in_flight_requests
    }

    pub fn active_connections(&self) -> u32 {
        self.active_connections
    }

    /// Admit a new connection under `limits.frame.max_connections`. Controlled reject — no panic.
    pub fn try_admit_connection(&mut self) -> Result<(), ProtocolError> {
        let max = self.limits.frame.max_connections;
        if self.active_connections >= max {
            return Err(ProtocolError::wire(
                ProtocolErrorCode::ConnectionClosed,
                "connection limit exceeded",
            ));
        }
        self.active_connections = self.active_connections.saturating_add(1);
        Ok(())
    }

    pub fn release_connection(&mut self) {
        self.active_connections = self.active_connections.saturating_sub(1);
    }

    /// Reject if concurrent in-flight would exceed config ceiling. Core stays Ready.
    pub fn try_begin_request(&mut self) -> Result<(), ProtocolError> {
        let max = self
            .limits
            .frame
            .max_concurrent_requests
            .min(self.limits.max_in_flight_requests);
        if self.in_flight_requests >= max {
            return Err(ProtocolError::wire(
                ProtocolErrorCode::InvalidRequest,
                "concurrent request limit exceeded",
            ));
        }
        self.begin_in_flight_request();
        Ok(())
    }

    pub fn has_active_transaction(&self) -> bool {
        self.ctx.transaction().is_some()
    }

    /// Force ROLLBACK of any open transaction — never COMMIT (shutdown / drain timeout).
    pub fn force_rollback_transaction(&mut self) -> Result<(), String> {
        if self.ctx.transaction().is_none() {
            return Ok(());
        }
        self.ctx
            .rollback_transaction()
            .map_err(|e| e.to_string())
    }

    /// Mark server Stopping — reject new work. Idempotent.
    pub fn mark_stopping(&mut self) {
        if matches!(
            self.operational.lifecycle,
            CoreLifecycle::Ready | CoreLifecycle::Initializing
        ) {
            self.operational.lifecycle = CoreLifecycle::Stopping;
            self.operational.last_readiness = None;
        }
    }

    /// Best-effort durable flush for shutdown (journal remains SoT; no new checkpoint).
    pub fn flush_for_shutdown(&mut self) -> Result<(), String> {
        if self.ctx.journal().is_none() {
            return Err("journal unavailable during shutdown flush".into());
        }
        // File journal appends already fsync; V1 verifies attachment as the flush gate.
        Ok(())
    }

    /// Wipe vault secrets + invalidate all AuthSessions. Idempotent if already locked/empty.
    pub fn wipe_for_shutdown(&mut self) {
        self.unlock_gate.lock();
        self.unlock_replay.clear();
        self.auth.restart();
        self.session_gates = SessionGateStore::new();
        self.in_flight_requests = 0;
    }

    /// Mark server Stopped after wipe. Idempotent.
    pub fn mark_stopped(&mut self) {
        self.operational.lifecycle = CoreLifecycle::Stopped;
        self.operational.last_readiness = None;
    }

    pub(crate) fn session_gate(&mut self, session_id: &str) -> Arc<Mutex<()>> {
        self.session_gates.gate_for(session_id)
    }

    pub(crate) fn unlock_blob_seen(&self, session_id: &str, nonce: [u8; 12]) -> bool {
        self.unlock_replay.contains(session_id, nonce)
    }

    pub(crate) fn mark_unlock_blob(&mut self, session_id: &str, nonce: [u8; 12]) {
        self.unlock_replay.mark(session_id, nonce);
    }
}
