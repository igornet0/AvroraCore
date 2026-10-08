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

/// Relative location of the CLIENT_OWNED key directory under the data root.
pub const CLIENT_KEYS_DIR: &str = "ownership/client";
/// Identity directory file (relative to the data root).
pub const IDENTITIES_FILE: &str = "ownership/identities.json";
/// Directory holding identities, the bootstrap marker and the key directory.
pub const OWNERSHIP_DIR: &str = "ownership";

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
    /// CLIENT_OWNED key directory (public keys, HPKE envelopes, grants). Opened lazily
    /// under `data_root/ownership/client`. Holds no private key material.
    client_keys: Option<dmc_security::ownership::ClientKeyDirectory>,
    invites: Option<dmc_security::ownership::InviteStore>,
    /// Session that opened the active SQL transaction (F8). Only that session may use,
    /// commit or roll it back; if it ends, the transaction is rolled back.
    txn_owner: Option<String>,
    /// D4-A stage 3: how to open SQL-plane storage once the vault is unlocked. `None`:
    /// storage was opened eagerly by the caller (tests / dev bootstrap).
    storage_opener: Option<Box<dyn StorageOpener>>,
    /// Whether `ctx` currently holds opened storage (only meaningful with an opener).
    storage_open: bool,
    /// D4-E: persistent key store (wrapped keys only); carried by encrypted backups.
    key_store: Option<PathBuf>,
}

/// Opens SQL-plane storage with the unlocked storage keys and returns a ready execution
/// context. Called on `VaultUnlock`; never before (data is not read while locked).
pub trait StorageOpener: Send {
    fn open(&self, cipher: &dmc_vault::StorageCipher) -> Result<ExecutionContext, String>;

    /// D4-E (variant B): open a pending emergency restore that the unlocking client
    /// authorized for exactly the backup whose `manifest.sealed` has SHA-256 `authorized`,
    /// whose checkpoint must not be below `min_generation` (checked before anything is
    /// written). Anything else (no restore pending, another artifact) is refused.
    fn open_authorized(
        &self,
        _cipher: &dmc_vault::StorageCipher,
        _authorized: &[u8; 32],
        _min_generation: u64,
    ) -> Result<ExecutionContext, AuthorizedOpenError> {
        Err(AuthorizedOpenError::Refused(
            "emergency restore is not supported by this store".into(),
        ))
    }

    /// D4-A stage 5: the store holds plaintext (pre-D4) SQL data that only an explicit
    /// migration may convert. Decided without keys.
    fn migration_required(&self) -> bool {
        false
    }

    /// D4-A stage 5: explicitly migrate a plaintext store to encrypted storage with
    /// `cipher` (build → verify → switch). Never called implicitly.
    fn migrate(
        &self,
        _cipher: &dmc_vault::StorageCipher,
        _purge_plaintext_backups: bool,
    ) -> Result<MigrationReport, MigrationError> {
        Err(MigrationError::Refused("this store cannot be migrated".into()))
    }
}

/// Why an authorized (emergency-restore) open did not happen. Nothing was restored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorizedOpenError {
    /// The authorized backup is older than the client's anti-rollback anchor.
    Rollback,
    /// Not the authorized artifact, no restore pending, or verification failed.
    Refused(String),
}

/// Outcome of an explicit storage migration (no paths, no values).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationReport {
    pub events: u64,
    pub tables: u64,
    pub purged_artifacts: u64,
}

/// Why an explicit storage migration did not happen. Nothing was switched in either case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MigrationError {
    /// Preconditions not met (nothing to migrate, plaintext backups without purge, ...).
    Refused(String),
    /// Build or verification failed; the plaintext store is untouched.
    Failed(String),
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
    /// Ephemeral vault (tests, restore tooling): a fresh key tree per call, nothing
    /// persisted. Production uses [`Self::open_persistent_with_hub`].
    pub fn new_locked_with_hub(
        auth: AuthService,
        ctx: ExecutionContext,
        data_root: PathBuf,
        runtime: RuntimeHub,
    ) -> Result<(Self, UnlockMaterial), dmc_protocol::ProtocolError> {
        let (unlock_gate, master) = UnlockGate::create_locked()?;
        Ok((Self::assemble(auth, ctx, data_root, runtime, unlock_gate), master))
    }

    /// Persistent vault (D4-A): key store at `key_store` is loaded, or created once. The
    /// Master Key is returned only when the key store was just created; afterwards every
    /// start is locked until a client unlocks with that same key.
    pub fn open_persistent_with_hub(
        auth: AuthService,
        ctx: ExecutionContext,
        data_root: PathBuf,
        key_store: &std::path::Path,
        runtime: RuntimeHub,
    ) -> Result<(Self, Option<UnlockMaterial>), dmc_protocol::ProtocolError> {
        let (unlock_gate, master) = UnlockGate::open_or_create(key_store)?;
        let mut state = Self::assemble(auth, ctx, data_root, runtime, unlock_gate);
        state.key_store = Some(key_store.to_path_buf());
        Ok((state, master))
    }

    fn assemble(
        auth: AuthService,
        ctx: ExecutionContext,
        data_root: PathBuf,
        runtime: RuntimeHub,
        unlock_gate: UnlockGate,
    ) -> Self {
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
            client_keys: None,
            invites: None,
            txn_owner: None,
            storage_opener: None,
            storage_open: false,
            key_store: None,
        }
    }

    /// Defer storage: nothing is read until `VaultUnlock`; `ctx` stays empty meanwhile.
    pub fn set_storage_opener(&mut self, opener: Box<dyn StorageOpener>) {
        self.ctx = ExecutionContext::new();
        self.storage_open = false;
        self.txn_owner = None;
        self.storage_opener = Some(opener);
    }

    /// D4-E: the persistent key store (`None` for an ephemeral vault).
    pub fn key_store_path(&self) -> Option<&std::path::Path> {
        self.key_store.as_deref()
    }

    /// Storage exists but is not opened (vault locked): SQL state is unavailable by design.
    pub fn storage_sealed(&self) -> bool {
        self.storage_opener.is_some() && !self.storage_open
    }

    /// Drop opened storage from memory (lock / restart). An open transaction is rolled
    /// back first — never committed.
    fn close_storage(&mut self) {
        if self.storage_opener.is_some() && self.storage_open {
            let _ = self.force_rollback_transaction();
            self.txn_owner = None;
            self.ctx = ExecutionContext::new();
            self.storage_open = false;
        }
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

    /// Directory for CLIENT_OWNED public keys / envelopes / grants.
    pub fn client_key_dir(
        &mut self,
    ) -> std::result::Result<&mut dmc_security::ownership::ClientKeyDirectory, dmc_security::Error> {
        if self.client_keys.is_none() {
            let dir = dmc_security::ownership::ClientKeyDirectory::open(
                self.data_root.join(CLIENT_KEYS_DIR),
            )?;
            self.client_keys = Some(dir);
        }
        Ok(self.client_keys.as_mut().expect("opened above"))
    }

    /// Auth, key directory and invite store, all mutable (enrollment touches all three).
    pub fn ownership_parts(
        &mut self,
    ) -> std::result::Result<
        (
            &mut AuthService,
            &mut dmc_security::ownership::ClientKeyDirectory,
            &mut dmc_security::ownership::InviteStore,
        ),
        dmc_security::Error,
    > {
        self.client_key_dir()?;
        if self.invites.is_none() {
            self.invites = Some(dmc_security::ownership::InviteStore::open(
                self.data_root.join(CLIENT_KEYS_DIR),
            )?);
        }
        Ok((
            &mut self.auth,
            self.client_keys.as_mut().expect("opened above"),
            self.invites.as_mut().expect("opened above"),
        ))
    }

    /// Persist the identity directory (hashed credentials, custody, subject ids) next to
    /// the key directory, so it survives restarts and travels in the backup's
    /// `ownership` component.
    pub fn persist_identities(&self) -> std::result::Result<(), dmc_security::Error> {
        self.auth.save_identities(&self.data_root.join(IDENTITIES_FILE))
    }

    /// Auth (read) + key directory (write) without cloning the identity directory.
    pub fn auth_and_client_key_dir(
        &mut self,
    ) -> std::result::Result<(&AuthService, &mut dmc_security::ownership::ClientKeyDirectory), dmc_security::Error> {
        self.client_key_dir()?;
        Ok((&self.auth, self.client_keys.as_mut().expect("opened above")))
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
        self.unlock_and_open(material, None)
    }

    /// `authorized`: (SHA-256 of the authorized `manifest.sealed`, client anchor).
    fn unlock_and_open(
        &mut self,
        material: &UnlockMaterial,
        authorized: Option<(&[u8; 32], u64)>,
    ) -> Result<(), dmc_protocol::ProtocolError> {
        self.unlock_gate.apply_unlock(material)?;
        if self.storage_sealed() {
            let opened = self
                .unlock_gate
                .storage_cipher()
                .map_err(|e| AuthorizedOpenError::Refused(e.to_string()))
                .and_then(|cipher| {
                    let opener = self.storage_opener.as_ref().expect("sealed implies opener");
                    match authorized {
                        None => opener.open(&cipher).map_err(AuthorizedOpenError::Refused),
                        Some((hash, min)) => opener.open_authorized(&cipher, hash, min),
                    }
                });
            match opened {
                Ok(ctx) => {
                    self.ctx = ctx;
                    self.storage_open = true;
                }
                Err(e) => {
                    // fail closed: no half-open state, keys wiped again
                    self.unlock_gate.lock();
                    return Err(match (authorized, e) {
                        (None, _) => dmc_protocol::ProtocolError::wire(
                            dmc_protocol::ProtocolErrorCode::InternalError,
                            "storage could not be opened",
                        ),
                        (Some(_), AuthorizedOpenError::Rollback) => {
                            dmc_protocol::ProtocolError::wire(
                                dmc_protocol::ProtocolErrorCode::StorageRollbackDetected,
                                "authorized backup is older than this client has already seen",
                            )
                        }
                        (Some(_), AuthorizedOpenError::Refused(_)) => {
                            dmc_protocol::ProtocolError::wire(
                                dmc_protocol::ProtocolErrorCode::UnlockFailed,
                                "emergency restore refused: not the client-authorized backup",
                            )
                        }
                    });
                }
            }
        } else if authorized.is_some() {
            // an authorization with nothing to restore is ambiguous: refuse, stay locked
            self.close_storage();
            self.unlock_gate.lock();
            return Err(dmc_protocol::ProtocolError::wire(
                dmc_protocol::ProtocolErrorCode::UnlockFailed,
                "emergency restore refused: no restore pending",
            ));
        }
        Ok(())
    }

    /// D4-A stage 5: whether the sealed store needs an explicit migration before it opens.
    pub fn storage_migration_required(&self) -> bool {
        self.storage_sealed()
            && self
                .storage_opener
                .as_ref()
                .is_some_and(|o| o.migration_required())
    }

    /// D4-A stage 5: unlock with `material`, explicitly migrate the plaintext store to
    /// encrypted storage, then open it. Any failure re-locks the vault (fail closed): no
    /// half-migrated or half-open state is ever exposed.
    pub fn migrate_storage(
        &mut self,
        material: &UnlockMaterial,
        purge_plaintext_backups: bool,
        min_generation: u64,
    ) -> Result<MigrationReport, MigrationError> {
        if !self.storage_migration_required() {
            return Err(MigrationError::Refused("storage does not need migration".into()));
        }
        self.unlock_gate
            .apply_unlock(material)
            .map_err(|_| MigrationError::Refused("unlock failed".into()))?;
        let result = self
            .unlock_gate
            .storage_cipher()
            .map_err(|e| MigrationError::Failed(e.to_string()))
            .and_then(|cipher| {
                let opener = self.storage_opener.as_ref().expect("sealed implies opener");
                let report = opener.migrate(&cipher, purge_plaintext_backups)?;
                let ctx = opener.open(&cipher).map_err(MigrationError::Failed)?;
                Ok((report, ctx))
            });
        match result {
            Ok((report, ctx)) => {
                self.ctx = ctx;
                self.storage_open = true;
                // D4-D: the migrated store carries the same journal (same generation)
                self.enforce_anchor(min_generation)
                    .map_err(|_| MigrationError::Refused("storage rollback detected".into()))?;
                Ok(report)
            }
            Err(e) => {
                self.unlock_gate.lock();
                Err(e)
            }
        }
    }

    /// D4-D: generation of the open SQL storage — its authenticated journal tip (grows with
    /// every committed write). `None` while storage is not open.
    pub fn storage_generation(&self) -> Option<u64> {
        self.ctx.journal().map(|j| j.tip_sequence())
    }

    /// D4-D: unlock, then refuse storage older than the client's anchor `min_generation`
    /// (the highest generation that client has seen): a rolled-back data root is closed again
    /// and the vault re-locked (fail closed). `min_generation` 0 = no anchor.
    pub fn apply_vault_unlock_anchored(
        &mut self,
        material: &UnlockMaterial,
        min_generation: u64,
    ) -> Result<u64, dmc_protocol::ProtocolError> {
        self.apply_vault_unlock(material)?;
        self.enforce_anchor(min_generation)
    }

    /// D4-E (variant B): unlock that also carries the client's emergency-restore
    /// authorization (`Some`: SHA-256 of exactly one backup's `manifest.sealed`); then the
    /// D4-D anchor. Without an authorization: [`Self::apply_vault_unlock_anchored`].
    pub fn apply_vault_unlock_authorized(
        &mut self,
        material: &UnlockMaterial,
        min_generation: u64,
        authorized: Option<&[u8; 32]>,
    ) -> Result<u64, dmc_protocol::ProtocolError> {
        self.unlock_and_open(material, authorized.map(|h| (h, min_generation)))?;
        self.enforce_anchor(min_generation)
    }

    fn enforce_anchor(&mut self, min_generation: u64) -> Result<u64, dmc_protocol::ProtocolError> {
        let generation = self.storage_generation().unwrap_or(0);
        if generation < min_generation {
            self.close_storage();
            self.unlock_gate.lock();
            return Err(dmc_protocol::ProtocolError::wire(
                dmc_protocol::ProtocolErrorCode::StorageRollbackDetected,
                "storage is older than this client has already seen (rollback); \
                 unlock refused",
            ));
        }
        Ok(generation)
    }

    /// Lock vault — AuthSessions remain valid; DEK/KeyTree secrets wiped; with deferred
    /// storage, opened data is dropped from memory as well.
    pub fn lock_vault(&mut self) {
        self.close_storage();
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
        self.close_storage();
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

    /// F8: may `session_id` touch SQL state now? Refused while another live session owns
    /// the open transaction. A transaction whose owner session ended is rolled back
    /// (never committed) and the request proceeds.
    pub(crate) fn transaction_guard(&mut self, session_id: &str) -> Result<(), String> {
        self.reap_orphan_transaction();
        match &self.txn_owner {
            Some(owner) if owner != session_id && self.ctx.in_transaction() => {
                Err("another session's transaction is active".into())
            }
            _ => Ok(()),
        }
    }

    /// After a request of `session_id`: record who owns a transaction it opened, forget
    /// the owner once no transaction is active.
    pub(crate) fn sync_transaction_owner(&mut self, session_id: &str) {
        if !self.ctx.in_transaction() {
            self.txn_owner = None;
        } else if self.txn_owner.is_none() {
            self.txn_owner = Some(session_id.to_string());
        }
    }

    /// Roll back a transaction whose owner session is no longer valid (connection closed,
    /// logout, identity disabled, expiry).
    pub fn reap_orphan_transaction(&mut self) {
        let Some(owner) = self.txn_owner.clone() else { return };
        let alive = {
            use dmc_security::auth::SessionManager;
            let channel = self.auth.request_channel().map(str::to_string);
            self.auth.end_request();
            let ok = self.auth.validate_session(&owner.clone().into()).is_ok();
            if let Some(c) = channel {
                self.auth.begin_request(&c);
            }
            ok
        };
        if !alive {
            let _ = self.force_rollback_transaction();
            self.txn_owner = None;
        }
    }

    pub fn has_active_transaction(&self) -> bool {
        self.ctx.transaction().is_some()
    }

    /// Whether `session_id` owns the active transaction (wire adapters report it, e.g.
    /// pgwire ReadyForQuery `T`). Other sessions never see someone else's transaction.
    pub fn transaction_owned_by(&self, session_id: &str) -> bool {
        self.ctx.in_transaction() && self.txn_owner.as_deref() == Some(session_id)
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
        // sealed storage (never unlocked) was never opened: nothing in memory to flush
        if self.storage_sealed() {
            return Ok(());
        }
        if self.ctx.journal().is_none() {
            return Err("journal unavailable during shutdown flush".into());
        }
        // File journal appends already fsync; V1 verifies attachment as the flush gate.
        Ok(())
    }

    /// Wipe vault secrets + invalidate all AuthSessions. Idempotent if already locked/empty.
    pub fn wipe_for_shutdown(&mut self) {
        self.close_storage();
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
