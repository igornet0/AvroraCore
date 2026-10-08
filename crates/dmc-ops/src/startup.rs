//! Phase 7.10.4–7.10.5 — Startup orchestration + Recovery-on-startup.
//!
//! Success → Ready + Locked. Recovery reuses ADR-024 [`dmc_backup::recover_with`] /
//! [`RecoveryGate`] — never unlocks vault or restores sessions.
//!
//! D4-A stage 4.6: a pending recovery is **not** run at startup (that would read SQL data
//! while the vault is locked). Startup checks only the restore metadata; the recovery
//! itself runs when storage is opened on `VaultUnlock`. A failed recovery keeps the vault
//! locked.
//!
//! D4-A final switch: SQL-plane storage is **encrypted-only**. Every store and restore
//! target is opened with the storage keys; a plaintext data root or plaintext backup is
//! refused at startup ("explicit migration required") — never converted implicitly.
//! An encrypted data root (marker [`ENCRYPTED_STORAGE_MARKER`], or any sealed SQL file)
//! whose key store is missing is refused — a new key store is never created over data.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use dmc_backup::{
    live_paths, recover_registered, BackupManifest, RecoveryArtifact, RecoveryGate, RecoveryState,
    RecoveryStateFile,
};
use dmc_materialized::StateMaterializer;
use dmc_model::Catalog;
use dmc_security::auth::AuthService;
use dmc_runtime::RuntimeHub;
use dmc_server::{CoreServerState, UnlockMaterial};
use dmc_sql_exec::{ExecutionContext, JournalBackend};
use serde::{Deserialize, Serialize};

use crate::config::{CoreConfig, RecoveryOnStartup};
use crate::error::{StartupError, StartupResult as Result};
use crate::layout::StorageLayout;
use crate::lifecycle::{LifecycleState, ProcessLifecycle, ProjectedReadiness};
use crate::limits::RuntimeLimitPolicy;
use crate::validate::validate_config;

/// Options for [`start_core`] — never includes unlock material or session restore.
#[derive(Clone, Default)]
pub struct StartupOptions {
    /// When stores are empty, apply `Catalog::bootstrap_default` events.
    pub bootstrap_empty_catalog: bool,
    /// Shared hub for co-hosted HTTP / future WebSocket adapters (one per process).
    pub runtime_hub: Option<RuntimeHub>,
    /// D4-F, dev only (`dmc serve --dev`): also seed the demo `users` table into a fresh
    /// catalog — at the first `VaultUnlock`, into the same encrypted store.
    pub dev_users_table: bool,
}

impl std::fmt::Debug for StartupOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartupOptions")
            .field("bootstrap_empty_catalog", &self.bootstrap_empty_catalog)
            .field("runtime_hub", &self.runtime_hub.as_ref().map(|_| "<RuntimeHub>"))
            .field("dev_users_table", &self.dev_users_table)
            .finish()
    }
}

impl StartupOptions {
    pub fn production() -> Self {
        Self {
            bootstrap_empty_catalog: true,
            runtime_hub: None,
            dev_users_table: false,
        }
    }

    /// D4-F: `dmc serve --dev` — the production path plus the demo `users` table.
    pub fn dev() -> Self {
        Self {
            dev_users_table: true,
            ..Self::production()
        }
    }

    pub fn with_runtime_hub(mut self, hub: RuntimeHub) -> Self {
        self.runtime_hub = Some(hub);
        self
    }
}

/// Result of a successful start — vault Locked, no sessions, lifecycle Ready.
pub struct StartedCore {
    pub config: CoreConfig,
    pub layout: StorageLayout,
    pub lifecycle: ProcessLifecycle,
    pub server: CoreServerState,
    /// Config-backed limit policy (7.10.7) — single production source.
    pub limits: RuntimeLimitPolicy,
    /// Master Key, returned **only** on the start that created the key store (wrap it into
    /// a client KeyPass then). `None` on every later start: unlock with the original key.
    pub unlock_material: Option<UnlockMaterial>,
    /// True when a restore target still has to be recovered; recovery runs on the first
    /// successful `VaultUnlock` (D4-A stage 4.6), never while the vault is locked.
    pub recovery_required: bool,
    pub recovery_state: Option<RecoveryState>,
    /// D4-A stage 5: the data root holds a plaintext pre-D4 SQL store; it opens only after
    /// an explicit `StorageMigrateEncrypt`.
    pub migration_required: bool,
}

impl std::fmt::Debug for StartedCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartedCore")
            .field("lifecycle", &self.lifecycle.state())
            .field("vault", &self.server.vault_state())
            .field("recovery_required", &self.recovery_required)
            .field("recovery_state", &self.recovery_state)
            .field("migration_required", &self.migration_required)
            .field("limits", &self.limits.snapshot())
            .field("data_root", &self.layout.data_root())
            .field("unlock_material", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl StartedCore {
    pub fn vault_locked(&self) -> bool {
        matches!(
            self.server.vault_state(),
            dmc_server::VaultState::Locked
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartupDiagnostics {
    pub lifecycle: String,
    pub projected_readiness: String,
    pub vault: String,
    pub recovery_required: bool,
    pub accepts_new_work: bool,
}

impl StartedCore {
    pub fn diagnostics(&self) -> StartupDiagnostics {
        let snap = self.lifecycle.snapshot();
        StartupDiagnostics {
            lifecycle: snap.state.as_str().into(),
            projected_readiness: snap.projected_readiness.as_str().into(),
            vault: if self.vault_locked() {
                "locked".into()
            } else {
                "unlocked".into()
            },
            recovery_required: self.recovery_required,
            accepts_new_work: snap.accepts_new_work,
        }
    }
}

/// Public marker: this data root holds D4-A encrypted SQL storage. No key material.
pub const ENCRYPTED_STORAGE_MARKER: &str = "encrypted-storage.json";
const MARKER_FORMAT_VERSION: u32 = 1;
const MARKER_ENCRYPTION: &str = "d4a-storage-cipher-v1";

#[derive(Serialize, Deserialize)]
struct StorageMarker {
    format_version: u32,
    encryption: String,
}

/// What a data root holds, decided without keys and without reading SQL content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RootKind {
    /// No SQL data yet.
    Fresh,
    /// Encrypted SQL storage (marker, sealed files, or an encrypted restore artifact).
    Encrypted,
    /// Plaintext SQL store from before D4-A — starts locked with `migration_required`;
    /// only an explicit `StorageMigrateEncrypt` converts it (stage 5).
    PlaintextLegacy,
    /// A plaintext backup restored as the data root — refused (migrate the source store,
    /// then take an encrypted backup).
    PlaintextBackup,
}

fn classify_root(layout: &StorageLayout) -> Result<RootKind> {
    let root = layout.data_root();
    let marker = root.join(ENCRYPTED_STORAGE_MARKER);
    if marker.is_file() {
        let raw = fs::read(&marker).map_err(|e| StartupError::Io(e.to_string()))?;
        let m: StorageMarker = serde_json::from_slice(&raw)
            .map_err(|_| StartupError::Storage("malformed encrypted-storage marker".into()))?;
        if m.format_version != MARKER_FORMAT_VERSION || m.encryption != MARKER_ENCRYPTION {
            return Err(StartupError::Storage(
                "unsupported encrypted-storage marker".into(),
            ));
        }
        return Ok(RootKind::Encrypted);
    }
    if looks_like_restore_target(root) {
        let raw = fs::read(root.join(dmc_backup::MANIFEST_FILE))
            .map_err(|e| StartupError::Io(e.to_string()))?;
        let manifest: BackupManifest = serde_json::from_slice(&raw)
            .map_err(|_| StartupError::Recovery("malformed restore manifest".into()))?;
        return Ok(if manifest.encrypted {
            RootKind::Encrypted
        } else {
            RootKind::PlaintextBackup
        });
    }
    let mut kind = RootKind::Fresh;
    for file in [
        layout.state_event_log(),
        layout.materialized_snapshot(),
        dmc_materialized::StatisticsCatalog::statistics_path(&layout.rowstore_root()),
    ] {
        let raw = match fs::read(&file) {
            Ok(raw) if !raw.is_empty() => raw,
            _ => continue,
        };
        if dmc_vault::storage_cipher::looks_sealed(&raw) {
            return Ok(RootKind::Encrypted);
        }
        kind = RootKind::PlaintextLegacy;
    }
    Ok(kind)
}

pub(crate) fn write_marker(root: &Path) -> Result<()> {
    let marker = StorageMarker {
        format_version: MARKER_FORMAT_VERSION,
        encryption: MARKER_ENCRYPTION.into(),
    };
    let bytes = serde_json::to_vec_pretty(&marker).map_err(|e| StartupError::Io(e.to_string()))?;
    let path = root.join(ENCRYPTED_STORAGE_MARKER);
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).map_err(|e| StartupError::Io(e.to_string()))?;
    fs::rename(&tmp, &path).map_err(|e| StartupError::Io(e.to_string()))
}

/// Orchestrate Config → Layout → provision → (recover if required) → open → Ready + Locked.
///
/// Does **not**: unlock vault, recreate AuthSessions, or accept SQL before UnlockGate.
pub fn start_core(config: CoreConfig, options: StartupOptions) -> Result<StartedCore> {
    let mut lifecycle = ProcessLifecycle::new();
    match start_inner(config, options, &mut lifecycle) {
        Ok(started) => Ok(started),
        Err(e) => {
            let _ = lifecycle.mark_failed();
            Err(e)
        }
    }
}

fn start_inner(
    config: CoreConfig,
    options: StartupOptions,
    lifecycle: &mut ProcessLifecycle,
) -> Result<StartedCore> {
    assert_eq!(lifecycle.state(), LifecycleState::Starting);

    validate_config(&config).map_err(|e| StartupError::Config(e.to_string()))?;
    let layout =
        StorageLayout::from_config(&config).map_err(|e| StartupError::Layout(e.to_string()))?;

    // D4-A stage 5: complete (switching) or drop (building) an interrupted migration
    // before anything else looks at the store. Needs no keys.
    crate::migrate::resume_interrupted(&layout).map_err(|_| {
        StartupError::Storage("could not complete an interrupted storage migration".into())
    })?;

    provision_layout(&layout)?;
    validate_provisioned(&layout)?;

    // D4-A: encrypted-only SQL storage; decided before any key store is created.
    let root_kind = classify_root(&layout)?;
    let key_store = layout.vault_root().join(dmc_server::KEY_TREE_FILE);
    match root_kind {
        RootKind::PlaintextBackup => {
            return Err(StartupError::Storage(
                "plaintext backup as data root: explicit migration required".into(),
            ));
        }
        // stage 5: starts locked; storage opens only after an explicit migration
        RootKind::PlaintextLegacy => {}
        RootKind::Encrypted if !key_store.is_file() => {
            // D4-E: a restore target carries its installation's key store (wrapped keys
            // only); it is authenticated at unlock and recovery, never created anew.
            let installed = dmc_backup::install_key_store(layout.data_root(), &key_store)
                .map_err(|e| StartupError::Vault(format!("carried key store refused: {e}")))?;
            if !installed {
                return Err(StartupError::Vault(
                    "encrypted storage without its key store: refusing to create a new one"
                        .into(),
                ));
            }
        }
        RootKind::Encrypted | RootKind::Fresh => {}
    }

    let recovery = probe_recovery(&layout)?;
    if recovery.required {
        match config.recovery.on_startup {
            RecoveryOnStartup::Auto => {
                // D4-A 4.6: metadata only (no SQL data, no keys); the recovery itself
                // runs on VaultUnlock (`OpsStorageOpener`).
                precheck_restore_metadata(layout.data_root())?;
            }
            RecoveryOnStartup::ManualFail => {
                return Err(StartupError::Recovery(
                    "recovery required; recovery.on_startup=manual_fail".into(),
                ));
            }
        }
    }

    // Inconsistent Ready metadata without live tree → Failed (not silent hierarchical open).
    if matches!(recovery.state, Some(RecoveryState::Ready)) {
        let gate = RecoveryGate::load(layout.data_root())
            .map_err(|e| StartupError::Recovery(e.to_string()))?;
        if !gate.live_root.is_dir() {
            return Err(StartupError::Recovery(
                "recovery state Ready but live root missing".into(),
            ));
        }
    }

    // D4-A stage 3: storage is validated structurally now (no keys needed) but opened
    // only after `VaultUnlock` — nothing is read into memory while the vault is locked.
    validate_store_structure(&layout, &recovery)?;
    let opener = OpsStorageOpener {
        layout: layout.clone(),
        bootstrap_empty_catalog: options.bootstrap_empty_catalog,
        dev_users_table: options.dev_users_table,
    };
    let ctx = ExecutionContext::new();

    // Persisted identities, verifiers, grants and bootstrap record (fail closed on a
    // corrupt file, or on a missing file after bootstrap).
    let mut auth = AuthService::new();
    dmc_security::auth::bootstrap::load_identity_directory(
        &mut auth,
        &layout.data_root().join(dmc_server::OWNERSHIP_DIR),
        &layout.data_root().join(dmc_server::IDENTITIES_FILE),
    )
    .map_err(|e| StartupError::Identity(e.to_string()))?;

    let policy = RuntimeLimitPolicy::from_validated_config(&config);
    let hub = options
        .runtime_hub
        .clone()
        .unwrap_or_else(RuntimeHub::new);
    // D4-A stage 1: persistent key store — created once (Master Key issued once), then
    // loaded on every start; never silently re-created.
    let (mut server, unlock_material) = CoreServerState::open_persistent_with_hub(
        auth,
        ctx,
        layout.data_root().to_path_buf(),
        &key_store,
        hub,
    )
    .map_err(|e| StartupError::Vault(e.to_string()))?;
    // marker only after the key store exists (a crash in between never strands data);
    // a plaintext store gets it only from the explicit migration
    if root_kind != RootKind::PlaintextLegacy
        && !layout.data_root().join(ENCRYPTED_STORAGE_MARKER).is_file()
    {
        write_marker(layout.data_root())?;
    }
    server.set_limits(policy.to_remote_limits());
    server.set_storage_opener(Box::new(opener));

    if !matches!(server.vault_state(), dmc_server::VaultState::Locked) {
        return Err(StartupError::Vault(
            "startup invariant violated: vault not locked".into(),
        ));
    }

    lifecycle
        .mark_ready()
        .map_err(|e| StartupError::Lifecycle(e.to_string()))?;

    Ok(StartedCore {
        config,
        layout,
        lifecycle: lifecycle.clone(),
        server,
        limits: policy,
        unlock_material,
        recovery_required: recovery.required,
        recovery_state: recovery.state,
        migration_required: root_kind == RootKind::PlaintextLegacy,
    })
}

#[derive(Clone)]
struct RecoveryProbe {
    required: bool,
    state: Option<RecoveryState>,
}

fn probe_recovery(layout: &StorageLayout) -> Result<RecoveryProbe> {
    let path = layout.recovery_state();
    if path.is_file() {
        let raw = fs::read(&path).map_err(|e| StartupError::Io(e.to_string()))?;
        let file: RecoveryStateFile = serde_json::from_slice(&raw).map_err(|_| {
            StartupError::RecoveryMetadata("malformed recovery/state.json".into())
        })?;
        if file.format_version != RecoveryStateFile::FORMAT_VERSION {
            return Err(StartupError::RecoveryMetadata(format!(
                "unsupported recovery format_version {}",
                file.format_version
            )));
        }
        let required = !matches!(file.state, RecoveryState::Ready);
        return Ok(RecoveryProbe {
            required,
            state: Some(file.state),
        });
    }

    // Restore publishes artifact layout without writing `recovery/state.json`.
    // `RecoveryGate::load` treats missing state as Restored — but only on a real
    // restore target (manifest + recovery metadata). Fresh StorageLayout roots
    // must not look like recovery_required.
    if looks_like_restore_target(layout.data_root()) {
        let gate = RecoveryGate::load(layout.data_root())
            .map_err(|e| StartupError::RecoveryMetadata(e.to_string()))?;
        return Ok(RecoveryProbe {
            required: !gate.is_ready(),
            state: Some(gate.state),
        });
    }

    Ok(RecoveryProbe {
        required: false,
        state: None,
    })
}

/// Startup check of a pending restore target that reads no SQL data: the root manifest
/// and the recovery metadata parse and agree on the checkpoint.
fn precheck_restore_metadata(root: &Path) -> Result<()> {
    let read = |rel: &str| -> Result<Vec<u8>> {
        fs::read(root.join(rel))
            .map_err(|_| StartupError::Recovery(format!("restore artifact missing {rel}")))
    };
    let manifest: BackupManifest = serde_json::from_slice(&read(dmc_backup::MANIFEST_FILE)?)
        .map_err(|_| StartupError::Recovery("malformed restore manifest".into()))?;
    let meta: RecoveryArtifact = serde_json::from_slice(&read("recovery/metadata.json")?)
        .map_err(|_| StartupError::Recovery("malformed recovery metadata".into()))?;
    if meta.checkpoint_sequence != manifest.checkpoint_sequence {
        return Err(StartupError::Recovery(
            "recovery metadata checkpoint does not match the manifest".into(),
        ));
    }
    Ok(())
}

fn looks_like_restore_target(root: &Path) -> bool {
    root.join(dmc_backup::MANIFEST_FILE).is_file()
        && root.join("recovery/metadata.json").is_file()
}

fn provision_layout(layout: &StorageLayout) -> Result<()> {
    for dir in layout.provision_directories() {
        fs::create_dir_all(&dir).map_err(|e| StartupError::Provision(e.to_string()))?;
    }
    Ok(())
}

fn validate_provisioned(layout: &StorageLayout) -> Result<()> {
    for dir in layout.provision_directories() {
        if !dir.is_dir() {
            return Err(StartupError::Provision(format!(
                "missing directory after provision: {}",
                dir.file_name().and_then(|s| s.to_str()).unwrap_or("?")
            )));
        }
    }
    Ok(())
}

enum StoreOpenKind {
    /// Hierarchical V1 layout under `data_root` (fresh / non-restore).
    Layout,
    /// ADR-024 recovered `live/` tree under a restore target.
    RecoveredLive,
}

fn resolve_store_paths(
    layout: &StorageLayout,
    recovery: &RecoveryProbe,
) -> Result<(PathBuf, PathBuf, PathBuf, StoreOpenKind)> {
    if matches!(recovery.state, Some(RecoveryState::Ready)) {
        let (rows, snapshot, log) = live_paths(layout.data_root());
        if !log.is_file() {
            return Err(StartupError::Recovery(
                "recovered live missing state_events.json".into(),
            ));
        }
        return Ok((rows, snapshot, log, StoreOpenKind::RecoveredLive));
    }
    Ok((
        layout.rowstore_root(),
        layout.materialized_snapshot(),
        layout.state_event_log(),
        StoreOpenKind::Layout,
    ))
}

/// Opens SQL-plane storage on `VaultUnlock` (see `dmc_server::StorageOpener`): first
/// completes a pending recovery (D4-A 4.6), then opens the store.
struct OpsStorageOpener {
    layout: StorageLayout,
    bootstrap_empty_catalog: bool,
    dev_users_table: bool,
}

impl OpsStorageOpener {
    fn recover_and_open(
        &self,
        cipher: &dmc_vault::StorageCipher,
    ) -> Result<StateMaterializer<dmc_materialized::FileStateEventLog>> {
        // D4-A: encrypted-only — the store and any restore target use the storage keys.
        let keys = Some(Arc::new(cipher.clone()));
        // D4-E: the key store that unlocked must be byte-identical to the one the restored
        // root carries (whose digest recovery authenticates) — checked before recovery.
        dmc_backup::ensure_key_store_matches(
            self.layout.data_root(),
            &self.layout.vault_root().join(dmc_server::KEY_TREE_FILE),
        )
        .map_err(|e| StartupError::Recovery(e.to_string()))?;
        let mut recovery = probe_recovery(&self.layout)?;
        if recovery.required {
            precheck_restore_metadata(self.layout.data_root())?;
            // ADR-024 owner of recovery semantics — ops only orchestrates. D4-C: only a
            // registered restore (sealed attestation for exactly this artifact) recovers.
            let cipher = keys.clone().expect("encrypted-only");
            recover_registered(self.layout.data_root(), cipher, None)
                .map_err(|e| StartupError::Recovery(e.to_string()))?;
            recovery = probe_recovery(&self.layout)?;
            if recovery.required {
                return Err(StartupError::Recovery(
                    "recover completed but recovery_required still true".into(),
                ));
            }
        }
        open_materializer(
            &self.layout,
            self.bootstrap_empty_catalog,
            self.dev_users_table,
            &recovery,
            keys,
        )
    }
}

impl dmc_server::StorageOpener for OpsStorageOpener {
    fn migration_required(&self) -> bool {
        matches!(classify_root(&self.layout), Ok(RootKind::PlaintextLegacy))
    }

    fn migrate(
        &self,
        cipher: &dmc_vault::StorageCipher,
        purge_plaintext_backups: bool,
    ) -> std::result::Result<dmc_server::MigrationReport, dmc_server::MigrationError> {
        if !self.migration_required() {
            return Err(dmc_server::MigrationError::Refused(
                "store does not need migration".into(),
            ));
        }
        crate::migrate::migrate_plaintext_store(&self.layout, cipher, purge_plaintext_backups)
    }

    fn open(&self, cipher: &dmc_vault::StorageCipher) -> std::result::Result<ExecutionContext, String> {
        if self.migration_required() {
            return Err("plaintext SQL store: explicit migration required".into());
        }
        execution_context(self.recover_and_open(cipher).map_err(|e| e.to_string())?)
    }

    /// D4-E (variant B): emergency restore. Only a pending restore, only the
    /// client-authorized artifact (fully authenticated, checkpoint not below the client's
    /// anchor) receives the restore attestation — then the ordinary registered recovery.
    fn open_authorized(
        &self,
        cipher: &dmc_vault::StorageCipher,
        authorized: &[u8; 32],
        min_generation: u64,
    ) -> std::result::Result<ExecutionContext, dmc_server::AuthorizedOpenError> {
        use dmc_server::AuthorizedOpenError::{Refused, Rollback};
        if self.migration_required() {
            return Err(Refused("plaintext SQL store: explicit migration required".into()));
        }
        let root = self.layout.data_root();
        dmc_backup::ensure_key_store_matches(
            root,
            &self.layout.vault_root().join(dmc_server::KEY_TREE_FILE),
        )
        .map_err(|e| Refused(e.to_string()))?;
        let recovery = probe_recovery(&self.layout).map_err(|e| Refused(e.to_string()))?;
        if !recovery.required {
            return Err(Refused(
                "restore authorization without a pending restore: refused".into(),
            ));
        }
        precheck_restore_metadata(root).map_err(|e| Refused(e.to_string()))?;
        match dmc_backup::authorize_emergency_restore(root, cipher, authorized, min_generation) {
            Ok(()) => {}
            Err(dmc_backup::BackupError::OlderThanAnchor { .. }) => return Err(Rollback),
            Err(e) => return Err(Refused(e.to_string())),
        }
        let mat = self.recover_and_open(cipher).map_err(|e| Refused(e.to_string()))?;
        execution_context(mat).map_err(Refused)
    }
}

fn execution_context(
    mat: StateMaterializer<dmc_materialized::FileStateEventLog>,
) -> std::result::Result<ExecutionContext, String> {
    let catalog = mat.catalog().clone();
    let mut ctx = ExecutionContext::new();
    ctx.attach_journal(JournalBackend::File(mat));
    ctx.attach_session_catalog(&catalog);
    ctx.register_materialized_tables_from_journal()
        .map_err(|e| e.to_string())?;
    Ok(ctx)
}

/// Startup-time check that needs no keys: the event log is well-formed. A sealed log
/// (D4-A) is opaque without keys — it is authenticated and parsed on `VaultUnlock`.
fn validate_store_structure(layout: &StorageLayout, recovery: &RecoveryProbe) -> Result<()> {
    let (_, _, log, _) = resolve_store_paths(layout, recovery)?;
    if log.is_file() {
        let raw = fs::read(&log).map_err(|e| StartupError::Io(e.to_string()))?;
        if !raw.is_empty() && !dmc_vault::storage_cipher::looks_sealed(&raw) {
            let _: serde_json::Value = serde_json::from_slice(&raw)
                .map_err(|_| StartupError::Journal("corrupt state_events.json".into()))?;
        }
    }
    Ok(())
}

fn open_materializer(
    layout: &StorageLayout,
    bootstrap_empty_catalog: bool,
    dev_users_table: bool,
    recovery: &RecoveryProbe,
    cipher: Option<Arc<dmc_vault::StorageCipher>>,
) -> Result<StateMaterializer<dmc_materialized::FileStateEventLog>> {
    let (rows, snapshot, log, kind) = resolve_store_paths(layout, recovery)?;

    let mut mat = match kind {
        StoreOpenKind::RecoveredLive if snapshot.is_file() => {
            StateMaterializer::open_recovered_with_cipher(&rows, snapshot.clone(), log, cipher)
                .map_err(|e| StartupError::Journal(e.to_string()))?
        }
        _ => StateMaterializer::open_with_cipher(&rows, snapshot.clone(), log, cipher)
            .map_err(|e| StartupError::Journal(e.to_string()))?,
    };

    let fresh = mat.tip_sequence() == 0 && !snapshot_has_catalog(&snapshot);
    if fresh && bootstrap_empty_catalog && matches!(kind, StoreOpenKind::Layout) {
        let mut catalog = Catalog::new();
        let mut events = catalog
            .bootstrap_default()
            .map_err(|e| StartupError::Catalog(e.to_string()))?;
        if dev_users_table {
            events.push(
                dmc_server::dev_users_table_event(&mut catalog).map_err(StartupError::Catalog)?,
            );
        }
        // `bootstrap_default` already applied events to `catalog`; journal them only.
        for event in events {
            mat.mutate_catalog(event)
                .map_err(|e| StartupError::Journal(e.to_string()))?;
        }
    }

    Ok(mat)
}

fn snapshot_has_catalog(path: &Path) -> bool {
    path.is_file()
        && fs::metadata(path)
            .map(|m| m.len() > 0)
            .unwrap_or(false)
}

/// Sanitized startup failure helpers for tests.
pub fn assert_startup_error_clean(err: &StartupError) {
    let text = err.to_string().to_lowercase();
    for needle in [
        "master_key",
        "unlock_material",
        "password",
        "\"dek\"",
        "\"kek\"",
        "keypass",
        "-----begin",
    ] {
        assert!(
            !text.contains(needle),
            "startup error leaked `{needle}`: {text}"
        );
    }
}

pub fn assert_started_invariants(started: &StartedCore) {
    assert_eq!(started.lifecycle.state(), LifecycleState::Ready);
    assert!(started.lifecycle.accepts_new_work());
    assert_eq!(
        started.lifecycle.snapshot().projected_readiness,
        ProjectedReadiness::Ready
    );
    assert!(started.vault_locked());
    assert!(!started.server.root_dek_present());
    let diag = started.diagnostics();
    assert_eq!(diag.vault, "locked");
    assert_eq!(diag.lifecycle, "ready");
    assert!(diag.accepts_new_work);
    let text = format!("{diag:?}").to_lowercase();
    assert!(!text.contains("password"));
    assert!(!text.contains("master_key"));
    assert!(!text.contains("unlock_material"));
}
