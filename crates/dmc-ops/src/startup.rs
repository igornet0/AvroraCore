//! Phase 7.10.4–7.10.5 — Startup orchestration + Recovery-on-startup.
//!
//! Success → Ready + Locked. Recovery reuses ADR-024 [`dmc_backup::recover`] /
//! [`RecoveryGate`] — never unlocks vault or restores sessions.

use std::fs;
use std::path::{Path, PathBuf};

use dmc_backup::{
    live_paths, recover, RecoveryGate, RecoveryState, RecoveryStateFile,
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
}

impl std::fmt::Debug for StartupOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartupOptions")
            .field("bootstrap_empty_catalog", &self.bootstrap_empty_catalog)
            .field("runtime_hub", &self.runtime_hub.as_ref().map(|_| "<RuntimeHub>"))
            .finish()
    }
}

impl StartupOptions {
    pub fn production() -> Self {
        Self {
            bootstrap_empty_catalog: true,
            runtime_hub: None,
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
    /// One-time material for client KeyPass wrap — **not** stored in server state.
    pub unlock_material: UnlockMaterial,
    /// True only if recovery is still required after this start (should be false on success).
    pub recovery_required: bool,
    pub recovery_state: Option<RecoveryState>,
}

impl std::fmt::Debug for StartedCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartedCore")
            .field("lifecycle", &self.lifecycle.state())
            .field("vault", &self.server.vault_state())
            .field("recovery_required", &self.recovery_required)
            .field("recovery_state", &self.recovery_state)
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

    provision_layout(&layout)?;
    validate_provisioned(&layout)?;

    let mut recovery = probe_recovery(&layout)?;
    if recovery.required {
        match config.recovery.on_startup {
            RecoveryOnStartup::Auto => {
                // ADR-024 owner of recovery semantics — ops only orchestrates.
                recover(layout.data_root()).map_err(|e| StartupError::Recovery(e.to_string()))?;
                recovery = probe_recovery(&layout)?;
                if recovery.required {
                    return Err(StartupError::Recovery(
                        "recover completed but recovery_required still true".into(),
                    ));
                }
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

    let mat = open_materializer(&layout, &options, &recovery)?;
    let catalog = mat.catalog().clone();

    let mut ctx = ExecutionContext::new();
    ctx.attach_journal(JournalBackend::File(mat));
    ctx.attach_session_catalog(&catalog);
    ctx.register_materialized_tables_from_journal()
        .map_err(|e| StartupError::Storage(e.to_string()))?;

    let auth = AuthService::new();

    let policy = RuntimeLimitPolicy::from_validated_config(&config);
    let hub = options
        .runtime_hub
        .clone()
        .unwrap_or_else(RuntimeHub::new);
    let (mut server, unlock_material) = CoreServerState::new_locked_with_hub(
        auth,
        ctx,
        layout.data_root().to_path_buf(),
        hub,
    )
    .map_err(|e| StartupError::Vault(e.to_string()))?;
    server.set_limits(policy.to_remote_limits());

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
    })
}

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

fn open_materializer(
    layout: &StorageLayout,
    options: &StartupOptions,
    recovery: &RecoveryProbe,
) -> Result<StateMaterializer<dmc_materialized::FileStateEventLog>> {
    let (rows, snapshot, log, kind) = resolve_store_paths(layout, recovery)?;

    if log.is_file() {
        let raw = fs::read(&log).map_err(|e| StartupError::Io(e.to_string()))?;
        if !raw.is_empty() {
            let _: serde_json::Value = serde_json::from_slice(&raw)
                .map_err(|_| StartupError::Journal("corrupt state_events.json".into()))?;
        }
    }

    let mut mat = match kind {
        StoreOpenKind::RecoveredLive if snapshot.is_file() => {
            StateMaterializer::open_recovered(&rows, snapshot.clone(), log)
                .map_err(|e| StartupError::Journal(e.to_string()))?
        }
        _ => StateMaterializer::open(&rows, snapshot.clone(), log)
            .map_err(|e| StartupError::Journal(e.to_string()))?,
    };

    let fresh = mat.tip_sequence() == 0 && !snapshot_has_catalog(&snapshot);
    if fresh && options.bootstrap_empty_catalog && matches!(kind, StoreOpenKind::Layout) {
        let mut catalog = Catalog::new();
        let events = catalog
            .bootstrap_default()
            .map_err(|e| StartupError::Catalog(e.to_string()))?;
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
