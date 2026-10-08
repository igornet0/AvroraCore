//! Phase 7.8.6 — Recovery / rebuild: restored artifact @ N → READY live DB @ N.
//!
//! Does **not** unlock vault or restore sessions. SQL remains gated by
//! [`RecoveryGate::require_ready`] + UnlockGate + AuthGate (server).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use dmc_materialized::{
    save_materialized_snapshot_with, write_state_event_log_with, MaterializedStateSnapshot,
    StateEventRecord, StateMaterializer, STATE_EVENT_LOG_FORMAT_VERSION,
};
use dmc_vault::StorageCipher;
use dmc_model::{Catalog, MaterializedWatermark};
use serde::{Deserialize, Serialize};

use crate::artifact::{
    CatalogArtifact, JournalArtifact, JournalSegmentFile, RecoveryArtifact, StorageArtifact,
};
use crate::digest::{copy_dir_all, write_json_atomic};
use crate::error::{BackupError, Result};
use crate::manifest::{BackupManifest, MANIFEST_FILE};
use crate::restore::{SessionRestoreState, VaultRestoreState};
use crate::sealed::{read_component, BackupKeys};
use crate::verify::verify_backup_with;

pub const LIVE_DIR: &str = "live";
pub const RECOVERY_STATE_FILE: &str = "recovery/state.json";
pub const RECOVER_STAGE_DIR: &str = ".recover";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryState {
    /// Files restored; derived projections not yet rebuilt.
    Restored,
    /// Rebuild in progress — never treat as SQL-ready.
    Recovering,
    /// Indexes + statistics rebuilt; checkpoint verified @ N.
    Ready,
    /// Last recover attempt failed; not SQL-ready.
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryStateFile {
    pub format_version: u32,
    pub checkpoint_sequence: u64,
    pub state: RecoveryState,
    pub indexes_rebuilt: bool,
    pub statistics_rebuilt: bool,
    pub live_relative: String,
}

impl RecoveryStateFile {
    pub const FORMAT_VERSION: u32 = 1;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryResult {
    pub checkpoint_sequence: u64,
    pub state: RecoveryState,
    pub live_root: PathBuf,
    pub indexes_rebuilt: bool,
    pub statistics_rebuilt: bool,
    pub vault: VaultRestoreState,
    pub sessions: SessionRestoreState,
}

/// Lifecycle gate: SQL must not run until [`RecoveryState::Ready`].
#[derive(Clone, Debug)]
pub struct RecoveryGate {
    pub state: RecoveryState,
    pub checkpoint_sequence: u64,
    pub live_root: PathBuf,
}

impl RecoveryGate {
    pub fn load(target: &Path) -> Result<Self> {
        let path = target.join(RECOVERY_STATE_FILE);
        if !path.is_file() {
            return Ok(Self {
                state: RecoveryState::Restored,
                checkpoint_sequence: 0,
                live_root: target.join(LIVE_DIR),
            });
        }
        let raw = fs::read(&path).map_err(|e| BackupError::Io(e.to_string()))?;
        let file: RecoveryStateFile =
            serde_json::from_slice(&raw).map_err(|e| BackupError::Corrupt(e.to_string()))?;
        Ok(Self {
            state: file.state,
            checkpoint_sequence: file.checkpoint_sequence,
            live_root: target.join(&file.live_relative),
        })
    }

    pub fn require_ready(&self) -> Result<()> {
        match self.state {
            RecoveryState::Ready => Ok(()),
            other => Err(BackupError::RecoveryNotReady(format!(
                "recovery state is {other:?}; SQL requires Ready"
            ))),
        }
    }

    pub fn is_ready(&self) -> bool {
        self.state == RecoveryState::Ready
    }
}

/// Recover a restored backup target into a runnable live DB @ N.
///
/// Idempotent: repeated calls on an already-Ready target re-verify and return success.
/// Keyless: only plaintext (dev/test, pre-D4) artifacts; see [`recover_with`].
pub fn recover(target: &Path) -> Result<RecoveryResult> {
    recover_with(target, None)
}

/// D4-C: production recovery. The restore target must carry a valid sealed restore
/// attestation for exactly its `manifest.sealed` (written by
/// [`crate::restore_backup_registered`]); with `registry_root` (the live storage root, when
/// reachable) the backup must also still be the registered one. Then [`recover_with`].
pub fn recover_registered(
    target: &Path,
    cipher: Arc<StorageCipher>,
    registry_root: Option<&Path>,
) -> Result<RecoveryResult> {
    let manifest: BackupManifest = read_json(&target.join(MANIFEST_FILE))?;
    if !manifest.encrypted {
        return Err(BackupError::BackupInvalid(
            "unencrypted backup: explicit migration required".into(),
        ));
    }
    crate::registry::check_attestation(target, &manifest, &cipher)?;
    if let Some(root) = registry_root {
        crate::registry::BackupRegistry::load(root, &cipher)?.confirm(target, &manifest)?;
    }
    // keyed verification inside authenticates manifest.json against manifest.sealed
    recover_with(target, Some(cipher))
}

/// [`recover`] with the storage keys (D4-A). An encrypted artifact is authenticated and
/// decrypted in memory; the live tree is written encrypted with the same keys. Without
/// keys an encrypted artifact is refused before anything is written ([`BackupError::KeysRequired`]).
/// Does **not** unlock the vault: the caller passes keys it already holds.
pub fn recover_with(target: &Path, cipher: Option<Arc<StorageCipher>>) -> Result<RecoveryResult> {
    if !target.is_dir() {
        return Err(BackupError::Io(format!(
            "recovery target is not a directory: {}",
            target.display()
        )));
    }

    // Existing Ready → verify still consistent, no work.
    if let Ok(gate) = RecoveryGate::load(target) {
        if gate.state == RecoveryState::Ready && gate.live_root.is_dir() {
            verify_checkpoints(target, cipher.as_deref())?;
            verify_live_at_n(&gate.live_root, gate.checkpoint_sequence, cipher.clone())?;
            return Ok(RecoveryResult {
                checkpoint_sequence: gate.checkpoint_sequence,
                state: RecoveryState::Ready,
                live_root: gate.live_root,
                indexes_rebuilt: true,
                statistics_rebuilt: true,
                vault: VaultRestoreState::Locked,
                sessions: SessionRestoreState::Invalid,
            });
        }
    }

    let n = verify_checkpoints(target, cipher.as_deref())?;
    write_recovery_state(
        target,
        RecoveryState::Recovering,
        n,
        false,
        false,
    )?;

    let run = (|| -> Result<RecoveryResult> {
        let live = prepare_live_tree(target, n, cipher.as_ref())?;
        rebuild_derived_projections(&live, n, cipher.clone())?;
        verify_live_at_n(&live, n, cipher.clone())?;
        write_recovery_state(target, RecoveryState::Ready, n, true, true)?;
        Ok(RecoveryResult {
            checkpoint_sequence: n,
            state: RecoveryState::Ready,
            live_root: live,
            indexes_rebuilt: true,
            statistics_rebuilt: true,
            vault: VaultRestoreState::Locked,
            sessions: SessionRestoreState::Invalid,
        })
    })();

    match run {
        Ok(result) => Ok(result),
        Err(e) => {
            let _ = write_recovery_state(target, RecoveryState::Failed, n, false, false);
            Err(e)
        }
    }
}

fn verify_checkpoints(target: &Path, cipher: Option<&StorageCipher>) -> Result<u64> {
    let manifest: BackupManifest = read_json(&target.join(MANIFEST_FILE))?;
    if manifest.encrypted && cipher.is_none() {
        return Err(BackupError::KeysRequired(
            "restored backup is encrypted; recovery needs the unlocked storage keys".into(),
        ));
    }
    let report = verify_backup_with(target, cipher)?;
    if !report.valid {
        return Err(BackupError::BackupInvalid(report.errors.join("; ")));
    }
    let n = report.checkpoint_sequence;

    let keys = cipher.map(|c| BackupKeys::for_manifest(c, &manifest));
    let journal: JournalArtifact = read_json(&target.join("journal/manifest.json"))?;
    let catalog: CatalogArtifact =
        read_component(target, "catalog/catalog.json", manifest.encrypted, keys.as_ref())?
            .ok_or_else(|| BackupError::KeysRequired("catalog is encrypted".into()))?;
    let storage: StorageArtifact = read_json(&target.join("storage/manifest.json"))?;
    let recovery: RecoveryArtifact = read_json(&target.join("recovery/metadata.json"))?;

    for (name, seq) in [
        ("manifest", manifest.checkpoint_sequence),
        ("journal", journal.tip_sequence),
        ("journal.checkpoint", journal.checkpoint_sequence),
        ("catalog", catalog.checkpoint_sequence),
        ("storage", storage.checkpoint_sequence),
        ("recovery", recovery.checkpoint_sequence),
    ] {
        if seq != n {
            return Err(BackupError::RecoveryCheckpointMismatch {
                component: name.into(),
                expected: n,
                got: seq,
            });
        }
    }
    Ok(n)
}

fn prepare_live_tree(target: &Path, n: u64, cipher: Option<&Arc<StorageCipher>>) -> Result<PathBuf> {
    let stage_root = target.join(RECOVER_STAGE_DIR);
    let stage = stage_root.join("live");
    if stage_root.exists() {
        fs::remove_dir_all(&stage_root).map_err(|e| BackupError::Io(e.to_string()))?;
    }
    fs::create_dir_all(&stage).map_err(|e| BackupError::Io(e.to_string()))?;

    let manifest: BackupManifest = read_json(&target.join(MANIFEST_FILE))?;
    let keys = cipher.map(|c| BackupKeys::for_manifest(c, &manifest));
    let events = load_journal_events(target, n, &manifest, keys.as_ref())?;
    let event_log_path = stage.join("state_events.json");
    write_state_event_log_with(&event_log_path, events.clone(), cipher.cloned())
        .map_err(|e| BackupError::Corrupt(format!("write state_events: {e}")))?;

    let rows = stage.join("rows");
    fs::create_dir_all(&rows).map_err(|e| BackupError::Io(e.to_string()))?;

    let storage: StorageArtifact = read_json(&target.join("storage/manifest.json"))?;
    let recovery: RecoveryArtifact = read_json(&target.join("recovery/metadata.json"))?;
    let catalog_art: CatalogArtifact =
        read_component(target, "catalog/catalog.json", manifest.encrypted, keys.as_ref())?
            .ok_or_else(|| BackupError::KeysRequired("catalog is encrypted".into()))?;
    let catalog = Catalog::from_snapshot_body(catalog_art.catalog.clone())
        .map_err(|e| BackupError::Corrupt(format!("catalog: {e}")))?;

    let use_rowstore = storage.include_segments && !recovery.require_rebuild_rowstore;
    if use_rowstore {
        let tables_src = target.join("storage/tables");
        if tables_src.is_dir() {
            for entry in fs::read_dir(&tables_src).map_err(|e| BackupError::Io(e.to_string()))? {
                let entry = entry.map_err(|e| BackupError::Io(e.to_string()))?;
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    let name = entry.file_name();
                    copy_dir_all(&entry.path(), &rows.join(name))?;
                }
            }
        }
        // Snapshot @ N — open_recovered trusts this vs tip.
        let seen: Vec<[u8; 16]> = events.iter().map(|e| e.event_id).collect();
        let snapshot = MaterializedStateSnapshot::new(
            MaterializedWatermark::at(n),
            catalog.to_snapshot_body(),
            seen,
        );
        save_materialized_snapshot_with(
            &stage.join("materialized_snapshot.json"),
            &snapshot,
            cipher.map(|c| c.as_ref()),
        )
        .map_err(|e| BackupError::Corrupt(format!("snapshot: {e}")))?;
    } else {
        // Empty snapshot path; open() will full-replay from state_events.
        let _ = STATE_EVENT_LOG_FORMAT_VERSION;
    }

    crate::ownership::install_into_live(target, &stage, &manifest, keys.as_ref())?;

    // Publish staged live → target/live atomically.
    let live = target.join(LIVE_DIR);
    if live.exists() {
        fs::remove_dir_all(&live).map_err(|e| BackupError::Io(e.to_string()))?;
    }
    fs::rename(&stage, &live).map_err(|e| BackupError::Io(e.to_string()))?;
    let _ = fs::remove_dir_all(&stage_root);
    Ok(live)
}

fn load_journal_events(
    target: &Path,
    n: u64,
    manifest: &BackupManifest,
    keys: Option<&BackupKeys<'_>>,
) -> Result<Vec<StateEventRecord>> {
    let journal: JournalArtifact = read_json(&target.join("journal/manifest.json"))?;
    let mut events = Vec::new();
    for seg in &journal.segments {
        let file: JournalSegmentFile =
            read_component(target, &seg.relative_path, manifest.encrypted, keys)?
                .ok_or_else(|| BackupError::KeysRequired("journal is encrypted".into()))?;
        events.extend(file.events);
    }
    events.sort_by_key(|e| e.sequence);
    let max = events.last().map(|e| e.sequence).unwrap_or(0);
    if max != n {
        return Err(BackupError::RecoveryCheckpointMismatch {
            component: "journal.events".into(),
            expected: n,
            got: max,
        });
    }
    Ok(events)
}

fn rebuild_derived_projections(
    live: &Path,
    n: u64,
    cipher: Option<Arc<StorageCipher>>,
) -> Result<()> {
    let rows = live.join("rows");
    let snapshot = live.join("materialized_snapshot.json");
    let log = live.join("state_events.json");

    let mut mat = if snapshot.is_file() {
        StateMaterializer::open_recovered_with_cipher(
            &rows,
            snapshot.clone(),
            log.clone(),
            cipher.clone(),
        )
        .map_err(|e| BackupError::Corrupt(format!("open_recovered: {e}")))?
    } else {
        StateMaterializer::open_with_cipher(&rows, snapshot.clone(), log.clone(), cipher.clone())
            .map_err(|e| BackupError::Corrupt(format!("open/replay: {e}")))?
    };

    if mat.tip_sequence() != n || mat.watermark().sequence != n {
        return Err(BackupError::RecoveryCheckpointMismatch {
            component: "materializer".into(),
            expected: n,
            got: mat.watermark().sequence,
        });
    }

    mat.rebuild_all_indexes()
        .map_err(|e| BackupError::Corrupt(format!("index rebuild: {e}")))?;
    mat.rebuild_all_statistics()
        .map_err(|e| BackupError::Corrupt(format!("statistics rebuild: {e}")))?;

    // Persist snapshot reflecting Ready materialization — including every store's
    // generation (D4-B), so later opens detect a rolled-back table / index.
    mat.persist_snapshot_if_configured()
        .map_err(|e| BackupError::Corrupt(format!("persist snapshot: {e}")))?;

    Ok(())
}

fn verify_live_at_n(live: &Path, n: u64, cipher: Option<Arc<StorageCipher>>) -> Result<()> {
    let rows = live.join("rows");
    let snapshot = live.join("materialized_snapshot.json");
    let log = live.join("state_events.json");
    if !log.is_file() {
        return Err(BackupError::Corrupt("live missing state_events.json".into()));
    }
    // Prefer recovered open when snapshot exists (avoid second full replay).
    let mat = if snapshot.is_file() {
        StateMaterializer::open_recovered_with_cipher(&rows, snapshot, log, cipher)
            .map_err(|e| BackupError::Corrupt(format!("verify live: {e}")))?
    } else {
        StateMaterializer::open_with_cipher(&rows, snapshot, log, cipher)
            .map_err(|e| BackupError::Corrupt(format!("verify live: {e}")))?
    };
    if mat.tip_sequence() != n || mat.watermark().sequence != n {
        return Err(BackupError::RecoveryCheckpointMismatch {
            component: "live.verify".into(),
            expected: n,
            got: mat.watermark().sequence,
        });
    }
    Ok(())
}

fn write_recovery_state(
    target: &Path,
    state: RecoveryState,
    n: u64,
    indexes_rebuilt: bool,
    statistics_rebuilt: bool,
) -> Result<()> {
    let file = RecoveryStateFile {
        format_version: RecoveryStateFile::FORMAT_VERSION,
        checkpoint_sequence: n,
        state,
        indexes_rebuilt,
        statistics_rebuilt,
        live_relative: LIVE_DIR.to_string(),
    };
    let path = target.join(RECOVERY_STATE_FILE);
    write_json_atomic(&path, &file)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let raw = fs::read(path).map_err(|e| BackupError::Io(e.to_string()))?;
    serde_json::from_slice(&raw).map_err(|e| BackupError::Corrupt(e.to_string()))
}

/// Paths for attaching SQL after recovery (still requires vault unlock at server).
pub fn live_paths(target: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let live = target.join(LIVE_DIR);
    (
        live.join("rows"),
        live.join("materialized_snapshot.json"),
        live.join("state_events.json"),
    )
}
