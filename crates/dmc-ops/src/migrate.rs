//! D4-A stage 5 — explicit migration of a plaintext (pre-D4) SQL store to encrypted storage.
//!
//! Runs only on an explicit, authorized request (`StorageMigrateEncrypt`), with the
//! storage keys of the unlocked vault. Never implicit, never partial:
//!
//! 1. **check** — the root is a plaintext pre-D4 store; plaintext backup / restore
//!    artifacts are refused unless the caller asked to purge them;
//! 2. **build** — the journal is re-written sealed and replayed into a new encrypted store
//!    under `<data_root>/.migrate-d4/new` (segments, indexes, statistics, snapshot sealed);
//!    the plaintext store is not touched;
//! 3. **verify** — the new store is reopened with the keys and compared with the plaintext
//!    one: journal tip, catalog, every row of every table, every index;
//! 4. **switch** — phase `switching` is recorded, the plaintext journal/storage trees move
//!    aside, the encrypted ones take their place, the encrypted-storage marker is written,
//!    then the plaintext trees (and, if asked, plaintext backups) are deleted.
//!
//! A crash before `switching` leaves the plaintext store as it was (the next start drops
//! the partial build); a crash during `switching` is rolled forward by the next start
//! (no keys needed: the encrypted store was already built and verified).
//!
//! Deleting files does not scrub storage media: copies of the old plaintext may survive
//! in filesystem blocks, snapshots or external backups — outside what this tool controls.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use dmc_materialized::{FileStateEventLog, StateEventLog, StateMaterializer};
use dmc_server::{MigrationError, MigrationReport};
use dmc_vault::StorageCipher;
use serde::{Deserialize, Serialize};

use crate::layout::StorageLayout;

/// Work directory of an explicit migration (under the data root).
pub const MIGRATION_DIR: &str = ".migrate-d4";
const STATE_FILE: &str = "state.json";

#[derive(Serialize, Deserialize)]
struct MigrationState {
    phase: String,
    /// Paths (relative to the data root) to delete once switched.
    purge: Vec<String>,
}

fn failed(what: &str, e: impl std::fmt::Display) -> MigrationError {
    MigrationError::Failed(format!("{what}: {e}"))
}

fn rel(layout: &StorageLayout, p: &Path) -> PathBuf {
    p.strip_prefix(layout.data_root())
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| p.to_path_buf())
}

/// The trees an encrypted store replaces (journal + storage), relative to the data root.
fn swapped_trees(layout: &StorageLayout) -> [PathBuf; 2] {
    [
        rel(layout, &layout.journal_root()),
        rel(layout, &layout.storage_root()),
    ]
}

fn write_state(dir: &Path, state: &MigrationState) -> Result<(), MigrationError> {
    let bytes = serde_json::to_vec_pretty(state).map_err(|e| failed("state", e))?;
    let tmp = dir.join("state.tmp");
    fs::write(&tmp, bytes).map_err(|e| failed("state", e))?;
    fs::rename(&tmp, dir.join(STATE_FILE)).map_err(|e| failed("state", e))
}

/// Plaintext backup / restore artifacts (and staging leftovers that may hold plaintext),
/// relative to the data root.
fn plaintext_artifacts(layout: &StorageLayout) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for root in [layout.backup_root(), layout.restore_root()] {
        let Ok(entries) = fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() || !holds_files(&path) {
                continue;
            }
            let encrypted = fs::read(path.join(dmc_backup::MANIFEST_FILE))
                .ok()
                .and_then(|raw| serde_json::from_slice::<dmc_backup::BackupManifest>(&raw).ok())
                .is_some_and(|m| m.encrypted);
            if !encrypted {
                out.push(rel(layout, &path));
            }
        }
    }
    out.sort();
    out
}

fn holds_files(dir: &Path) -> bool {
    fs::read_dir(dir).is_ok_and(|entries| {
        entries
            .flatten()
            .any(|e| e.path().is_file() || (e.path().is_dir() && holds_files(&e.path())))
    })
}

fn open_plain(
    layout: &StorageLayout,
) -> Result<StateMaterializer<FileStateEventLog>, MigrationError> {
    StateMaterializer::open(
        layout.rowstore_root(),
        layout.materialized_snapshot(),
        layout.state_event_log(),
    )
    .map_err(|e| failed("open plaintext store", e))
}

fn open_sealed(
    layout: &StorageLayout,
    cipher: &Arc<StorageCipher>,
) -> Result<StateMaterializer<FileStateEventLog>, MigrationError> {
    StateMaterializer::open_with_cipher(
        layout.rowstore_root(),
        layout.materialized_snapshot(),
        layout.state_event_log(),
        Some(cipher.clone()),
    )
    .map_err(|e| failed("open encrypted store", e))
}

/// Every row of every table and every index of `b` equals `a`.
fn verify_equal(
    a: &StateMaterializer<FileStateEventLog>,
    b: &StateMaterializer<FileStateEventLog>,
) -> Result<(), MigrationError> {
    let mismatch = |what: &str| MigrationError::Failed(format!("verification: {what} differs"));
    if a.tip_sequence() != b.tip_sequence() || a.watermark() != b.watermark() {
        return Err(mismatch("journal tip"));
    }
    let body = |m: &StateMaterializer<FileStateEventLog>| {
        serde_json::to_value(m.catalog().to_snapshot_body()).unwrap_or_default()
    };
    if body(a) != body(b) {
        return Err(mismatch("catalog"));
    }
    if a.sealed_columns() != b.sealed_columns() {
        return Err(mismatch("protected-column rules"));
    }
    for table in a.catalog().tables() {
        let (Ok(ta), Ok(tb)) = (
            a.shared_table_store(table.id),
            b.shared_table_store(table.id),
        ) else {
            if a.shared_table_store(table.id).is_ok() != b.shared_table_store(table.id).is_ok() {
                return Err(mismatch("table set"));
            }
            continue;
        };
        let (ta, tb) = (ta.lock().expect("table"), tb.lock().expect("table"));
        let ids = ta.live_row_ids();
        if ids != tb.live_row_ids() {
            return Err(mismatch("row ids"));
        }
        for id in ids {
            let va = ta.get(id).map_err(|e| failed("read", e))?;
            let vb = tb.get(id).map_err(|e| failed("read", e))?;
            if va != vb {
                return Err(mismatch("row"));
            }
        }
        for index in &table.indexes {
            let ib = b
                .shared_index_store(index.id)
                .map_err(|_| mismatch("index set"))?;
            let valid = ib
                .lock()
                .expect("index")
                .validate(&tb)
                .map_err(|e| failed("index", e))?;
            if !valid {
                return Err(mismatch("index"));
            }
        }
    }
    Ok(())
}

/// Explicit migration (see module docs). `cipher`: keys of the unlocked vault.
pub(crate) fn migrate_plaintext_store(
    layout: &StorageLayout,
    cipher: &StorageCipher,
    purge_plaintext_backups: bool,
) -> Result<MigrationReport, MigrationError> {
    let cipher = Arc::new(cipher.clone());
    let root = layout.data_root();

    // 1. check
    let artifacts = plaintext_artifacts(layout);
    if !artifacts.is_empty() && !purge_plaintext_backups {
        return Err(MigrationError::Refused(format!(
            // client-visible: phrased for the protocol message sanitizer
            "{} unencrypted backup or restore artifact(s) present; re-run with purge to delete them",
            artifacts.len()
        )));
    }

    // 2. build (the plaintext store is only read)
    let dir = root.join(MIGRATION_DIR);
    if dir.exists() {
        fs::remove_dir_all(&dir).map_err(|e| failed("reset work dir", e))?;
    }
    fs::create_dir_all(&dir).map_err(|e| failed("work dir", e))?;
    write_state(
        &dir,
        &MigrationState {
            phase: "building".into(),
            purge: Vec::new(),
        },
    )?;
    let new_layout = StorageLayout::new(dir.join("new"), layout.names().clone())
        .map_err(|e| failed("layout", e))?;
    let plain = open_plain(layout)?;
    let events = plain.event_log().events().to_vec();
    let event_count = events.len() as u64;
    fs::create_dir_all(new_layout.rowstore_root()).map_err(|e| failed("build", e))?;
    let rules = layout
        .rowstore_root()
        .join(dmc_materialized::protect::SEALED_COLUMNS_FILE);
    if rules.is_file() {
        fs::copy(
            &rules,
            new_layout
                .rowstore_root()
                .join(dmc_materialized::protect::SEALED_COLUMNS_FILE),
        )
        .map_err(|e| failed("build", e))?;
    }
    dmc_materialized::write_state_event_log_with(
        new_layout.state_event_log(),
        events,
        Some(cipher.clone()),
    )
    .map_err(|e| failed("build journal", e))?;
    {
        let mut built = open_sealed(&new_layout, &cipher)?;
        built
            .rebuild_all_indexes()
            .map_err(|e| failed("build indexes", e))?;
        built
            .rebuild_all_statistics()
            .map_err(|e| failed("build statistics", e))?;
        built
            .persist_snapshot_if_configured()
            .map_err(|e| failed("build snapshot", e))?;
    }

    // 3. verify (fresh open of the encrypted store with the keys)
    let reopened = open_sealed(&new_layout, &cipher)?;
    verify_equal(&plain, &reopened)?;
    let tables = plain.catalog().tables().count() as u64;
    drop(reopened);
    drop(plain);

    // 4. switch
    write_state(
        &dir,
        &MigrationState {
            phase: "switching".into(),
            purge: artifacts
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect(),
        },
    )?;
    let purged = finish_switch(layout).map_err(|e| failed("switch", e))?;
    Ok(MigrationReport {
        events: event_count,
        tables,
        purged_artifacts: purged,
    })
}

/// Roll a recorded switch forward (idempotent), write the marker, delete the plaintext
/// trees and requested artifacts, remove the work dir. Needs no keys.
fn finish_switch(layout: &StorageLayout) -> std::io::Result<u64> {
    let root = layout.data_root();
    let dir = root.join(MIGRATION_DIR);
    let state: MigrationState =
        serde_json::from_slice(&fs::read(dir.join(STATE_FILE))?).map_err(std::io::Error::other)?;
    for tree in swapped_trees(layout) {
        let new = dir.join("new").join(&tree);
        if !new.exists() {
            continue; // already switched
        }
        let live = root.join(&tree);
        let old = dir.join("old").join(&tree);
        if live.exists() && !old.exists() {
            fs::create_dir_all(old.parent().expect("parent"))?;
            fs::rename(&live, &old)?;
        } else if live.exists() {
            fs::remove_dir_all(&live)?; // a partial earlier attempt; `old` holds the original
        }
        fs::rename(&new, &live)?;
    }
    crate::startup::write_marker(root).map_err(std::io::Error::other)?;
    let mut purged = 0;
    for p in &state.purge {
        let path = root.join(p);
        if path.exists() {
            fs::remove_dir_all(&path)?;
            purged += 1;
        }
    }
    fs::remove_dir_all(&dir)?;
    Ok(purged)
}

/// Startup: complete or discard an interrupted migration. `building` (or unreadable
/// state) → the partial build is dropped, the plaintext store is untouched; `switching` →
/// rolled forward.
pub(crate) fn resume_interrupted(layout: &StorageLayout) -> std::io::Result<()> {
    let dir = layout.data_root().join(MIGRATION_DIR);
    if !dir.exists() {
        return Ok(());
    }
    let switching = fs::read(dir.join(STATE_FILE))
        .ok()
        .and_then(|raw| serde_json::from_slice::<MigrationState>(&raw).ok())
        .is_some_and(|s| s.phase == "switching");
    if switching {
        finish_switch(layout).map(|_| ())
    } else {
        fs::remove_dir_all(&dir)
    }
}
