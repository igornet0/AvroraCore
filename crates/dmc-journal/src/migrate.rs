use std::fs;

use dmc_vault::persist::DbSnapshot;

use crate::error::{Error, Result};
use crate::layout::StorageLayout;
use crate::meta::JournalMeta;

/// Migrate a v1 `store.dbs.json` into base snapshot + empty journal.
/// Returns `true` if a migration ran.
pub fn migrate_v1_to_v2(layout: &StorageLayout) -> Result<bool> {
    if layout.base_snapshot().is_file() || layout.migrated_marker().is_file() {
        return Ok(false);
    }
    let legacy = layout.legacy_snapshot();
    if !legacy.is_file() {
        return Ok(false);
    }

    layout.ensure_dirs()?;
    fs::copy(&legacy, layout.legacy_backup()).map_err(Error::io)?;

    let mut snap = DbSnapshot::load(&legacy)?;
    snap.version = 2;
    snap.last_applied_sequence = 0;
    snap.journal_format = 1;
    snap.save(&layout.base_snapshot())?;

    if !layout.journal_meta().is_file() {
        JournalMeta::default().save(&layout.journal_meta())?;
    }

    fs::write(layout.migrated_marker(), b"phase-1-journal-v1\n").map_err(Error::io)?;
    Ok(true)
}
