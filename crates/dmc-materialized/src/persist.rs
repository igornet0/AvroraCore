use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use dmc_model::{CatalogSnapshotBody, MaterializedWatermark};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const MATERIALIZED_SNAPSHOT_FORMAT_VERSION: u32 = 1;

/// Global materialized-state checkpoint: catalog + row watermark (row data lives in table dirs).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializedStateSnapshot {
    pub format_version: u32,
    pub watermark: MaterializedWatermark,
    pub catalog: CatalogSnapshotBody,
    /// Idempotency aid for replay — ordering remains [`MaterializedWatermark::sequence`].
    pub seen_event_ids: Vec<[u8; 16]>,
}

impl MaterializedStateSnapshot {
    pub fn new(
        watermark: MaterializedWatermark,
        catalog: CatalogSnapshotBody,
        seen_event_ids: Vec<[u8; 16]>,
    ) -> Self {
        Self {
            format_version: MATERIALIZED_SNAPSHOT_FORMAT_VERSION,
            watermark,
            catalog,
            seen_event_ids,
        }
    }
}

pub fn load_materialized_snapshot(path: &Path) -> Result<Option<MaterializedStateSnapshot>> {
    if !path.is_file() {
        return Ok(None);
    }
    let raw = fs::read(path).map_err(|e| Error::Io(e.to_string()))?;
    let snapshot: MaterializedStateSnapshot =
        serde_json::from_slice(&raw).map_err(|e| Error::Corrupt(e.to_string()))?;
    if snapshot.format_version != MATERIALIZED_SNAPSHOT_FORMAT_VERSION {
        return Err(Error::Corrupt(format!(
            "unsupported materialized snapshot version {}",
            snapshot.format_version
        )));
    }
    Ok(Some(snapshot))
}

pub fn save_materialized_snapshot(path: &Path, snapshot: &MaterializedStateSnapshot) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| Error::Io(e.to_string()))?;
    }
    let raw =
        serde_json::to_vec_pretty(snapshot).map_err(|e| Error::Corrupt(e.to_string()))?;
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp).map_err(|e| Error::Io(e.to_string()))?;
        f.write_all(&raw).map_err(|e| Error::Io(e.to_string()))?;
        f.sync_all().map_err(|e| Error::Io(e.to_string()))?;
    }
    fs::rename(&tmp, path).map_err(|e| Error::Io(e.to_string()))?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}
