//! Optional optimizer statistics catalog (Phase 6.15.1).
//!
//! Not journal-backed. Safe to delete — SQL correctness is unchanged; only plan quality may suffer.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use dmc_model::{
    statistics_snapshot_from_bytes, statistics_snapshot_to_bytes, StatisticsSnapshot,
    TableId, TableStatistics, STATISTICS_SNAPSHOT_FORMAT_VERSION,
};

use crate::error::{Error, Result};

const STATISTICS_FILE: &str = "statistics.json";

/// In-memory statistics catalog with optional disk persistence.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct StatisticsCatalog {
    tables: BTreeMap<TableId, TableStatistics>,
    storage_root: Option<PathBuf>,
}

impl StatisticsCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open or create catalog under `storage_root/statistics.json`.
    /// Missing file → empty catalog (valid fallback for optimiser).
    pub fn open(storage_root: impl Into<PathBuf>) -> Result<Self> {
        let storage_root = storage_root.into();
        let path = Self::statistics_path(&storage_root);
        if !path.is_file() {
            return Ok(Self {
                tables: BTreeMap::new(),
                storage_root: Some(storage_root),
            });
        }
        let raw = std::fs::read(&path).map_err(|e| Error::Io(e.to_string()))?;
        let snapshot = statistics_snapshot_from_bytes(&raw).map_err(map_model_error)?;
        if snapshot.format_version != STATISTICS_SNAPSHOT_FORMAT_VERSION {
            return Err(Error::Corrupt(format!(
                "unsupported statistics version {}",
                snapshot.format_version
            )));
        }
        Ok(Self {
            tables: snapshot.into_map().map_err(map_model_error)?,
            storage_root: Some(storage_root),
        })
    }

    pub fn statistics_path(storage_root: &Path) -> PathBuf {
        storage_root.join(STATISTICS_FILE)
    }

    pub fn persist_path(&self) -> Option<PathBuf> {
        self.storage_root
            .as_ref()
            .map(|root| Self::statistics_path(root))
    }

    /// Lookup — `None` means no statistics (optimiser uses conservative fallback later).
    pub fn get(&self, table_id: TableId) -> Option<&TableStatistics> {
        self.tables.get(&table_id)
    }

    pub fn contains(&self, table_id: TableId) -> bool {
        self.tables.contains_key(&table_id)
    }

    pub fn tables(&self) -> impl Iterator<Item = &TableStatistics> {
        self.tables.values()
    }

    /// Insert or replace table statistics (validated).
    pub fn upsert(&mut self, stats: TableStatistics) -> Result<()> {
        stats.validate().map_err(map_model_error)?;
        self.tables.insert(stats.table_id, stats);
        Ok(())
    }

    pub fn remove(&mut self, table_id: TableId) -> Option<TableStatistics> {
        self.tables.remove(&table_id)
    }

    pub fn len(&self) -> usize {
        self.tables.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tables.is_empty()
    }

    pub fn clear(&mut self) {
        self.tables.clear();
    }

    pub fn snapshot(&self) -> Result<StatisticsSnapshot> {
        StatisticsSnapshot::from_tables(self.tables.values().cloned()).map_err(map_model_error)
    }

    pub fn persist(&self) -> Result<()> {
        let path = self
            .storage_root
            .as_ref()
            .ok_or_else(|| Error::Io("statistics catalog has no storage root".into()))?;
        save_statistics_catalog(&Self::statistics_path(path), self)
    }

    pub fn reload(&mut self) -> Result<()> {
        let Some(root) = self.storage_root.clone() else {
            return Err(Error::Io("statistics catalog has no storage root".into()));
        };
        *self = Self::open(root)?;
        Ok(())
    }
}

pub fn save_statistics_catalog(path: &Path, catalog: &StatisticsCatalog) -> Result<()> {
    let snapshot = catalog.snapshot()?;
    let raw = statistics_snapshot_to_bytes(&snapshot).map_err(map_model_error)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::Io(e.to_string()))?;
    }
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp).map_err(|e| Error::Io(e.to_string()))?;
        f.write_all(&raw).map_err(|e| Error::Io(e.to_string()))?;
        f.sync_all().map_err(|e| Error::Io(e.to_string()))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| Error::Io(e.to_string()))?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

fn map_model_error(err: dmc_model::Error) -> Error {
    match err {
        dmc_model::Error::Corrupt(msg) => Error::Corrupt(msg),
        dmc_model::Error::InvalidEvent(msg) => Error::Corrupt(msg),
        dmc_model::Error::Io(msg) => Error::Io(msg),
        other => Error::Corrupt(other.to_string()),
    }
}
