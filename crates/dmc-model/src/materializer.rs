use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::apply::ApplyMode;
use crate::catalog::Catalog;
use crate::error::{Error, Result};
use crate::event::CatalogEvent;
use crate::persist::{
    load_catalog_snapshot, save_catalog_snapshot, CatalogSnapshot,
};
use crate::watermark::CatalogWatermark;

pub const CATALOG_EVENT_LOG_FORMAT_VERSION: u32 = 1;

/// One durable catalog mutation with monotonic sequence (journal-equivalent record for 6.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogEventRecord {
    pub sequence: u64,
    pub event: CatalogEvent,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct CatalogEventLogFile {
    format_version: u32,
    events: Vec<CatalogEventRecord>,
}

pub trait CatalogEventLog {
    fn append(&mut self, event: CatalogEvent) -> Result<CatalogEventRecord>;
    fn events(&self) -> &[CatalogEventRecord];
    fn next_sequence(&self) -> u64;
}

#[derive(Clone, Debug, Default)]
pub struct MemoryCatalogEventLog {
    events: Vec<CatalogEventRecord>,
}

impl CatalogEventLog for MemoryCatalogEventLog {
    fn append(&mut self, event: CatalogEvent) -> Result<CatalogEventRecord> {
        event.validate()?;
        let sequence = self.next_sequence();
        let record = CatalogEventRecord { sequence, event };
        self.events.push(record.clone());
        Ok(record)
    }

    fn events(&self) -> &[CatalogEventRecord] {
        &self.events
    }

    fn next_sequence(&self) -> u64 {
        self.events.last().map(|r| r.sequence + 1).unwrap_or(1)
    }
}

pub struct FileCatalogEventLog {
    path: PathBuf,
    file: CatalogEventLogFile,
}

impl FileCatalogEventLog {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let file = if path.is_file() {
            let raw = fs::read(&path).map_err(|e| Error::Io(e.to_string()))?;
            serde_json::from_slice(&raw).map_err(|e| Error::Corrupt(e.to_string()))?
        } else {
            CatalogEventLogFile {
                format_version: CATALOG_EVENT_LOG_FORMAT_VERSION,
                events: Vec::new(),
            }
        };
        if file.format_version != CATALOG_EVENT_LOG_FORMAT_VERSION {
            return Err(Error::Corrupt(format!(
                "unsupported catalog event log version {}",
                file.format_version
            )));
        }
        Ok(Self { path, file })
    }

    pub fn persist(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::Io(e.to_string()))?;
        }
        let raw =
            serde_json::to_vec_pretty(&self.file).map_err(|e| Error::Corrupt(e.to_string()))?;
        let tmp = self.path.with_extension("tmp");
        {
            let mut f = File::create(&tmp).map_err(|e| Error::Io(e.to_string()))?;
            f.write_all(&raw).map_err(|e| Error::Io(e.to_string()))?;
            f.sync_all().map_err(|e| Error::Io(e.to_string()))?;
        }
        fs::rename(&tmp, &self.path).map_err(|e| Error::Io(e.to_string()))?;
        Ok(())
    }
}

impl CatalogEventLog for FileCatalogEventLog {
    fn append(&mut self, event: CatalogEvent) -> Result<CatalogEventRecord> {
        event.validate()?;
        let sequence = self.next_sequence();
        let record = CatalogEventRecord { sequence, event };
        self.file.events.push(record.clone());
        self.persist()?;
        Ok(record)
    }

    fn events(&self) -> &[CatalogEventRecord] {
        &self.file.events
    }

    fn next_sequence(&self) -> u64 {
        self.file
            .events
            .last()
            .map(|r| r.sequence + 1)
            .unwrap_or(1)
    }
}

/// Applies catalog events, tracks [`CatalogWatermark`], persists materialized snapshot.
pub struct CatalogMaterializer<L: CatalogEventLog> {
    pub catalog: Catalog,
    pub watermark: CatalogWatermark,
    log: L,
    snapshot_path: Option<PathBuf>,
}

impl CatalogMaterializer<MemoryCatalogEventLog> {
    pub fn in_memory() -> Self {
        Self {
            catalog: Catalog::new(),
            watermark: CatalogWatermark::default(),
            log: MemoryCatalogEventLog::default(),
            snapshot_path: None,
        }
    }
}

impl CatalogMaterializer<FileCatalogEventLog> {
    pub fn open(snapshot_path: PathBuf, event_log_path: PathBuf) -> Result<Self> {
        let log = FileCatalogEventLog::open(event_log_path)?;
        let mut mat = Self {
            catalog: Catalog::new(),
            watermark: CatalogWatermark::default(),
            log,
            snapshot_path: Some(snapshot_path),
        };
        if !mat.log.events().is_empty() {
            mat.replay_from_log()?;
        } else if let Some(path) = &mat.snapshot_path {
            if let Some(snapshot) = load_catalog_snapshot(path)? {
                mat.watermark = snapshot.watermark;
                mat.catalog = snapshot.into_catalog()?;
            }
        }
        Ok(mat)
    }
}

impl<L: CatalogEventLog> CatalogMaterializer<L> {
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    pub fn watermark(&self) -> CatalogWatermark {
        self.watermark
    }

    pub fn event_log(&self) -> &L {
        &self.log
    }

    /// Append authoritative event, apply live, advance watermark, optionally persist snapshot.
    pub fn mutate(&mut self, event: CatalogEvent) -> Result<CatalogEventRecord> {
        let record = self.log.append(event)?;
        self.apply_record(&record, ApplyMode::Live)?;
        self.persist_snapshot_if_configured()?;
        Ok(record)
    }

    pub fn apply_record(
        &mut self,
        record: &CatalogEventRecord,
        mode: ApplyMode,
    ) -> Result<()> {
        if record.sequence <= self.watermark.sequence {
            if mode == ApplyMode::Live {
                return Err(Error::DuplicateSequence(record.sequence));
            }
            return Ok(());
        }
        if self.watermark.sequence != 0 && record.sequence != self.watermark.sequence + 1 {
            return Err(Error::OutOfOrderSequence {
                expected: self.watermark.sequence + 1,
                got: record.sequence,
            });
        }
        self.catalog.apply(&record.event, mode)?;
        self.watermark = CatalogWatermark::at(record.sequence);
        Ok(())
    }

    pub fn replay_from_log(&mut self) -> Result<()> {
        let events: Vec<_> = self.log.events().to_vec();
        self.catalog = Catalog::new();
        self.watermark = CatalogWatermark::default();
        for record in events {
            self.apply_record(&record, ApplyMode::Replay)?;
        }
        Ok(())
    }

    pub fn persist_snapshot_if_configured(&self) -> Result<()> {
        if let Some(path) = &self.snapshot_path {
            let snapshot = CatalogSnapshot::from_catalog(&self.catalog, self.watermark);
            save_catalog_snapshot(path, &snapshot)?;
        }
        Ok(())
    }
}

impl CatalogMaterializer<FileCatalogEventLog> {
    pub fn close(self) -> Result<()> {
        self.persist_snapshot_if_configured()?;
        Ok(())
    }
}

/// Rebuild materialized catalog from authoritative event log when snapshot is corrupt/missing.
pub fn rebuild_catalog_from_event_log(
    event_log_path: &Path,
) -> Result<(Catalog, CatalogWatermark)> {
    let log = FileCatalogEventLog::open(event_log_path)?;
    let mut catalog = Catalog::new();
    let mut watermark = CatalogWatermark::default();
    for record in log.events() {
        if watermark.sequence != 0 && record.sequence != watermark.sequence + 1 {
            return Err(Error::OutOfOrderSequence {
                expected: watermark.sequence + 1,
                got: record.sequence,
            });
        }
        catalog.apply(&record.event, ApplyMode::Replay)?;
        watermark = CatalogWatermark::at(record.sequence);
    }
    Ok((catalog, watermark))
}

pub fn validate_catalog_event_bytes(raw: &[u8]) -> Result<CatalogEvent> {
    let event: CatalogEvent =
        serde_json::from_slice(raw).map_err(|e| Error::Corrupt(e.to_string()))?;
    event.validate()?;
    Ok(event)
}
