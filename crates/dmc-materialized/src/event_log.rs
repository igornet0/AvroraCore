use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

use dmc_model::StateEvent;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const STATE_EVENT_LOG_FORMAT_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StateEventRecord {
    pub sequence: u64,
    pub event_id: [u8; 16],
    pub event: StateEvent,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
struct StateEventLogFile {
    format_version: u32,
    events: Vec<StateEventRecord>,
}

pub trait StateEventLog {
    fn append(&mut self, event: StateEvent) -> Result<StateEventRecord>;
    fn events(&self) -> &[StateEventRecord];
    fn next_sequence(&self) -> u64;

    /// Durable tip: last appended sequence, or `0` when empty.
    fn tip_sequence(&self) -> u64 {
        self.events().last().map(|r| r.sequence).unwrap_or(0)
    }
}

pub fn event_id_for_sequence(sequence: u64) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&sequence.to_be_bytes());
    id
}

#[derive(Clone, Debug, Default)]
pub struct MemoryStateEventLog {
    events: Vec<StateEventRecord>,
}

impl StateEventLog for MemoryStateEventLog {
    fn append(&mut self, event: StateEvent) -> Result<StateEventRecord> {
        event.validate()?;
        let sequence = self.next_sequence();
        let record = StateEventRecord {
            sequence,
            event_id: event_id_for_sequence(sequence),
            event,
        };
        self.events.push(record.clone());
        Ok(record)
    }

    fn events(&self) -> &[StateEventRecord] {
        &self.events
    }

    fn next_sequence(&self) -> u64 {
        self.events.last().map(|r| r.sequence + 1).unwrap_or(1)
    }
}

pub struct FileStateEventLog {
    path: PathBuf,
    file: StateEventLogFile,
}

impl FileStateEventLog {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let file = if path.is_file() {
            let raw = fs::read(&path).map_err(|e| Error::Io(e.to_string()))?;
            serde_json::from_slice(&raw).map_err(|e| Error::Corrupt(e.to_string()))?
        } else {
            StateEventLogFile {
                format_version: STATE_EVENT_LOG_FORMAT_VERSION,
                events: Vec::new(),
            }
        };
        if file.format_version != STATE_EVENT_LOG_FORMAT_VERSION {
            return Err(Error::Corrupt(format!(
                "unsupported state event log version {}",
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

/// Write a complete state-event log file (backup → live conversion / recovery).
pub fn write_state_event_log(path: impl Into<PathBuf>, events: Vec<StateEventRecord>) -> Result<()> {
    let path = path.into();
    let log = FileStateEventLog {
        path,
        file: StateEventLogFile {
            format_version: STATE_EVENT_LOG_FORMAT_VERSION,
            events,
        },
    };
    log.persist()
}

impl StateEventLog for FileStateEventLog {
    fn append(&mut self, event: StateEvent) -> Result<StateEventRecord> {
        event.validate()?;
        let sequence = self.next_sequence();
        let record = StateEventRecord {
            sequence,
            event_id: event_id_for_sequence(sequence),
            event,
        };
        self.file.events.push(record.clone());
        self.persist()?;
        Ok(record)
    }

    fn events(&self) -> &[StateEventRecord] {
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
