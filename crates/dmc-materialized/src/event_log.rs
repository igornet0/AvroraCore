use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use dmc_model::StateEvent;
use dmc_vault::{StorageCipher, StoragePurpose};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const STATE_EVENT_LOG_FORMAT_VERSION: u32 = 1;
/// Logical name bound into the AAD of an encrypted event log (D4-A).
pub const EVENT_LOG_CONTEXT: &str = "state_events.json";

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
    /// D4-A: with a cipher the file holds only sealed bytes (purpose `Events`).
    cipher: Option<Arc<StorageCipher>>,
}

/// Decode an event-log file (rules: [`crate::sealed_io`]).
fn decode_log(raw: &[u8], cipher: Option<&StorageCipher>) -> Result<StateEventLogFile> {
    let plain = crate::sealed_io::decode_file(
        raw,
        cipher,
        StoragePurpose::Events,
        EVENT_LOG_CONTEXT,
        "event log",
    )?;
    if plain.is_empty() {
        return Ok(StateEventLogFile {
            format_version: STATE_EVENT_LOG_FORMAT_VERSION,
            events: Vec::new(),
        });
    }
    serde_json::from_slice(&plain).map_err(|e| Error::Corrupt(e.to_string()))
}

impl FileStateEventLog {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        Self::open_with(path, None)
    }

    /// Open with an optional storage cipher (D4-A). See [`decode_log`] for the rules.
    pub fn open_with(path: impl Into<PathBuf>, cipher: Option<Arc<StorageCipher>>) -> Result<Self> {
        let path = path.into();
        let file = if path.is_file() {
            let raw = fs::read(&path).map_err(|e| Error::Io(e.to_string()))?;
            decode_log(&raw, cipher.as_deref())?
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
        Ok(Self { path, file, cipher })
    }

    pub fn is_encrypted(&self) -> bool {
        self.cipher.is_some()
    }

    pub fn persist(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::Io(e.to_string()))?;
        }
        let plain = Zeroizing::new(
            serde_json::to_vec_pretty(&self.file).map_err(|e| Error::Corrupt(e.to_string()))?,
        );
        crate::sealed_io::refuse_plaintext_over_sealed(
            &self.path,
            self.cipher.as_deref(),
            "state event log",
        )?;
        // sealed before anything touches the disk (the temp file included)
        let raw = crate::sealed_io::encode_file(
            &plain,
            self.cipher.as_deref(),
            StoragePurpose::Events,
            EVENT_LOG_CONTEXT,
        )?;
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
pub fn write_state_event_log(
    path: impl Into<PathBuf>,
    events: Vec<StateEventRecord>,
) -> Result<()> {
    write_state_event_log_with(path, events, None)
}

/// Write a complete event-log file, sealed when `cipher` is given (D4-A).
pub fn write_state_event_log_with(
    path: impl Into<PathBuf>,
    events: Vec<StateEventRecord>,
    cipher: Option<Arc<StorageCipher>>,
) -> Result<()> {
    let path = path.into();
    let log = FileStateEventLog {
        path,
        file: StateEventLogFile {
            format_version: STATE_EVENT_LOG_FORMAT_VERSION,
            events,
        },
        cipher,
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
