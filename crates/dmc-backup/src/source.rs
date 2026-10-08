use std::sync::Arc;

use dmc_materialized::StateEventRecord;
use dmc_vault::StorageCipher;

use crate::error::{BackupError, Result};

/// Frozen event source for the writer. Writer never queries live tip/watermark.
#[derive(Clone, Debug)]
pub struct BackupSource {
    events: Vec<StateEventRecord>,
    /// D4-A storage keys: when set, the artifact is written encrypted.
    cipher: Option<Arc<StorageCipher>>,
}

impl BackupSource {
    pub fn from_events(events: Vec<StateEventRecord>) -> Self {
        Self {
            events,
            cipher: None,
        }
    }

    pub fn from_log(log: &impl dmc_materialized::StateEventLog) -> Self {
        Self {
            events: log.events().to_vec(),
            cipher: None,
        }
    }

    /// Write the artifact encrypted with these storage keys (`None` = plaintext, dev/test).
    pub fn with_cipher(mut self, cipher: Option<Arc<StorageCipher>>) -> Self {
        self.cipher = cipher;
        self
    }

    pub fn cipher(&self) -> Option<&Arc<StorageCipher>> {
        self.cipher.as_ref()
    }

    pub fn events(&self) -> &[StateEventRecord] {
        &self.events
    }

    /// Events with `sequence <= N`. Invariant: `max(sequence) == N` when `N > 0`.
    pub fn events_through(&self, n: u64) -> Result<Vec<StateEventRecord>> {
        if n > 0 && !self.events.iter().any(|e| e.sequence == n) {
            return Err(BackupError::Validation(format!(
                "backup source missing checkpoint sequence {n}"
            )));
        }
        let mut filtered: Vec<_> = self
            .events
            .iter()
            .filter(|e| e.sequence <= n)
            .cloned()
            .collect();
        filtered.sort_by_key(|e| e.sequence);
        let max = filtered.last().map(|e| e.sequence).unwrap_or(0);
        if max != n {
            return Err(BackupError::Validation(format!(
                "journal max sequence {max} != checkpoint {n}"
            )));
        }
        // Contiguous 1..=N when N > 0.
        if n > 0 {
            for (i, record) in filtered.iter().enumerate() {
                let expected = (i as u64) + 1;
                if record.sequence != expected {
                    return Err(BackupError::Validation(format!(
                        "journal hole: expected sequence {expected}, got {}",
                        record.sequence
                    )));
                }
            }
        }
        Ok(filtered)
    }
}
