use dmc_materialized::StateEventRecord;

use crate::error::{BackupError, Result};

/// Frozen event source for the writer. Writer never queries live tip/watermark.
#[derive(Clone, Debug)]
pub struct BackupSource {
    events: Vec<StateEventRecord>,
}

impl BackupSource {
    pub fn from_events(events: Vec<StateEventRecord>) -> Self {
        Self { events }
    }

    pub fn from_log(log: &impl dmc_materialized::StateEventLog) -> Self {
        Self {
            events: log.events().to_vec(),
        }
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
