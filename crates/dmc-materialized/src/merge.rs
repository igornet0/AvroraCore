use dmc_model::StateEvent;

use crate::error::Result;
use crate::event_log::StateEventRecord;

/// Merge globally ordered state events from multiple partition logs (same contract as journal merge).
pub fn merge_state_event_records(
    partitions: &[&[StateEventRecord]],
) -> Result<Vec<StateEventRecord>> {
    let mut merged: Vec<StateEventRecord> = partitions.iter().flat_map(|p| p.iter().cloned()).collect();
    merged.sort_by_key(|r| r.sequence);
    let mut last = 0u64;
    for record in &merged {
        if last != 0 && record.sequence != last + 1 {
            return Err(dmc_model::Error::OutOfOrderSequence {
                expected: last + 1,
                got: record.sequence,
            });
        }
        last = record.sequence;
    }
    Ok(merged)
}

pub fn state_event_from_journal_payload(raw: &[u8]) -> Result<StateEvent> {
    let event: StateEvent =
        serde_json::from_slice(raw).map_err(|e| dmc_model::Error::Corrupt(e.to_string()))?;
    event.validate()?;
    Ok(event)
}
