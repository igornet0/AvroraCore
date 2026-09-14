use dmc_materialized::{StateEventLog, StateMaterializer};

use crate::error::{BackupError, Result};

/// Point-in-time consistency capture for V1: fully materialized journal tip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsistencyPoint {
    pub checkpoint_sequence: u64,
    pub journal_tip: u64,
    pub materialized_watermark: u64,
    pub catalog_checkpoint: u64,
    pub event_count: u64,
}

/// V1 rule: `N = JournalTip` and `JournalTip == MaterializedWatermark`.
pub fn require_fully_materialized_tip<L: StateEventLog>(
    mat: &StateMaterializer<L>,
) -> Result<ConsistencyPoint> {
    let journal_tip = mat.tip_sequence();
    let watermark = mat.watermark().sequence;
    if journal_tip != watermark {
        return Err(BackupError::InconsistentCheckpoint {
            journal_tip,
            watermark,
        });
    }
    Ok(ConsistencyPoint {
        checkpoint_sequence: journal_tip,
        journal_tip,
        materialized_watermark: watermark,
        catalog_checkpoint: watermark,
        event_count: mat.event_log().events().len() as u64,
    })
}
