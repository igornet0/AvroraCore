use serde::{Deserialize, Serialize};

use crate::ids::TransactionId;

/// Read snapshot bound — last committed journal sequence visible to the transaction.
/// Separate from GroupOffset, subscription offset, and consumer state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SnapshotSequence {
    pub sequence: u64,
}

impl SnapshotSequence {
    pub const fn at(sequence: u64) -> Self {
        Self { sequence }
    }

    pub const fn latest() -> Self {
        Self { sequence: u64::MAX }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionStatus {
    Active,
    Committed,
    Aborted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionState {
    pub id: TransactionId,
    pub snapshot_sequence: SnapshotSequence,
    pub status: TransactionStatus,
}

impl TransactionState {
    pub fn active(id: TransactionId, snapshot_sequence: SnapshotSequence) -> Self {
        Self {
            id,
            snapshot_sequence,
            status: TransactionStatus::Active,
        }
    }
}
