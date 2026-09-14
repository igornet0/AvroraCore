use dmc_model::{SnapshotSequence, VisibilityEvaluator};

use crate::codec::StoredValue;

/// Logical row version metadata used by MVCC scans and conflict checks.
#[derive(Clone, Debug, PartialEq)]
pub struct RowVersion {
    pub row_id: u64,
    pub begin_sequence: u64,
    pub end_sequence: u64,
    pub deleted: bool,
    pub values: Vec<StoredValue>,
}

impl RowVersion {
    pub fn is_visible_at(&self, snapshot: SnapshotSequence) -> bool {
        VisibilityEvaluator::is_visible(
            self.begin_sequence,
            self.end_sequence,
            self.deleted,
            snapshot,
        )
    }
}
