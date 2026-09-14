use crate::transaction::SnapshotSequence;

/// MVCC visibility rule — kept separate from executors and storage mutation paths.
pub struct VisibilityEvaluator;

impl VisibilityEvaluator {
    /// `end_sequence == 0` means the version is still open (visible until closed).
    pub fn is_visible(
        begin_sequence: u64,
        end_sequence: u64,
        deleted: bool,
        snapshot: SnapshotSequence,
    ) -> bool {
        if deleted {
            return false;
        }
        if begin_sequence > snapshot.sequence {
            return false;
        }
        end_sequence == 0 || snapshot.sequence < end_sequence
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visibility_examples_from_spec() {
        let s110 = SnapshotSequence::at(110);
        let s130 = SnapshotSequence::at(130);
        let s160 = SnapshotSequence::at(160);

        // INSERT @100
        assert!(VisibilityEvaluator::is_visible(100, 120, false, s110));
        assert!(!VisibilityEvaluator::is_visible(120, 0, false, s110));

        // UPDATE closes v100 @120, new v @120
        assert!(VisibilityEvaluator::is_visible(120, 0, false, s130));
        assert!(!VisibilityEvaluator::is_visible(100, 120, false, s130));

        // DELETE closes @150
        assert!(!VisibilityEvaluator::is_visible(120, 150, false, s160));
    }
}
