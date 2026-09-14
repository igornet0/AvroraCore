//! Segment compactor API (Phase 5.6.2+ — artifact write and manifest publication).

use crate::compaction::{
    CompactionArtifact, CompactionCandidate, CompactionPolicy,
};
use crate::error::Result;
use crate::journal::Journal;
use crate::journal_manifest::JournalManifest;
use crate::partition::PartitionId;

/// Storage-preserving segment rewrite (5.6.2+) and manifest publication (5.6.3+).
pub trait SegmentCompactor {
    fn select_candidate(&self, policy: &CompactionPolicy) -> Result<Option<CompactionCandidate>>;

    fn select_candidate_for_partition(
        &self,
        partition_id: PartitionId,
        policy: &CompactionPolicy,
    ) -> Result<Option<CompactionCandidate>>;

    fn compact(&mut self, candidate: &CompactionCandidate) -> Result<CompactionArtifact>;

    fn publish(&mut self, artifact: &CompactionArtifact) -> Result<JournalManifest>;
}

/// Default compactor bound to a journal instance.
pub struct JournalSegmentCompactor<'a> {
    journal: &'a mut Journal,
}

impl<'a> JournalSegmentCompactor<'a> {
    pub fn new(journal: &'a mut Journal) -> Self {
        Self { journal }
    }
}

impl SegmentCompactor for JournalSegmentCompactor<'_> {
    fn select_candidate(&self, policy: &CompactionPolicy) -> Result<Option<CompactionCandidate>> {
        self.journal.select_compaction_candidate(policy)
    }

    fn select_candidate_for_partition(
        &self,
        partition_id: PartitionId,
        policy: &CompactionPolicy,
    ) -> Result<Option<CompactionCandidate>> {
        self.journal
            .select_compaction_candidate_for_partition(partition_id, policy)
    }

    fn compact(&mut self, candidate: &CompactionCandidate) -> Result<CompactionArtifact> {
        let _guard = self.journal.begin_topology_mutation()?;
        self.journal.compact_candidate(candidate)
    }

    fn publish(&mut self, artifact: &CompactionArtifact) -> Result<JournalManifest> {
        self.journal.publish_compaction(artifact)
    }
}
