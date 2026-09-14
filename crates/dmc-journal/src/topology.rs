//! Serializes journal topology mutations: append rotation, trim, compaction (Phase 5.6.1).
//!
//! Read/replay/consume do not take this lock — only operations that change physical segment layout.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::error::{Error, Result};

/// Global serialization for topology-changing operations on one journal directory.
#[derive(Debug, Clone)]
pub struct JournalTopology {
    busy: Arc<AtomicBool>,
}

impl Default for JournalTopology {
    fn default() -> Self {
        Self::new()
    }
}

impl JournalTopology {
    pub fn new() -> Self {
        Self {
            busy: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Acquire the topology lock. Fails if another topology mutation is in progress.
    pub fn begin_mutation(&self) -> Result<JournalTopologyGuard> {
        if self
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(Error::TopologyMutationActive);
        }
        Ok(JournalTopologyGuard {
            busy: Arc::clone(&self.busy),
        })
    }
}

pub struct JournalTopologyGuard {
    busy: Arc<AtomicBool>,
}

impl std::fmt::Debug for JournalTopologyGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JournalTopologyGuard").finish_non_exhaustive()
    }
}

impl Drop for JournalTopologyGuard {
    fn drop(&mut self) {
        self.busy.store(false, Ordering::SeqCst);
    }
}
