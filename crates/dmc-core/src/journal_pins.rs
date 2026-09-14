//! Runtime-specific journal retention pins (Phase 5.1).
//!
//! `dmc-journal` only sees sequence floors; reason labels stay here.

use dmc_journal::JournalPin;

use crate::ids::SubscriptionId;
use crate::subscription::ConsumerMetadata;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinReason {
    Consumer,
    Snapshot,
    Replay,
    Retention,
    Replication,
}

/// Subscription offset: last sequence the consumer no longer needs (ACK'd position).
/// Pending at `offset + 1` is preserved automatically.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsumerPin {
    pub subscription_id: SubscriptionId,
    pub offset: u64,
    pub reason: PinReason,
}

impl ConsumerPin {
    pub fn new(subscription_id: SubscriptionId, offset: u64) -> Self {
        Self {
            subscription_id,
            offset,
            reason: PinReason::Consumer,
        }
    }
}

impl JournalPin for ConsumerPin {
    fn sequence(&self) -> u64 {
        self.offset
    }
}

/// Published snapshot floor from crash-safe manifest (Phase 5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotPin {
    pub sequence: u64,
}

impl JournalPin for SnapshotPin {
    fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Temporary replay lease: `from_sequence` must remain readable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayPin {
    pub lease_id: String,
    pub subscription_id: SubscriptionId,
    pub from_sequence: u64,
    pub expires_at_ms: u64,
}

impl ReplayPin {
    pub fn pin_sequence(&self) -> u64 {
        self.from_sequence.saturating_sub(1)
    }

    pub fn active_at(&self, now_ms: u64) -> bool {
        now_ms < self.expires_at_ms
    }
}

impl JournalPin for ReplayPin {
    fn sequence(&self) -> u64 {
        self.pin_sequence()
    }
}

/// Dynamic retention policy pin (Phase 5.5). Recalculated from policy + journal on each watermark pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionPolicyPin {
    pub trim_through: u64,
}

impl JournalPin for RetentionPolicyPin {
    fn sequence(&self) -> u64 {
        self.trim_through
    }
}

pub fn consumer_pins_from_meta(meta: &ConsumerMetadata) -> Vec<ConsumerPin> {
    meta.progress
        .iter()
        .map(|(id, progress)| ConsumerPin::new(SubscriptionId::from(id.as_str()), progress.offset))
        .collect()
}
