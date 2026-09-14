//! Durable subscriptions: offset is last ACK; pending delivery is in-flight only.

use std::collections::{BTreeSet, HashMap};
use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::ids::{ConsumerId, StreamId, SubscriptionId};
use dmc_security::{CapabilityId, UserId};

/// Last **confirmed** journal sequence (ACK). The next `consume()` starts at `sequence + 1`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalPosition {
    pub sequence: u64,
}

impl JournalPosition {
    pub fn next_sequence(self) -> u64 {
        self.sequence.saturating_add(1)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubscriptionStatus {
    Active,
    Paused,
}

impl Default for SubscriptionStatus {
    fn default() -> Self {
        Self::Active
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeliveryId(pub String);

impl DeliveryId {
    pub fn new() -> Self {
        Self(format!("del_{}", Uuid::new_v4().simple()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for DeliveryId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DeliveryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Ephemeral hand-off of one journal event to one consumer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delivery {
    pub delivery_id: DeliveryId,
    pub subscription_id: SubscriptionId,
    pub event_id: String,
    pub sequence: u64,
    pub attempt: u32,
}

/// Durable in-flight record for `(subscription_id, sequence)`. Deleted after ACK.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingDelivery {
    pub subscription_id: SubscriptionId,
    pub sequence: u64,
    pub event_id: String,
    pub attempt: u32,
    pub last_delivery_id: DeliveryId,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Per-subscription retry. Lives in consumer metadata, not AVJL.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub multiplier: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            initial_backoff_ms: 100,
            max_backoff_ms: 30_000,
            multiplier: 2,
        }
    }
}

impl RetryPolicy {
    /// No delay; high attempt cap. Used by tests that assert immediate redelivery.
    pub fn immediate() -> Self {
        Self {
            max_attempts: 32,
            initial_backoff_ms: 0,
            max_backoff_ms: 0,
            multiplier: 2,
        }
    }

    pub fn validate(self) -> Result<Self> {
        if self.max_attempts < 1 {
            return Err(Error::Invalid("max_attempts must be >= 1".into()));
        }
        if self.multiplier < 1 {
            return Err(Error::Invalid("retry multiplier must be >= 1".into()));
        }
        if self.max_backoff_ms < self.initial_backoff_ms {
            return Err(Error::Invalid(
                "max_backoff_ms must be >= initial_backoff_ms".into(),
            ));
        }
        Ok(self)
    }

    /// Delay after a completed `attempt` before the next consume may issue a new Delivery.
    pub fn backoff_after(self, attempt: u32) -> u64 {
        if self.initial_backoff_ms == 0 {
            return 0;
        }
        let exp = attempt.saturating_sub(1).min(16);
        let factor = u64::from(self.multiplier.max(1)).saturating_pow(exp);
        self.initial_backoff_ms
            .saturating_mul(factor)
            .min(self.max_backoff_ms)
    }

    pub fn retry_at_ms(self, updated_at: u64, attempt: u32) -> u64 {
        updated_at.saturating_add(self.backoff_after(attempt))
    }
}

/// Backpressure / batch limits. Default matches Phase 3: one in-flight delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumerPolicy {
    pub max_in_flight: u32,
    pub max_batch_events: u32,
    pub max_batch_bytes: u64,
}

impl Default for ConsumerPolicy {
    fn default() -> Self {
        Self {
            max_in_flight: 1,
            max_batch_events: 1,
            max_batch_bytes: 1_048_576,
        }
    }
}

impl ConsumerPolicy {
    pub fn validate(self) -> Result<Self> {
        if self.max_in_flight < 1 {
            return Err(Error::Invalid("max_in_flight must be >= 1".into()));
        }
        if self.max_batch_events < 1 {
            return Err(Error::Invalid("max_batch_events must be >= 1".into()));
        }
        if self.max_batch_bytes < 1 {
            return Err(Error::Invalid("max_batch_bytes must be >= 1".into()));
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BatchLimits {
    pub max_events: usize,
    pub max_bytes: u64,
}

impl BatchLimits {
    pub fn one() -> Self {
        Self {
            max_events: 1,
            max_bytes: u64::MAX,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AckBatchResult {
    pub offset: u64,
    pub acked: Vec<String>,
    pub stale: Vec<String>,
    pub unknown: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConsumerProgress {
    pub offset: u64,
    pub pending: Option<PendingDelivery>,
    #[serde(default)]
    pub last_acked_delivery_id: Option<DeliveryId>,
    #[serde(default)]
    pub retry: RetryPolicy,
    /// In-flight `retry_dlq()` delivery. Does not block `consume()`.
    #[serde(default)]
    pub dlq_retry: Option<PendingDelivery>,
    #[serde(default)]
    pub policy: ConsumerPolicy,
    /// ACKed sequences above `offset` waiting for a contiguous prefix.
    #[serde(default)]
    pub confirmed: BTreeSet<u64>,
}

impl ConsumerProgress {
    /// Sequential ACK of the current pending (next matching event).
    pub fn advance_offset(&mut self, sequence: u64) {
        self.offset = self.offset.max(sequence);
        self.confirmed.remove(&sequence);
        self.compact_confirmed();
    }

    /// Out-of-order ACK: only move offset through a gap-free prefix.
    pub fn confirm_out_of_order(&mut self, sequence: u64) {
        if sequence <= self.offset {
            return;
        }
        self.confirmed.insert(sequence);
        self.compact_confirmed();
    }

    fn compact_confirmed(&mut self) {
        loop {
            let next = self.offset.saturating_add(1);
            if self.confirmed.remove(&next) {
                self.offset = next;
            } else {
                break;
            }
        }
    }

    pub fn in_flight(&self) -> u32 {
        let mut n = 0;
        if self.pending.is_some() {
            n += 1;
        }
        if self.dlq_retry.is_some() {
            n += 1;
        }
        n
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConsumerMetadata {
    pub progress: HashMap<String, ConsumerProgress>,
}

impl ConsumerMetadata {
    pub fn ensure(&mut self, subscription_id: &SubscriptionId) -> &mut ConsumerProgress {
        self.progress
            .entry(subscription_id.0.clone())
            .or_default()
    }

    pub fn get(&self, subscription_id: &SubscriptionId) -> Option<&ConsumerProgress> {
        self.progress.get(subscription_id.as_str())
    }

    /// Persist-first consume: new attempt for existing pending, or new pending at `sequence`.
    pub fn begin_delivery(
        &mut self,
        subscription_id: &SubscriptionId,
        sequence: u64,
        event_id: String,
        now_ms: u64,
    ) -> Delivery {
        let id = DeliveryId::new();
        let progress = self.ensure(subscription_id);
        let pending = match progress.pending.take() {
            Some(mut p) if p.sequence == sequence => {
                p.attempt = p.attempt.saturating_add(1);
                p.last_delivery_id = id.clone();
                p.event_id = event_id.clone();
                p.updated_at = now_ms;
                p
            }
            _ => PendingDelivery {
                subscription_id: subscription_id.clone(),
                sequence,
                event_id: event_id.clone(),
                attempt: 1,
                last_delivery_id: id.clone(),
                created_at: now_ms,
                updated_at: now_ms,
            },
        };
        let attempt = pending.attempt;
        progress.pending = Some(pending);
        Delivery {
            delivery_id: id,
            subscription_id: subscription_id.clone(),
            event_id,
            sequence,
            attempt,
        }
    }

    /// Atomic ACK: verify current delivery, advance offset, drop pending.
    /// Duplicate ACK of the last acked delivery is a no-op success.
    pub fn ack(&mut self, subscription_id: &SubscriptionId, delivery_id: &DeliveryId) -> Result<u64> {
        let progress = self
            .progress
            .get_mut(subscription_id.as_str())
            .ok_or_else(|| Error::UnknownSubscription(subscription_id.to_string()))?;
        if progress
            .last_acked_delivery_id
            .as_ref()
            .is_some_and(|id| id == delivery_id)
        {
            return Ok(progress.offset);
        }
        let pending = progress
            .pending
            .as_ref()
            .ok_or_else(|| Error::UnknownDelivery(delivery_id.to_string()))?;
        if pending.last_delivery_id != *delivery_id {
            return Err(Error::StaleDelivery(delivery_id.to_string()));
        }
        let sequence = pending.sequence;
        progress.last_acked_delivery_id = Some(delivery_id.clone());
        progress.pending = None;
        progress.advance_offset(sequence);
        Ok(progress.offset)
    }

    /// ACK consume pending or `retry_dlq` pending. Offset never moves backward.
    pub fn ack_delivery(
        &mut self,
        subscription_id: &SubscriptionId,
        delivery_id: &DeliveryId,
    ) -> Result<u64> {
        let progress = self
            .progress
            .get(subscription_id.as_str())
            .ok_or_else(|| Error::UnknownSubscription(subscription_id.to_string()))?;
        if progress
            .last_acked_delivery_id
            .as_ref()
            .is_some_and(|id| id == delivery_id)
        {
            return Ok(progress.offset);
        }
        if progress
            .pending
            .as_ref()
            .is_some_and(|p| p.last_delivery_id == *delivery_id)
        {
            return self.ack(subscription_id, delivery_id);
        }
        if progress
            .dlq_retry
            .as_ref()
            .is_some_and(|p| p.last_delivery_id == *delivery_id)
        {
            return self.ack_dlq_retry(subscription_id, delivery_id);
        }
        if progress.pending.is_some() || progress.dlq_retry.is_some() {
            return Err(Error::StaleDelivery(delivery_id.to_string()));
        }
        if progress.last_acked_delivery_id.is_some() {
            return Err(Error::StaleDelivery(delivery_id.to_string()));
        }
        Err(Error::UnknownDelivery(delivery_id.to_string()))
    }

    pub fn ack_batch(
        &mut self,
        subscription_id: &SubscriptionId,
        delivery_ids: &[DeliveryId],
    ) -> Result<AckBatchResult> {
        self.ensure(subscription_id);
        let mut result = AckBatchResult::default();
        for id in delivery_ids {
            match self.ack_delivery(subscription_id, id) {
                Ok(_) => result.acked.push(id.to_string()),
                Err(Error::StaleDelivery(_)) => result.stale.push(id.to_string()),
                Err(Error::UnknownDelivery(_)) => result.unknown.push(id.to_string()),
                Err(e) => return Err(e),
            }
        }
        result.offset = self
            .get(subscription_id)
            .map(|p| p.offset)
            .unwrap_or(0);
        Ok(result)
    }

    pub fn ack_dlq_retry(
        &mut self,
        subscription_id: &SubscriptionId,
        delivery_id: &DeliveryId,
    ) -> Result<u64> {
        let progress = self
            .progress
            .get_mut(subscription_id.as_str())
            .ok_or_else(|| Error::UnknownSubscription(subscription_id.to_string()))?;
        if progress
            .last_acked_delivery_id
            .as_ref()
            .is_some_and(|id| id == delivery_id)
        {
            return Ok(progress.offset);
        }
        let pending = progress
            .dlq_retry
            .as_ref()
            .ok_or_else(|| Error::UnknownDelivery(delivery_id.to_string()))?;
        if pending.last_delivery_id != *delivery_id {
            return Err(Error::StaleDelivery(delivery_id.to_string()));
        }
        let sequence = pending.sequence;
        progress.last_acked_delivery_id = Some(delivery_id.clone());
        progress.dlq_retry = None;
        progress.advance_offset(sequence);
        Ok(progress.offset)
    }

    pub fn complete_dlq(&mut self, subscription_id: &SubscriptionId, sequence: u64) {
        let progress = self.ensure(subscription_id);
        if progress
            .pending
            .as_ref()
            .is_some_and(|p| p.sequence == sequence)
        {
            progress.pending = None;
        }
    }

    pub fn begin_dlq_retry(
        &mut self,
        subscription_id: &SubscriptionId,
        sequence: u64,
        event_id: String,
        now_ms: u64,
    ) -> Delivery {
        let id = DeliveryId::new();
        let progress = self.ensure(subscription_id);
        let pending = match progress.dlq_retry.take() {
            Some(mut p) if p.sequence == sequence => {
                p.attempt = p.attempt.saturating_add(1);
                p.last_delivery_id = id.clone();
                p.event_id = event_id.clone();
                p.updated_at = now_ms;
                p
            }
            _ => PendingDelivery {
                subscription_id: subscription_id.clone(),
                sequence,
                event_id: event_id.clone(),
                attempt: 1,
                last_delivery_id: id.clone(),
                created_at: now_ms,
                updated_at: now_ms,
            },
        };
        let attempt = pending.attempt;
        progress.dlq_retry = Some(pending);
        Delivery {
            delivery_id: id,
            subscription_id: subscription_id.clone(),
            event_id,
            sequence,
            attempt,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Subscription {
    pub id: SubscriptionId,
    pub stream_id: StreamId,
    pub consumer_id: ConsumerId,
    pub subject: UserId,
    pub capability_id: CapabilityId,
    pub capability_generation: u64,
    pub position: JournalPosition,
    pub status: SubscriptionStatus,
}

#[derive(Clone, Debug)]
pub struct DeliveredEvent {
    pub sequence: u64,
    pub event_id: String,
    pub path: String,
    pub payload: Vec<u8>,
    pub operation: String,
    pub delivery: Delivery,
}

#[derive(Clone, Default)]
pub struct SubscriptionManager {
    by_id: HashMap<String, Subscription>,
    by_consumer: HashMap<String, String>,
}

impl SubscriptionManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, sub: Subscription) -> Result<Subscription> {
        if self.by_id.contains_key(sub.id.as_str()) {
            return Err(Error::Invalid(format!("subscription exists: {}", sub.id)));
        }
        self.by_consumer
            .insert(sub.consumer_id.0.clone(), sub.id.0.clone());
        self.by_id.insert(sub.id.0.clone(), sub.clone());
        Ok(sub)
    }

    pub fn get(&self, id: &SubscriptionId) -> Result<&Subscription> {
        self.by_id
            .get(id.as_str())
            .ok_or_else(|| Error::UnknownSubscription(id.to_string()))
    }

    pub fn get_mut(&mut self, id: &SubscriptionId) -> Result<&mut Subscription> {
        self.by_id
            .get_mut(id.as_str())
            .ok_or_else(|| Error::UnknownSubscription(id.to_string()))
    }

    pub fn by_consumer(&self, consumer_id: &str) -> Option<&Subscription> {
        self.by_consumer
            .get(consumer_id)
            .and_then(|id| self.by_id.get(id))
    }

    pub fn apply_offset(&mut self, consumer_id: &str, sequence: u64) {
        if let Some(sub) = self.by_id.get_mut(consumer_id) {
            sub.position.sequence = sequence;
            return;
        }
        if let Some(id) = self.by_consumer.get(consumer_id).cloned() {
            if let Some(sub) = self.by_id.get_mut(&id) {
                sub.position.sequence = sequence;
            }
        }
    }

    pub fn list(&self) -> Vec<Subscription> {
        let mut v: Vec<_> = self.by_id.values().cloned().collect();
        v.sort_by(|a, b| a.id.0.cmp(&b.id.0));
        v
    }

    pub fn clear(&mut self) {
        self.by_id.clear();
        self.by_consumer.clear();
    }
}

impl ConsumerMetadata {
    pub fn now_ms() -> u64 {
        crate::clock::system_now_ms()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_does_not_create_subscription() {
        let mut mgr = SubscriptionManager::new();
        mgr.apply_offset("missing", 10);
        assert!(mgr.list().is_empty());
    }

    #[test]
    fn position_is_last_acked_not_next() {
        let pos = JournalPosition { sequence: 40 };
        assert_eq!(pos.next_sequence(), 41);
    }

    #[test]
    fn attempts_are_per_subscription_sequence() {
        let mut meta = ConsumerMetadata::default();
        let a = SubscriptionId::from("sub-a");
        let b = SubscriptionId::from("sub-b");
        let d1 = meta.begin_delivery(&a, 100, "e".into(), 1);
        assert_eq!(d1.attempt, 1);
        let d2 = meta.begin_delivery(&a, 100, "e".into(), 2);
        assert_eq!(d2.attempt, 2);
        assert_ne!(d1.delivery_id, d2.delivery_id);
        let db = meta.begin_delivery(&b, 100, "e".into(), 3);
        assert_eq!(db.attempt, 1);
    }

    #[test]
    fn ack_is_idempotent_and_rejects_stale() {
        let mut meta = ConsumerMetadata::default();
        let sub = SubscriptionId::from("sub-a");
        let d1 = meta.begin_delivery(&sub, 41, "e".into(), 1);
        let d2 = meta.begin_delivery(&sub, 41, "e".into(), 2);
        assert!(meta.ack(&sub, &d1.delivery_id).is_err());
        assert_eq!(meta.ack(&sub, &d2.delivery_id).unwrap(), 41);
        assert!(meta.get(&sub).unwrap().pending.is_none());
        assert_eq!(meta.ack(&sub, &d2.delivery_id).unwrap(), 41);
        assert_eq!(meta.get(&sub).unwrap().offset, 41);
    }

    #[test]
    fn exponential_backoff_caps_at_max() {
        let p = RetryPolicy {
            max_attempts: 8,
            initial_backoff_ms: 100,
            max_backoff_ms: 800,
            multiplier: 2,
        };
        assert_eq!(p.backoff_after(1), 100);
        assert_eq!(p.backoff_after(2), 200);
        assert_eq!(p.backoff_after(3), 400);
        assert_eq!(p.backoff_after(4), 800);
        assert_eq!(p.backoff_after(5), 800);
        assert_eq!(RetryPolicy::immediate().backoff_after(3), 0);
    }

    #[test]
    fn contiguous_ack_does_not_skip_gaps() {
        let mut p = ConsumerProgress {
            offset: 100,
            ..ConsumerProgress::default()
        };
        p.confirm_out_of_order(101);
        p.confirm_out_of_order(102);
        p.confirm_out_of_order(104);
        assert_eq!(p.offset, 102);
        p.confirm_out_of_order(103);
        assert_eq!(p.offset, 104);
    }

    #[test]
    fn ack_batch_reports_stale_and_duplicate() {
        let mut meta = ConsumerMetadata::default();
        let sub = SubscriptionId::from("sub-a");
        let d1 = meta.begin_delivery(&sub, 41, "e".into(), 1);
        let d2 = meta.begin_delivery(&sub, 41, "e".into(), 2);
        let batch = meta
            .ack_batch(&sub, &[d2.delivery_id.clone(), d2.delivery_id.clone(), d1.delivery_id])
            .unwrap();
        assert_eq!(batch.offset, 41);
        assert_eq!(batch.acked.len(), 2);
        assert_eq!(batch.stale.len(), 1);
    }

    #[test]
    fn dlq_retry_ack_does_not_move_offset_backward() {
        let mut meta = ConsumerMetadata::default();
        let sub = SubscriptionId::from("sub-a");
        let d = meta.begin_delivery(&sub, 52, "e2".into(), 1);
        assert_eq!(meta.ack(&sub, &d.delivery_id).unwrap(), 52);
        let r = meta.begin_dlq_retry(&sub, 51, "e1".into(), 2);
        assert_eq!(meta.ack_delivery(&sub, &r.delivery_id).unwrap(), 52);
        assert_eq!(meta.get(&sub).unwrap().offset, 52);
        assert!(meta.get(&sub).unwrap().dlq_retry.is_none());
    }
}
