//! DLQ is an encrypted path in the journal: `_system/dlq/{subscription}/{entry}`.

use serde::{Deserialize, Serialize};

use crate::ids::{DlqEntryId, SubscriptionId};
use crate::overlay::OverlayStore;
use crate::subscription::{DeliveryId, PendingDelivery};
use dmc_vault::key::KeyPath;

pub const DLQ_PREFIX: &str = "_system/dlq";
pub const DLQ_SOURCE: &str = "dlq";
pub const DLQ_REASON_MAX_ATTEMPTS: &str = "max_attempts_exceeded";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DlqEntry {
    pub id: DlqEntryId,
    pub original_event_id: String,
    pub original_sequence: u64,
    pub original_path: String,
    pub subscription_id: SubscriptionId,
    pub attempts: u32,
    pub first_attempt_at: u64,
    pub last_attempt_at: u64,
    pub last_delivery_id: DeliveryId,
    pub failure_reason: String,
    pub payload: Vec<u8>,
}

pub fn is_dlq_path(path: &KeyPath) -> bool {
    let s = path.as_str().trim_start_matches('/');
    s == DLQ_PREFIX || s.starts_with(&format!("{DLQ_PREFIX}/"))
}

pub fn dlq_subscription_path(subscription_id: &SubscriptionId) -> String {
    format!("{DLQ_PREFIX}/{subscription_id}")
}

pub fn dlq_entry_path(subscription_id: &SubscriptionId, id: &DlqEntryId) -> String {
    format!("{DLQ_PREFIX}/{subscription_id}/{id}")
}

pub fn parse_overlay_entry(payload: &[u8]) -> Option<DlqEntry> {
    serde_json::from_slice(payload).ok()
}

pub fn list_overlay_entries(overlay: &OverlayStore, subscription_id: &SubscriptionId) -> Vec<DlqEntry> {
    let prefix = dlq_subscription_path(subscription_id);
    let mut out: Vec<_> = overlay
        .list_under(&prefix)
        .into_iter()
        .filter(|p| !p.deleted)
        .filter_map(|p| parse_overlay_entry(&p.payload))
        .filter(|e| e.subscription_id == *subscription_id)
        .collect();
    out.sort_by_key(|e| (e.original_sequence, e.id.0.clone()));
    out
}

pub fn find_overlay_entry(overlay: &OverlayStore, id: &DlqEntryId) -> Option<DlqEntry> {
    overlay
        .list_under(DLQ_PREFIX)
        .into_iter()
        .filter(|p| !p.deleted)
        .filter_map(|p| parse_overlay_entry(&p.payload))
        .find(|e| e.id == *id)
}

/// Sequences already dead-lettered for this subscription (durable journal/overlay marker).
pub fn dead_sequences(overlay: &OverlayStore, subscription_id: &SubscriptionId) -> Vec<u64> {
    list_overlay_entries(overlay, subscription_id)
        .into_iter()
        .map(|e| e.original_sequence)
        .collect()
}

pub fn from_pending(
    id: DlqEntryId,
    pending: &PendingDelivery,
    original_path: String,
    payload: Vec<u8>,
) -> DlqEntry {
    DlqEntry {
        id,
        original_event_id: pending.event_id.clone(),
        original_sequence: pending.sequence,
        original_path,
        subscription_id: pending.subscription_id.clone(),
        attempts: pending.attempt,
        first_attempt_at: pending.created_at,
        last_attempt_at: pending.updated_at,
        last_delivery_id: pending.last_delivery_id.clone(),
        failure_reason: DLQ_REASON_MAX_ATTEMPTS.into(),
        payload,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subscription::ConsumerMetadata;

    #[test]
    fn reconcile_clears_pending_when_marker_exists() {
        let mut meta = ConsumerMetadata::default();
        let sub = SubscriptionId::from("sub-a");
        let _ = meta.begin_delivery(&sub, 51, "e".into(), 1);
        assert!(meta.get(&sub).unwrap().pending.is_some());
        meta.complete_dlq(&sub, 51);
        assert!(meta.get(&sub).unwrap().pending.is_none());
        assert_eq!(meta.get(&sub).unwrap().offset, 0);
    }
}
