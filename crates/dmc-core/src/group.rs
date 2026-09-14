//! Consumer groups: membership, generation, lease, assignment, GroupOffset, delivery, ACK (Phase 5.8.2–5.8.6).

use std::collections::{BTreeMap, HashMap};

use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use crate::clock::{clamp_member_lease_ms, DEFAULT_MEMBER_LEASE_MS};
use crate::error::{Error, Result};
use crate::group_meta::GROUP_META_FORMAT_VERSION;
use crate::ids::{GroupId, MemberId, SessionId, StreamId};
use crate::subscription::DeliveryId;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GroupState {
    Empty,
    Stable,
    Rebalancing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemberState {
    Active,
    Leaving,
    Expired,
}

/// Bootstrap cursor when a group is created (GroupOffset foundation).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GroupStartPosition {
    /// Offset = journal head (global last sequence). Next event is head+1.
    #[default]
    Latest,
    /// Offset = oldest_available.saturating_sub(1). Next event is oldest available.
    Earliest,
}

/// Deterministic retry schedule for explicit `group_retry` (Phase 5.8.9).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupRetryPolicy {
    #[serde(default = "default_group_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_group_backoff_ms")]
    pub backoff_ms: Vec<u64>,
}

fn default_group_max_attempts() -> u32 {
    5
}

fn default_group_backoff_ms() -> Vec<u64> {
    vec![0, 1_000, 5_000, 30_000, 60_000]
}

impl Default for GroupRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: default_group_max_attempts(),
            backoff_ms: default_group_backoff_ms(),
        }
    }
}

impl GroupRetryPolicy {
    pub fn validate(self) -> Result<Self> {
        if self.max_attempts < 1 {
            return Err(Error::Invalid("group retry max_attempts must be >= 1".into()));
        }
        if self.backoff_ms.is_empty() {
            return Err(Error::Invalid(
                "group retry backoff_ms must not be empty".into(),
            ));
        }
        Ok(self)
    }

    /// Delay after the current `attempt` before the next `group_consume` redelivery.
    pub fn backoff_after_attempt(&self, attempt: u32) -> u64 {
        let idx = attempt.saturating_sub(1) as usize;
        let last = self.backoff_ms.len() - 1;
        self.backoff_ms[idx.min(last)]
    }

    pub fn retry_at_ms(&self, now_ms: u64, attempt: u32) -> u64 {
        now_ms.saturating_add(self.backoff_after_attempt(attempt))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupPolicy {
    pub member_lease_ms: u64,
    #[serde(default)]
    pub start_position: GroupStartPosition,
    /// Max outstanding (unacked) deliveries per partition. Default 1 preserves 5.8.5 semantics.
    #[serde(default = "default_max_in_flight")]
    pub max_in_flight: u32,
    #[serde(default)]
    pub retry: GroupRetryPolicy,
    /// Deprecated: use `retry.backoff_ms`. Kept for metadata backward compatibility.
    #[serde(default)]
    pub redelivery_backoff_ms: u64,
}

fn default_max_in_flight() -> u32 {
    1
}

impl Default for GroupPolicy {
    fn default() -> Self {
        Self {
            member_lease_ms: DEFAULT_MEMBER_LEASE_MS,
            start_position: GroupStartPosition::Latest,
            max_in_flight: default_max_in_flight(),
            retry: GroupRetryPolicy::default(),
            redelivery_backoff_ms: 0,
        }
    }
}

impl GroupPolicy {
    pub fn effective_member_lease_ms(&self) -> u64 {
        clamp_member_lease_ms(self.member_lease_ms)
    }

    pub fn effective_max_in_flight(&self) -> u32 {
        self.max_in_flight.max(1)
    }

    pub fn validate(&self) -> Result<()> {
        self.retry.clone().validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMember {
    pub member_id: MemberId,
    pub group_id: GroupId,
    pub session_id: SessionId,
    pub generation_joined: u64,
    pub joined_at: u64,
    #[serde(alias = "heartbeat_at")]
    pub last_heartbeat_at_ms: u64,
    #[serde(alias = "lease_expires_at", default = "default_unset_lease")]
    pub lease_expires_at_ms: u64,
    pub device_id: Option<String>,
    pub state: MemberState,
}

fn default_unset_lease() -> u64 {
    u64::MAX
}

impl GroupMember {
    fn is_lease_expired(&self, now_ms: u64) -> bool {
        self.state == MemberState::Active && self.lease_expires_at_ms <= now_ms
    }

    fn refresh_lease(&mut self, now_ms: u64, lease_ms: u64) {
        self.last_heartbeat_at_ms = now_ms;
        self.lease_expires_at_ms = now_ms.saturating_add(lease_ms);
        self.state = MemberState::Active;
    }
}

/// Authoritative ownership: partition → member for the current generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionOwner {
    pub partition_id: u32,
    pub member_id: MemberId,
    pub generation: u64,
}

/// GroupOffset: per-partition cursor (global journal sequence), owned by the group — not a member.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupPartitionOffset {
    pub partition_id: u32,
    pub sequence: u64,
}

/// Durable in-flight work for one `(partition, sequence)`.
///
/// **Pending** = durable work state (sequence, event_id, attempt, retry_at). Survives rebalance.
/// **Delivery** = ephemeral hand-off (`GroupDelivery` / `last_delivery_id` + member/generation on pending).
/// After rebalance, pending remains; the next `group_consume` issues a new delivery_id at the new generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupPendingDelivery {
    pub group_id: GroupId,
    pub partition_id: u32,
    pub sequence: u64,
    pub event_id: String,
    pub member_id: MemberId,
    pub generation: u64,
    pub attempt: u32,
    pub last_delivery_id: DeliveryId,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    /// Wall-clock of the last hand-off (attempt).
    #[serde(default)]
    pub delivered_at_ms: u64,
    /// Earliest time a non-crash redelivery may bump attempt. Crash recovery bypasses this.
    #[serde(default)]
    pub retry_at_ms: u64,
    /// Set on unlock / rebalance; cleared after redelivery. Not persisted.
    #[serde(skip)]
    pub await_redelivery: bool,
}

/// Result of a successful `group_ack` (including idempotent duplicate).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupAckResult {
    pub partition_id: u32,
    pub acknowledged_sequence: u64,
    pub new_offset: u64,
    pub advanced: bool,
}

/// Result of a successful explicit `group_retry`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupRetryResult {
    pub partition_id: u32,
    pub sequence: u64,
    pub attempt: u32,
    pub retry_at_ms: u64,
}

/// Terminal DLQ disposition for one `(partition, sequence)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupDlqReason {
    MaxAttemptsExceeded,
}

/// Durable per-group DLQ record. Journal event is never moved or copied.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupDlqEntry {
    pub group_id: GroupId,
    pub partition_id: u32,
    pub sequence: u64,
    pub event_id: String,
    pub attempts: u32,
    pub first_delivered_at_ms: u64,
    pub last_delivered_at_ms: u64,
    pub reason: GroupDlqReason,
    pub created_at_ms: u64,
    pub generation: u64,
}

/// Result of moving a pending sequence to DLQ (including idempotent replay).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupDlqResult {
    pub partition_id: u32,
    pub sequence: u64,
    pub new_offset: u64,
    pub advanced: bool,
    pub entry: GroupDlqEntry,
}

/// Outcome of `group_retry`: schedule backoff or terminal DLQ when attempts exhausted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GroupRetryResponse {
    Retry(GroupRetryResult),
    Dlq(GroupDlqResult),
}

/// Ephemeral hand-off of one journal event to one group member.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupDelivery {
    pub delivery_id: DeliveryId,
    pub group_id: GroupId,
    pub member_id: MemberId,
    pub generation: u64,
    pub partition_id: u32,
    pub sequence: u64,
    pub event_id: String,
    pub attempt: u32,
}

/// Payload + delivery metadata returned by `group_consume`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupDeliveredEvent {
    pub sequence: u64,
    pub event_id: String,
    pub path: String,
    pub payload: Vec<u8>,
    pub operation: String,
    pub partition_id: u32,
    pub delivery: GroupDelivery,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumerGroup {
    pub group_id: GroupId,
    /// Unique instance id — new on each `create_group`, survives delete/recreate distinction.
    pub instance_id: String,
    pub stream_id: StreamId,
    pub generation: u64,
    pub state: GroupState,
    pub members: HashMap<MemberId, GroupMember>,
    #[serde(default)]
    pub policy: GroupPolicy,
    /// Topology size captured at create (physical journal partition_count).
    #[serde(default = "default_partition_count")]
    pub partition_count: u32,
    /// partition_id → owning member_id (authoritative). Empty when no members.
    #[serde(default)]
    pub assignments: BTreeMap<u32, MemberId>,
    /// partition_id → last contiguous ACK'd global sequence (GroupOffset). Survives rebalance.
    #[serde(default)]
    pub offsets: BTreeMap<u32, u64>,
    /// partition_id → (sequence → durable pending). Multi in-flight for contiguous ACK.
    #[serde(default, deserialize_with = "deserialize_group_pending")]
    pub pending: BTreeMap<u32, BTreeMap<u64, GroupPendingDelivery>>,
    /// partition_id → last successfully ACK'd delivery_id (idempotent duplicate ACK).
    #[serde(default)]
    pub last_acked_delivery_id: BTreeMap<u32, DeliveryId>,
    /// partition_id → highest sequence ever delivered into pending on that partition.
    #[serde(default)]
    pub delivered_high: BTreeMap<u32, u64>,
    /// partition_id → (sequence → terminal DLQ entry). Survives journal physical GC.
    #[serde(default)]
    pub dlq: BTreeMap<u32, BTreeMap<u64, GroupDlqEntry>>,
    pub created_at: u64,
}

fn default_partition_count() -> u32 {
    1
}

/// Accept 5.8.5 shape `{pid: Pending}` or 5.8.6 shape `{pid: {seq: Pending}}`.
fn deserialize_group_pending<'de, D>(
    deserializer: D,
) -> std::result::Result<BTreeMap<u32, BTreeMap<u64, GroupPendingDelivery>>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw: BTreeMap<String, serde_json::Value> = Deserialize::deserialize(deserializer)?;
    let mut out: BTreeMap<u32, BTreeMap<u64, GroupPendingDelivery>> = BTreeMap::new();
    for (key, value) in raw {
        let pid: u32 = key.parse().map_err(DeError::custom)?;
        if value.get("sequence").is_some() {
            let pending: GroupPendingDelivery =
                serde_json::from_value(value).map_err(DeError::custom)?;
            out.entry(pid).or_default().insert(pending.sequence, pending);
            continue;
        }
        let nested: BTreeMap<String, GroupPendingDelivery> =
            serde_json::from_value(value).map_err(DeError::custom)?;
        let mut inner = BTreeMap::new();
        for (seq_key, pending) in nested {
            let seq: u64 = seq_key.parse().map_err(DeError::custom)?;
            inner.insert(seq, pending);
        }
        out.insert(pid, inner);
    }
    Ok(out)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMetadata {
    pub format_version: u32,
    pub groups: HashMap<GroupId, ConsumerGroup>,
}

impl Default for GroupMetadata {
    fn default() -> Self {
        Self {
            format_version: GROUP_META_FORMAT_VERSION,
            groups: HashMap::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberDescription {
    pub member_id: MemberId,
    pub generation_joined: u64,
    pub lease_expires_at_ms: u64,
    pub state: MemberState,
    pub partitions: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupDescription {
    pub group_id: GroupId,
    pub instance_id: String,
    pub stream_id: StreamId,
    pub generation: u64,
    pub state: GroupState,
    pub members: Vec<MemberDescription>,
    pub partition_count: u32,
    /// Sorted partition → owner.
    pub assignments: Vec<PartitionOwner>,
    /// Sorted partition → GroupOffset sequence.
    pub offsets: Vec<GroupPartitionOffset>,
    pub created_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct LeaseReconcileResult {
    pub expired_members: Vec<(GroupId, MemberId)>,
}

/// Deterministic round-robin assignment. Pure: no journal I/O.
///
/// Partitions and members are sorted; partition `i` → member `i % members.len()`.
pub fn assign_partitions(
    partition_ids: &[u32],
    member_ids: &[MemberId],
) -> BTreeMap<u32, MemberId> {
    let mut partitions = partition_ids.to_vec();
    partitions.sort_unstable();
    partitions.dedup();
    let mut members = member_ids.to_vec();
    members.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = BTreeMap::new();
    if members.is_empty() || partitions.is_empty() {
        return out;
    }
    for (i, pid) in partitions.into_iter().enumerate() {
        out.insert(pid, members[i % members.len()].clone());
    }
    out
}

pub fn bootstrap_offsets(
    partition_count: u32,
    start: GroupStartPosition,
    journal_head: u64,
    oldest_available: u64,
) -> BTreeMap<u32, u64> {
    let count = partition_count.max(1);
    let sequence = match start {
        GroupStartPosition::Latest => journal_head,
        GroupStartPosition::Earliest => oldest_available.saturating_sub(1),
    };
    (0..count).map(|pid| (pid, sequence)).collect()
}

impl ConsumerGroup {
    pub fn describe(&self) -> GroupDescription {
        let mut members: Vec<_> = self
            .members
            .values()
            .map(|m| MemberDescription {
                member_id: m.member_id.clone(),
                generation_joined: m.generation_joined,
                lease_expires_at_ms: m.lease_expires_at_ms,
                state: m.state,
                partitions: self.partitions_for_member(&m.member_id),
            })
            .collect();
        members.sort_by(|a, b| a.member_id.0.cmp(&b.member_id.0));
        let assignments: Vec<_> = self
            .assignments
            .iter()
            .map(|(pid, mid)| PartitionOwner {
                partition_id: *pid,
                member_id: mid.clone(),
                generation: self.generation,
            })
            .collect();
        let offsets: Vec<_> = self
            .offsets
            .iter()
            .map(|(pid, seq)| GroupPartitionOffset {
                partition_id: *pid,
                sequence: *seq,
            })
            .collect();
        GroupDescription {
            group_id: self.group_id.clone(),
            instance_id: self.instance_id.clone(),
            stream_id: self.stream_id.clone(),
            generation: self.generation,
            state: self.state,
            members,
            partition_count: self.partition_count,
            assignments,
            offsets,
            created_at: self.created_at,
        }
    }

    pub fn partitions_for_member(&self, member_id: &MemberId) -> Vec<u32> {
        self.assignments
            .iter()
            .filter(|(_, owner)| *owner == member_id)
            .map(|(pid, _)| *pid)
            .collect()
    }

    pub fn owner_of(&self, partition_id: u32) -> Option<&MemberId> {
        self.assignments.get(&partition_id)
    }

    /// Recompute partition → member map. Does **not** bump generation or mutate offsets.
    /// Pending is retained and marked for redelivery (new owner picks it up on consume).
    pub fn recompute_assignment(&mut self) {
        let partitions: Vec<u32> = (0..self.partition_count.max(1)).collect();
        let members: Vec<MemberId> = self.members.keys().cloned().collect();
        self.assignments = assign_partitions(&partitions, &members);
        self.state = if self.members.is_empty() {
            GroupState::Empty
        } else {
            GroupState::Stable
        };
        self.mark_pending_for_redelivery();
    }

    /// Phase 5.8.8: one membership transition → generation += 1 + assignment recompute (atomic in metadata write).
    /// GroupOffset and pending entries are never removed or rewound.
    pub fn bump_generation_and_rebalance(&mut self) -> u64 {
        self.generation = self.generation.saturating_add(1);
        self.recompute_assignment();
        self.generation
    }

    /// Mark every pending delivery so the next consume redelivers before creating new ones.
    pub fn mark_pending_for_redelivery(&mut self) {
        for by_seq in self.pending.values_mut() {
            for pending in by_seq.values_mut() {
                pending.await_redelivery = true;
            }
        }
    }

    /// After unlock / crash: only in-flight deliveries without an explicit retry schedule.
    pub fn mark_orphaned_pending_for_crash_recovery(&mut self) {
        for by_seq in self.pending.values_mut() {
            for pending in by_seq.values_mut() {
                if pending.updated_at_ms <= pending.delivered_at_ms {
                    pending.await_redelivery = true;
                }
            }
        }
    }

    /// Assigned partitions for a member, sorted ascending (consume selection order).
    pub fn assigned_partitions_sorted(&self, member_id: &MemberId) -> Vec<u32> {
        let mut parts = self.partitions_for_member(member_id);
        parts.sort_unstable();
        parts
    }

    pub fn pending_count_for_partition(&self, partition_id: u32) -> usize {
        self.pending
            .get(&partition_id)
            .map(|m| m.len())
            .unwrap_or(0)
    }

    pub fn max_pending_sequence(&self, partition_id: u32) -> Option<u64> {
        self.pending.get(&partition_id)?.keys().next_back().copied()
    }

    /// Exclusive cursor used when creating a new delivery on a partition.
    pub fn consume_from_exclusive(&self, partition_id: u32) -> u64 {
        let offset = self.offset_for_partition(partition_id);
        self.max_pending_sequence(partition_id)
            .map(|s| s.max(offset))
            .unwrap_or(offset)
    }

    /// Lowest pending that should be redelivered on this partition (await flag or orphaned).
    pub fn next_redelivery_pending(
        &self,
        partition_id: u32,
        member_id: &MemberId,
    ) -> Option<&GroupPendingDelivery> {
        let by_seq = self.pending.get(&partition_id)?;
        by_seq.values().find(|p| {
            p.await_redelivery
                || p.member_id != *member_id
                || p.generation != self.generation
        })
    }


    /// Whether this pending may be redelivered now (crash/rebalance or explicit retry due).
    pub fn pending_ready_for_redelivery(&self, pending: &GroupPendingDelivery, now_ms: u64) -> bool {
        if pending.await_redelivery {
            return true;
        }
        pending.updated_at_ms > pending.delivered_at_ms && now_ms >= pending.retry_at_ms
    }

    /// Explicit retry was scheduled and is still waiting for `retry_at_ms`.
    pub fn pending_retry_scheduled(&self, pending: &GroupPendingDelivery) -> bool {
        pending.updated_at_ms > pending.delivered_at_ms
    }

    fn locate_pending_by_delivery_id(
        &self,
        delivery_id: &DeliveryId,
    ) -> Result<(u32, u64, GroupPendingDelivery)> {
        let mut found: Option<(u32, u64)> = None;
        for (pid, by_seq) in &self.pending {
            for (seq, pending) in by_seq {
                if &pending.last_delivery_id == delivery_id {
                    found = Some((*pid, *seq));
                    break;
                }
            }
            if found.is_some() {
                break;
            }
        }
        let (partition_id, sequence) = found.ok_or_else(|| {
            Error::StaleDelivery(delivery_id.to_string())
        })?;
        let pending = self
            .pending
            .get(&partition_id)
            .and_then(|m| m.get(&sequence))
            .cloned()
            .ok_or_else(|| Error::StaleDelivery(delivery_id.to_string()))?;
        Ok((partition_id, sequence, pending))
    }

    fn verify_active_delivery(
        &self,
        member_id: &MemberId,
        generation: u64,
        delivery_id: &DeliveryId,
        pending: &GroupPendingDelivery,
        partition_id: u32,
    ) -> Result<()> {
        if generation != self.generation {
            return Err(Error::StaleGeneration {
                got: generation,
                current: self.generation,
            });
        }
        if pending.member_id != *member_id {
            return Err(Error::NotAssigned {
                member_id: member_id.to_string(),
                partition_id,
            });
        }
        if pending.generation != self.generation {
            return Err(Error::StaleDelivery(delivery_id.to_string()));
        }
        if pending.last_delivery_id != *delivery_id {
            return Err(Error::StaleDelivery(delivery_id.to_string()));
        }
        let owner = self.assignments.get(&partition_id).ok_or_else(|| Error::NotAssigned {
            member_id: member_id.to_string(),
            partition_id,
        })?;
        if owner != member_id {
            return Err(Error::NotAssigned {
                member_id: member_id.to_string(),
                partition_id,
            });
        }
        Ok(())
    }

    /// Lowest pending needing crash/orphan redelivery across assigned partitions (partition ASC, sequence ASC).
    pub fn next_recovery_pending(
        &self,
        member_id: &MemberId,
    ) -> Option<&GroupPendingDelivery> {
        for pid in self.assigned_partitions_sorted(member_id) {
            if let Some(p) = self.next_redelivery_pending(pid, member_id) {
                return Some(p);
            }
        }
        None
    }

    /// Lowest pending sequence on the partition (for backpressure redelivery).
    pub fn lowest_pending(&self, partition_id: u32) -> Option<&GroupPendingDelivery> {
        self.pending.get(&partition_id)?.values().next()
    }

    /// Create or redeliver pending for `(partition, sequence)`. Does not change GroupOffset.
    pub fn begin_group_delivery(
        &mut self,
        member_id: &MemberId,
        partition_id: u32,
        sequence: u64,
        event_id: String,
        now_ms: u64,
    ) -> Result<GroupDelivery> {
        let generation = self.generation;
        let owner = self
            .assignments
            .get(&partition_id)
            .ok_or_else(|| Error::NotAssigned {
                member_id: member_id.to_string(),
                partition_id,
            })?;
        if owner != member_id {
            return Err(Error::NotAssigned {
                member_id: member_id.to_string(),
                partition_id,
            });
        }
        let delivery_id = DeliveryId::new();
        let bucket = self.pending.entry(partition_id).or_default();
        let pending = match bucket.remove(&sequence) {
            Some(mut p) => {
                p.attempt = p.attempt.saturating_add(1);
                p.last_delivery_id = delivery_id.clone();
                p.event_id = event_id.clone();
                p.member_id = member_id.clone();
                p.generation = generation;
                p.updated_at_ms = now_ms;
                p.delivered_at_ms = now_ms;
                p.retry_at_ms = 0;
                p.await_redelivery = false;
                p
            }
            None => GroupPendingDelivery {
                group_id: self.group_id.clone(),
                partition_id,
                sequence,
                event_id: event_id.clone(),
                member_id: member_id.clone(),
                generation,
                attempt: 1,
                last_delivery_id: delivery_id.clone(),
                created_at_ms: now_ms,
                updated_at_ms: now_ms,
                delivered_at_ms: now_ms,
                retry_at_ms: 0,
                await_redelivery: false,
            },
        };
        let delivery = GroupDelivery {
            delivery_id: pending.last_delivery_id.clone(),
            group_id: self.group_id.clone(),
            member_id: member_id.clone(),
            generation,
            partition_id,
            sequence,
            event_id,
            attempt: pending.attempt,
        };
        bucket.insert(sequence, pending);
        let high = self.delivered_high.entry(partition_id).or_insert(0);
        *high = (*high).max(sequence);
        Ok(delivery)
    }

    pub fn pending_for_partition(
        &self,
        partition_id: u32,
    ) -> Option<&BTreeMap<u64, GroupPendingDelivery>> {
        self.pending.get(&partition_id)
    }

    pub fn offset_for_partition(&self, partition_id: u32) -> u64 {
        self.offsets.get(&partition_id).copied().unwrap_or(0)
    }

    pub fn list_dlq_entries(&self) -> Vec<GroupDlqEntry> {
        let mut out = Vec::new();
        for by_seq in self.dlq.values() {
            out.extend(by_seq.values().cloned());
        }
        out.sort_by(|a, b| {
            a.partition_id
                .cmp(&b.partition_id)
                .then(a.sequence.cmp(&b.sequence))
        });
        out
    }

    pub fn get_dlq_entry(&self, partition_id: u32, sequence: u64) -> Option<&GroupDlqEntry> {
        self.dlq.get(&partition_id)?.get(&sequence)
    }

    fn remove_pending(&mut self, partition_id: u32, sequence: u64) {
        if let Some(bucket) = self.pending.get_mut(&partition_id) {
            bucket.remove(&sequence);
            if bucket.is_empty() {
                self.pending.remove(&partition_id);
            }
        }
    }

    /// Advance GroupOffset across contiguous resolved sequences (ACK or DLQ removed pending).
    fn advance_contiguous_offset(&mut self, partition_id: u32, resolved_sequence: u64) -> (u64, bool) {
        let high = self
            .delivered_high
            .get(&partition_id)
            .copied()
            .unwrap_or(resolved_sequence)
            .max(resolved_sequence);
        self.delivered_high.insert(partition_id, high);
        let old_offset = self.offset_for_partition(partition_id);
        let mut new_offset = old_offset;
        while new_offset < high {
            let next = new_offset + 1;
            if self
                .pending
                .get(&partition_id)
                .is_some_and(|m| m.contains_key(&next))
            {
                break;
            }
            new_offset = next;
        }
        self.offsets.insert(partition_id, new_offset);
        (new_offset, new_offset > old_offset)
    }

    /// Atomic ACK: verify delivery ownership, remove pending, advance contiguous GroupOffset.
    pub fn ack_group_delivery(
        &mut self,
        member_id: &MemberId,
        generation: u64,
        delivery_id: &DeliveryId,
    ) -> Result<GroupAckResult> {
        if generation != self.generation {
            return Err(Error::StaleGeneration {
                got: generation,
                current: self.generation,
            });
        }

        // Idempotent duplicate of last ACK'd delivery on any partition.
        for (pid, last) in &self.last_acked_delivery_id {
            if last == delivery_id {
                let offset = self.offset_for_partition(*pid);
                return Ok(GroupAckResult {
                    partition_id: *pid,
                    acknowledged_sequence: offset,
                    new_offset: offset,
                    advanced: false,
                });
            }
        }

        let (partition_id, sequence, pending) = self.locate_pending_by_delivery_id(delivery_id)?;
        self.verify_active_delivery(
            member_id,
            generation,
            delivery_id,
            &pending,
            partition_id,
        )?;
        if pending.updated_at_ms > pending.delivered_at_ms {
            return Err(Error::StaleDelivery(delivery_id.to_string()));
        }

        self.remove_pending(partition_id, sequence);
        let (new_offset, advanced) = self.advance_contiguous_offset(partition_id, sequence);
        self.last_acked_delivery_id
            .insert(partition_id, delivery_id.clone());

        Ok(GroupAckResult {
            partition_id,
            acknowledged_sequence: sequence,
            new_offset,
            advanced,
        })
    }

    /// Terminal DLQ transition for an exhausted pending delivery (atomic with offset advance).
    pub fn move_pending_to_dlq(
        &mut self,
        member_id: &MemberId,
        generation: u64,
        delivery_id: &DeliveryId,
        now_ms: u64,
    ) -> Result<GroupDlqResult> {
        if generation != self.generation {
            return Err(Error::StaleGeneration {
                got: generation,
                current: self.generation,
            });
        }

        let (partition_id, sequence, pending) = self.locate_pending_by_delivery_id(delivery_id)?;
        self.verify_active_delivery(
            member_id,
            generation,
            delivery_id,
            &pending,
            partition_id,
        )?;

        let max_attempts = self.policy.retry.max_attempts.max(1);
        if pending.attempt < max_attempts {
            return Err(Error::Invalid(
                "pending attempt not exhausted for DLQ transition".into(),
            ));
        }

        if let Some(existing) = self
            .dlq
            .get(&partition_id)
            .and_then(|m| m.get(&sequence))
            .cloned()
        {
            self.remove_pending(partition_id, sequence);
            let (new_offset, advanced) = self.advance_contiguous_offset(partition_id, sequence);
            return Ok(GroupDlqResult {
                partition_id,
                sequence,
                new_offset,
                advanced,
                entry: existing,
            });
        }

        let entry = GroupDlqEntry {
            group_id: self.group_id.clone(),
            partition_id,
            sequence,
            event_id: pending.event_id.clone(),
            attempts: pending.attempt,
            first_delivered_at_ms: pending.created_at_ms,
            last_delivered_at_ms: pending.delivered_at_ms,
            reason: GroupDlqReason::MaxAttemptsExceeded,
            created_at_ms: now_ms,
            generation: pending.generation,
        };
        self.dlq
            .entry(partition_id)
            .or_default()
            .insert(sequence, entry.clone());
        self.remove_pending(partition_id, sequence);
        let (new_offset, advanced) = self.advance_contiguous_offset(partition_id, sequence);
        Ok(GroupDlqResult {
            partition_id,
            sequence,
            new_offset,
            advanced,
            entry,
        })
    }

    /// Explicit retry: schedule redelivery, or move to DLQ when attempts exhausted.
    pub fn retry_group_delivery(
        &mut self,
        member_id: &MemberId,
        generation: u64,
        delivery_id: &DeliveryId,
        now_ms: u64,
    ) -> Result<GroupRetryResponse> {
        let (partition_id, sequence, pending) = self.locate_pending_by_delivery_id(delivery_id)?;
        self.verify_active_delivery(
            member_id,
            generation,
            delivery_id,
            &pending,
            partition_id,
        )?;

        let max_attempts = self.policy.retry.max_attempts.max(1);
        if pending.attempt >= max_attempts {
            return Ok(GroupRetryResponse::Dlq(self.move_pending_to_dlq(
                member_id,
                generation,
                delivery_id,
                now_ms,
            )?));
        }

        let retry_at_ms = self.policy.retry.retry_at_ms(now_ms, pending.attempt);
        let bucket = self.pending.entry(partition_id).or_default();
        let pending = bucket
            .get_mut(&sequence)
            .ok_or_else(|| Error::StaleDelivery(delivery_id.to_string()))?;
        pending.updated_at_ms = now_ms.max(pending.delivered_at_ms.saturating_add(1));
        pending.retry_at_ms = retry_at_ms;

        Ok(GroupRetryResponse::Retry(GroupRetryResult {
            partition_id,
            sequence,
            attempt: pending.attempt,
            retry_at_ms,
        }))
    }


    /// Upgrade 5.8.2 metadata where lease was `u64::MAX` placeholder.
    pub fn normalize_legacy_leases(&mut self) {
        let lease_ms = self.policy.effective_member_lease_ms();
        for member in self.members.values_mut() {
            if member.lease_expires_at_ms == u64::MAX && member.state == MemberState::Active {
                let base = if member.last_heartbeat_at_ms != 0 {
                    member.last_heartbeat_at_ms
                } else {
                    member.joined_at
                };
                member.lease_expires_at_ms = base.saturating_add(lease_ms);
            }
        }
        // Legacy groups without offsets / partition_count.
        if self.partition_count == 0 {
            self.partition_count = 1;
        }
        if self.offsets.is_empty() {
            self.offsets = bootstrap_offsets(
                self.partition_count,
                self.policy.start_position,
                0,
                0,
            );
        }
        if self.assignments.is_empty() && !self.members.is_empty() {
            self.recompute_assignment();
        }
    }

    fn remove_expired_members(&mut self, now_ms: u64) -> Vec<MemberId> {
        let expired: Vec<_> = self
            .members
            .values()
            .filter(|m| m.is_lease_expired(now_ms))
            .map(|m| m.member_id.clone())
            .collect();
        if expired.is_empty() {
            return expired;
        }
        for id in &expired {
            self.members.remove(id);
        }
        self.bump_generation_and_rebalance();
        expired
    }
}

impl GroupMetadata {
    pub fn get(&self, id: &GroupId) -> Result<&ConsumerGroup> {
        self.groups
            .get(id)
            .ok_or_else(|| Error::UnknownGroup(id.to_string()))
    }

    pub fn get_mut(&mut self, id: &GroupId) -> Result<&mut ConsumerGroup> {
        self.groups
            .get_mut(id)
            .ok_or_else(|| Error::UnknownGroup(id.to_string()))
    }

    pub fn create_group(
        &mut self,
        group_id: GroupId,
        stream_id: StreamId,
        now_ms: u64,
        partition_count: u32,
        journal_head: u64,
        oldest_available: u64,
        policy: GroupPolicy,
    ) -> Result<&ConsumerGroup> {
        if group_id.as_str().trim().is_empty() {
            return Err(Error::Invalid("group_id must not be empty".into()));
        }
        if self.groups.contains_key(&group_id) {
            return Err(Error::GroupExists(group_id.to_string()));
        }
        policy.validate()?;
        let partition_count = partition_count.max(1);
        let offsets = bootstrap_offsets(
            partition_count,
            policy.start_position,
            journal_head,
            oldest_available,
        );
        let group = ConsumerGroup {
            group_id: group_id.clone(),
            instance_id: Uuid::new_v4().to_string(),
            stream_id,
            generation: 1,
            state: GroupState::Empty,
            members: HashMap::new(),
            policy,
            partition_count,
            assignments: BTreeMap::new(),
            pending: BTreeMap::new(),
            offsets,
            last_acked_delivery_id: BTreeMap::new(),
            delivered_high: BTreeMap::new(),
            dlq: BTreeMap::new(),
            created_at: now_ms,
        };
        self.groups.insert(group_id.clone(), group);
        Ok(self.groups.get(&group_id).unwrap())
    }

    pub fn join_group(
        &mut self,
        group_id: &GroupId,
        member_id: MemberId,
        session_id: SessionId,
        device_id: Option<String>,
        now_ms: u64,
    ) -> Result<GroupMember> {
        if member_id.as_str().trim().is_empty() {
            return Err(Error::Invalid("member_id must not be empty".into()));
        }
        let group = self.get_mut(group_id)?;
        if group.members.contains_key(&member_id) {
            return Err(Error::MemberExists(member_id.to_string()));
        }
        let lease_ms = group.policy.effective_member_lease_ms();
        let generation_joined = group.generation.saturating_add(1);
        let member = GroupMember {
            member_id: member_id.clone(),
            group_id: group_id.clone(),
            session_id,
            generation_joined,
            joined_at: now_ms,
            last_heartbeat_at_ms: now_ms,
            lease_expires_at_ms: now_ms.saturating_add(lease_ms),
            device_id,
            state: MemberState::Active,
        };
        group.members.insert(member_id, member.clone());
        group.generation = generation_joined;
        group.recompute_assignment();
        Ok(member)
    }

    pub fn leave_group(&mut self, group_id: &GroupId, member_id: &MemberId) -> Result<()> {
        let group = self.get_mut(group_id)?;
        if !group.members.contains_key(member_id) {
            return Err(Error::UnknownMember(member_id.to_string()));
        }
        group.members.remove(member_id);
        group.bump_generation_and_rebalance();
        Ok(())
    }

    pub fn heartbeat_member(
        &mut self,
        group_id: &GroupId,
        member_id: &MemberId,
        now_ms: u64,
    ) -> Result<GroupMember> {
        let group = self.get_mut(group_id)?;
        let lease_ms = group.policy.effective_member_lease_ms();
        let member = group
            .members
            .get_mut(member_id)
            .ok_or_else(|| Error::UnknownMember(member_id.to_string()))?;
        if member.state != MemberState::Active {
            return Err(Error::MemberNotActive(member_id.to_string()));
        }
        member.refresh_lease(now_ms, lease_ms);
        Ok(member.clone())
    }

    /// Remove all members whose lease has expired (`lease_expires_at_ms <= now_ms`).
    /// One reconciliation pass bumps generation at most once per group and recomputes assignment.

    pub fn mark_all_pending_for_redelivery(&mut self) {
        for group in self.groups.values_mut() {
            group.mark_orphaned_pending_for_crash_recovery();
        }
    }

    pub fn reconcile_group_leases(&mut self, now_ms: u64) -> LeaseReconcileResult {
        let mut expired_members = Vec::new();
        for (group_id, group) in self.groups.iter_mut() {
            group.normalize_legacy_leases();
            let removed = group.remove_expired_members(now_ms);
            for member_id in removed {
                expired_members.push((group_id.clone(), member_id));
            }
        }
        LeaseReconcileResult { expired_members }
    }

    pub fn delete_group(&mut self, group_id: &GroupId) -> Result<()> {
        let group = self.get(group_id)?;
        if !group.members.is_empty() {
            return Err(Error::GroupNotEmpty(group_id.to_string()));
        }
        self.groups.remove(group_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assign_round_robin_is_deterministic() {
        let parts = [3u32, 1, 0, 2];
        let members = [
            MemberId::from("B"),
            MemberId::from("A"),
            MemberId::from("C"),
        ];
        let a = assign_partitions(&parts, &members);
        let b = assign_partitions(&[0, 1, 2, 3], &[
            MemberId::from("A"),
            MemberId::from("B"),
            MemberId::from("C"),
        ]);
        assert_eq!(a, b);
        assert_eq!(a.get(&0).unwrap().as_str(), "A");
        assert_eq!(a.get(&1).unwrap().as_str(), "B");
        assert_eq!(a.get(&2).unwrap().as_str(), "C");
        assert_eq!(a.get(&3).unwrap().as_str(), "A");
    }

    #[test]
    fn assign_more_members_than_partitions() {
        let a = assign_partitions(&[0, 1], &[
            MemberId::from("A"),
            MemberId::from("B"),
            MemberId::from("C"),
        ]);
        assert_eq!(a.len(), 2);
        assert_eq!(a.get(&0).unwrap().as_str(), "A");
        assert_eq!(a.get(&1).unwrap().as_str(), "B");
    }


    #[test]
    fn expire_preserves_pending_and_offsets() {
        let mut meta = GroupMetadata::default();
        let gid = GroupId::from("g");
        meta.create_group(
            gid.clone(),
            StreamId::from("s"),
            0,
            1,
            100,
            1,
            GroupPolicy::default(),
        )
        .unwrap();
        let mid = MemberId::from("A");
        meta.join_group(&gid, mid.clone(), SessionId::from("sess"), None, 0)
            .unwrap();
        let group = meta.get_mut(&gid).unwrap();
        group.offsets.insert(0, 100);
        group
            .begin_group_delivery(&mid, 0, 101, "e101".into(), 0)
            .unwrap();
        assert_eq!(group.pending_count_for_partition(0), 1);
        // Force lease expiry
        group.members.get_mut(&mid).unwrap().lease_expires_at_ms = 0;
        let removed = group.remove_expired_members(1);
        assert_eq!(removed.len(), 1);
        assert_eq!(group.pending_count_for_partition(0), 1);
        assert_eq!(group.offset_for_partition(0), 100);
        assert!(group.pending_for_partition(0).unwrap().get(&101).unwrap().await_redelivery);
    }

    #[test]
    fn group_retry_policy_default_backoff_table() {
        let policy = GroupRetryPolicy::default();
        assert_eq!(policy.max_attempts, 5);
        assert_eq!(policy.backoff_after_attempt(1), 0);
        assert_eq!(policy.backoff_after_attempt(2), 1_000);
        assert_eq!(policy.backoff_after_attempt(5), 60_000);
        assert_eq!(policy.backoff_after_attempt(99), 60_000);
        assert_eq!(policy.retry_at_ms(10_000, 2), 11_000);
    }

    #[test]
    fn group_retry_schedules_backoff_without_bumping_attempt() {
        let mut meta = GroupMetadata::default();
        let gid = GroupId::from("retry-g");
        meta.create_group(
            gid.clone(),
            StreamId::from("s"),
            0,
            1,
            100,
            1,
            GroupPolicy {
                retry: GroupRetryPolicy {
                    max_attempts: 5,
                    backoff_ms: vec![0, 5_000],
                },
                ..Default::default()
            },
        )
        .unwrap();
        let mid = MemberId::from("A");
        meta.join_group(&gid, mid.clone(), SessionId::from("sess"), None, 0)
            .unwrap();
        let group = meta.get_mut(&gid).unwrap();
        let delivery = group
            .begin_group_delivery(&mid, 0, 101, "e101".into(), 1_000)
            .unwrap();
        assert_eq!(delivery.attempt, 1);
        let generation = group.generation;
        let result = group
            .retry_group_delivery(&mid, generation, &delivery.delivery_id, 2_000)
            .unwrap();
        let GroupRetryResponse::Retry(result) = result else {
            panic!("expected retry schedule");
        };
        assert_eq!(result.attempt, 1);
        assert_eq!(result.retry_at_ms, 2_000);
        assert_eq!(group.offset_for_partition(0), 100);
        let pending = group.pending_for_partition(0).unwrap().get(&101).unwrap();
        assert_eq!(pending.attempt, 1);
        assert_eq!(pending.retry_at_ms, 2_000);
    }

    #[test]
    fn group_retry_exhausted_at_max_attempts() {
        let mut meta = GroupMetadata::default();
        let gid = GroupId::from("exhaust");
        meta.create_group(
            gid.clone(),
            StreamId::from("s"),
            0,
            1,
            100,
            1,
            GroupPolicy {
                retry: GroupRetryPolicy {
                    max_attempts: 2,
                    backoff_ms: vec![0],
                },
                ..Default::default()
            },
        )
        .unwrap();
        let mid = MemberId::from("A");
        meta.join_group(&gid, mid.clone(), SessionId::from("sess"), None, 0)
            .unwrap();
        let group = meta.get_mut(&gid).unwrap();
        let d1 = group
            .begin_group_delivery(&mid, 0, 101, "e101".into(), 0)
            .unwrap();
        let generation = group.generation;
        group
            .retry_group_delivery(&mid, generation, &d1.delivery_id, 0)
            .unwrap();
        let d2 = group
            .begin_group_delivery(&mid, 0, 101, "e101".into(), 1)
            .unwrap();
        assert_eq!(d2.attempt, 2);
        match group
            .retry_group_delivery(&mid, generation, &d2.delivery_id, 2)
            .unwrap()
        {
            GroupRetryResponse::Dlq(r) => {
                assert_eq!(r.sequence, 101);
                assert_eq!(group.offset_for_partition(0), 101);
                assert_eq!(r.entry.attempts, 2);
            }
            other => panic!("expected DLQ, got {other:?}"),
        }
        let err = group
            .retry_group_delivery(&mid, generation, &d2.delivery_id, 3)
            .unwrap_err();
        assert!(matches!(err, Error::StaleDelivery(_)), "got {err}");
    }

    #[test]
    fn dlq_advances_contiguous_offset_with_gaps() {
        let mut meta = GroupMetadata::default();
        let gid = GroupId::from("dlq-gap");
        meta.create_group(
            gid.clone(),
            StreamId::from("s"),
            0,
            1,
            100,
            1,
            GroupPolicy {
                max_in_flight: 4,
                retry: GroupRetryPolicy {
                    max_attempts: 1,
                    backoff_ms: vec![0],
                },
                ..Default::default()
            },
        )
        .unwrap();
        let mid = MemberId::from("A");
        meta.join_group(&gid, mid.clone(), SessionId::from("sess"), None, 0)
            .unwrap();
        let group = meta.get_mut(&gid).unwrap();
        group.offsets.insert(0, 100);
        for seq in 101..=104u64 {
            group
                .begin_group_delivery(&mid, 0, seq, format!("e{seq}"), 0)
                .unwrap();
        }
        let generation = group.generation;
        let ids: Vec<_> = (101..=104u64)
            .map(|seq| {
                group
                    .pending_for_partition(0)
                    .unwrap()
                    .get(&seq)
                    .unwrap()
                    .last_delivery_id
                    .clone()
            })
            .collect();
        group.ack_group_delivery(&mid, generation, &ids[0]).unwrap();
        group
            .move_pending_to_dlq(&mid, generation, &ids[1], 1)
            .unwrap();
        group
            .move_pending_to_dlq(&mid, generation, &ids[2], 2)
            .unwrap();
        assert_eq!(group.offset_for_partition(0), 103);
        assert!(group.pending_for_partition(0).unwrap().contains_key(&104));
    }

        #[test]
    fn assign_zero_members_empty() {
        assert!(assign_partitions(&[0, 1, 2], &[]).is_empty());
    }

    #[test]
    fn contiguous_ack_respects_gaps() {
        let mut meta = GroupMetadata::default();
        let gid = GroupId::from("g");
        meta.create_group(
            gid.clone(),
            StreamId::from("s"),
            0,
            1,
            100,
            1,
            GroupPolicy {
                max_in_flight: 8,
                ..Default::default()
            },
        )
        .unwrap();
        let mid = MemberId::from("A");
        meta.join_group(&gid, mid.clone(), SessionId::from("sess"), None, 0)
            .unwrap();
        let group = meta.get_mut(&gid).unwrap();
        group.offsets.insert(0, 100);
        for seq in 101..=104u64 {
            group
                .begin_group_delivery(&mid, 0, seq, format!("e{seq}"), 0)
                .unwrap();
        }
        let generation = group.generation;
        let ids: Vec<_> = (101..=104u64)
            .map(|seq| {
                group
                    .pending_for_partition(0)
                    .unwrap()
                    .get(&seq)
                    .unwrap()
                    .last_delivery_id
                    .clone()
            })
            .collect();
        let r = group.ack_group_delivery(&mid, generation, &ids[0]).unwrap();
        assert_eq!(r.new_offset, 101);
        assert!(r.advanced);
        let r = group.ack_group_delivery(&mid, generation, &ids[2]).unwrap();
        assert_eq!(r.new_offset, 101);
        assert!(!r.advanced);
        let r = group.ack_group_delivery(&mid, generation, &ids[3]).unwrap();
        assert_eq!(r.new_offset, 101);
        let r = group.ack_group_delivery(&mid, generation, &ids[1]).unwrap();
        assert_eq!(r.new_offset, 104);
        assert!(r.advanced);
        assert_eq!(group.pending_count_for_partition(0), 0);
    }
}
