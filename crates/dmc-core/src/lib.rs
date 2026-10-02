//! Avrora runtime: streams, channels, roles, triggers, overlay, subsystems, audit.
//! Encrypted base bytes and the key tree live in `dmc-vault`.
//! Identity, sessions, and AuthZ live in `dmc-security` (in-process in Phase 1).

pub mod audit;
pub mod backup;
pub mod channel;
pub mod clock;
pub mod compaction_meta;
pub mod consumer_meta;
pub mod control;
pub mod dispatch;
pub mod dlq;
pub mod error;
pub mod event;
pub mod group;
pub mod group_crash_injection;
pub mod group_meta;
pub mod ids;
pub mod journal_pins;
pub mod keypass;
pub mod materializer;
pub mod menu;
pub mod overlay;
pub mod producer_meta;
pub mod retention_meta;
pub mod runtime;
pub mod server;
pub mod stream;
pub mod subscription;
pub mod subsystem;
pub mod trigger;

pub use audit::{AuditLog, AuditRecord};
pub use channel::{ChannelInfo, ChannelKind, ChannelRegistry, ChannelSpec};
pub use dlq::{DlqEntry, DLQ_PREFIX};
pub use dmc_security::{
    AccessControl, CapabilityId, CapabilityStatus, IssuedCapability, RotationReport, Session, User,
    UserId,
};
pub use error::{Error, Result};
pub use event::{CoreEvent, EventKind, EventLog};
pub use clock::{
    runtime_now_ms, system_now_ms, DEFAULT_MEMBER_LEASE_MS, MAX_MEMBER_LEASE_MS,
    MIN_MEMBER_LEASE_MS,
};
pub use group_crash_injection::{
    is_simulated_group_crash, set_test_group_crash_point, GroupCrashPoint,
};
pub use group::{
    assign_partitions, bootstrap_offsets, ConsumerGroup, GroupAckResult, GroupDeliveredEvent, GroupDelivery,
    GroupDescription, GroupDlqEntry, GroupDlqReason, GroupDlqResult, GroupMember, GroupMetadata,
    GroupPartitionOffset, GroupPendingDelivery, GroupPolicy, GroupRetryPolicy, GroupRetryResponse,
    GroupRetryResult, GroupStartPosition, GroupState, LeaseReconcileResult, MemberDescription,
    MemberState, PartitionOwner,
};
pub use ids::{
    ChannelId, ConsumerId, DlqEntryId, GroupId, MemberId, SessionId, StreamId, SubsystemId,
    SubscriptionId, TriggerId,
};
pub use keypass::{KeyPassStatus, VolumeInfo};
pub use materializer::ConsumerOffset;
pub use overlay::{OverlayPatch, OverlayStore, ResolvedView};
pub use dmc_journal::{
    calculate_watermark, CompactionArtifact, CompactionCandidate, CompactionPolicy, JournalManifest,
    JournalPin, RetentionWatermark, SequencePin,
};
pub use journal_pins::{ConsumerPin, PinReason, ReplayPin, RetentionPolicyPin, SnapshotPin};
pub use retention_meta::RetentionPolicy;
pub use dmc_runtime::{RuntimeHub, RuntimeSchemaSnapshot};
pub use runtime::{
    ConsumerLag, ConsumerMetrics, DbStatus, PendingSummary, PutOptions, PutResult, Runtime,
    SchemaSnapshot,
};
pub use stream::{StreamDirection, StreamManager, StreamMessage, StreamSpec};
pub use subscription::{
    AckBatchResult, BatchLimits, ConsumerMetadata, ConsumerPolicy, ConsumerProgress, DeliveredEvent,
    Delivery, DeliveryId, JournalPosition, PendingDelivery, RetryPolicy, Subscription,
    SubscriptionStatus,
};
pub use subsystem::{SubsystemInfo, SubsystemSpec};
pub use trigger::{TriggerAction, TriggerDef, TriggerEngine};
