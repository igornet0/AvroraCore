//! Security audit events. Auth operations need not be journal mutations.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::capabilities::CapabilityId;
use crate::identity::{now_unix_ms, DeviceId, SessionId, UserId};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuditId(pub String);

impl AuditId {
    pub fn new() -> Self {
        Self(format!("aud_{}", Uuid::new_v4().simple()))
    }
}

impl Default for AuditId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    Allow,
    Deny,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditReason {
    UserDisabled,
    SessionExpired,
    UnknownSession,
    CapabilityRevoked,
    CapabilityExpired,
    CapabilityStale,
    PermissionDenied,
    PathOutOfScope,
    DelegationDenied,
    Other(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOperation {
    Login,
    LoginFailed,
    SessionOpen,
    SessionRevoked,
    CapabilityGranted,
    CapabilityRevoked,
    CapabilityRotated,
    UserCreated,
    UserDisabled,
    RoleAssigned,
    Authorize,
    Put,
    Update,
    Delete,
    Other(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub audit_id: AuditId,
    pub timestamp: u64,
    pub user_id: Option<UserId>,
    pub device_id: Option<DeviceId>,
    pub session_id: Option<SessionId>,
    pub capability_id: Option<CapabilityId>,
    pub event_id: Option<String>,
    pub sequence: Option<u64>,
    pub operation: AuditOperation,
    pub path: Option<String>,
    pub result: AuditResult,
    pub reason: Option<AuditReason>,
}

#[derive(Clone, Debug, Default)]
pub struct AuditTrail {
    events: Vec<AuditEvent>,
}

impl AuditTrail {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, mut event: AuditEvent) -> AuditEvent {
        if event.audit_id.0.is_empty() {
            event.audit_id = AuditId::new();
        }
        if event.timestamp == 0 {
            event.timestamp = now_unix_ms();
        }
        self.events.push(event.clone());
        event
    }

    pub fn emit(
        &mut self,
        operation: AuditOperation,
        result: AuditResult,
        user_id: Option<UserId>,
        device_id: Option<DeviceId>,
        session_id: Option<SessionId>,
        capability_id: Option<CapabilityId>,
        path: Option<String>,
        reason: Option<AuditReason>,
    ) -> AuditEvent {
        self.record(AuditEvent {
            audit_id: AuditId::new(),
            timestamp: now_unix_ms(),
            user_id,
            device_id,
            session_id,
            capability_id,
            event_id: None,
            sequence: None,
            operation,
            path,
            result,
            reason,
        })
    }

    pub fn list(&self) -> &[AuditEvent] {
        &self.events
    }
}

/// Legacy Phase 1/2.1 event names. Prefer [`AuditEvent`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecurityEvent {
    UserCreated,
    UserDeleted,
    RoleChanged,
    PermissionChanged,
    CapabilityRevoked,
    SessionRevoked,
    KeyRotated,
}
