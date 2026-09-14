//! Structured event catalog (ADR-025 / 7.9.2).

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::context::ObservabilityContext;

pub const FIELD_OPERATION: &str = "operation";
pub const FIELD_STATEMENT_KIND: &str = "statement_kind";
pub const FIELD_PARAMETER_COUNT: &str = "parameter_count";
pub const FIELD_ERROR_CODE: &str = "error_code";
pub const FIELD_REASON: &str = "reason";
pub const FIELD_BACKUP_ID: &str = "backup_id";
pub const FIELD_CHECKPOINT_SEQUENCE: &str = "checkpoint_sequence";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    Sql,
    Auth,
    Vault,
    Backup,
    Recovery,
    Transport,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventOutcome {
    Success,
    Failure,
    Denied,
}

/// Closed event catalog — no free-form event strings in application code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    SqlRequest,
    SqlCompleted,
    SqlFailed,
    AuthLoginSuccess,
    AuthLoginFailure,
    AuthLogout,
    AuthzDenied,
    SessionRevoked,
    VaultUnlock,
    VaultUnlockFailed,
    VaultLock,
    BackupCreated,
    BackupFailed,
    BackupVerified,
    BackupRestored,
    RecoveryStarted,
    RecoveryCompleted,
    RecoveryFailed,
}

impl EventKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::SqlRequest => "sql.request",
            Self::SqlCompleted => "sql.completed",
            Self::SqlFailed => "sql.failed",
            Self::AuthLoginSuccess => "auth.login.success",
            Self::AuthLoginFailure => "auth.login.failure",
            Self::AuthLogout => "auth.logout",
            Self::AuthzDenied => "authz.denied",
            Self::SessionRevoked => "session.revoked",
            Self::VaultUnlock => "vault.unlock.success",
            Self::VaultUnlockFailed => "vault.unlock.failure",
            Self::VaultLock => "vault.lock",
            Self::BackupCreated => "backup.created",
            Self::BackupFailed => "backup.failed",
            Self::BackupVerified => "backup.verified",
            Self::BackupRestored => "backup.restored",
            Self::RecoveryStarted => "recovery.started",
            Self::RecoveryCompleted => "recovery.completed",
            Self::RecoveryFailed => "recovery.failed",
        }
    }

    pub fn category(self) -> EventCategory {
        match self {
            Self::SqlRequest | Self::SqlCompleted | Self::SqlFailed => EventCategory::Sql,
            Self::AuthLoginSuccess
            | Self::AuthLoginFailure
            | Self::AuthLogout
            | Self::AuthzDenied
            | Self::SessionRevoked => EventCategory::Auth,
            Self::VaultUnlock | Self::VaultUnlockFailed | Self::VaultLock => EventCategory::Vault,
            Self::BackupCreated
            | Self::BackupFailed
            | Self::BackupVerified
            | Self::BackupRestored => EventCategory::Backup,
            Self::RecoveryStarted | Self::RecoveryCompleted | Self::RecoveryFailed => {
                EventCategory::Recovery
            }
        }
    }

    pub fn default_outcome(self) -> EventOutcome {
        match self {
            Self::SqlFailed
            | Self::AuthLoginFailure
            | Self::VaultUnlockFailed
            | Self::BackupFailed
            | Self::RecoveryFailed => EventOutcome::Failure,
            Self::AuthzDenied => EventOutcome::Denied,
            _ => EventOutcome::Success,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservabilityEvent {
    pub kind: EventKind,
    pub category: EventCategory,
    pub outcome: EventOutcome,
    pub timestamp_ms: u64,
    pub context: ObservabilityContext,
    /// Additional structured fields (already intended to be secret-free).
    pub fields: BTreeMap<String, String>,
}

impl ObservabilityEvent {
    pub fn new(kind: EventKind, context: ObservabilityContext) -> Self {
        Self {
            kind,
            category: kind.category(),
            outcome: kind.default_outcome(),
            timestamp_ms: now_ms(),
            context,
            fields: BTreeMap::new(),
        }
    }

    pub fn with_outcome(mut self, outcome: EventOutcome) -> Self {
        self.outcome = outcome;
        self
    }

    pub fn field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }

    pub fn name(&self) -> &'static str {
        self.kind.name()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
