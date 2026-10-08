//! Phase 7.9.5 — Security / accountability audit trail (separate from logs & metrics).
//!
//! Audit is observational only: sink failure MUST NOT alter SQL / Auth / vault / journal outcomes.
//! Audit is **not** part of Journal atomicity.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::context::ObservabilityContext;
use crate::sanitize::{sanitize_value, truncate_id_pub};

/// Closed V1 audit catalog (ADR-025 §7 / 7.9.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuditEventKind {
    AuthenticationSucceeded,
    AuthenticationFailed,
    SessionCreated,
    SessionInvalidated,
    AuthorizationDenied,
    VaultUnlocked,
    VaultUnlockFailed,
    VaultLocked,
    SqlExecuted,
    TransactionCommitted,
    TransactionRolledBack,
    TransactionConflict,
    BackupCreated,
    BackupVerified,
    BackupRestoreStarted,
    BackupRestored,
    RecoveryStarted,
    RecoveryCompleted,
    RecoveryFailed,
    /// A privilege was granted (who: principal, to whom: target, what: privilege).
    PrivilegeGranted,
    PrivilegeRevoked,
    /// D4-A: a plaintext SQL store was migrated to encrypted storage (explicit request).
    StorageMigrated,
    /// D4-A: an explicit storage migration was refused or failed (nothing switched).
    StorageMigrationFailed,
}

impl AuditEventKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::AuthenticationSucceeded => "audit.authentication.succeeded",
            Self::AuthenticationFailed => "audit.authentication.failed",
            Self::SessionCreated => "audit.session.created",
            Self::SessionInvalidated => "audit.session.invalidated",
            Self::AuthorizationDenied => "audit.authorization.denied",
            Self::VaultUnlocked => "audit.vault.unlocked",
            Self::VaultUnlockFailed => "audit.vault.unlock_failed",
            Self::VaultLocked => "audit.vault.locked",
            Self::SqlExecuted => "audit.sql.executed",
            Self::TransactionCommitted => "audit.transaction.committed",
            Self::TransactionRolledBack => "audit.transaction.rolled_back",
            Self::TransactionConflict => "audit.transaction.conflict",
            Self::BackupCreated => "audit.backup.created",
            Self::BackupVerified => "audit.backup.verified",
            Self::BackupRestoreStarted => "audit.backup.restore_started",
            Self::BackupRestored => "audit.backup.restored",
            Self::RecoveryStarted => "audit.recovery.started",
            Self::RecoveryCompleted => "audit.recovery.completed",
            Self::RecoveryFailed => "audit.recovery.failed",
            Self::PrivilegeGranted => "audit.privilege.granted",
            Self::PrivilegeRevoked => "audit.privilege.revoked",
            Self::StorageMigrated => "audit.storage.migrated",
            Self::StorageMigrationFailed => "audit.storage.migration_failed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    Success,
    Failure,
    Denied,
}

/// Security/accountability event — opaque ids only; never secrets or full SQL.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp_ms: u64,
    pub kind: AuditEventKind,
    pub request_id: Option<String>,
    pub connection_id: Option<String>,
    pub session_id: Option<String>,
    pub principal_id: Option<String>,
    pub transaction_id: Option<String>,
    pub result: AuditResult,
    pub error_code: Option<String>,
    /// Low-cardinality SQL operation class (SELECT/INSERT/…), never statement text.
    pub operation: Option<String>,
    pub parameter_count: Option<u32>,
    /// Identity a privilege change applies to (opaque id).
    #[serde(default)]
    pub target_id: Option<String>,
    /// Privilege changed, e.g. `SELECT table:avrora.public.notes` (catalog identifiers only).
    #[serde(default)]
    pub privilege: Option<String>,
}

impl AuditEvent {
    pub fn new(kind: AuditEventKind, result: AuditResult) -> Self {
        Self {
            timestamp_ms: now_ms(),
            kind,
            request_id: None,
            connection_id: None,
            session_id: None,
            principal_id: None,
            transaction_id: None,
            result,
            error_code: None,
            operation: None,
            parameter_count: None,
            target_id: None,
            privilege: None,
        }
    }

    pub fn from_context(kind: AuditEventKind, result: AuditResult, ctx: &ObservabilityContext) -> Self {
        Self {
            timestamp_ms: now_ms(),
            kind,
            request_id: ctx.request_id.clone(),
            connection_id: ctx.connection_id.clone(),
            session_id: ctx.session_id.clone(),
            principal_id: None,
            transaction_id: ctx.transaction_id.clone(),
            result,
            error_code: None,
            operation: None,
            parameter_count: None,
            target_id: None,
            privilege: None,
        }
    }

    pub fn with_principal_id(mut self, id: impl Into<String>) -> Self {
        self.principal_id = Some(id.into());
        self
    }

    pub fn with_error_code(mut self, code: impl Into<String>) -> Self {
        self.error_code = Some(code.into());
        self
    }

    pub fn with_operation(mut self, op: impl Into<String>) -> Self {
        self.operation = Some(op.into());
        self
    }

    pub fn with_target_id(mut self, id: impl Into<String>) -> Self {
        self.target_id = Some(id.into());
        self
    }

    pub fn with_privilege(mut self, privilege: impl Into<String>) -> Self {
        self.privilege = Some(privilege.into());
        self
    }

    pub fn with_parameter_count(mut self, n: u32) -> Self {
        self.parameter_count = Some(n);
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

/// All V1 audit kind names — catalog tests.
pub fn v1_audit_kind_names() -> &'static [&'static str] {
    &[
        "audit.authentication.succeeded",
        "audit.authentication.failed",
        "audit.session.created",
        "audit.session.invalidated",
        "audit.authorization.denied",
        "audit.vault.unlocked",
        "audit.vault.unlock_failed",
        "audit.vault.locked",
        "audit.sql.executed",
        "audit.transaction.committed",
        "audit.transaction.rolled_back",
        "audit.transaction.conflict",
        "audit.backup.created",
        "audit.backup.verified",
        "audit.backup.restore_started",
        "audit.backup.restored",
        "audit.recovery.started",
        "audit.recovery.completed",
        "audit.recovery.failed",
    ]
}

#[derive(Clone, Debug)]
pub struct AuditError(pub String);

pub trait AuditSink: Send + Sync {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError>;

    fn available(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Default)]
pub struct NoopAuditSink;

impl AuditSink for NoopAuditSink {
    fn record(&self, _: &AuditEvent) -> Result<(), AuditError> {
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct FailingAuditSink;

impl AuditSink for FailingAuditSink {
    fn record(&self, _: &AuditEvent) -> Result<(), AuditError> {
        Err(AuditError("audit unavailable".into()))
    }

    fn available(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Default)]
pub struct TracingAuditSink;

impl AuditSink for TracingAuditSink {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        tracing::info!(
            audit = event.name(),
            result = ?event.result,
            request_id = event.request_id.as_deref().unwrap_or(""),
            connection_id = event.connection_id.as_deref().unwrap_or(""),
            session_id = event.session_id.as_deref().unwrap_or(""),
            principal_id = event.principal_id.as_deref().unwrap_or(""),
            transaction_id = event.transaction_id.as_deref().unwrap_or(""),
            error_code = event.error_code.as_deref().unwrap_or(""),
            operation = event.operation.as_deref().unwrap_or(""),
            parameter_count = event.parameter_count.unwrap_or(0),
            "audit"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemoryAuditSink {
    events: Arc<Mutex<Vec<AuditEvent>>>,
}

impl MemoryAuditSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> Vec<AuditEvent> {
        self.events.lock().map(|g| g.clone()).unwrap_or_default()
    }

    pub fn clear(&self) {
        if let Ok(mut g) = self.events.lock() {
            g.clear();
        }
    }

    pub fn kinds(&self) -> Vec<AuditEventKind> {
        self.snapshot().into_iter().map(|e| e.kind).collect()
    }

    pub fn count_kind(&self, kind: AuditEventKind) -> usize {
        self.snapshot().into_iter().filter(|e| e.kind == kind).count()
    }
}

impl AuditSink for MemoryAuditSink {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let mut g = self
            .events
            .lock()
            .map_err(|_| AuditError("lock".into()))?;
        g.push(event.clone());
        Ok(())
    }
}

/// Failure-isolated audit facade.
#[derive(Clone)]
pub struct Audit {
    sink: Arc<dyn AuditSink>,
}

impl Default for Audit {
    fn default() -> Self {
        Self::tracing()
    }
}

impl Audit {
    pub fn new(sink: Arc<dyn AuditSink>) -> Self {
        Self { sink }
    }

    pub fn tracing() -> Self {
        Self::new(Arc::new(TracingAuditSink))
    }

    pub fn noop() -> Self {
        Self::new(Arc::new(NoopAuditSink))
    }

    pub fn failing() -> Self {
        Self::new(Arc::new(FailingAuditSink))
    }

    pub fn memory(sink: MemoryAuditSink) -> Self {
        Self::new(Arc::new(sink))
    }

    /// Record an audit event. **Never** returns an error to the caller.
    pub fn record(&self, event: AuditEvent) {
        let event = sanitize_audit_event(event);
        let _ = self.sink.record(&event);
    }

    /// Probe sink availability for diagnostics (failure ≠ Core NotReady).
    pub fn probe(&self) -> crate::diagnostics::ObservabilityComponentStatus {
        use crate::diagnostics::ObservabilityComponentStatus;
        if self.sink.available() {
            ObservabilityComponentStatus::Available
        } else {
            ObservabilityComponentStatus::Degraded
        }
    }
}

/// Strip/redact anything that must not appear on the audit trail.
pub fn sanitize_audit_event(mut event: AuditEvent) -> AuditEvent {
    if let Some(v) = event.request_id.as_mut() {
        *v = truncate_id_pub(v);
    }
    if let Some(v) = event.connection_id.as_mut() {
        *v = truncate_id_pub(v);
    }
    if let Some(v) = event.session_id.as_mut() {
        *v = truncate_id_pub(v);
    }
    if let Some(v) = event.principal_id.as_mut() {
        *v = truncate_id_pub(v);
    }
    if let Some(v) = event.transaction_id.as_mut() {
        *v = truncate_id_pub(v);
    }
    if let Some(v) = event.error_code.as_mut() {
        *v = sanitize_value(v);
    }
    if let Some(v) = event.target_id.as_mut() {
        *v = truncate_id_pub(v);
    }
    if let Some(v) = event.privilege.as_mut() {
        // `<ACTION> <kind>:<identifier>[.<identifier>]*` — catalog identifiers only.
        let ok = v.len() <= 200
            && v.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | ' ' | '-'));
        if !ok {
            *v = "OTHER".into();
        }
    }
    if let Some(v) = event.operation.as_mut() {
        // Keep closed operation tokens only; scrub anything path-like.
        let upper = v.to_ascii_uppercase();
        *v = match upper.as_str() {
            "SELECT" | "INSERT" | "UPDATE" | "DELETE" | "CREATE" | "DROP" | "ALTER"
            | "BEGIN" | "COMMIT" | "ROLLBACK" | "EXPLAIN" | "OTHER" | "DDL" | "TRANSACTION" => {
                upper
            }
            _ => "OTHER".into(),
        };
    }
    event
}

/// Ensure audit JSON cannot carry secret markers or full-SQL fields.
pub fn assert_no_secrets_in_audit(event: &AuditEvent) -> Result<(), String> {
    let json = serde_json::to_string(event).map_err(|e| e.to_string())?;
    let lower = json.to_lowercase();
    for needle in [
        "master_key",
        "unlockmaterial",
        "unlock_material",
        "\"dek\"",
        "\"kek\"",
        "keypass",
        "private_key",
        "-----begin",
        "password",
    ] {
        if lower.contains(needle) {
            return Err(format!("secret marker `{needle}` in audit JSON"));
        }
    }
    if lower.contains("\"sql\":")
        || lower.contains("\"statement\":")
        || lower.contains("\"query\":")
    {
        return Err("full SQL field present in audit".into());
    }
    Ok(())
}
