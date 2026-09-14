//! Phase 7.9 — Observability facade (logs + metrics + audit; observational only).

mod audit;
mod context;
mod diagnostics;
mod event;
mod health;
mod logger;
mod metrics;
mod sanitize;

pub use audit::{
    assert_no_secrets_in_audit, sanitize_audit_event, v1_audit_kind_names, Audit, AuditError,
    AuditEvent, AuditEventKind, AuditResult, AuditSink, FailingAuditSink, MemoryAuditSink,
    NoopAuditSink, TracingAuditSink,
};
pub use context::ObservabilityContext;
pub use diagnostics::{
    assert_no_secrets_in_diagnostics, ComponentReady, ConnectionDiagnostics, DiagnosticsSnapshot,
    JournalDiagnostics, MaterializerDiagnostics, ObservabilityComponentStatus,
    ObservabilityDiagnostics, RecoveryDiagnostics, RuntimeDiagnostics, StorageDiagnostics,
};
pub use event::{
    EventCategory, EventKind, EventOutcome, ObservabilityEvent, FIELD_BACKUP_ID,
    FIELD_CHECKPOINT_SEQUENCE, FIELD_ERROR_CODE, FIELD_OPERATION, FIELD_PARAMETER_COUNT,
    FIELD_REASON, FIELD_STATEMENT_KIND,
};
pub use health::{HealthStatus, Liveness, Readiness, ReadinessReasonCode, VaultHealth};
pub use logger::{
    log_event, set_global, FailingSink, MemorySink, NoopSink, Observability, TracingSink,
};
pub use metrics::{
    v1_metric_names, FailingMetricsSink, MemoryMetricsSink, Metric, MetricLabels, MetricOperation,
    MetricResult, MetricSample, MetricTransport, Metrics, MetricsError, MetricsSink,
    NoopMetricsSink, TracingMetricsSink,
};
pub use sanitize::{assert_no_secrets_in_event, sanitize_event, sanitize_value};

/// Classify leading SQL keyword without parsing the full statement (no SQL text retained).
pub fn statement_kind(sql: &str) -> &'static str {
    let trimmed = sql.trim_start();
    let word = trimmed
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_end_matches(';')
        .to_ascii_uppercase();
    match word.as_str() {
        "SELECT" => "SELECT",
        "INSERT" => "INSERT",
        "UPDATE" => "UPDATE",
        "DELETE" => "DELETE",
        "CREATE" => "CREATE",
        "DROP" => "DROP",
        "ALTER" => "ALTER",
        "BEGIN" => "BEGIN",
        "COMMIT" => "COMMIT",
        "ROLLBACK" => "ROLLBACK",
        "EXPLAIN" => "EXPLAIN",
        _ => "OTHER",
    }
}
