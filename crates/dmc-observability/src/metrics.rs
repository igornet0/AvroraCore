//! Phase 7.9.4 — Closed V1 metric catalog + failure-isolated facade.
//!
//! Metrics are observational only. Sink failures never alter SQL / Auth / vault outcomes.
//! Correlation ids (`request_id`, `session_id`, …) MUST NOT appear as metric labels.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Closed V1 metric catalog (ADR-025 §5 / 7.9.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Metric {
    // Server / transport
    ConnectionsAcceptedTotal,
    ConnectionsActive,
    RequestsTotal,
    RequestsFailedTotal,
    RequestDurationMs,
    // Authentication / security
    AuthSuccessTotal,
    AuthFailureTotal,
    AuthorizationDeniedTotal,
    SessionInvalidTotal,
    // Vault
    VaultUnlockSuccessTotal,
    VaultUnlockFailureTotal,
    VaultLockTotal,
    VaultLockedRequestsTotal,
    // SQL
    SqlStatementsTotal,
    SqlErrorsTotal,
    SqlTransactionsCommittedTotal,
    SqlTransactionsRolledBackTotal,
    SqlWriteConflictsTotal,
    // Health / readiness (7.9.6)
    CoreLiveness,
    CoreReady,
}

impl Metric {
    /// Deterministic export name (no free-form strings from callers).
    pub fn name(self) -> &'static str {
        match self {
            Self::ConnectionsAcceptedTotal => "connections_accepted_total",
            Self::ConnectionsActive => "connections_active",
            Self::RequestsTotal => "requests_total",
            Self::RequestsFailedTotal => "requests_failed_total",
            Self::RequestDurationMs => "request_duration_ms",
            Self::AuthSuccessTotal => "auth_success_total",
            Self::AuthFailureTotal => "auth_failure_total",
            Self::AuthorizationDeniedTotal => "authorization_denied_total",
            Self::SessionInvalidTotal => "session_invalid_total",
            Self::VaultUnlockSuccessTotal => "vault_unlock_success_total",
            Self::VaultUnlockFailureTotal => "vault_unlock_failure_total",
            Self::VaultLockTotal => "vault_lock_total",
            Self::VaultLockedRequestsTotal => "vault_locked_requests_total",
            Self::SqlStatementsTotal => "sql_statements_total",
            Self::SqlErrorsTotal => "sql_errors_total",
            Self::SqlTransactionsCommittedTotal => "sql_transactions_committed_total",
            Self::SqlTransactionsRolledBackTotal => "sql_transactions_rolled_back_total",
            Self::SqlWriteConflictsTotal => "sql_write_conflicts_total",
            Self::CoreLiveness => "core_liveness",
            Self::CoreReady => "core_ready",
        }
    }

    pub fn is_gauge(self) -> bool {
        matches!(
            self,
            Self::ConnectionsActive | Self::CoreLiveness | Self::CoreReady
        )
    }

    pub fn is_histogram(self) -> bool {
        matches!(self, Self::RequestDurationMs)
    }
}

/// Allowed `operation` label values only (low cardinality).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MetricOperation {
    Select,
    Insert,
    Update,
    Delete,
    Ddl,
    Transaction,
}

impl MetricOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Select => "SELECT",
            Self::Insert => "INSERT",
            Self::Update => "UPDATE",
            Self::Delete => "DELETE",
            Self::Ddl => "DDL",
            Self::Transaction => "TRANSACTION",
        }
    }

    /// Map statement keyword class → closed operation enum (never retains SQL text).
    pub fn from_statement_kind(kind: &str) -> Self {
        match kind {
            "SELECT" => Self::Select,
            "INSERT" => Self::Insert,
            "UPDATE" => Self::Update,
            "DELETE" => Self::Delete,
            "BEGIN" | "COMMIT" | "ROLLBACK" => Self::Transaction,
            // CREATE / DROP / ALTER / EXPLAIN / OTHER → DDL bucket
            _ => Self::Ddl,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MetricResult {
    Success,
    Error,
}

impl MetricResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MetricTransport {
    Local,
    Remote,
}

impl MetricTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Remote => "remote",
        }
    }
}

/// Low-cardinality labels only. Never attach correlation / identity / SQL / paths.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MetricLabels {
    pub operation: Option<MetricOperation>,
    pub result: Option<MetricResult>,
    pub transport: Option<MetricTransport>,
}

impl MetricLabels {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_operation(mut self, op: MetricOperation) -> Self {
        self.operation = Some(op);
        self
    }

    pub fn with_result(mut self, result: MetricResult) -> Self {
        self.result = Some(result);
        self
    }

    pub fn with_transport(mut self, transport: MetricTransport) -> Self {
        self.transport = Some(transport);
        self
    }

    /// Deterministic label map for exporters / tests.
    pub fn as_map(&self) -> BTreeMap<&'static str, &'static str> {
        let mut m = BTreeMap::new();
        if let Some(op) = self.operation {
            m.insert("operation", op.as_str());
        }
        if let Some(r) = self.result {
            m.insert("result", r.as_str());
        }
        if let Some(t) = self.transport {
            m.insert("transport", t.as_str());
        }
        m
    }

    /// Reject known high-cardinality / forbidden label keys (defense in depth for tests).
    pub fn is_forbidden_label_key(key: &str) -> bool {
        matches!(
            key,
            "request_id"
                | "session_id"
                | "transaction_id"
                | "connection_id"
                | "user_id"
                | "identity_id"
                | "table_name"
                | "sql"
                | "sql_text"
                | "error_message"
                | "message"
                | "path"
                | "backup_id"
        )
    }
}

/// Sink error — never propagated to SQL/Auth callers.
#[derive(Clone, Debug)]
pub struct MetricsError(pub String);

pub trait MetricsSink: Send + Sync {
    fn increment(
        &self,
        metric: Metric,
        value: u64,
        labels: &MetricLabels,
    ) -> Result<(), MetricsError>;

    fn observe(
        &self,
        metric: Metric,
        value: f64,
        labels: &MetricLabels,
    ) -> Result<(), MetricsError>;

    fn set_gauge(
        &self,
        metric: Metric,
        value: i64,
        labels: &MetricLabels,
    ) -> Result<(), MetricsError>;

    fn available(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Default)]
pub struct NoopMetricsSink;

impl MetricsSink for NoopMetricsSink {
    fn increment(&self, _: Metric, _: u64, _: &MetricLabels) -> Result<(), MetricsError> {
        Ok(())
    }
    fn observe(&self, _: Metric, _: f64, _: &MetricLabels) -> Result<(), MetricsError> {
        Ok(())
    }
    fn set_gauge(&self, _: Metric, _: i64, _: &MetricLabels) -> Result<(), MetricsError> {
        Ok(())
    }
}

/// Always fails — failure-isolation tests.
#[derive(Clone, Debug, Default)]
pub struct FailingMetricsSink;

impl MetricsSink for FailingMetricsSink {
    fn increment(&self, _: Metric, _: u64, _: &MetricLabels) -> Result<(), MetricsError> {
        Err(MetricsError("metrics unavailable".into()))
    }
    fn observe(&self, _: Metric, _: f64, _: &MetricLabels) -> Result<(), MetricsError> {
        Err(MetricsError("metrics unavailable".into()))
    }
    fn set_gauge(&self, _: Metric, _: i64, _: &MetricLabels) -> Result<(), MetricsError> {
        Err(MetricsError("metrics unavailable".into()))
    }
    fn available(&self) -> bool {
        false
    }
}

/// Default production sink — structured `tracing` (subscriber decides export).
#[derive(Clone, Debug, Default)]
pub struct TracingMetricsSink;

impl MetricsSink for TracingMetricsSink {
    fn increment(
        &self,
        metric: Metric,
        value: u64,
        labels: &MetricLabels,
    ) -> Result<(), MetricsError> {
        tracing::info!(
            metric = metric.name(),
            kind = "counter",
            value,
            labels = %serde_json::to_string(&labels.as_map()).unwrap_or_else(|_| "{}".into()),
            "metrics"
        );
        Ok(())
    }

    fn observe(
        &self,
        metric: Metric,
        value: f64,
        labels: &MetricLabels,
    ) -> Result<(), MetricsError> {
        tracing::info!(
            metric = metric.name(),
            kind = "histogram",
            value,
            labels = %serde_json::to_string(&labels.as_map()).unwrap_or_else(|_| "{}".into()),
            "metrics"
        );
        Ok(())
    }

    fn set_gauge(
        &self,
        metric: Metric,
        value: i64,
        labels: &MetricLabels,
    ) -> Result<(), MetricsError> {
        tracing::info!(
            metric = metric.name(),
            kind = "gauge",
            value,
            labels = %serde_json::to_string(&labels.as_map()).unwrap_or_else(|_| "{}".into()),
            "metrics"
        );
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub enum MetricSample {
    Counter {
        metric: Metric,
        value: u64,
        labels: MetricLabels,
    },
    Observe {
        metric: Metric,
        value: f64,
        labels: MetricLabels,
    },
    Gauge {
        metric: Metric,
        value: i64,
        labels: MetricLabels,
    },
}

/// In-memory capture for tests.
#[derive(Clone, Debug, Default)]
pub struct MemoryMetricsSink {
    samples: Arc<Mutex<Vec<MetricSample>>>,
}

impl MemoryMetricsSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> Vec<MetricSample> {
        self.samples.lock().map(|g| g.clone()).unwrap_or_default()
    }

    pub fn clear(&self) {
        if let Ok(mut g) = self.samples.lock() {
            g.clear();
        }
    }

    pub fn counter_sum(&self, metric: Metric) -> u64 {
        self.snapshot()
            .into_iter()
            .filter_map(|s| match s {
                MetricSample::Counter {
                    metric: m, value, ..
                } if m == metric => Some(value),
                _ => None,
            })
            .sum()
    }

    pub fn last_gauge(&self, metric: Metric) -> Option<i64> {
        self.snapshot().into_iter().rev().find_map(|s| match s {
            MetricSample::Gauge {
                metric: m, value, ..
            } if m == metric => Some(value),
            _ => None,
        })
    }

    pub fn observe_values(&self, metric: Metric) -> Vec<f64> {
        self.snapshot()
            .into_iter()
            .filter_map(|s| match s {
                MetricSample::Observe {
                    metric: m, value, ..
                } if m == metric => Some(value),
                _ => None,
            })
            .collect()
    }
}

impl MetricsSink for MemoryMetricsSink {
    fn increment(
        &self,
        metric: Metric,
        value: u64,
        labels: &MetricLabels,
    ) -> Result<(), MetricsError> {
        let mut g = self
            .samples
            .lock()
            .map_err(|_| MetricsError("lock".into()))?;
        g.push(MetricSample::Counter {
            metric,
            value,
            labels: labels.clone(),
        });
        Ok(())
    }

    fn observe(
        &self,
        metric: Metric,
        value: f64,
        labels: &MetricLabels,
    ) -> Result<(), MetricsError> {
        let mut g = self
            .samples
            .lock()
            .map_err(|_| MetricsError("lock".into()))?;
        g.push(MetricSample::Observe {
            metric,
            value,
            labels: labels.clone(),
        });
        Ok(())
    }

    fn set_gauge(
        &self,
        metric: Metric,
        value: i64,
        labels: &MetricLabels,
    ) -> Result<(), MetricsError> {
        let mut g = self
            .samples
            .lock()
            .map_err(|_| MetricsError("lock".into()))?;
        g.push(MetricSample::Gauge {
            metric,
            value,
            labels: labels.clone(),
        });
        Ok(())
    }
}

/// Failure-isolated metrics facade.
#[derive(Clone)]
pub struct Metrics {
    sink: Arc<dyn MetricsSink>,
    connections_active: Arc<AtomicI64>,
    connections_accepted: Arc<AtomicU64>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::tracing()
    }
}

impl Metrics {
    pub fn new(sink: Arc<dyn MetricsSink>) -> Self {
        Self {
            sink,
            connections_active: Arc::new(AtomicI64::new(0)),
            connections_accepted: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn tracing() -> Self {
        Self::new(Arc::new(TracingMetricsSink))
    }

    pub fn noop() -> Self {
        Self::new(Arc::new(NoopMetricsSink))
    }

    pub fn failing() -> Self {
        Self::new(Arc::new(FailingMetricsSink))
    }

    pub fn memory(sink: MemoryMetricsSink) -> Self {
        Self::new(Arc::new(sink))
    }

    /// Counter increment. Errors swallowed.
    pub fn increment(&self, metric: Metric, value: u64, labels: MetricLabels) {
        let _ = self.sink.increment(metric, value, &labels);
    }

    /// Histogram / timing observation. Errors swallowed.
    pub fn observe(&self, metric: Metric, value: f64, labels: MetricLabels) {
        let _ = self.sink.observe(metric, value, &labels);
    }

    /// Absolute gauge. Errors swallowed.
    pub fn set_gauge(&self, metric: Metric, value: i64, labels: MetricLabels) {
        let _ = self.sink.set_gauge(metric, value, &labels);
    }

    pub fn connection_accepted(&self, transport: Option<MetricTransport>) {
        let labels = transport
            .map(|t| MetricLabels::new().with_transport(t))
            .unwrap_or_default();
        self.connections_accepted.fetch_add(1, Ordering::Relaxed);
        self.increment(Metric::ConnectionsAcceptedTotal, 1, labels.clone());
        let n = self.connections_active.fetch_add(1, Ordering::Relaxed) + 1;
        self.set_gauge(Metric::ConnectionsActive, n, labels);
    }

    pub fn connection_closed(&self, transport: Option<MetricTransport>) {
        let labels = transport
            .map(|t| MetricLabels::new().with_transport(t))
            .unwrap_or_default();
        let n = self
            .connections_active
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(if v > 0 { v - 1 } else { 0 })
            })
            .unwrap_or(0);
        let after = if n > 0 { n - 1 } else { 0 };
        self.set_gauge(Metric::ConnectionsActive, after, labels);
    }

    pub fn connections_active(&self) -> i64 {
        self.connections_active.load(Ordering::Relaxed)
    }

    pub fn connections_accepted_total(&self) -> u64 {
        self.connections_accepted.load(Ordering::Relaxed)
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

/// All V1 metric names — for catalog / forbidden-label tests.
pub fn v1_metric_names() -> &'static [&'static str] {
    &[
        "connections_accepted_total",
        "connections_active",
        "requests_total",
        "requests_failed_total",
        "request_duration_ms",
        "auth_success_total",
        "auth_failure_total",
        "authorization_denied_total",
        "session_invalid_total",
        "vault_unlock_success_total",
        "vault_unlock_failure_total",
        "vault_lock_total",
        "vault_locked_requests_total",
        "sql_statements_total",
        "sql_errors_total",
        "sql_transactions_committed_total",
        "sql_transactions_rolled_back_total",
        "sql_write_conflicts_total",
        "core_liveness",
        "core_ready",
    ]
}
