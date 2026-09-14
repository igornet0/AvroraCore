//! Phase 7.9.4 — Metrics catalog unit tests (low cardinality, failure isolation at sink).

use dmc_observability::{
    v1_metric_names, FailingMetricsSink, MemoryMetricsSink, Metric, MetricLabels, MetricOperation,
    MetricResult, MetricTransport, Metrics, MetricsSink,
};
use std::sync::Arc;

#[test]
fn counter_increment() {
    let mem = MemoryMetricsSink::new();
    let m = Metrics::memory(mem.clone());
    m.increment(Metric::AuthSuccessTotal, 1, MetricLabels::default());
    m.increment(Metric::AuthSuccessTotal, 2, MetricLabels::default());
    assert_eq!(mem.counter_sum(Metric::AuthSuccessTotal), 3);
}

#[test]
fn gauge_set_and_connection_lifecycle() {
    let mem = MemoryMetricsSink::new();
    let m = Metrics::memory(mem.clone());
    m.connection_accepted(Some(MetricTransport::Local));
    assert_eq!(m.connections_active(), 1);
    assert_eq!(mem.last_gauge(Metric::ConnectionsActive), Some(1));
    assert_eq!(mem.counter_sum(Metric::ConnectionsAcceptedTotal), 1);
    m.connection_accepted(Some(MetricTransport::Local));
    assert_eq!(m.connections_active(), 2);
    m.connection_closed(Some(MetricTransport::Local));
    assert_eq!(m.connections_active(), 1);
    assert_eq!(mem.last_gauge(Metric::ConnectionsActive), Some(1));
}

#[test]
fn histogram_timing_observe() {
    let mem = MemoryMetricsSink::new();
    let m = Metrics::memory(mem.clone());
    m.observe(
        Metric::RequestDurationMs,
        12.5,
        MetricLabels::new().with_result(MetricResult::Success),
    );
    let vals = mem.observe_values(Metric::RequestDurationMs);
    assert_eq!(vals, vec![12.5]);
}

#[test]
fn deterministic_metric_names() {
    let names = v1_metric_names();
    assert!(names.contains(&"connections_accepted_total"));
    assert!(names.contains(&"sql_write_conflicts_total"));
    assert_eq!(Metric::AuthSuccessTotal.name(), "auth_success_total");
    assert_eq!(Metric::RequestDurationMs.name(), "request_duration_ms");
    // Every catalog entry has a unique name.
    let mut sorted: Vec<_> = names.to_vec();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len());
}

#[test]
fn allowed_labels_only() {
    let labels = MetricLabels::new()
        .with_operation(MetricOperation::Insert)
        .with_result(MetricResult::Success)
        .with_transport(MetricTransport::Remote);
    let map = labels.as_map();
    assert_eq!(map.get("operation"), Some(&"INSERT"));
    assert_eq!(map.get("result"), Some(&"success"));
    assert_eq!(map.get("transport"), Some(&"remote"));
    assert_eq!(map.len(), 3);
}

#[test]
fn forbidden_high_cardinality_label_keys() {
    for key in [
        "request_id",
        "session_id",
        "transaction_id",
        "connection_id",
        "user_id",
        "table_name",
        "sql",
        "error_message",
        "path",
    ] {
        assert!(
            MetricLabels::is_forbidden_label_key(key),
            "expected forbidden: {key}"
        );
    }
    assert!(!MetricLabels::is_forbidden_label_key("operation"));
    assert!(!MetricLabels::is_forbidden_label_key("result"));
    assert!(!MetricLabels::is_forbidden_label_key("transport"));
}

#[test]
fn operation_from_statement_kind_is_closed_enum() {
    assert_eq!(
        MetricOperation::from_statement_kind("SELECT"),
        MetricOperation::Select
    );
    assert_eq!(
        MetricOperation::from_statement_kind("COMMIT"),
        MetricOperation::Transaction
    );
    assert_eq!(
        MetricOperation::from_statement_kind("CREATE"),
        MetricOperation::Ddl
    );
}

#[test]
fn failing_metrics_sink_errors_are_swallowed_by_facade() {
    let m = Metrics::new(Arc::new(FailingMetricsSink));
    // Must not panic / return error to caller.
    m.increment(Metric::RequestsTotal, 1, MetricLabels::default());
    m.observe(Metric::RequestDurationMs, 1.0, MetricLabels::default());
    m.set_gauge(Metric::ConnectionsActive, 0, MetricLabels::default());
    m.connection_accepted(None);
    m.connection_closed(None);
}

#[test]
fn failing_sink_direct_returns_err() {
    let sink = FailingMetricsSink;
    assert!(sink
        .increment(Metric::AuthFailureTotal, 1, &MetricLabels::default())
        .is_err());
}
