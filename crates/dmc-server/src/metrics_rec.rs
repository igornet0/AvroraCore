//! Thin metrics recording helpers (7.9.4). Observational only — never affects outcomes.

use std::time::Duration;

use dmc_observability::{
    statement_kind, Metric, MetricLabels, MetricOperation, MetricResult,
};
use dmc_protocol::{ProtocolErrorCode, ResponseStatus};

use crate::state::CoreServerState;

fn transport_labels(state: &CoreServerState) -> MetricLabels {
    state
        .metrics_transport
        .map(|t| MetricLabels::new().with_transport(t))
        .unwrap_or_default()
}

pub fn finish_request(state: &CoreServerState, status: ResponseStatus, elapsed: Duration) {
    let success = status == ResponseStatus::Ok;
    let labels = transport_labels(state).with_result(if success {
        MetricResult::Success
    } else {
        MetricResult::Error
    });
    state
        .metrics
        .increment(Metric::RequestsTotal, 1, labels.clone());
    if !success {
        state
            .metrics
            .increment(Metric::RequestsFailedTotal, 1, labels.clone());
    }
    state.metrics.observe(
        Metric::RequestDurationMs,
        elapsed.as_secs_f64() * 1000.0,
        labels,
    );
}

pub fn auth_success(state: &CoreServerState) {
    state
        .metrics
        .increment(Metric::AuthSuccessTotal, 1, transport_labels(state));
}

pub fn auth_failure(state: &CoreServerState) {
    state
        .metrics
        .increment(Metric::AuthFailureTotal, 1, transport_labels(state));
}

pub fn authorization_denied(state: &CoreServerState) {
    state.metrics.increment(
        Metric::AuthorizationDeniedTotal,
        1,
        transport_labels(state),
    );
}

pub fn session_invalid(state: &CoreServerState) {
    state
        .metrics
        .increment(Metric::SessionInvalidTotal, 1, transport_labels(state));
}

pub fn vault_unlock_success(state: &CoreServerState) {
    state.metrics.increment(
        Metric::VaultUnlockSuccessTotal,
        1,
        transport_labels(state),
    );
}

pub fn vault_unlock_failure(state: &CoreServerState) {
    state.metrics.increment(
        Metric::VaultUnlockFailureTotal,
        1,
        transport_labels(state),
    );
}

pub fn vault_lock(state: &CoreServerState) {
    state
        .metrics
        .increment(Metric::VaultLockTotal, 1, transport_labels(state));
}

pub fn vault_locked_request(state: &CoreServerState) {
    state.metrics.increment(
        Metric::VaultLockedRequestsTotal,
        1,
        transport_labels(state),
    );
}

pub fn sql_completed(state: &CoreServerState, sql: &str) {
    let op = MetricOperation::from_statement_kind(statement_kind(sql));
    let labels = transport_labels(state)
        .with_operation(op)
        .with_result(MetricResult::Success);
    state
        .metrics
        .increment(Metric::SqlStatementsTotal, 1, labels);
    match statement_kind(sql) {
        "COMMIT" => state.metrics.increment(
            Metric::SqlTransactionsCommittedTotal,
            1,
            transport_labels(state),
        ),
        "ROLLBACK" => state.metrics.increment(
            Metric::SqlTransactionsRolledBackTotal,
            1,
            transport_labels(state),
        ),
        _ => {}
    }
}

pub fn sql_failed(state: &CoreServerState, sql: &str, code: ProtocolErrorCode) {
    let op = MetricOperation::from_statement_kind(statement_kind(sql));
    let labels = transport_labels(state)
        .with_operation(op)
        .with_result(MetricResult::Error);
    state
        .metrics
        .increment(Metric::SqlStatementsTotal, 1, labels.clone());
    state
        .metrics
        .increment(Metric::SqlErrorsTotal, 1, labels);
    match code {
        ProtocolErrorCode::AuthorizationDenied => authorization_denied(state),
        ProtocolErrorCode::VaultLocked => vault_locked_request(state),
        ProtocolErrorCode::TransactionConflict => state.metrics.increment(
            Metric::SqlWriteConflictsTotal,
            1,
            transport_labels(state),
        ),
        _ => {}
    }
}

pub fn connection_accepted(state: &CoreServerState) {
    state.metrics.connection_accepted(state.metrics_transport);
}

pub fn connection_closed(state: &CoreServerState) {
    state.metrics.connection_closed(state.metrics_transport);
}
