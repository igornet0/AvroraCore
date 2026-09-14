//! Request / connection correlation (7.9.3). Diagnostic metadata only — never credentials.

use std::sync::atomic::{AtomicU64, Ordering};

use dmc_observability::ObservabilityContext;

use crate::state::CoreServerState;

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

/// Opaque connection id allocated once per accepted socket (IPC or TLS).
pub fn allocate_connection_id() -> String {
    let n = NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
    format!("conn-{n}")
}

/// Build base context for a protocol request on a live connection.
///
/// `session_id` is set only when the caller has validated a session (not a proof of auth).
pub fn context_for_request(
    connection_id: &str,
    request_id: u64,
    session_id: Option<&str>,
) -> ObservabilityContext {
    let mut ctx = ObservabilityContext::default()
        .with_request_id(request_id.to_string())
        .with_connection_id(connection_id.to_string());
    if let Some(sid) = session_id {
        ctx = ctx.with_session_id(sid.to_string());
    }
    ctx
}

/// Enrich with active transaction id when a transaction context exists.
pub fn with_active_transaction(
    mut ctx: ObservabilityContext,
    state: &CoreServerState,
) -> ObservabilityContext {
    if let Some(txn) = state.ctx.transaction() {
        ctx = ctx.with_transaction_id(txn.state.id.raw().to_string());
    }
    ctx
}

/// Attach journal tip only when it advanced (actual append happened).
pub fn with_sequence_if_appended(
    mut ctx: ObservabilityContext,
    tip_before: Option<u64>,
    tip_after: Option<u64>,
) -> ObservabilityContext {
    match (tip_before, tip_after) {
        (Some(before), Some(after)) if after > before => {
            ctx = ctx.with_journal_sequence(after);
        }
        (None, Some(after)) => {
            ctx = ctx.with_journal_sequence(after);
        }
        _ => {}
    }
    ctx
}

pub fn journal_tip(state: &CoreServerState) -> Option<u64> {
    state.ctx.journal().map(|j| j.tip_sequence())
}

/// Capture txn id before an operation that may clear it (COMMIT / ROLLBACK).
pub fn active_transaction_id(state: &CoreServerState) -> Option<String> {
    state
        .ctx
        .transaction()
        .map(|txn| txn.state.id.raw().to_string())
}
