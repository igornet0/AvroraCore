//! Audit recording helpers (7.9.5). Observational only — never affects outcomes.

use dmc_observability::{
    statement_kind, AuditEvent, AuditEventKind, AuditResult, ObservabilityContext,
};
use dmc_protocol::ProtocolErrorCode;
use dmc_security::auth::SessionManager;

use crate::state::CoreServerState;

fn principal_for_session(state: &CoreServerState, session_id: Option<&str>) -> Option<String> {
    let sid = session_id?;
    state
        .auth
        .principal_for(&sid.to_string().into())
        .ok()
        .map(|p| p.identity_id.as_str().to_string())
}

fn enrich(
    kind: AuditEventKind,
    result: AuditResult,
    ctx: &ObservabilityContext,
    state: &CoreServerState,
    principal_id: Option<&str>,
) -> AuditEvent {
    let mut ev = AuditEvent::from_context(kind, result, ctx);
    if let Some(pid) = principal_id {
        ev = ev.with_principal_id(pid);
    } else if let Some(pid) = principal_for_session(state, ctx.session_id.as_deref()) {
        ev = ev.with_principal_id(pid);
    }
    ev
}

pub fn authentication_succeeded(
    state: &CoreServerState,
    ctx: &ObservabilityContext,
    principal_id: &str,
) {
    state.audit.record(enrich(
        AuditEventKind::AuthenticationSucceeded,
        AuditResult::Success,
        ctx,
        state,
        Some(principal_id),
    ));
    state.audit.record(enrich(
        AuditEventKind::SessionCreated,
        AuditResult::Success,
        ctx,
        state,
        Some(principal_id),
    ));
}

pub fn authentication_failed(state: &CoreServerState, ctx: &ObservabilityContext) {
    state.audit.record(enrich(
        AuditEventKind::AuthenticationFailed,
        AuditResult::Failure,
        ctx,
        state,
        None,
    ));
}

pub fn session_invalidated(state: &CoreServerState, ctx: &ObservabilityContext) {
    state.audit.record(enrich(
        AuditEventKind::SessionInvalidated,
        AuditResult::Success,
        ctx,
        state,
        None,
    ));
}

pub fn authorization_denied(
    state: &CoreServerState,
    ctx: &ObservabilityContext,
    sql: &str,
) {
    let op = statement_kind(sql);
    state.audit.record(
        enrich(
            AuditEventKind::AuthorizationDenied,
            AuditResult::Denied,
            ctx,
            state,
            None,
        )
        .with_operation(op)
        .with_error_code(ProtocolErrorCode::AuthorizationDenied.as_str()),
    );
}

pub fn vault_unlocked(state: &CoreServerState, ctx: &ObservabilityContext) {
    state.audit.record(enrich(
        AuditEventKind::VaultUnlocked,
        AuditResult::Success,
        ctx,
        state,
        None,
    ));
}

pub fn vault_unlock_failed(state: &CoreServerState, ctx: &ObservabilityContext) {
    state.audit.record(enrich(
        AuditEventKind::VaultUnlockFailed,
        AuditResult::Failure,
        ctx,
        state,
        None,
    ));
}

pub fn vault_locked(state: &CoreServerState, ctx: &ObservabilityContext) {
    state.audit.record(enrich(
        AuditEventKind::VaultLocked,
        AuditResult::Success,
        ctx,
        state,
        None,
    ));
}

pub fn sql_executed(
    state: &CoreServerState,
    ctx: &ObservabilityContext,
    sql: &str,
    result: AuditResult,
    error_code: Option<ProtocolErrorCode>,
    parameter_count: Option<u32>,
) {
    let op = statement_kind(sql);
    let mut ev = enrich(AuditEventKind::SqlExecuted, result, ctx, state, None).with_operation(op);
    if let Some(code) = error_code {
        ev = ev.with_error_code(code.as_str());
    }
    if let Some(n) = parameter_count {
        ev = ev.with_parameter_count(n);
    }
    state.audit.record(ev);
}

pub fn sql_completed_audit(state: &CoreServerState, ctx: &ObservabilityContext, sql: &str) {
    match statement_kind(sql) {
        "COMMIT" => {
            state.audit.record(enrich(
                AuditEventKind::TransactionCommitted,
                AuditResult::Success,
                ctx,
                state,
                None,
            ));
        }
        "ROLLBACK" => {
            state.audit.record(enrich(
                AuditEventKind::TransactionRolledBack,
                AuditResult::Success,
                ctx,
                state,
                None,
            ));
        }
        _ => {
            sql_executed(state, ctx, sql, AuditResult::Success, None, None);
        }
    }
}

pub fn sql_failed_audit(
    state: &CoreServerState,
    ctx: &ObservabilityContext,
    sql: &str,
    code: ProtocolErrorCode,
) {
    match code {
        ProtocolErrorCode::AuthorizationDenied => authorization_denied(state, ctx, sql),
        ProtocolErrorCode::TransactionConflict => {
            state.audit.record(
                enrich(
                    AuditEventKind::TransactionConflict,
                    AuditResult::Failure,
                    ctx,
                    state,
                    None,
                )
                .with_error_code(code.as_str()),
            );
        }
        _ => {
            sql_executed(
                state,
                ctx,
                sql,
                AuditResult::Failure,
                Some(code),
                None,
            );
        }
    }
}

pub fn backup_created(state: &CoreServerState, ctx: &ObservabilityContext) {
    state.audit.record(enrich(
        AuditEventKind::BackupCreated,
        AuditResult::Success,
        ctx,
        state,
        None,
    ));
}

pub fn backup_verified(state: &CoreServerState, ctx: &ObservabilityContext, valid: bool) {
    state.audit.record(enrich(
        AuditEventKind::BackupVerified,
        if valid {
            AuditResult::Success
        } else {
            AuditResult::Failure
        },
        ctx,
        state,
        None,
    ));
}

pub fn backup_restore_started(state: &CoreServerState, ctx: &ObservabilityContext) {
    state.audit.record(enrich(
        AuditEventKind::BackupRestoreStarted,
        AuditResult::Success,
        ctx,
        state,
        None,
    ));
}

pub fn backup_restored(state: &CoreServerState, ctx: &ObservabilityContext) {
    state.audit.record(enrich(
        AuditEventKind::BackupRestored,
        AuditResult::Success,
        ctx,
        state,
        None,
    ));
}

pub fn recovery_started(state: &CoreServerState, ctx: &ObservabilityContext) {
    state.audit.record(enrich(
        AuditEventKind::RecoveryStarted,
        AuditResult::Success,
        ctx,
        state,
        None,
    ));
}

pub fn recovery_completed(state: &CoreServerState, ctx: &ObservabilityContext) {
    state.audit.record(enrich(
        AuditEventKind::RecoveryCompleted,
        AuditResult::Success,
        ctx,
        state,
        None,
    ));
}

pub fn recovery_failed(state: &CoreServerState, ctx: &ObservabilityContext, code: ProtocolErrorCode) {
    state.audit.record(
        enrich(
            AuditEventKind::RecoveryFailed,
            AuditResult::Failure,
            ctx,
            state,
            None,
        )
        .with_error_code(code.as_str()),
    );
}
