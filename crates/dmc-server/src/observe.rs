//! Thin helpers: emit structured events + metrics + audit without affecting outcomes.

use dmc_observability::{
    statement_kind, EventKind, EventOutcome, ObservabilityContext, ObservabilityEvent,
    FIELD_BACKUP_ID, FIELD_CHECKPOINT_SEQUENCE, FIELD_ERROR_CODE, FIELD_OPERATION,
    FIELD_PARAMETER_COUNT, FIELD_REASON, FIELD_STATEMENT_KIND,
};
use dmc_protocol::ProtocolErrorCode;

use crate::state::CoreServerState;

pub fn emit(state: &CoreServerState, event: ObservabilityEvent) {
    state.observability.emit(event);
}

pub fn emit_auth_login_success(
    state: &CoreServerState,
    ctx: ObservabilityContext,
    principal_id: &str,
) {
    emit(
        state,
        ObservabilityEvent::new(EventKind::AuthLoginSuccess, ctx.clone()),
    );
    crate::metrics_rec::auth_success(state);
    crate::audit_rec::authentication_succeeded(state, &ctx, principal_id);
}

pub fn emit_auth_login_failure(state: &CoreServerState, ctx: ObservabilityContext) {
    emit(
        state,
        ObservabilityEvent::new(EventKind::AuthLoginFailure, ctx.clone())
            .field(FIELD_REASON, "invalid_credential"),
    );
    crate::metrics_rec::auth_failure(state);
    crate::audit_rec::authentication_failed(state, &ctx);
}

pub fn emit_auth_logout(state: &CoreServerState, ctx: ObservabilityContext) {
    emit(
        state,
        ObservabilityEvent::new(EventKind::AuthLogout, ctx.clone()),
    );
    emit(
        state,
        ObservabilityEvent::new(EventKind::SessionRevoked, ctx.clone()),
    );
    crate::audit_rec::session_invalidated(state, &ctx);
}

pub fn emit_vault_unlock(state: &CoreServerState, ctx: ObservabilityContext) {
    emit(
        state,
        ObservabilityEvent::new(EventKind::VaultUnlock, ctx.clone()),
    );
    crate::metrics_rec::vault_unlock_success(state);
    crate::audit_rec::vault_unlocked(state, &ctx);
}

pub fn emit_vault_unlock_failed(state: &CoreServerState, ctx: ObservabilityContext) {
    emit(
        state,
        ObservabilityEvent::new(EventKind::VaultUnlockFailed, ctx.clone())
            .field(FIELD_REASON, "invalid_credential"),
    );
    crate::metrics_rec::vault_unlock_failure(state);
    crate::audit_rec::vault_unlock_failed(state, &ctx);
}

pub fn emit_vault_lock(state: &CoreServerState, ctx: ObservabilityContext) {
    emit(
        state,
        ObservabilityEvent::new(EventKind::VaultLock, ctx.clone()),
    );
    crate::metrics_rec::vault_lock(state);
    crate::audit_rec::vault_locked(state, &ctx);
}

pub fn emit_vault_denied(state: &CoreServerState, ctx: ObservabilityContext) {
    emit(
        state,
        ObservabilityEvent::new(EventKind::SqlFailed, ctx.clone())
            .with_outcome(EventOutcome::Denied)
            .field(FIELD_ERROR_CODE, ProtocolErrorCode::VaultLocked.as_str())
            .field(FIELD_REASON, "vault_locked"),
    );
    crate::metrics_rec::vault_locked_request(state);
    // Not a dedicated AuditEventKind — accountability via failed SqlExecuted.
    crate::audit_rec::sql_executed(
        state,
        &ctx,
        "OTHER",
        dmc_observability::AuditResult::Failure,
        Some(ProtocolErrorCode::VaultLocked),
        None,
    );
}

pub fn emit_sql_request(
    state: &CoreServerState,
    ctx: ObservabilityContext,
    sql: &str,
    parameter_count: usize,
) {
    let kind = statement_kind(sql);
    emit(
        state,
        ObservabilityEvent::new(EventKind::SqlRequest, ctx)
            .field(FIELD_OPERATION, kind)
            .field(FIELD_STATEMENT_KIND, kind)
            .field(FIELD_PARAMETER_COUNT, parameter_count.to_string()),
    );
}

pub fn emit_sql_completed(state: &CoreServerState, ctx: ObservabilityContext, sql: &str) {
    let kind = statement_kind(sql);
    emit(
        state,
        ObservabilityEvent::new(EventKind::SqlCompleted, ctx.clone())
            .field(FIELD_OPERATION, kind)
            .field(FIELD_STATEMENT_KIND, kind),
    );
    crate::metrics_rec::sql_completed(state, sql);
    crate::audit_rec::sql_completed_audit(state, &ctx, sql);
}

pub fn emit_sql_failed(
    state: &CoreServerState,
    ctx: ObservabilityContext,
    sql: &str,
    code: ProtocolErrorCode,
) {
    let kind = statement_kind(sql);
    let event_kind = if code == ProtocolErrorCode::AuthorizationDenied {
        EventKind::AuthzDenied
    } else {
        EventKind::SqlFailed
    };
    emit(
        state,
        ObservabilityEvent::new(event_kind, ctx.clone())
            .field(FIELD_OPERATION, kind)
            .field(FIELD_STATEMENT_KIND, kind)
            .field(FIELD_ERROR_CODE, code.as_str()),
    );
    crate::metrics_rec::sql_failed(state, sql, code);
    crate::audit_rec::sql_failed_audit(state, &ctx, sql, code);
}

pub fn emit_backup_created(
    state: &CoreServerState,
    ctx: ObservabilityContext,
    backup_id: &str,
    checkpoint_sequence: u64,
) {
    emit(
        state,
        ObservabilityEvent::new(EventKind::BackupCreated, ctx.clone())
            .field(FIELD_BACKUP_ID, backup_id)
            .field(FIELD_CHECKPOINT_SEQUENCE, checkpoint_sequence.to_string()),
    );
    crate::audit_rec::backup_created(state, &ctx);
}

pub fn emit_backup_failed(
    state: &CoreServerState,
    ctx: ObservabilityContext,
    backup_id: &str,
    code: ProtocolErrorCode,
) {
    emit(
        state,
        ObservabilityEvent::new(EventKind::BackupFailed, ctx)
            .field(FIELD_BACKUP_ID, backup_id)
            .field(FIELD_ERROR_CODE, code.as_str()),
    );
}

pub fn emit_backup_verified(
    state: &CoreServerState,
    ctx: ObservabilityContext,
    backup_id: &str,
    checkpoint_sequence: u64,
    valid: bool,
) {
    let outcome = if valid {
        EventOutcome::Success
    } else {
        EventOutcome::Failure
    };
    emit(
        state,
        ObservabilityEvent::new(EventKind::BackupVerified, ctx.clone())
            .with_outcome(outcome)
            .field(FIELD_BACKUP_ID, backup_id)
            .field(FIELD_CHECKPOINT_SEQUENCE, checkpoint_sequence.to_string()),
    );
    crate::audit_rec::backup_verified(state, &ctx, valid);
}

pub fn emit_backup_restore_started(state: &CoreServerState, ctx: ObservabilityContext) {
    crate::audit_rec::backup_restore_started(state, &ctx);
}

pub fn emit_backup_restored(
    state: &CoreServerState,
    ctx: ObservabilityContext,
    backup_id: &str,
    checkpoint_sequence: u64,
) {
    emit(
        state,
        ObservabilityEvent::new(EventKind::BackupRestored, ctx.clone())
            .field(FIELD_BACKUP_ID, backup_id)
            .field(FIELD_CHECKPOINT_SEQUENCE, checkpoint_sequence.to_string()),
    );
    crate::audit_rec::backup_restored(state, &ctx);
}

pub fn emit_recovery_started(state: &CoreServerState, ctx: ObservabilityContext) {
    emit(
        state,
        ObservabilityEvent::new(EventKind::RecoveryStarted, ctx.clone()),
    );
    crate::audit_rec::recovery_started(state, &ctx);
}

pub fn emit_recovery_completed(
    state: &CoreServerState,
    ctx: ObservabilityContext,
    checkpoint_sequence: u64,
) {
    emit(
        state,
        ObservabilityEvent::new(EventKind::RecoveryCompleted, ctx.clone())
            .field(FIELD_CHECKPOINT_SEQUENCE, checkpoint_sequence.to_string()),
    );
    crate::audit_rec::recovery_completed(state, &ctx);
}

pub fn emit_recovery_failed(
    state: &CoreServerState,
    ctx: ObservabilityContext,
    code: ProtocolErrorCode,
) {
    emit(
        state,
        ObservabilityEvent::new(EventKind::RecoveryFailed, ctx.clone())
            .field(FIELD_ERROR_CODE, code.as_str()),
    );
    crate::audit_rec::recovery_failed(state, &ctx, code);
}
