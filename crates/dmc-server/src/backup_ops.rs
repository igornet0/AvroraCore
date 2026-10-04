//! Phase 7.8.7 — Control Plane backup/restore/recover ops over `dmc-backup`.

use std::path::PathBuf;

use dmc_backup::{
    backup_path, list_backups, recover, restore_backup, restore_target_path, verify_backup,
    BackupCoordinator, BackupOptions, BackupRequest, RecoveryGate, RecoveryState,
};
use dmc_protocol::{BackupListItem, ControlResponse, ProtocolErrorCode, ResponseEnvelope};
use dmc_security::auth::SessionManager;
use dmc_sql_exec::JournalBackend;

use crate::state::CoreServerState;

fn backups_root(state: &CoreServerState) -> PathBuf {
    state.data_root.join("backups")
}

fn restores_root(state: &CoreServerState) -> PathBuf {
    state.data_root.join("restores")
}

fn require_session(
    state: &CoreServerState,
    request_id: u64,
    session_id: &str,
) -> std::result::Result<(), ResponseEnvelope<ControlResponse>> {
    let sid = session_id.to_string().into();
    match state.auth.validate_session(&sid) {
        Ok(_) => Ok(()),
        Err(_) => Err(ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::SessionInvalid,
            "session invalid",
        )),
    }
}

fn map_backup_err(request_id: u64, err: dmc_backup::BackupError) -> ResponseEnvelope<ControlResponse> {
    use dmc_backup::BackupError;
    match err {
        BackupError::BackupInvalid(_) | BackupError::Corrupt(_) | BackupError::Validation(_) => {
            ResponseEnvelope::err(
                request_id,
                ProtocolErrorCode::BackupInvalid,
                "backup invalid",
            )
        }
        BackupError::TargetNotEmpty(_) => ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::BackupTargetNotEmpty,
            "restore target not empty",
        ),
        BackupError::RecoveryNotReady(_) => ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::RecoveryNotReady,
            "recovery not ready",
        ),
        BackupError::AlreadyExists => ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::InvalidRequest,
            "backup already exists",
        ),
        _ => ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::InternalError,
            "internal error",
        ),
    }
}

fn opaque_id_ok(id: &str) -> bool {
    !id.is_empty()
        && !id.contains('/')
        && !id.contains('\\')
        && !id.contains("..")
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn recovery_state_label(state: RecoveryState) -> &'static str {
    match state {
        RecoveryState::Restored => "restored",
        RecoveryState::Recovering => "recovering",
        RecoveryState::Ready => "ready",
        RecoveryState::Failed => "failed",
    }
}


fn obs_ctx(connection_id: &str, request_id: u64, session_id: &str) -> dmc_observability::ObservabilityContext {
    crate::correlation::context_for_request(connection_id, request_id, Some(session_id))
}

/// Keep relative artifact hints; never forward absolute filesystem paths.
fn client_safe_verify_error(msg: &str) -> String {
    let lower = msg.to_lowercase();
    if lower.contains("master")
        || lower.contains("dek")
        || lower.contains("kek")
        || msg.contains(":\\")
        || (msg.starts_with('/') && msg.contains('/'))
    {
        return "backup invalid".into();
    }
    let relative = msg.replace('\\', "/").replace('/', ".");
    dmc_protocol::sanitize_client_message(relative)
}

pub fn backup_create(
    state: &mut CoreServerState,
    request_id: u64,
    connection_id: &str,
    session_id: &str,
    backup_id: &str,
    include_rowstore: bool,
) -> ResponseEnvelope<ControlResponse> {
    if let Err(resp) = require_session(state, request_id, session_id) {
        return resp;
    }
    if !opaque_id_ok(backup_id) {
        return ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::InvalidRequest,
            "invalid backup id",
        );
    }
    let root = backups_root(state);
    let req = BackupRequest::new("avrora")
        .with_options(BackupOptions {
            include_rowstore,
            include_statistics: false,
            include_index_store: false,
        })
        // CLIENT_OWNED key directory travels with the data (public / wrapped only).
        .with_ownership_dir(state.data_root.join("ownership"));

    let published = match state.ctx.journal() {
        Some(JournalBackend::File(mat)) => {
            BackupCoordinator::create_and_publish(mat, &req, &root, backup_id)
        }
        Some(JournalBackend::Memory(mat)) => {
            BackupCoordinator::create_and_publish(mat, &req, &root, backup_id)
        }
        None => {
            return ResponseEnvelope::err(
                request_id,
                ProtocolErrorCode::InternalError,
                "journal unavailable",
            )
        }
    };
    match published {
        Ok(p) => {
            crate::observe::emit_backup_created(
                state,
                obs_ctx(connection_id, request_id, session_id),
                backup_id,
                p.manifest.checkpoint_sequence,
            );
            ResponseEnvelope::ok(
                request_id,
                ControlResponse::BackupCreate {
                    backup_id: backup_id.to_string(),
                    checkpoint_sequence: p.manifest.checkpoint_sequence,
                },
            )
        }
        Err(e) => {
            let resp = map_backup_err(request_id, e);
            if let Some(code) = resp.error_code {
                crate::observe::emit_backup_failed(state, obs_ctx(connection_id, request_id, session_id), backup_id, code);
            }
            resp
        }
    }
}

pub fn backup_verify(
    state: &CoreServerState,
    request_id: u64,
    connection_id: &str,
    session_id: &str,
    backup_id: &str,
) -> ResponseEnvelope<ControlResponse> {
    if let Err(resp) = require_session(state, request_id, session_id) {
        return resp;
    }
    if !opaque_id_ok(backup_id) {
        return ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::InvalidRequest,
            "invalid backup id",
        );
    }
    let path = backup_path(&backups_root(state), backup_id);
    if !path.is_dir() {
        return ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::BackupNotFound,
            "backup not found",
        );
    }
    match verify_backup(&path) {
        Ok(report) => {
            crate::observe::emit_backup_verified(
                state,
                obs_ctx(connection_id, request_id, session_id),
                backup_id,
                report.checkpoint_sequence,
                report.valid,
            );
            ResponseEnvelope::ok(
                request_id,
                ControlResponse::BackupVerify {
                    backup_id: backup_id.to_string(),
                    checkpoint_sequence: report.checkpoint_sequence,
                    valid: report.valid,
                    errors: report
                        .errors
                        .into_iter()
                        .map(|e| client_safe_verify_error(&e))
                        .collect(),
                },
            )
        }
        Err(e) => map_backup_err(request_id, e),
    }
}

pub fn backup_list(
    state: &CoreServerState,
    request_id: u64,
    connection_id: &str,
    session_id: &str,
) -> ResponseEnvelope<ControlResponse> {
    let _ = connection_id;
    if let Err(resp) = require_session(state, request_id, session_id) {
        return resp;
    }
    match list_backups(&backups_root(state)) {
        Ok(items) => ResponseEnvelope::ok(
            request_id,
            ControlResponse::BackupList {
                items: items
                    .into_iter()
                    .map(|i| BackupListItem {
                        backup_id: i.backup_id,
                        checkpoint_sequence: i.checkpoint_sequence,
                        created_at: i.created_at,
                        valid: i.valid,
                        state: i.state,
                    })
                    .collect(),
            },
        ),
        Err(e) => map_backup_err(request_id, e),
    }
}

pub fn backup_restore(
    state: &CoreServerState,
    request_id: u64,
    connection_id: &str,
    session_id: &str,
    backup_id: &str,
    target_id: &str,
) -> ResponseEnvelope<ControlResponse> {
    if let Err(resp) = require_session(state, request_id, session_id) {
        return resp;
    }
    if !opaque_id_ok(backup_id) || !opaque_id_ok(target_id) {
        return ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::InvalidRequest,
            "invalid backup or target id",
        );
    }
    let backup = backup_path(&backups_root(state), backup_id);
    if !backup.is_dir() {
        return ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::BackupNotFound,
            "backup not found",
        );
    }
    let target = restore_target_path(&restores_root(state), target_id);
    let ctx = obs_ctx(connection_id, request_id, session_id);
    crate::observe::emit_backup_restore_started(state, ctx.clone());
    match restore_backup(&backup, &target) {
        Ok(r) => {
            crate::observe::emit_backup_restored(
                state,
                ctx,
                backup_id,
                r.checkpoint_sequence,
            );
            ResponseEnvelope::ok(
                request_id,
                ControlResponse::BackupRestore {
                    backup_id: backup_id.to_string(),
                    target_id: target_id.to_string(),
                    checkpoint_sequence: r.checkpoint_sequence,
                    vault_locked: true,
                    sessions_invalid: true,
                },
            )
        }
        Err(e) => map_backup_err(request_id, e),
    }
}

pub fn backup_recover(
    state: &CoreServerState,
    request_id: u64,
    connection_id: &str,
    session_id: &str,
    target_id: &str,
) -> ResponseEnvelope<ControlResponse> {
    if let Err(resp) = require_session(state, request_id, session_id) {
        return resp;
    }
    if !opaque_id_ok(target_id) {
        return ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::InvalidRequest,
            "invalid target id",
        );
    }
    let target = restore_target_path(&restores_root(state), target_id);
    if !target.is_dir() {
        return ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::BackupNotFound,
            "restore target not found",
        );
    }
    crate::observe::emit_recovery_started(state, obs_ctx(connection_id, request_id, session_id));
    match recover(&target) {
        Ok(r) => {
            crate::observe::emit_recovery_completed(
                state,
                obs_ctx(connection_id, request_id, session_id),
                r.checkpoint_sequence,
            );
            ResponseEnvelope::ok(
                request_id,
                ControlResponse::BackupRecover {
                    target_id: target_id.to_string(),
                    checkpoint_sequence: r.checkpoint_sequence,
                    state: recovery_state_label(r.state).into(),
                    vault_locked: true,
                    sessions_invalid: true,
                },
            )
        }
        Err(e) => {
            let resp = map_backup_err(request_id, e);
            if let Some(code) = resp.error_code {
                crate::observe::emit_recovery_failed(state, obs_ctx(connection_id, request_id, session_id), code);
            }
            resp
        }
    }
}

pub fn backup_status(
    state: &CoreServerState,
    request_id: u64,
    connection_id: &str,
    session_id: &str,
    target_id: &str,
) -> ResponseEnvelope<ControlResponse> {
    let _ = connection_id;
    if let Err(resp) = require_session(state, request_id, session_id) {
        return resp;
    }
    if !opaque_id_ok(target_id) {
        return ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::InvalidRequest,
            "invalid target id",
        );
    }
    let target = restore_target_path(&restores_root(state), target_id);
    if !target.is_dir() {
        return ResponseEnvelope::ok(
            request_id,
            ControlResponse::BackupStatus {
                target_id: target_id.to_string(),
                state: "absent".into(),
                checkpoint_sequence: 0,
                vault_locked: true,
                sessions_invalid: true,
            },
        );
    }
    match RecoveryGate::load(&target) {
        Ok(gate) => ResponseEnvelope::ok(
            request_id,
            ControlResponse::BackupStatus {
                target_id: target_id.to_string(),
                state: recovery_state_label(gate.state).into(),
                checkpoint_sequence: gate.checkpoint_sequence,
                vault_locked: true,
                sessions_invalid: true,
            },
        ),
        Err(e) => map_backup_err(request_id, e),
    }
}
