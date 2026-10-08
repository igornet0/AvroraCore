use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, DataResponse, ProtocolError, ProtocolErrorCode,
    RemoteLimits, RequestEnvelope, ResponseEnvelope, Result, SqlCell, SqlResult,
    validate_control_request, validate_data_request, VaultStateWire,
};
use dmc_security::auth::SessionManager;
use dmc_security::Error as SecurityError;
use dmc_sql_exec::{
    collect_rows, execute_authorized_sql, ExecutionError, Value,
};

use crate::state::CoreServerState;
use crate::unlock_blob::open_unlock_blob_full;
use crate::unlock_gate::VaultState;

pub fn handle_control(
    state: &mut CoreServerState,
    env: RequestEnvelope<ControlRequest>,
    limits: &RemoteLimits,
    connection_id: &str,
) -> Result<ResponseEnvelope<ControlResponse>> {
    let start = std::time::Instant::now();
    let result = handle_control_inner(state, env, limits, connection_id);
    if let Ok(ref resp) = result {
        crate::metrics_rec::finish_request(state, resp.status.clone(), start.elapsed());
        if resp.error_code == Some(ProtocolErrorCode::SessionInvalid) {
            crate::metrics_rec::session_invalid(state);
        }
    }
    result
}

fn handle_control_inner(
    state: &mut CoreServerState,
    env: RequestEnvelope<ControlRequest>,
    limits: &RemoteLimits,
    connection_id: &str,
) -> Result<ResponseEnvelope<ControlResponse>> {
    let request_id = env.request_id;
    let ctx_base = || crate::correlation::context_for_request(connection_id, request_id, None);
    let ctx_sess = |sid: &str| crate::correlation::context_for_request(connection_id, request_id, Some(sid));
    if let Err(err) = validate_control_request(&env.body, limits) {
        return Ok(map_control_validation_err(request_id, err));
    }
    if !control_allowed_while_stopping(&env.body) && !state.accepts_new_work() {
        return Ok(ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::ConnectionClosed,
            "core shutting down",
        ));
    }
    if let Err(err) = state.try_begin_request() {
        return Ok(map_limit_err_control(request_id, err));
    }
    // D5: every session check during this request is bound to this connection.
    state.auth.begin_request(connection_id);
    let ddl_session = runtime_session_id(&env.body).to_string();
    if !ddl_session.is_empty()
        && let Err(msg) = state.transaction_guard(&ddl_session)
    {
        state.auth.end_request();
        state.end_in_flight_request();
        return Ok(ResponseEnvelope::err(request_id, ProtocolErrorCode::TransactionConflict, msg));
    }
    let result = handle_control_body(state, env, limits, connection_id, request_id, ctx_base, ctx_sess);
    state.auth.end_request();
    state.end_in_flight_request();
    result
}

fn control_allowed_while_stopping(body: &ControlRequest) -> bool {
    matches!(
        body,
        ControlRequest::Health
        | ControlRequest::Readiness
        | ControlRequest::Diagnostics
        | ControlRequest::GetCapabilities
    )
}

fn handle_control_body(
    state: &mut CoreServerState,
    env: RequestEnvelope<ControlRequest>,
    _limits: &RemoteLimits,
    connection_id: &str,
    request_id: u64,
    ctx_base: impl Fn() -> dmc_observability::ObservabilityContext,
    ctx_sess: impl Fn(&str) -> dmc_observability::ObservabilityContext,
) -> Result<ResponseEnvelope<ControlResponse>> {
    match env.body {
        ControlRequest::Authenticate {
            identity_name,
            password,
        } => match state.auth.login(&identity_name, &password) {
            Ok((session, _principal)) => {
                crate::observe::emit_auth_login_success(
                    state,
                    ctx_sess(session.id.as_str()),
                    session.identity_id.as_str(),
                );
                Ok(ResponseEnvelope::ok(
                    request_id,
                    ControlResponse::Authenticate {
                        session_id: session.id.as_str().to_string(),
                        identity_id: session.identity_id.as_str().to_string(),
                        unlock_binding_key: session.unlock_binding_key.to_vec(),
                    },
                ))
            }
            Err(SecurityError::AuthenticationFailed(msg)) => {
                crate::observe::emit_auth_login_failure(state, ctx_base());
                Ok(ResponseEnvelope::err(
                    request_id,
                    ProtocolErrorCode::AuthenticationFailed,
                    msg,
                ))
            }
            Err(SecurityError::Auth(err)) => {
                crate::observe::emit_auth_login_failure(state, ctx_base());
                Ok(ResponseEnvelope::err(
                    request_id,
                    ProtocolErrorCode::AuthenticationFailed,
                    err.to_string(),
                ))
            }
            Err(SecurityError::IdentityDisabled(msg)) => {
                crate::observe::emit_auth_login_failure(state, ctx_base());
                Ok(ResponseEnvelope::err(
                    request_id,
                    ProtocolErrorCode::AuthenticationFailed,
                    msg,
                ))
            }
            Err(SecurityError::UnknownIdentity(msg)) => {
                crate::observe::emit_auth_login_failure(state, ctx_base());
                Ok(ResponseEnvelope::err(
                    request_id,
                    ProtocolErrorCode::AuthenticationFailed,
                    msg,
                ))
            }
            Err(err) => {
                crate::observe::emit_auth_login_failure(state, ctx_base());
                Ok(ResponseEnvelope::err(
                    request_id,
                    ProtocolErrorCode::InternalError,
                    err.to_string(),
                ))
            }
        },
        ControlRequest::SessionInfo { session_id } => {
            let sid = session_id.into();
            match state.auth.validate_session(&sid) {
                Ok(session) => Ok(ResponseEnvelope::ok(
                    request_id,
                    ControlResponse::SessionInfo {
                        active: true,
                        identity_id: Some(session.identity_id.as_str().to_string()),
                        expires_at_ms: Some(session.expires_at_ms),
                    },
                )),
                Err(SecurityError::SessionExpired(_)) => Ok(ResponseEnvelope::err(
                    request_id,
                    ProtocolErrorCode::SessionInvalid,
                    "session expired",
                )),
                Err(SecurityError::UnknownSession(_)) => Ok(ResponseEnvelope::err(
                    request_id,
                    ProtocolErrorCode::SessionInvalid,
                    "unknown session",
                )),
                Err(err) => Ok(ResponseEnvelope::err(
                    request_id,
                    ProtocolErrorCode::InternalError,
                    err.to_string(),
                )),
            }
        }
        ControlRequest::Health => {
            let status = crate::health::evaluate_health(state);
            let (liveness, readiness, vault, reason_code) =
                crate::health::health_to_wire(&status);
            Ok(ResponseEnvelope::ok(
                request_id,
                ControlResponse::Health {
                    liveness,
                    readiness,
                    vault,
                    reason_code,
                },
            ))
        }
        ControlRequest::Readiness => {
            let (readiness, reason) = crate::health::evaluate_readiness(state);
            Ok(ResponseEnvelope::ok(
                request_id,
                ControlResponse::Readiness {
                    readiness: readiness.as_str().into(),
                    reason_code: reason.map(|c| c.as_str().into()),
                },
            ))
        }
        ControlRequest::Diagnostics => {
            let snap = crate::diagnostics::evaluate_diagnostics(state);
            Ok(ResponseEnvelope::ok(
                request_id,
                ControlResponse::Diagnostics(crate::diagnostics::diagnostics_to_wire(&snap)),
            ))
        }
        ControlRequest::Logout { session_id } => {
            let sid = session_id.clone().into();
            match state.auth.logout(&sid) {
                Ok(()) => {
                    crate::observe::emit_auth_logout(state, ctx_sess(&session_id));
                    Ok(ResponseEnvelope::ok(
                        request_id,
                        ControlResponse::Logout { ok: true },
                    ))
                }
                Err(SecurityError::UnknownSession(_)) | Err(SecurityError::SessionExpired(_)) => {
                    Ok(ResponseEnvelope::err(
                        request_id,
                        ProtocolErrorCode::SessionInvalid,
                        "session invalid",
                    ))
                }
                Err(_) => Ok(ResponseEnvelope::err(
                    request_id,
                    ProtocolErrorCode::InternalError,
                    "internal error",
                )),
            }
        },
        ControlRequest::VaultStatus { session_id } => {
            match require_vault_session(state, request_id, &session_id) {
                Ok(()) => Ok(ResponseEnvelope::ok(
                    request_id,
                    ControlResponse::VaultStatus {
                        state: vault_state_wire(state.vault_state()),
                        generation: state.storage_generation().unwrap_or(0),
                    },
                )),
                Err(resp) => Ok(resp),
            }
        }
        ControlRequest::VaultLock { session_id } => {
            match require_vault_session(state, request_id, &session_id) {
                Ok(()) => {
                    state.lock_vault();
                    crate::observe::emit_vault_lock(state, ctx_sess(&session_id));
                    Ok(ResponseEnvelope::ok(
                        request_id,
                        ControlResponse::VaultLock {
                            state: VaultStateWire::Locked,
                        },
                    ))
                }
                Err(resp) => Ok(resp),
            }
        }
        ControlRequest::VaultUnlock { session_id, blob } => {
            if blob.session_id != session_id {
                return Ok(ResponseEnvelope::err(
                    request_id,
                    ProtocolErrorCode::UnlockSessionMismatch,
                    "unlock blob session mismatch",
                ));
            }
            match require_vault_session(state, request_id, &session_id) {
                Ok(()) => {}
                Err(resp) => return Ok(resp),
            }
            if state.unlock_blob_seen(&session_id, blob.nonce) {
                return Ok(ResponseEnvelope::err(
                    request_id,
                    ProtocolErrorCode::UnlockBlobReplay,
                    "unlock blob replay",
                ));
            }
            let binding_key = match state.auth.unlock_binding_key(&session_id.clone().into()) {
                Ok(key) => key,
                Err(SecurityError::SessionExpired(_)) => {
                    return Ok(ResponseEnvelope::err(
                        request_id,
                        ProtocolErrorCode::SessionInvalid,
                        "session expired",
                    ));
                }
                Err(SecurityError::UnknownSession(_)) => {
                    return Ok(ResponseEnvelope::err(
                        request_id,
                        ProtocolErrorCode::SessionInvalid,
                        "unknown session",
                    ));
                }
                Err(_) => {
                    return Ok(ResponseEnvelope::err(
                        request_id,
                        ProtocolErrorCode::InternalError,
                        "internal error",
                    ));
                }
            };
            let opened = match open_unlock_blob_full(&blob, &binding_key) {
                Ok(m) => m,
                Err(ProtocolError::Wire { code, message }) => {
                    return Ok(ResponseEnvelope::err(request_id, code, message));
                }
                Err(_) => {
                    return Ok(ResponseEnvelope::err(
                        request_id,
                        ProtocolErrorCode::UnlockBlobInvalid,
                        "unlock blob invalid",
                    ));
                }
            };
            match state.apply_vault_unlock_authorized(
                &opened.material,
                opened.min_generation,
                opened.restore_authorization.as_ref(),
            ) {
                Ok(generation) => {
                    state.mark_unlock_blob(&session_id, blob.nonce);
                    crate::observe::emit_vault_unlock(state, ctx_sess(&session_id));
                    Ok(ResponseEnvelope::ok(
                        request_id,
                        ControlResponse::VaultUnlock {
                            state: VaultStateWire::Unlocked,
                            generation,
                        },
                    ))
                }
                Err(ProtocolError::Wire { code, message }) => {
                    crate::observe::emit_vault_unlock_failed(state, ctx_sess(&session_id));
                    Ok(ResponseEnvelope::err(request_id, code, message))
                }
                Err(_) => {
                    crate::observe::emit_vault_unlock_failed(state, ctx_sess(&session_id));
                    Ok(ResponseEnvelope::err(
                        request_id,
                        ProtocolErrorCode::InternalError,
                        "internal error",
                    ))
                }
            }
        }
        req @ (ControlRequest::ClientKeyRegister { .. }
        | ControlRequest::ClientKeyGet { .. }
        | ControlRequest::ClientKeyRotate { .. }
        | ControlRequest::KeyEnvelopePut { .. }
        | ControlRequest::KeyEnvelopeGet { .. }
        | ControlRequest::GrantCreate { .. }
        | ControlRequest::GrantList { .. }
        | ControlRequest::GrantRevoke { .. }
        | ControlRequest::SealedColumnDeclare { .. }
        | ControlRequest::IdentityInviteCreate { .. }
        | ControlRequest::IdentityEnroll { .. }
        | ControlRequest::ClientAuthBegin { .. }
        | ControlRequest::ClientAuthFinish { .. }) => {
            Ok(crate::ownership_ops::handle(state, request_id, req))
        }
        req @ (ControlRequest::PrivilegeGrant { .. }
        | ControlRequest::PrivilegeRevoke { .. }
        | ControlRequest::PrivilegeList { .. }) => {
            Ok(crate::privilege_ops::handle(state, request_id, connection_id, req))
        }
        ControlRequest::StorageMigrateEncrypt {
            session_id,
            blob,
            purge_plaintext_backups,
        } => {
            if let Err(resp) = require_vault_session(state, request_id, &session_id) {
                return Ok(resp);
            }
            Ok(crate::storage_migration_ops::handle(
                state,
                request_id,
                connection_id,
                &session_id,
                &blob,
                purge_plaintext_backups,
            ))
        }
        ControlRequest::BackupCreate {
            session_id,
            backup_id,
            include_rowstore,
        } => Ok(crate::backup_ops::backup_create(
            state,
            request_id,
            connection_id,
            &session_id,
            &backup_id,
            include_rowstore,
        )),
        ControlRequest::BackupVerify {
            session_id,
            backup_id,
        } => Ok(crate::backup_ops::backup_verify(
            state,
            request_id,
            connection_id,
            &session_id,
            &backup_id,
        )),
        ControlRequest::BackupList { session_id } => Ok(crate::backup_ops::backup_list(
            state,
            request_id,
            connection_id,
            &session_id,
        )),
        ControlRequest::BackupRestore {
            session_id,
            backup_id,
            target_id,
        } => Ok(crate::backup_ops::backup_restore(
            state,
            request_id,
            connection_id,
            &session_id,
            &backup_id,
            &target_id,
        )),
        ControlRequest::BackupRecover {
            session_id,
            target_id,
        } => Ok(crate::backup_ops::backup_recover(
            state,
            request_id,
            connection_id,
            &session_id,
            &target_id,
        )),
        ControlRequest::BackupStatus {
            session_id,
            target_id,
        } => Ok(crate::backup_ops::backup_status(
            state,
            request_id,
            connection_id,
            &session_id,
            &target_id,
        )),
        ControlRequest::GetCapabilities => Ok(crate::runtime_ops::handle_runtime(
            state,
            request_id,
            ControlRequest::GetCapabilities,
        )),
        req @ (ControlRequest::ChannelList { .. }
        | ControlRequest::ChannelGet { .. }
        | ControlRequest::ChannelConfigure { .. }
        | ControlRequest::ChannelStart { .. }
        | ControlRequest::ChannelStop { .. }
        | ControlRequest::StreamList { .. }
        | ControlRequest::StreamGet { .. }
        | ControlRequest::StreamCreate { .. }
        | ControlRequest::StreamIngest { .. }
        | ControlRequest::TriggerList { .. }
        | ControlRequest::TriggerGet { .. }
        | ControlRequest::TriggerCreate { .. }
        | ControlRequest::EventList { .. }
        | ControlRequest::RuntimeSchema { .. }
        | ControlRequest::CatalogList { .. }
        | ControlRequest::DatabaseList { .. }
        | ControlRequest::SchemaList { .. }
        | ControlRequest::TableList { .. }
        | ControlRequest::TableGet { .. }
        | ControlRequest::ColumnList { .. }
        | ControlRequest::IndexList { .. }
        | ControlRequest::ConstraintList { .. }
        | ControlRequest::CreateTable { .. }
        | ControlRequest::DropTable { .. }
        | ControlRequest::RenameTable { .. }
        | ControlRequest::AddColumn { .. }
        | ControlRequest::AlterColumn { .. }
        | ControlRequest::DropColumn { .. }
        | ControlRequest::RenameColumn { .. }
        | ControlRequest::CreateIndex { .. }
        | ControlRequest::DropIndex { .. }) => {
            let session_id = runtime_session_id(&req);
            if let Err(resp) = require_vault_session(state, request_id, session_id) {
                return Ok(resp);
            }
            Ok(crate::runtime_ops::handle_runtime(state, request_id, req))
        }
    }
}

fn runtime_session_id(req: &ControlRequest) -> &str {
    match req {
        ControlRequest::ChannelList { session_id }
        | ControlRequest::ChannelGet { session_id, .. }
        | ControlRequest::ChannelConfigure { session_id, .. }
        | ControlRequest::ChannelStart { session_id, .. }
        | ControlRequest::ChannelStop { session_id, .. }
        | ControlRequest::StreamList { session_id }
        | ControlRequest::StreamGet { session_id, .. }
        | ControlRequest::StreamCreate { session_id, .. }
        | ControlRequest::StreamIngest { session_id, .. }
        | ControlRequest::TriggerList { session_id }
        | ControlRequest::TriggerGet { session_id, .. }
        | ControlRequest::TriggerCreate { session_id, .. }
        | ControlRequest::EventList { session_id, .. }
        | ControlRequest::RuntimeSchema { session_id }
        | ControlRequest::CatalogList { session_id }
        | ControlRequest::DatabaseList { session_id }
        | ControlRequest::SchemaList { session_id, .. }
        | ControlRequest::TableList { session_id, .. }
        | ControlRequest::TableGet { session_id, .. }
        | ControlRequest::ColumnList { session_id, .. }
        | ControlRequest::IndexList { session_id, .. }
        | ControlRequest::ConstraintList { session_id, .. }
        | ControlRequest::CreateTable { session_id, .. }
        | ControlRequest::DropTable { session_id, .. }
        | ControlRequest::RenameTable { session_id, .. }
        | ControlRequest::AddColumn { session_id, .. }
        | ControlRequest::AlterColumn { session_id, .. }
        | ControlRequest::DropColumn { session_id, .. }
        | ControlRequest::RenameColumn { session_id, .. }
        | ControlRequest::CreateIndex { session_id, .. }
        | ControlRequest::DropIndex { session_id, .. } => session_id,
        _ => "",
    }
}

fn vault_state_wire(state: VaultState) -> VaultStateWire {
    match state {
        VaultState::Locked => VaultStateWire::Locked,
        VaultState::Unlocked => VaultStateWire::Unlocked,
    }
}

fn require_vault_session(
    state: &CoreServerState,
    request_id: u64,
    session_id: &str,
) -> std::result::Result<(), ResponseEnvelope<ControlResponse>> {
    match state.auth.validate_session(&session_id.into()) {
        Ok(_) => Ok(()),
        Err(SecurityError::SessionExpired(_)) => Err(ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::SessionInvalid,
            "session expired",
        )),
        Err(SecurityError::UnknownSession(_)) => Err(ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::SessionInvalid,
            "unknown session",
        )),
        Err(err) => Err(ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::InternalError,
            err.to_string(),
        )),
    }
}

fn map_control_validation_err(
    request_id: u64,
    err: ProtocolError,
) -> ResponseEnvelope<ControlResponse> {
    match err {
        ProtocolError::Wire { code, message } => ResponseEnvelope::err(request_id, code, message),
        other => ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::InternalError,
            other.to_string(),
        ),
    }
}

fn map_limit_err_control(
    request_id: u64,
    err: ProtocolError,
) -> ResponseEnvelope<ControlResponse> {
    map_control_validation_err(request_id, err)
}

fn map_limit_err_data(request_id: u64, err: ProtocolError) -> ResponseEnvelope<DataResponse> {
    map_validation_err(request_id, err)
}

pub fn handle_data(
    state: &mut CoreServerState,
    env: RequestEnvelope<DataRequest>,
    limits: &RemoteLimits,
    connection_id: &str,
) -> Result<ResponseEnvelope<DataResponse>> {
    let start = std::time::Instant::now();
    let result = handle_data_inner(state, env, limits, connection_id);
    if let Ok(ref resp) = result {
        crate::metrics_rec::finish_request(state, resp.status.clone(), start.elapsed());
        if resp.error_code == Some(ProtocolErrorCode::SessionInvalid) {
            // Session validation failures may not emit sql.* events.
            crate::metrics_rec::session_invalid(state);
        }
    }
    result
}

fn handle_data_inner(
    state: &mut CoreServerState,
    env: RequestEnvelope<DataRequest>,
    limits: &RemoteLimits,
    connection_id: &str,
) -> Result<ResponseEnvelope<DataResponse>> {
    let request_id = env.request_id;
    if let Err(err) = validate_data_request(&env.body, limits) {
        return Ok(map_validation_err(request_id, err));
    }
    if !state.accepts_new_work() && !data_allowed_while_stopping(&env.body) {
        return Ok(ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::ConnectionClosed,
            "core shutting down",
        ));
    }
    if let Err(err) = state.try_begin_request() {
        return Ok(map_limit_err_data(request_id, err));
    }
    state.auth.begin_request(connection_id);
    let session_id = match &env.body {
        DataRequest::ExecuteSql { session_id, .. }
        | DataRequest::Begin { session_id }
        | DataRequest::Commit { session_id }
        | DataRequest::Rollback { session_id } => session_id.clone(),
    };
    let result = handle_data_body(state, env, limits, connection_id, request_id);
    state.sync_transaction_owner(&session_id);
    state.auth.end_request();
    state.end_in_flight_request();
    result
}

fn data_allowed_while_stopping(body: &DataRequest) -> bool {
    // Cooperative drain: finish open txn with COMMIT/ROLLBACK only — never new work.
    matches!(
        body,
        DataRequest::Commit { .. } | DataRequest::Rollback { .. }
    )
}

fn handle_data_body(
    state: &mut CoreServerState,
    env: RequestEnvelope<DataRequest>,
    _limits: &RemoteLimits,
    connection_id: &str,
    request_id: u64,
) -> Result<ResponseEnvelope<DataResponse>> {
    let body = env.body;
    let session_id = match &body {
        DataRequest::ExecuteSql { session_id, .. }
        | DataRequest::Begin { session_id }
        | DataRequest::Commit { session_id }
        | DataRequest::Rollback { session_id } => session_id.clone(),
    };

    let gate = state.session_gate(&session_id);
    let _guard = gate
        .lock()
        .map_err(|_| ProtocolError::wire(ProtocolErrorCode::InternalError, "session lock"))?;

    let principal = match state.auth.principal_for(&session_id.clone().into()) {
        Ok(p) => p,
        Err(SecurityError::SessionExpired(_)) => {
            return Ok(ResponseEnvelope::err(
                request_id,
                ProtocolErrorCode::SessionInvalid,
                "session expired",
            ));
        }
        Err(SecurityError::UnknownSession(_)) => {
            return Ok(ResponseEnvelope::err(
                request_id,
                ProtocolErrorCode::SessionInvalid,
                "unknown session",
            ));
        }
        Err(err) => {
            return Ok(ResponseEnvelope::err(
                request_id,
                ProtocolErrorCode::InternalError,
                err.to_string(),
            ));
        }
    };

    // F8: a transaction belongs to the session that opened it.
    if let Err(msg) = state.transaction_guard(&session_id) {
        return Ok(ResponseEnvelope::err(request_id, ProtocolErrorCode::TransactionConflict, msg));
    }

    // Session validated → correlation may include session_id (not an auth proof).
    let mk_ctx = |state: &CoreServerState| {
        crate::correlation::with_active_transaction(
            crate::correlation::context_for_request(connection_id, request_id, Some(&session_id)),
            state,
        )
    };

    // UnlockGate: vault must be unlocked before AuthZ / bind / execute.
    if let Err(err) = state.unlock_gate.require_unlocked() {
        crate::observe::emit_vault_denied(state, mk_ctx(state));
        return Ok(match err {
            ProtocolError::Wire { code, message } => {
                ResponseEnvelope::err(request_id, code, message)
            }
            other => ResponseEnvelope::err(
                request_id,
                ProtocolErrorCode::VaultLocked,
                other.to_string(),
            ),
        });
    }

    match body {
        DataRequest::ExecuteSql { sql, params, .. } => {
            crate::observe::emit_sql_request(state, mk_ctx(state), &sql, params.len());
            if !params.is_empty() {
                crate::observe::emit_sql_failed(
                    state,
                    mk_ctx(state),
                    &sql,
                    ProtocolErrorCode::InvalidRequest,
                );
                return Ok(ResponseEnvelope::err(
                    request_id,
                    ProtocolErrorCode::InvalidRequest,
                    "bound parameters not yet supported; send SQL text only",
                ));
            }
            let tip_before = crate::correlation::journal_tip(state);
            let txn_before = crate::correlation::active_transaction_id(state);
            match execute_authorized_sql(&sql, &state.auth, &principal, &mut state.ctx) {
                Ok(chunks) => {
                    let tip_after = crate::correlation::journal_tip(state);
                    let mut ctx = crate::correlation::context_for_request(
                        connection_id,
                        request_id,
                        Some(&session_id),
                    );
                    if let Some(tid) = crate::correlation::active_transaction_id(state).or(txn_before)
                    {
                        ctx = ctx.with_transaction_id(tid);
                    }
                    ctx = crate::correlation::with_sequence_if_appended(ctx, tip_before, tip_after);
                    crate::observe::emit_sql_completed(state, ctx, &sql);
                    Ok(ResponseEnvelope::ok(
                        request_id,
                        DataResponse::SqlResult(chunks_to_sql_result(&chunks)),
                    ))
                }
                Err(err) => {
                    let resp = map_exec_err(request_id, err);
                    if let Some(code) = resp.error_code {
                        crate::observe::emit_sql_failed(state, mk_ctx(state), &sql, code);
                    }
                    Ok(resp)
                }
            }
        }
        DataRequest::Begin { .. } => {
            crate::observe::emit_sql_request(state, mk_ctx(state), "BEGIN", 0);
            let tip_before = crate::correlation::journal_tip(state);
            match execute_authorized_sql("BEGIN", &state.auth, &principal, &mut state.ctx) {
                Ok(_) => {
                    let tip_after = crate::correlation::journal_tip(state);
                    let mut ctx = mk_ctx(state);
                    ctx = crate::correlation::with_sequence_if_appended(ctx, tip_before, tip_after);
                    crate::observe::emit_sql_completed(state, ctx, "BEGIN");
                    Ok(ResponseEnvelope::ok(request_id, DataResponse::Ok))
                }
                Err(err) => {
                    let resp = map_exec_err(request_id, err);
                    if let Some(code) = resp.error_code {
                        crate::observe::emit_sql_failed(state, mk_ctx(state), "BEGIN", code);
                    }
                    Ok(resp)
                }
            }
        }
        DataRequest::Commit { .. } => {
            let txn_before = crate::correlation::active_transaction_id(state);
            crate::observe::emit_sql_request(state, mk_ctx(state), "COMMIT", 0);
            let tip_before = crate::correlation::journal_tip(state);
            match execute_authorized_sql("COMMIT", &state.auth, &principal, &mut state.ctx) {
                Ok(_) => {
                    let tip_after = crate::correlation::journal_tip(state);
                    let mut ctx = crate::correlation::context_for_request(
                        connection_id,
                        request_id,
                        Some(&session_id),
                    );
                    if let Some(tid) = txn_before {
                        ctx = ctx.with_transaction_id(tid);
                    }
                    ctx = crate::correlation::with_sequence_if_appended(ctx, tip_before, tip_after);
                    crate::observe::emit_sql_completed(state, ctx, "COMMIT");
                    Ok(ResponseEnvelope::ok(request_id, DataResponse::Ok))
                }
                Err(err) => {
                    let resp = map_exec_err(request_id, err);
                    if let Some(code) = resp.error_code {
                        let mut ctx = mk_ctx(state);
                        if let Some(tid) = txn_before {
                            ctx = ctx.with_transaction_id(tid);
                        }
                        crate::observe::emit_sql_failed(state, ctx, "COMMIT", code);
                    }
                    Ok(resp)
                }
            }
        }
        DataRequest::Rollback { .. } => {
            let txn_before = crate::correlation::active_transaction_id(state);
            crate::observe::emit_sql_request(state, mk_ctx(state), "ROLLBACK", 0);
            let tip_before = crate::correlation::journal_tip(state);
            match execute_authorized_sql("ROLLBACK", &state.auth, &principal, &mut state.ctx) {
                Ok(_) => {
                    let tip_after = crate::correlation::journal_tip(state);
                    let mut ctx = crate::correlation::context_for_request(
                        connection_id,
                        request_id,
                        Some(&session_id),
                    );
                    if let Some(tid) = txn_before {
                        ctx = ctx.with_transaction_id(tid);
                    }
                    ctx = crate::correlation::with_sequence_if_appended(ctx, tip_before, tip_after);
                    crate::observe::emit_sql_completed(state, ctx, "ROLLBACK");
                    Ok(ResponseEnvelope::ok(request_id, DataResponse::Ok))
                }
                Err(err) => {
                    let resp = map_exec_err(request_id, err);
                    if let Some(code) = resp.error_code {
                        let mut ctx = mk_ctx(state);
                        if let Some(tid) = txn_before {
                            ctx = ctx.with_transaction_id(tid);
                        }
                        crate::observe::emit_sql_failed(state, ctx, "ROLLBACK", code);
                    }
                    Ok(resp)
                }
            }
        }
    }
}

fn map_validation_err(request_id: u64, err: ProtocolError) -> ResponseEnvelope<DataResponse> {
    match err {
        ProtocolError::Wire { code, message } => ResponseEnvelope::err(request_id, code, message),
        ProtocolError::FrameTooLarge(_) => ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::FrameTooLarge,
            "frame too large",
        ),
        _other => ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::InternalError,
            "internal error",
        ),
    }
}

fn map_exec_err(request_id: u64, err: ExecutionError) -> ResponseEnvelope<DataResponse> {
    match err {
        ExecutionError::AuthenticationFailed(msg) => ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::AuthenticationFailed,
            msg,
        ),
        ExecutionError::AuthorizationDenied(msg) => ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::AuthorizationDenied,
            msg,
        ),
        ExecutionError::SessionInvalid(msg) => {
            ResponseEnvelope::err(request_id, ProtocolErrorCode::SessionInvalid, msg)
        }
        ExecutionError::ConstraintViolation(msg) => ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::ConstraintViolation,
            msg,
        ),
        ExecutionError::WriteConflict(msg) => ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::TransactionConflict,
            msg,
        ),
        ExecutionError::InvalidPlan(msg) => {
            ResponseEnvelope::err(request_id, ProtocolErrorCode::InvalidSql, msg)
        }
        ExecutionError::Transaction(msg) => ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::TransactionConflict,
            msg,
        ),
        other => ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::ExecutionError,
            // Sanitize — ResponseEnvelope::err also sanitizes; avoid raw storage paths.
            other.to_string(),
        ),
    }
}

fn chunks_to_sql_result(chunks: &[dmc_sql_exec::DataChunk]) -> SqlResult {
    let rows = collect_rows(chunks);
    let columns = chunks
        .first()
        .map(|c| {
            (0..c.schema.len())
                .map(|idx| format!("col_{idx}"))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    SqlResult {
        columns,
        rows: rows
            .into_iter()
            .map(|row| dmc_protocol::SqlRow {
                cells: row.into_iter().map(value_to_cell).collect(),
            })
            .collect(),
    }
}

fn value_to_cell(value: Value) -> SqlCell {
    if value.is_null() {
        SqlCell {
            value: "NULL".into(),
            is_null: true,
            text: String::new(),
        }
    } else if let Value::Binary(bytes) = &value {
        // Lossless bytea-style hex (`\x…`), so sealed values survive the wire unchanged.
        let hex = format!("\\x{}", hex::encode(bytes));
        SqlCell {
            value: hex.clone(),
            is_null: false,
            text: hex,
        }
    } else {
        SqlCell {
            value: format!("{value:?}"),
            is_null: false,
            text: value_text(&value),
        }
    }
}

/// PostgreSQL text output of a non-NULL value (dates / timestamps are the engine's integer
/// encodings, rendered as such).
fn value_text(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Boolean(b) => if *b { "t" } else { "f" }.to_string(),
        Value::Int(n) | Value::BigInt(n) => n.to_string(),
        Value::Double(d) => d.to_string(),
        Value::String(s) | Value::Decimal(s) => s.clone(),
        Value::Binary(b) => format!("\\x{}", hex::encode(b)),
        Value::Date(d) => d.to_string(),
        Value::Timestamp(t) => t.to_string(),
    }
}

pub fn map_security_to_protocol(err: SecurityError) -> ProtocolError {
    match err {
        SecurityError::AuthenticationFailed(msg) => {
            ProtocolError::wire(ProtocolErrorCode::AuthenticationFailed, msg)
        }
        SecurityError::IdentityDisabled(msg) => {
            ProtocolError::wire(ProtocolErrorCode::AuthenticationFailed, msg)
        }
        SecurityError::UnknownIdentity(msg) => {
            ProtocolError::wire(ProtocolErrorCode::AuthenticationFailed, msg)
        }
        SecurityError::PermissionDenied(msg) => {
            ProtocolError::wire(ProtocolErrorCode::AuthorizationDenied, msg)
        }
        SecurityError::SessionExpired(msg) | SecurityError::UnknownSession(msg) => {
            ProtocolError::wire(ProtocolErrorCode::SessionInvalid, msg)
        }
        other => ProtocolError::wire(ProtocolErrorCode::InternalError, other.to_string()),
    }
}
