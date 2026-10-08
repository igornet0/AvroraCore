//! D4-A stage 5 — explicit storage migration (plaintext pre-D4 SQL store → encrypted).
//!
//! * Never implicit: only this request migrates; opening a plaintext store fails with
//!   "explicit migration required".
//! * Keys arrive exactly as for `VaultUnlock` (unlock blob bound to this session, opened
//!   with the session's binding key, single use) — no new key-input path.
//! * Authority: the caller's session must hold `GRANT` on `system` (administrator).
//! * Fail closed: on refusal or failure the vault is locked again and the plaintext store
//!   is untouched; on success the vault is unlocked and the encrypted store is open.
//! * Audited (`audit.storage.migrated` / `audit.storage.migration_failed`,
//!   `audit.authorization.denied`): caller and outcome only — no paths, no values.
//! * Not part of `transport_policy`: DMC IPC only.

use dmc_observability::{AuditEvent, AuditEventKind, AuditResult};
use dmc_protocol::{
    ControlResponse, ProtocolError, ProtocolErrorCode, ResponseEnvelope, UnlockBlob,
};
use dmc_security::auth::{Action, Resource, SessionManager};

use crate::state::{CoreServerState, MigrationError};
use crate::unlock_blob::open_unlock_blob_anchored;

fn audit(
    state: &CoreServerState,
    kind: AuditEventKind,
    result: AuditResult,
    connection_id: &str,
    session_id: &str,
    caller: Option<&str>,
) {
    let mut ev = AuditEvent::new(kind, result).with_privilege("migrate storage");
    ev.connection_id = Some(connection_id.to_string());
    ev.session_id = Some(session_id.to_string());
    if let Some(c) = caller {
        ev = ev.with_principal_id(c);
    }
    state.audit.record(ev);
}

pub fn handle(
    state: &mut CoreServerState,
    request_id: u64,
    connection_id: &str,
    session_id: &str,
    blob: &UnlockBlob,
    purge_plaintext_backups: bool,
) -> ResponseEnvelope<ControlResponse> {
    let principal = state
        .auth
        .principal_for(&session_id.to_string().into())
        .ok();
    let caller = principal
        .as_ref()
        .map(|p| p.identity_id.as_str().to_string());
    let authorized = principal.as_ref().is_some_and(|p| {
        state
            .auth
            .grants()
            .has_grant(&p.identity_id, &Resource::System, Action::Grant)
    });
    if !authorized {
        audit(
            state,
            AuditEventKind::AuthorizationDenied,
            AuditResult::Denied,
            connection_id,
            session_id,
            caller.as_deref(),
        );
        return ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::AuthorizationDenied,
            "storage migration not allowed",
        );
    }

    if blob.session_id != session_id {
        return ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::UnlockSessionMismatch,
            "unlock blob session mismatch",
        );
    }
    if state.unlock_blob_seen(session_id, blob.nonce) {
        return ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::UnlockBlobReplay,
            "unlock blob replay",
        );
    }
    let binding_key = match state
        .auth
        .unlock_binding_key(&session_id.to_string().into())
    {
        Ok(key) => key,
        Err(_) => {
            return ResponseEnvelope::err(
                request_id,
                ProtocolErrorCode::SessionInvalid,
                "session invalid",
            );
        }
    };
    let (material, min_generation) = match open_unlock_blob_anchored(blob, &binding_key) {
        Ok(m) => m,
        Err(ProtocolError::Wire { code, message }) => {
            return ResponseEnvelope::err(request_id, code, message);
        }
        Err(_) => {
            return ResponseEnvelope::err(
                request_id,
                ProtocolErrorCode::UnlockBlobInvalid,
                "unlock blob invalid",
            );
        }
    };
    // single use, whatever the outcome
    state.mark_unlock_blob(session_id, blob.nonce);

    match state.migrate_storage(&material, purge_plaintext_backups, min_generation) {
        Ok(report) => {
            audit(
                state,
                AuditEventKind::StorageMigrated,
                AuditResult::Success,
                connection_id,
                session_id,
                caller.as_deref(),
            );
            ResponseEnvelope::ok(
                request_id,
                ControlResponse::StorageMigrateEncrypt {
                    events: report.events,
                    tables: report.tables,
                    purged_artifacts: report.purged_artifacts,
                },
            )
        }
        Err(e) => {
            audit(
                state,
                AuditEventKind::StorageMigrationFailed,
                AuditResult::Failure,
                connection_id,
                session_id,
                caller.as_deref(),
            );
            match e {
                MigrationError::Refused(reason) => ResponseEnvelope::err(
                    request_id,
                    ProtocolErrorCode::InvalidRequest,
                    dmc_protocol::sanitize_client_message(format!(
                        "storage migration refused: {reason}"
                    )),
                ),
                MigrationError::Failed(_) => ResponseEnvelope::err(
                    request_id,
                    ProtocolErrorCode::InternalError,
                    "storage migration failed; nothing was changed",
                ),
            }
        }
    }
}
