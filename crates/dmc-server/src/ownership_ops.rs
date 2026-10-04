//! CLIENT_OWNED key management over DMC IPC.
//!
//! The server stores and returns only public keys, HPKE envelopes and grants
//! (`dmc_security::ownership::ClientKeyDirectory`). No request or response carries a
//! private key, root, recovery code or plaintext DEK, and nothing here can open an
//! envelope: this crate does not depend on any HPKE/X25519 private-key implementation.
//! All checks are identity-level (session, custody, subject, tenant) plus structural
//! validation; the server never asserts that a fingerprint is "trusted".

use dmc_protocol::{ClientGrantWire, ControlRequest, ControlResponse, ProtocolErrorCode, ResponseEnvelope};
use dmc_security::auth::SessionManager;
use dmc_security::Error as SecurityError;

use crate::state::CoreServerState;

/// Transport label inside challenges. The HTTP and control-plane adapters reuse this
/// dispatcher; their requests carry their own channel ids (`http:`, `control:` prefixes),
/// so a challenge is still bound to the exact transport channel.
const TRANSPORT: &str = "avrora-core";

fn sid(s: &str) -> dmc_security::SessionId {
    s.to_string().into()
}

fn map_err(request_id: u64, err: SecurityError) -> ResponseEnvelope<ControlResponse> {
    let (code, msg) = match &err {
        SecurityError::UnknownSession(_) | SecurityError::SessionExpired(_) => {
            (ProtocolErrorCode::SessionInvalid, "session invalid".to_string())
        }
        SecurityError::IdentityDisabled(_) => {
            (ProtocolErrorCode::AuthenticationFailed, "identity disabled".to_string())
        }
        // one message for every authentication/enrollment failure (no oracle)
        SecurityError::AuthenticationFailed(_) => {
            (ProtocolErrorCode::AuthenticationFailed, "authentication failed".to_string())
        }
        SecurityError::KeyAccessDenied(m) => (ProtocolErrorCode::AuthorizationDenied, m.clone()),
        SecurityError::Conflict(m) => (ProtocolErrorCode::InvalidRequest, m.clone()),
        SecurityError::Ownership(e) => (ProtocolErrorCode::InvalidRequest, e.to_string()),
        _ => (ProtocolErrorCode::InternalError, "key directory error".to_string()),
    };
    ResponseEnvelope::err(request_id, code, msg)
}

pub fn handle(
    state: &mut CoreServerState,
    request_id: u64,
    req: ControlRequest,
) -> ResponseEnvelope<ControlResponse> {
    let result = handle_inner(state, request_id, req);
    match result {
        Ok(resp) => resp,
        Err(e) => map_err(request_id, e),
    }
}

fn handle_inner(
    state: &mut CoreServerState,
    request_id: u64,
    req: ControlRequest,
) -> Result<ResponseEnvelope<ControlResponse>, SecurityError> {
    let ok = |body| Ok(ResponseEnvelope::ok(request_id, body));
    match req {
        ControlRequest::ClientKeyRegister { session_id, key } => {
            let (key_id, key_version) = (key.key_id(), key.key_version);
            let (auth, dir) = state.auth_and_client_key_dir()?;
            dir.register_public_key(auth, &sid(&session_id), key)?;
            ok(ControlResponse::ClientKeyAck { key_id, key_version })
        }
        ControlRequest::ClientKeyRotate { session_id, key, proof } => {
            let (key_id, key_version) = (key.key_id(), key.key_version);
            let (auth, dir) = state.auth_and_client_key_dir()?;
            dir.rotate_public_key(auth, &sid(&session_id), key, &proof)?;
            ok(ControlResponse::ClientKeyAck { key_id, key_version })
        }
        ControlRequest::IdentityInviteCreate {
            session_id,
            name,
            tenant,
            ttl_ms,
        } => {
            let (auth, _dir, invites) = state.ownership_parts()?;
            let issued = invites.create(auth, &sid(&session_id), &name, tenant, ttl_ms)?;
            ok(ControlResponse::IdentityInvite {
                invite_id: issued.invite_id.clone(),
                token: issued.token.to_vec(),
                name: issued.name.clone(),
                tenant: issued.tenant.clone(),
                subject: issued.subject,
                expires_at_ms: issued.expires_at_ms,
            })
        }
        ControlRequest::IdentityEnroll {
            invite_id,
            token,
            key,
            signature,
        } => {
            let key_id = key.key_id();
            let (auth, dir, invites) = state.ownership_parts()?;
            let (identity_id, subject) = invites.enroll(auth, dir, &invite_id, &token, key, &signature)?;
            state.persist_identities()?;
            ok(ControlResponse::IdentityEnrolled {
                identity_id: identity_id.as_str().to_string(),
                subject,
                key_id,
            })
        }
        ControlRequest::ClientAuthBegin { subject, tenant } => {
            let (auth, dir, _) = state.ownership_parts()?;
            let challenge = auth.client_auth_begin(dir, TRANSPORT, subject, tenant)?;
            ok(ControlResponse::ClientAuthChallenge { challenge })
        }
        ControlRequest::ClientAuthFinish { nonce, signature } => {
            let nonce: [u8; 32] = nonce
                .as_slice()
                .try_into()
                .map_err(|_| SecurityError::AuthenticationFailed("malformed".into()))?;
            let (auth, dir, _) = state.ownership_parts()?;
            let session = auth.client_auth_finish(dir, TRANSPORT, nonce, &signature)?;
            ok(ControlResponse::ClientAuthOk {
                session_id: session.id.as_str().to_string(),
                expires_at_ms: session.expires_at_ms,
                key_version: session.auth_key_version.unwrap_or_default(),
            })
        }
        ControlRequest::ClientKeyGet { session_id, subject } => {
            let (auth, dir) = state.auth_and_client_key_dir()?;
            let keys = dir.public_keys(auth, &sid(&session_id), subject)?;
            ok(ControlResponse::ClientKeys { keys })
        }
        ControlRequest::KeyEnvelopePut { session_id, envelope } => {
            let (auth, dir) = state.auth_and_client_key_dir()?;
            dir.put_envelope(auth, &sid(&session_id), envelope)?;
            ok(ControlResponse::KeyEnvelopeAck)
        }
        ControlRequest::KeyEnvelopeGet { session_id } => {
            let (auth, dir) = state.auth_and_client_key_dir()?;
            let envelopes = dir.envelopes_for(auth, &sid(&session_id))?;
            ok(ControlResponse::KeyEnvelopes { envelopes })
        }
        ControlRequest::GrantCreate {
            session_id,
            grantee,
            expires_at_ms,
        } => {
            let (auth, dir) = state.auth_and_client_key_dir()?;
            dir
                .grant(auth, &sid(&session_id), grantee, expires_at_ms)?;
            ok(ControlResponse::GrantAck { changed: true })
        }
        ControlRequest::GrantList { session_id } => {
            let (auth, dir) = state.auth_and_client_key_dir()?;
            let grants = dir
                .list_grants(auth, &sid(&session_id))?
                .into_iter()
                .map(|g| ClientGrantWire {
                    owner: g.owner,
                    grantee: g.grantee,
                    tenant: g.tenant,
                    granted_at_ms: g.granted_at_ms,
                    expires_at_ms: g.expires_at_ms,
                })
                .collect();
            ok(ControlResponse::Grants { grants })
        }
        ControlRequest::GrantRevoke { session_id, grantee } => {
            let (auth, dir) = state.auth_and_client_key_dir()?;
            let changed = dir.revoke(auth, &sid(&session_id), grantee)?;
            ok(ControlResponse::GrantAck { changed })
        }
        ControlRequest::SealedColumnDeclare {
            session_id,
            schema,
            table,
            column,
            owner_column,
        } => Ok(declare_sealed_column(
            state,
            request_id,
            &session_id,
            &schema,
            &table,
            &column,
            owner_column.as_deref(),
        )),
        _ => Err(SecurityError::Conflict("not a key-management request".into())),
    }
}

fn declare_sealed_column(
    state: &mut CoreServerState,
    request_id: u64,
    session_id: &str,
    schema: &str,
    table: &str,
    column: &str,
    owner_column: Option<&str>,
) -> ResponseEnvelope<ControlResponse> {
    if let Err(err) = state.unlock_gate.require_unlocked() {
        return match err {
            dmc_protocol::ProtocolError::Wire { code, message } => ResponseEnvelope::err(request_id, code, message),
            other => ResponseEnvelope::err(request_id, ProtocolErrorCode::VaultLocked, other.to_string()),
        };
    }
    let principal = match state.auth.principal_for(&sid(session_id)) {
        Ok(p) => p,
        Err(_) => return ResponseEnvelope::err(request_id, ProtocolErrorCode::SessionInvalid, "invalid session"),
    };
    let catalog = match state.ctx.journal_mut() {
        Some(j) => j.catalog(),
        None => return ResponseEnvelope::err(request_id, ProtocolErrorCode::InternalError, "no journal"),
    };
    let Some(schema_entry) = catalog.schemas().find(|s| s.name == schema) else {
        return ResponseEnvelope::err(request_id, ProtocolErrorCode::ResourceNotFound, "unknown schema");
    };
    let Some(database) = catalog.database(schema_entry.database_id).map(|d| d.name.clone()) else {
        return ResponseEnvelope::err(request_id, ProtocolErrorCode::ResourceNotFound, "unknown database");
    };
    if state
        .auth
        .authorizer()
        .authorize_table(&principal, &database, schema, table, dmc_security::auth::Action::Create)
        .is_err()
    {
        return ResponseEnvelope::err(request_id, ProtocolErrorCode::AuthorizationDenied, "not allowed");
    }
    let Some(t) = catalog.table_by_name(schema_entry.id, table) else {
        return ResponseEnvelope::err(request_id, ProtocolErrorCode::ResourceNotFound, "unknown table");
    };
    let find = |name: &str| t.columns.iter().find(|c| c.name == name).map(|c| c.id.raw());
    let Some(column_id) = find(column) else {
        return ResponseEnvelope::err(request_id, ProtocolErrorCode::ResourceNotFound, "unknown column");
    };
    let owner_column_id = match owner_column {
        Some(name) => match find(name) {
            Some(id) => Some(id),
            None => return ResponseEnvelope::err(request_id, ProtocolErrorCode::ResourceNotFound, "unknown owner column"),
        },
        None => None,
    };
    let rule = dmc_materialized::protect::SealedColumnRule {
        table_id: t.id.raw(),
        column_id,
        owner_column_id,
    };
    match state.ctx.journal_mut().map(|j| j.declare_sealed_column(rule)) {
        Some(Ok(())) => ResponseEnvelope::ok(request_id, ControlResponse::SealedColumnAck),
        Some(Err(e)) => ResponseEnvelope::err(request_id, ProtocolErrorCode::ConstraintViolation, e.to_string()),
        None => ResponseEnvelope::err(request_id, ProtocolErrorCode::InternalError, "no journal"),
    }
}
