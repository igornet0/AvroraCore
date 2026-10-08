//! Network privilege administration (DMC IPC only).
//!
//! * Authority: the caller's session must hold `GRANT` on `system`; nobody may grant to or
//!   revoke from itself (checked in `dmc_security::auth::AuthService`).
//! * Every change is persisted with the identity directory before it is acknowledged; if
//!   the write fails, the in-memory change is undone and the request fails.
//! * Every change and every refusal is audited (`audit.privilege.*`,
//!   `audit.authorization.denied`): caller, grantee, privilege — never secrets.
//! * Not part of `transport_policy`: the HTTP adapter and the control-plane tunnel never
//!   forward these requests.

use dmc_observability::{AuditEvent, AuditEventKind, AuditResult};
use dmc_protocol::{
    ControlRequest, ControlResponse, PrivilegeActionWire, PrivilegeResourceWire, PrivilegeWire, ProtocolErrorCode,
    ResponseEnvelope,
};
use dmc_security::auth::{Action, Resource, SessionManager};
use dmc_security::Error as SecurityError;

use crate::state::CoreServerState;

pub fn resource_from_wire(r: &PrivilegeResourceWire) -> Resource {
    match r {
        PrivilegeResourceWire::System => Resource::System,
        PrivilegeResourceWire::Database { name } => Resource::database(name),
        PrivilegeResourceWire::Schema { database, name } => Resource::schema(database, name),
        PrivilegeResourceWire::Table { database, schema, name } => Resource::table(database, schema, name),
    }
}

pub fn resource_to_wire(r: &Resource) -> PrivilegeResourceWire {
    match r {
        Resource::System => PrivilegeResourceWire::System,
        Resource::Database { name } => PrivilegeResourceWire::Database { name: name.clone() },
        Resource::Schema { database, name } => PrivilegeResourceWire::Schema {
            database: database.clone(),
            name: name.clone(),
        },
        Resource::Table { database, schema, name } => PrivilegeResourceWire::Table {
            database: database.clone(),
            schema: schema.clone(),
            name: name.clone(),
        },
    }
}

pub fn action_from_wire(a: PrivilegeActionWire) -> Action {
    match a {
        PrivilegeActionWire::Connect => Action::Connect,
        PrivilegeActionWire::Usage => Action::Usage,
        PrivilegeActionWire::Select => Action::Select,
        PrivilegeActionWire::Insert => Action::Insert,
        PrivilegeActionWire::Update => Action::Update,
        PrivilegeActionWire::Delete => Action::Delete,
        PrivilegeActionWire::Create => Action::Create,
        PrivilegeActionWire::Drop => Action::Drop,
        PrivilegeActionWire::Grant => Action::Grant,
    }
}

pub fn action_to_wire(a: Action) -> PrivilegeActionWire {
    match a {
        Action::Connect => PrivilegeActionWire::Connect,
        Action::Usage => PrivilegeActionWire::Usage,
        Action::Select => PrivilegeActionWire::Select,
        Action::Insert => PrivilegeActionWire::Insert,
        Action::Update => PrivilegeActionWire::Update,
        Action::Delete => PrivilegeActionWire::Delete,
        Action::Create => PrivilegeActionWire::Create,
        Action::Drop => PrivilegeActionWire::Drop,
        Action::Grant => PrivilegeActionWire::Grant,
    }
}

fn caller_id(state: &CoreServerState, session_id: &str) -> Option<String> {
    state
        .auth
        .principal_for(&session_id.to_string().into())
        .ok()
        .map(|p| p.identity_id.as_str().to_string())
}

fn audit(
    state: &CoreServerState,
    kind: AuditEventKind,
    result: AuditResult,
    connection_id: &str,
    session_id: &str,
    caller: Option<&str>,
    target: Option<&str>,
    privilege: &str,
) {
    let mut ev = AuditEvent::new(kind, result).with_privilege(privilege);
    ev.connection_id = Some(connection_id.to_string());
    ev.session_id = Some(session_id.to_string());
    if let Some(c) = caller {
        ev = ev.with_principal_id(c);
    }
    if let Some(t) = target {
        ev = ev.with_target_id(t);
    }
    state.audit.record(ev);
}

fn denied(request_id: u64, err: &SecurityError) -> ResponseEnvelope<ControlResponse> {
    let code = match err {
        SecurityError::UnknownSession(_) | SecurityError::SessionExpired(_) => ProtocolErrorCode::SessionInvalid,
        SecurityError::PermissionDenied(_) => ProtocolErrorCode::AuthorizationDenied,
        _ => ProtocolErrorCode::InternalError,
    };
    let msg = match code {
        ProtocolErrorCode::SessionInvalid => "session invalid",
        ProtocolErrorCode::AuthorizationDenied => "privilege change not allowed",
        _ => "privilege change failed",
    };
    ResponseEnvelope::err(request_id, code, msg)
}

pub fn handle(
    state: &mut CoreServerState,
    request_id: u64,
    connection_id: &str,
    req: ControlRequest,
) -> ResponseEnvelope<ControlResponse> {
    match req {
        ControlRequest::PrivilegeGrant {
            session_id,
            grantee,
            privilege,
        } => change(state, request_id, connection_id, &session_id, &grantee, &privilege, true),
        ControlRequest::PrivilegeRevoke {
            session_id,
            grantee,
            privilege,
        } => change(state, request_id, connection_id, &session_id, &grantee, &privilege, false),
        ControlRequest::PrivilegeList { session_id, identity } => {
            match state.auth.list_privileges(&session_id.clone().into(), &identity) {
                Ok(list) => ResponseEnvelope::ok(
                    request_id,
                    ControlResponse::Privileges {
                        privileges: list
                            .iter()
                            .map(|(r, a)| PrivilegeWire {
                                resource: resource_to_wire(r),
                                action: action_to_wire(*a),
                            })
                            .collect(),
                    },
                ),
                Err(e) => denied(request_id, &e),
            }
        }
        _ => ResponseEnvelope::err(request_id, ProtocolErrorCode::InvalidRequest, "not a privilege request"),
    }
}

fn change(
    state: &mut CoreServerState,
    request_id: u64,
    connection_id: &str,
    session_id: &str,
    grantee: &str,
    privilege: &PrivilegeWire,
    grant: bool,
) -> ResponseEnvelope<ControlResponse> {
    let resource = resource_from_wire(&privilege.resource);
    let action = action_from_wire(privilege.action);
    let label = format!("{action} {resource}");
    let caller = caller_id(state, session_id);
    let sid = session_id.to_string().into();
    let outcome = if grant {
        state.auth.grant_privilege(&sid, grantee, resource.clone(), action)
    } else {
        state.auth.revoke_privilege(&sid, grantee, &resource, action)
    };
    let (changed, target) = match outcome {
        Ok(v) => v,
        Err(e) => {
            audit(
                state,
                AuditEventKind::AuthorizationDenied,
                AuditResult::Denied,
                connection_id,
                session_id,
                caller.as_deref(),
                None,
                &label,
            );
            return denied(request_id, &e);
        }
    };
    if changed {
        if state.persist_identities().is_err() {
            // undo: an unpersisted privilege change must not take effect
            if grant {
                state.auth.grants_mut().revoke(&target, &resource, action);
            } else {
                state.auth.grants_mut().grant(target.clone(), resource, action);
            }
            return ResponseEnvelope::err(request_id, ProtocolErrorCode::InternalError, "privilege change not persisted");
        }
        audit(
            state,
            if grant {
                AuditEventKind::PrivilegeGranted
            } else {
                AuditEventKind::PrivilegeRevoked
            },
            AuditResult::Success,
            connection_id,
            session_id,
            caller.as_deref(),
            Some(target.as_str()),
            &label,
        );
    }
    ResponseEnvelope::ok(request_id, ControlResponse::PrivilegeAck { changed })
}
