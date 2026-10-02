use crate::error::ProtocolErrorCode;
use crate::limits::RemoteLimits;
use crate::message::{ControlRequest, DataRequest};
use crate::unlock_blob::validate_unlock_blob;
use crate::{ProtocolError, Result};

pub fn validate_data_request(body: &DataRequest, limits: &RemoteLimits) -> Result<()> {
    match body {
        DataRequest::ExecuteSql { sql, params, .. } => {
            if sql.len() as u32 > limits.max_sql_size {
                return Err(ProtocolError::wire(
                    ProtocolErrorCode::InvalidRequest,
                    "sql too large",
                ));
            }
            if params.len() as u32 > limits.max_params {
                return Err(ProtocolError::wire(
                    ProtocolErrorCode::InvalidRequest,
                    "too many parameters",
                ));
            }
            for param in params {
                if param.value.len() as u32 > limits.max_parameter_size {
                    return Err(ProtocolError::wire(
                        ProtocolErrorCode::InvalidRequest,
                        "parameter too large",
                    ));
                }
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn validate_control_request(body: &ControlRequest, limits: &RemoteLimits) -> Result<()> {
    match body {
        ControlRequest::VaultUnlock { blob, session_id } => {
            if blob.session_id != *session_id {
                return Err(ProtocolError::wire(
                    ProtocolErrorCode::UnlockSessionMismatch,
                    "unlock blob session mismatch",
                ));
            }
            validate_unlock_blob(blob, limits.max_unlock_blob_size)?;
        }
        ControlRequest::VaultStatus { session_id }
        | ControlRequest::VaultLock { session_id }
        | ControlRequest::Logout { session_id }
        | ControlRequest::BackupCreate { session_id, .. }
        | ControlRequest::BackupVerify { session_id, .. }
        | ControlRequest::BackupList { session_id }
        | ControlRequest::BackupRestore { session_id, .. }
        | ControlRequest::BackupRecover { session_id, .. }
        | ControlRequest::BackupStatus { session_id, .. }
        | ControlRequest::ChannelList { session_id }
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
        | ControlRequest::DropIndex { session_id, .. } => {
            if session_id.is_empty() {
                return Err(ProtocolError::wire(
                    ProtocolErrorCode::InvalidRequest,
                    "missing session id",
                ));
            }
        }
        ControlRequest::GetCapabilities | ControlRequest::Health | ControlRequest::Readiness
        | ControlRequest::Diagnostics | ControlRequest::Authenticate { .. }
        | ControlRequest::SessionInfo { .. } => {}
    }
    validate_runtime_fields(body, limits)
}

fn validate_runtime_fields(body: &ControlRequest, limits: &RemoteLimits) -> Result<()> {
    let max_id = limits.max_runtime_id_len as usize;
    let check_id = |id: &str| -> Result<()> {
        if id.is_empty() || id.len() > max_id {
            return Err(ProtocolError::wire(
                ProtocolErrorCode::InvalidRequest,
                "invalid runtime id",
            ));
        }
        Ok(())
    };
    match body {
        ControlRequest::ChannelGet { id, .. }
        | ControlRequest::ChannelStart { id, .. }
        | ControlRequest::ChannelStop { id, .. }
        | ControlRequest::StreamGet { id, .. }
        | ControlRequest::TriggerGet { id, .. } => check_id(id),
        ControlRequest::ChannelConfigure { spec, .. } => check_id(&spec.id),
        ControlRequest::StreamCreate { spec, .. } => {
            check_id(&spec.id)?;
            check_id(&spec.channel_id)
        }
        ControlRequest::StreamIngest {
            stream_id, payload, ..
        } => {
            check_id(stream_id)?;
            if payload.len() as u32 > limits.max_ingest_payload {
                return Err(ProtocolError::wire(
                    ProtocolErrorCode::InvalidRequest,
                    "ingest payload too large",
                ));
            }
            Ok(())
        }
        ControlRequest::TriggerCreate { def, .. } => {
            check_id(&def.id)?;
            check_id(&def.action.stream_id)
        }
        _ => Ok(()),
    }
}
