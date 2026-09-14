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
        | ControlRequest::BackupStatus { session_id, .. } => {
            if session_id.is_empty() {
                return Err(ProtocolError::wire(
                    ProtocolErrorCode::InvalidRequest,
                    "missing session id",
                ));
            }
        }
        _ => {}
    }
    Ok(())
}
