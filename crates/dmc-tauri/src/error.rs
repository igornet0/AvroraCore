use serde::{Deserialize, Serialize};
use thiserror::Error;

use dmc_client::{ClientError, ProtocolErrorCode};

pub type Result<T> = std::result::Result<T, FrontendError>;

/// Stable frontend error model (7.7.7). Messages are sanitized / non-secret.
#[derive(Clone, Debug, PartialEq, Eq, Error, Serialize, Deserialize)]
#[error("{code}: {message}")]
pub struct FrontendError {
    pub code: FrontendErrorCode,
    pub message: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum FrontendErrorCode {
    NotConnected,
    AuthenticationFailed,
    SessionInvalid,
    VaultLocked,
    UnlockFailed,
    AuthorizationDenied,
    InvalidSql,
    TransactionConflict,
    TransportError,
    BackupInvalid,
    BackupTargetNotEmpty,
    RecoveryNotReady,
    BackupNotFound,
    InternalError,
}

impl std::fmt::Display for FrontendErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotConnected => "NotConnected",
            Self::AuthenticationFailed => "AuthenticationFailed",
            Self::SessionInvalid => "SessionInvalid",
            Self::VaultLocked => "VaultLocked",
            Self::UnlockFailed => "UnlockFailed",
            Self::AuthorizationDenied => "AuthorizationDenied",
            Self::InvalidSql => "InvalidSql",
            Self::TransactionConflict => "TransactionConflict",
            Self::TransportError => "TransportError",
            Self::BackupInvalid => "BackupInvalid",
            Self::BackupTargetNotEmpty => "BackupTargetNotEmpty",
            Self::RecoveryNotReady => "RecoveryNotReady",
            Self::BackupNotFound => "BackupNotFound",
            Self::InternalError => "InternalError",
        })
    }
}

impl FrontendError {
    pub fn new(code: FrontendErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: sanitize(message.into()),
        }
    }

    pub fn from_client(err: ClientError) -> Self {
        if let Some(code) = err.protocol_code() {
            return Self::from_protocol_code(code, err.to_string());
        }
        match err {
            ClientError::NotConnected | ClientError::AlreadyConnected => {
                Self::new(FrontendErrorCode::NotConnected, err.to_string())
            }
            ClientError::NotAuthenticated => {
                Self::new(FrontendErrorCode::SessionInvalid, err.to_string())
            }
            ClientError::KeyPass(_) => {
                Self::new(FrontendErrorCode::UnlockFailed, "unlock failed")
            }
            ClientError::LocalUnsupported => {
                Self::new(FrontendErrorCode::TransportError, err.to_string())
            }
            ClientError::Protocol(_)
            | ClientError::UnexpectedControl
            | ClientError::UnexpectedData
            | ClientError::Message(_) => {
                Self::new(FrontendErrorCode::InternalError, err.to_string())
            }
        }
    }

    pub fn from_protocol_code(code: ProtocolErrorCode, message: impl Into<String>) -> Self {
        let mapped = match code {
            ProtocolErrorCode::AuthenticationFailed => FrontendErrorCode::AuthenticationFailed,
            ProtocolErrorCode::SessionInvalid => FrontendErrorCode::SessionInvalid,
            ProtocolErrorCode::VaultLocked => FrontendErrorCode::VaultLocked,
            ProtocolErrorCode::UnlockFailed
            | ProtocolErrorCode::UnlockBlobInvalid
            | ProtocolErrorCode::UnlockBlobReplay
            | ProtocolErrorCode::UnlockSessionMismatch
            | ProtocolErrorCode::LegacyUnlockDisabled => FrontendErrorCode::UnlockFailed,
            ProtocolErrorCode::AuthorizationDenied => FrontendErrorCode::AuthorizationDenied,
            ProtocolErrorCode::InvalidSql => FrontendErrorCode::InvalidSql,
            ProtocolErrorCode::TransactionConflict => FrontendErrorCode::TransactionConflict,
            ProtocolErrorCode::TransportError
            | ProtocolErrorCode::TlsHandshakeFailed
            | ProtocolErrorCode::CertificateInvalid
            | ProtocolErrorCode::CertificateExpired
            | ProtocolErrorCode::CertificateUntrusted
            | ProtocolErrorCode::HostnameMismatch
            | ProtocolErrorCode::ConnectionClosed => FrontendErrorCode::TransportError,
            ProtocolErrorCode::BackupInvalid => FrontendErrorCode::BackupInvalid,
            ProtocolErrorCode::BackupTargetNotEmpty => FrontendErrorCode::BackupTargetNotEmpty,
            ProtocolErrorCode::RecoveryNotReady => FrontendErrorCode::RecoveryNotReady,
            ProtocolErrorCode::BackupNotFound => FrontendErrorCode::BackupNotFound,
            _ => FrontendErrorCode::InternalError,
        };
        Self::new(mapped, message)
    }
}

fn sanitize(message: String) -> String {
    let lower = message.to_lowercase();
    // Strip obvious secret / path leakage; keep protocol semantics in `code`.
    if lower.contains("master_key")
        || lower.contains("unlockmaterial")
        || lower.contains("unlock_binding")
        || lower.contains("keytree")
        || lower.contains("/users/")
        || lower.contains("/home/")
        || lower.contains("c:\\")
    {
        return "internal error".into();
    }
    message
}
