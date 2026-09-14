use thiserror::Error;

pub type Result<T> = std::result::Result<T, ProtocolError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u16)]
pub enum ProtocolErrorCode {
    AuthenticationFailed = 1,
    AuthorizationDenied = 2,
    SessionInvalid = 3,
    InvalidRequest = 4,
    InvalidFrame = 5,
    UnsupportedVersion = 6,
    ResourceNotFound = 7,
    ExecutionError = 8,
    InternalError = 9,
    FrameTooLarge = 10,
    ProtocolError = 11,
    TransportError = 12,
    InvalidSql = 13,
    ConstraintViolation = 14,
    TransactionConflict = 15,
    TlsHandshakeFailed = 16,
    CertificateInvalid = 17,
    CertificateExpired = 18,
    CertificateUntrusted = 19,
    HostnameMismatch = 20,
    ConnectionClosed = 21,
    VaultLocked = 22,
    UnlockFailed = 23,
    UnlockBlobInvalid = 24,
    UnlockBlobReplay = 25,
    UnlockSessionMismatch = 26,
    /// Plaintext `master_key_hex` / legacy Unlock is not a production path (7.6.4).
    LegacyUnlockDisabled = 27,
    BackupInvalid = 28,
    BackupTargetNotEmpty = 29,
    RecoveryNotReady = 30,
    BackupNotFound = 31,
}

impl ProtocolErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticationFailed => "AuthenticationFailed",
            Self::AuthorizationDenied => "AuthorizationDenied",
            Self::SessionInvalid => "SessionInvalid",
            Self::InvalidRequest => "InvalidRequest",
            Self::InvalidFrame => "InvalidFrame",
            Self::UnsupportedVersion => "UnsupportedVersion",
            Self::ResourceNotFound => "ResourceNotFound",
            Self::ExecutionError => "ExecutionError",
            Self::InternalError => "InternalError",
            Self::FrameTooLarge => "FrameTooLarge",
            Self::ProtocolError => "ProtocolError",
            Self::TransportError => "TransportError",
            Self::InvalidSql => "InvalidSql",
            Self::ConstraintViolation => "ConstraintViolation",
            Self::TransactionConflict => "TransactionConflict",
            Self::TlsHandshakeFailed => "TlsHandshakeFailed",
            Self::CertificateInvalid => "CertificateInvalid",
            Self::CertificateExpired => "CertificateExpired",
            Self::CertificateUntrusted => "CertificateUntrusted",
            Self::HostnameMismatch => "HostnameMismatch",
            Self::ConnectionClosed => "ConnectionClosed",
            Self::VaultLocked => "VaultLocked",
            Self::UnlockFailed => "UnlockFailed",
            Self::UnlockBlobInvalid => "UnlockBlobInvalid",
            Self::UnlockBlobReplay => "UnlockBlobReplay",
            Self::UnlockSessionMismatch => "UnlockSessionMismatch",
            Self::LegacyUnlockDisabled => "LegacyUnlockDisabled",
            Self::BackupInvalid => "BackupInvalid",
            Self::BackupTargetNotEmpty => "BackupTargetNotEmpty",
            Self::RecoveryNotReady => "RecoveryNotReady",
            Self::BackupNotFound => "BackupNotFound",
        }
    }
}

impl std::fmt::Display for ProtocolErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("{code}: {message}")]
    Wire {
        code: ProtocolErrorCode,
        message: String,
    },
    #[error("invalid frame: {0}")]
    InvalidFrame(String),
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(u32),
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("unknown message type {0}")]
    UnknownMessageType(u16),
    #[error("codec: {0}")]
    Codec(String),
    #[error("io: {0}")]
    Io(String),
}

impl ProtocolError {
    pub fn wire(code: ProtocolErrorCode, message: impl Into<String>) -> Self {
        Self::Wire {
            code,
            message: sanitize_client_message(message.into()),
        }
    }

    /// Internal failure with a fixed client-safe message (never forwards raw error chains).
    pub fn internal() -> Self {
        Self::wire(ProtocolErrorCode::InternalError, "internal error")
    }

    pub fn code(&self) -> Option<ProtocolErrorCode> {
        match self {
            Self::Wire { code, .. } => Some(*code),
            Self::FrameTooLarge(_) => Some(ProtocolErrorCode::FrameTooLarge),
            Self::UnsupportedVersion(_) => Some(ProtocolErrorCode::UnsupportedVersion),
            Self::UnknownMessageType(_) => Some(ProtocolErrorCode::InvalidFrame),
            Self::InvalidFrame(_) => Some(ProtocolErrorCode::InvalidFrame),
            Self::Codec(_) => Some(ProtocolErrorCode::ProtocolError),
            Self::Io(_) => Some(ProtocolErrorCode::InternalError),
        }
    }
}

/// Strip secret / path / crypto internals from client-visible error text (Phase 7.6.6).
pub fn sanitize_client_message(message: String) -> String {
    let lower = message.to_lowercase();
    let blocked = [
        "password",
        "keypass",
        "master key",
        "master_key",
        "masterkey",
        "unlockmaterial",
        "unlock_material",
        "unlock material",
        "private key",
        "ciphertext",
        "plaintext",
        "argon2",
        "key material",
        "keymaterial",
        ".pem",
        ".key",
        ".crt",
        ".dbs",
        "wrapped_dek",
        "unwrap",
    ];
    if blocked.iter().any(|p| lower.contains(p))
        || lower.split(|c: char| !c.is_ascii_alphanumeric()).any(|t| {
            matches!(t, "dek" | "kek")
        })
        || message.contains('/')
        || message.contains('\\')
        || looks_like_hex_secret(&lower)
    {
        return "request rejected".into();
    }
    if message.len() > 256 {
        message.chars().take(256).collect()
    } else {
        message
    }
}

fn looks_like_hex_secret(lower: &str) -> bool {
    // Contiguous hex ≥ 64 chars ≈ 32-byte key hex — not safe client text.
    // (UUIDs use dashes / shorter runs and must not trigger this.)
    let mut run = 0usize;
    for c in lower.chars() {
        if c.is_ascii_hexdigit() {
            run += 1;
            if run >= 64 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

impl From<postcard::Error> for ProtocolError {
    fn from(value: postcard::Error) -> Self {
        Self::Codec(value.to_string())
    }
}

impl From<std::io::Error> for ProtocolError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}
