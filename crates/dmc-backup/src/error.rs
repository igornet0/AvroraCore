use thiserror::Error;

pub type Result<T> = std::result::Result<T, BackupError>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BackupError {
    #[error("inconsistent checkpoint: journal tip {journal_tip}, materialized watermark {watermark}")]
    InconsistentCheckpoint { journal_tip: u64, watermark: u64 },

    #[error("backup validation failed: {0}")]
    Validation(String),

    #[error("backup invalid: {0}")]
    BackupInvalid(String),

    #[error("restore target not empty: {0}")]
    TargetNotEmpty(String),

    #[error("recovery not ready: {0}")]
    RecoveryNotReady(String),

    #[error("recovery checkpoint mismatch: {component} expected {expected}, got {got}")]
    RecoveryCheckpointMismatch {
        component: String,
        expected: u64,
        got: u64,
    },

    #[error("backup io: {0}")]
    Io(String),

    #[error("backup corrupt: {0}")]
    Corrupt(String),

    #[error("backup already exists")]
    AlreadyExists,

    #[error("internal error")]
    Internal,
}
