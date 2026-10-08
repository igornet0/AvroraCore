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

    /// D4-A: the artifact is encrypted and the operation needs the storage keys
    /// (vault unlocked). Never satisfied by reading the artifact as plaintext.
    #[error("storage keys required: {0}")]
    KeysRequired(String),

    /// D4-E: the client authorized this backup but also has seen a newer state than its
    /// (authenticated) checkpoint — an unrequested rollback; nothing is restored.
    #[error("backup checkpoint {checkpoint} is older than the client's anchor {min_generation}")]
    OlderThanAnchor { checkpoint: u64, min_generation: u64 },

    #[error("internal error")]
    Internal,
}
