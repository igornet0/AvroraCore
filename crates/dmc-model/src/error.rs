use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("catalog already exists: {0}")]
    AlreadyExists(String),
    #[error("catalog not found: {0}")]
    NotFound(String),
    #[error("catalog event sequence out of order: expected > {expected}, got {got}")]
    OutOfOrderSequence { expected: u64, got: u64 },
    #[error("duplicate catalog event at sequence {0}")]
    DuplicateSequence(u64),
    #[error("catalog event replay conflict at sequence {sequence}: {reason}")]
    ReplayConflict { sequence: u64, reason: String },
    #[error("corrupt catalog state: {0}")]
    Corrupt(String),
    #[error("invalid catalog event: {0}")]
    InvalidEvent(String),
    #[error("write conflict at sequence {sequence}: {reason}")]
    WriteConflict { sequence: u64, reason: String },
    #[error("constraint violation ({kind}): {reason}")]
    ConstraintViolation { kind: String, reason: String },
    #[error("transaction error: {0}")]
    Transaction(String),
    #[error("io error: {0}")]
    Io(String),
}

pub type Result<T> = std::result::Result<T, Error>;
