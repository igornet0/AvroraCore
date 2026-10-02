use thiserror::Error;

pub type Result<T> = std::result::Result<T, DdlError>;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DdlError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),
    #[error("invalid definition: {0}")]
    InvalidDefinition(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("unsafe operation: {0}")]
    UnsafeOperation(String),
    #[error("database error: {0}")]
    DatabaseError(String),
    #[error("internal: {0}")]
    Internal(String),
}

impl From<dmc_model::Error> for DdlError {
    fn from(err: dmc_model::Error) -> Self {
        match err {
            dmc_model::Error::NotFound(m) => Self::NotFound(m),
            dmc_model::Error::AlreadyExists(m) => Self::AlreadyExists(m),
            dmc_model::Error::InvalidEvent(m) => Self::InvalidDefinition(m),
            other => Self::DatabaseError(other.to_string()),
        }
    }
}
