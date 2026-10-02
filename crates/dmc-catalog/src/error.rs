use thiserror::Error;

pub type Result<T> = std::result::Result<T, CatalogError>;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CatalogError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),
    #[error("database error: {0}")]
    DatabaseError(String),
    #[error("internal: {0}")]
    Internal(String),
}
