use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Store(#[from] dmc_vault::Error),

    #[error("not in a transaction")]
    NotInTransaction,

    #[error("already in a transaction")]
    AlreadyInTransaction,

    #[error("row store I/O: {0}")]
    Io(String),

    #[error("row store codec: {0}")]
    Codec(String),

    #[error("row store corrupt: {0}")]
    Corrupt(String),

    #[error("row store manifest: {0}")]
    Manifest(String),

    #[error("row not found: {0}")]
    RowNotFound(u64),

    #[error("table not found")]
    TableNotFound,

    #[error("column not found")]
    ColumnNotFound,

    #[error("schema mismatch: {0}")]
    SchemaMismatch(String),

    #[error("index not found")]
    IndexNotFound,

    #[error("unique index violation: {key}")]
    UniqueViolation { key: String },
}

impl Error {
    pub fn io(e: impl std::error::Error) -> Self {
        Self::Io(e.to_string())
    }
}
