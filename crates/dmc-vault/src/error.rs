use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid key path: {0}")]
    InvalidPath(String),

    #[error("unknown key node: {0}")]
    UnknownNode(String),

    #[error("parent key required to derive child '{0}'")]
    MissingParent(String),

    #[error("access denied: missing {0} on '{1}'")]
    AccessDenied(String, String),

    #[error("capability cannot be delegated: missing GRANT on '{0}'")]
    CannotDelegate(String),

    #[error("node revoked: {0}")]
    Revoked(String),

    #[error("key unwrap failed (wrong parent or corrupted wrap)")]
    UnwrapFailed,

    #[error("AEAD encrypt/decrypt failed")]
    AeadFailed,

    #[error("value not found: {0}")]
    NotFound(String),

    #[error("wrong master key: data cannot be decrypted")]
    WrongMasterKey,

    #[error("database is locked")]
    Locked,

    #[error("database already unlocked")]
    AlreadyUnlocked,

    #[error("database already exists")]
    AlreadyExists,

    #[error("database does not exist yet")]
    NotInitialized,

    #[error("invalid master key encoding")]
    InvalidMasterKey,

    #[error("master password is too short (min {0} characters)")]
    InvalidMasterPassword(usize),

    #[error("wrong master password or corrupted keypass")]
    WrongMasterPassword,

    #[error("keypass not found")]
    KeyPassNotFound,

    #[error("keypass does not match this database")]
    KeyPassDbMismatch,

    #[error("key derivation failed")]
    KdfFailed,

    #[error("io error: {0}")]
    Io(String),

    #[error("persist format error: {0}")]
    Persist(String),
}
