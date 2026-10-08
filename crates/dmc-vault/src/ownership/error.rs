use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Cryptographic-ownership failures.
///
/// Every variant is terminal for the operation that produced it: there is no
/// fallback key, no default key and no plaintext path. Messages never contain
/// key material.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// The credential-derived wrapping key did not open the subject KEK.
    #[error("security: credential does not unlock this keyring")]
    WrongCredential,

    /// No keyring persisted for this subject. Fail closed — a new key is never generated
    /// implicitly in its place.
    #[error("security: keyring not found for subject {0}")]
    KeyringNotFound(String),

    /// Keyring MAC or envelope binding did not verify (tampering / rollback / corruption).
    #[error("security: keyring integrity check failed")]
    KeyringTampered,

    /// The key version needed to decrypt is unknown, destroyed or not held by this session.
    #[error("security: key version {0} unavailable")]
    KeyVersionUnavailable(u32),

    /// AEAD authentication failed: wrong key, modified ciphertext or wrong context.
    #[error("security: decryption failed (wrong key, wrong context or modified ciphertext)")]
    DecryptFailed,

    /// Record header does not match the requested context (owner / version).
    #[error("security: record does not belong to the requested context")]
    ContextMismatch,

    /// Invalid lifecycle transition (e.g. destroying a version that is still referenced).
    #[error("security: key lifecycle violation: {0}")]
    Lifecycle(String),

    /// Concurrent keyring update lost the optimistic-concurrency race.
    #[error("keyring update conflict: {0}")]
    Conflict(String),

    #[error("ownership format error: {0}")]
    Format(String),

    #[error("password does not meet policy: {0}")]
    WeakCredential(String),

    #[error("key derivation failed")]
    Kdf,

    #[error("io error: {0}")]
    Io(String),
}

impl Error {
    pub(crate) fn io(e: impl std::fmt::Display) -> Self {
        Self::Io(e.to_string())
    }
}
