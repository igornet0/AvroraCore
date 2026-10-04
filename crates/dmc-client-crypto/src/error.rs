use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Client-side cryptographic failures. All terminal: no fallback, no plaintext path.
#[derive(Debug, Error)]
pub enum Error {
    #[error("security: HPKE operation failed")]
    Hpke,

    #[error(transparent)]
    Ownership(#[from] dmc_vault::ownership::Error),

    /// KEY_CHANGED: the server presented a different public key than the one pinned for
    /// this subject. Refused by default; accept only after out-of-band verification.
    #[error("security: KEY_CHANGED for subject {subject} (pinned fingerprint differs)")]
    KeyChanged { subject: String },

    /// The server presented an older key version than the one already pinned.
    #[error("security: key version rollback for subject {subject} (pinned v{pinned}, offered v{offered})")]
    KeyRollback { subject: String, pinned: u32, offered: u32 },

    /// Server returned fewer own key versions than this client has already seen.
    #[error("security: key version rollback detected (have v{seen}, server offers up to v{offered})")]
    Rollback { seen: u32, offered: u32 },

    #[error("security: envelope is not addressed to this client key")]
    NotForThisKey,

    #[error("security: no key for owner {owner} version {version}")]
    MissingKey { owner: String, version: u32 },

    #[error("invalid recovery code")]
    RecoveryCode,

    #[error("client crypto format error: {0}")]
    Format(String),

    #[error("io error: {0}")]
    Io(String),
}

impl Error {
    pub(crate) fn io(e: impl std::fmt::Display) -> Self {
        Self::Io(e.to_string())
    }
}
