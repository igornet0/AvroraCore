use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Authentication / enrollment failures (UI access key + TOTP).
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Conflict(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Authorization and security-domain failures.
#[derive(Debug, Error)]
pub enum Error {
    #[error("database is locked")]
    Locked,

    #[error("unknown identity '{0}'")]
    UnknownIdentity(String),

    #[error("identity disabled '{0}'")]
    IdentityDisabled(String),

    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("unknown session '{0}'")]
    UnknownSession(String),

    #[error("unknown role '{0}'")]
    UnknownRole(String),

    #[error("unknown user '{0}'")]
    UnknownUser(String),

    #[error("user disabled '{0}'")]
    UserDisabled(String),

    #[error("session expired '{0}'")]
    SessionExpired(String),

    #[error("unknown capability '{0}'")]
    UnknownCapability(String),

    #[error("capability revoked '{0}'")]
    CapabilityRevoked(String),

    #[error("capability expired '{0}'")]
    CapabilityExpired(String),

    #[error("capability generation mismatch '{0}'")]
    CapabilityStale(String),

    #[error("delegation denied: {0}")]
    DelegationDenied(String),

    #[error("invalid user '{0}'")]
    InvalidUser(String),

    #[error("{0}")]
    Conflict(String),

    #[error(transparent)]
    Vault(dmc_vault::Error),

    #[error(transparent)]
    Auth(#[from] AuthError),
}

impl Error {
    pub fn from_vault(err: dmc_vault::Error) -> Self {
        match err {
            dmc_vault::Error::Locked => Self::Locked,
            other => Self::Vault(other),
        }
    }
}
