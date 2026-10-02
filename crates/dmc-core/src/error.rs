use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Vault(#[from] dmc_vault::Error),

    #[error(transparent)]
    Storage(#[from] dmc_storage::Error),

    #[error(transparent)]
    Journal(#[from] dmc_journal::Error),

    #[error("database is locked")]
    Locked,

    #[error("unknown stream '{0}'")]
    UnknownStream(String),

    #[error("unknown channel '{0}'")]
    UnknownChannel(String),

    #[error("unknown trigger '{0}'")]
    UnknownTrigger(String),

    #[error("unknown subscription '{0}'")]
    UnknownSubscription(String),

    #[error("unknown consumer group '{0}'")]
    UnknownGroup(String),

    #[error("consumer group '{0}' already exists")]
    GroupExists(String),

    #[error("consumer group '{0}' is not empty")]
    GroupNotEmpty(String),

    #[error("unknown group member '{0}'")]
    UnknownMember(String),

    #[error("group member '{0}' already exists")]
    MemberExists(String),

    #[error("group member '{0}' is not active")]
    MemberNotActive(String),

    #[error("stale group generation: got {got}, current {current}")]
    StaleGeneration { got: u64, current: u64 },

    #[error("partition {partition_id} is not assigned to member '{member_id}'")]
    NotAssigned { member_id: String, partition_id: u32 },

    #[error("authorization denied: {0}")]
    AuthorizationDenied(String),

    #[error("stale delivery '{0}'")]
    StaleDelivery(String),

    #[error("unknown delivery '{0}'")]
    UnknownDelivery(String),

    #[error(
        "retry backoff for subscription '{subscription_id}' sequence {sequence}: retry at {retry_at_ms}"
    )]
    RetryBackoff {
        subscription_id: String,
        sequence: u64,
        attempt: u32,
        retry_at_ms: u64,
    },

    #[error(
        "retry backoff for group '{group_id}' member '{member_id}' partition {partition_id} sequence {sequence}: retry at {retry_at_ms}"
    )]
    GroupRetryBackoff {
        group_id: String,
        member_id: String,
        partition_id: u32,
        sequence: u64,
        attempt: u32,
        retry_at_ms: u64,
    },

    #[error(
        "group retry exhausted for '{group_id}' partition {partition_id} sequence {sequence} after {attempt} attempts (max {max_attempts})"
    )]
    GroupRetryExhausted {
        group_id: String,
        partition_id: u32,
        sequence: u64,
        attempt: u32,
        max_attempts: u32,
    },

    #[error(
        "delivery exhausted for subscription '{subscription_id}' sequence {sequence} after {attempt} attempts"
    )]
    DeliveryExhausted {
        subscription_id: String,
        sequence: u64,
        attempt: u32,
    },

    #[error("unknown DLQ entry '{0}'")]
    UnknownDlq(String),

    #[error(
        "group DLQ entry not found for group '{group_id}' partition {partition_id} sequence {sequence}"
    )]
    UnknownGroupDlqEntry {
        group_id: String,
        partition_id: u32,
        sequence: u64,
    },

    #[error(
        "backpressure for subscription '{subscription_id}': in_flight={in_flight} max={max_in_flight}"
    )]
    Backpressure {
        subscription_id: String,
        in_flight: u32,
        max_in_flight: u32,
    },

    #[error("trim beyond watermark: requested {requested}, max safe {watermark}")]
    TrimBeyondWatermark { requested: u64, watermark: u64 },

    #[error("trim unsafe: no retention watermark")]
    TrimUnsafe,

    #[error(
        "history unavailable: requested from sequence {requested_from}, oldest available {oldest_available}"
    )]
    HistoryUnavailable {
        requested_from: u64,
        oldest_available: u64,
    },

    #[error("unknown session '{0}'")]
    UnknownSession(String),

    #[error("unknown role '{0}'")]
    UnknownRole(String),

    #[error("stream '{0}' is not inbound")]
    NotInbound(String),

    #[error("stream '{0}' is not outbound")]
    NotOutbound(String),

    #[error("path '{0}' is outside stream scope")]
    OutsideScope(String),

    #[error("channel '{0}' already exists")]
    ChannelExists(String),

    #[error("stream '{0}' already exists")]
    StreamExists(String),

    #[error("unknown subsystem '{0}'")]
    UnknownSubsystem(String),

    #[error("{0}")]
    Invalid(String),
}

impl From<dmc_runtime::Error> for Error {
    fn from(err: dmc_runtime::Error) -> Self {
        match err {
            dmc_runtime::Error::Vault(v) => Self::from_vault(v),
            dmc_runtime::Error::UnknownStream(s) => Self::UnknownStream(s),
            dmc_runtime::Error::UnknownChannel(s) => Self::UnknownChannel(s),
            dmc_runtime::Error::UnknownTrigger(s) => Self::UnknownTrigger(s),
            dmc_runtime::Error::NotInbound(s) => Self::NotInbound(s),
            dmc_runtime::Error::OutsideScope(s) => Self::OutsideScope(s),
            dmc_runtime::Error::ChannelExists(s) => Self::ChannelExists(s),
            dmc_runtime::Error::StreamExists(s) => Self::StreamExists(s),
            dmc_runtime::Error::Invalid(s) => Self::Invalid(s),
        }
    }
}

impl Error {
    pub fn from_vault(err: dmc_vault::Error) -> Self {
        match err {
            dmc_vault::Error::Locked => Self::Locked,
            other => Self::Vault(other),
        }
    }
}

impl From<dmc_security::Error> for Error {
    fn from(err: dmc_security::Error) -> Self {
        match err {
            dmc_security::Error::Locked => Self::Locked,
            dmc_security::Error::UnknownSession(s) => Self::UnknownSession(s),
            dmc_security::Error::UnknownRole(s) => Self::UnknownRole(s),
            dmc_security::Error::UnknownUser(s) => Self::Invalid(format!("unknown user: {s}")),
            dmc_security::Error::UserDisabled(s) => Self::Invalid(format!("user disabled: {s}")),
            dmc_security::Error::SessionExpired(s) => Self::Invalid(format!("session expired: {s}")),
            dmc_security::Error::UnknownCapability(s) => {
                Self::Invalid(format!("unknown capability: {s}"))
            }
            dmc_security::Error::CapabilityRevoked(s) => Self::AuthorizationDenied(format!(
                "capability revoked: {s}"
            )),
            dmc_security::Error::CapabilityExpired(s) => Self::AuthorizationDenied(format!(
                "capability expired: {s}"
            )),
            dmc_security::Error::CapabilityStale(s) => Self::AuthorizationDenied(format!(
                "capability generation mismatch: {s}"
            )),
            dmc_security::Error::DelegationDenied(s) => Self::Invalid(format!("delegation denied: {s}")),
            dmc_security::Error::InvalidUser(s) => Self::Invalid(format!("invalid user: {s}")),
            dmc_security::Error::UnknownIdentity(s) => Self::Invalid(format!("unknown identity: {s}")),
            dmc_security::Error::IdentityDisabled(s) => {
                Self::Invalid(format!("identity disabled: {s}"))
            }
            dmc_security::Error::AuthenticationFailed(s) => Self::Invalid(s),
            dmc_security::Error::PermissionDenied(s) => Self::AuthorizationDenied(s),
            dmc_security::Error::Conflict(s) => Self::Invalid(s),
            dmc_security::Error::Vault(v) => Self::from_vault(v),
            dmc_security::Error::Auth(a) => Self::Invalid(a.to_string()),
        }
    }
}
