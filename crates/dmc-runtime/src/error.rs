use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Vault(#[from] dmc_vault::Error),

    #[error("unknown stream '{0}'")]
    UnknownStream(String),

    #[error("unknown channel '{0}'")]
    UnknownChannel(String),

    #[error("unknown trigger '{0}'")]
    UnknownTrigger(String),

    #[error("stream '{0}' is not inbound")]
    NotInbound(String),

    #[error("path '{0}' is outside stream scope")]
    OutsideScope(String),

    #[error("channel '{0}' already exists")]
    ChannelExists(String),

    #[error("stream '{0}' already exists")]
    StreamExists(String),

    #[error("{0}")]
    Invalid(String),
}

impl Error {
    pub fn from_vault(err: dmc_vault::Error) -> Self {
        Self::Vault(err)
    }
}
