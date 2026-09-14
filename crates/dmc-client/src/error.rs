use dmc_protocol::ProtocolError;
use thiserror::Error;

use dmc_server::KeyPassError;

pub type Result<T> = std::result::Result<T, ClientError>;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    #[error("not connected")]
    NotConnected,

    #[error("already connected")]
    AlreadyConnected,

    #[error("not authenticated")]
    NotAuthenticated,

    #[error("keypass unlock failed")]
    KeyPass(#[from] KeyPassError),

    #[error("unexpected control response")]
    UnexpectedControl,

    #[error("unexpected data response")]
    UnexpectedData,

    #[error("local IPC is only supported on Unix")]
    LocalUnsupported,

    #[error("{0}")]
    Message(String),
}

impl ClientError {
    pub fn protocol_code(&self) -> Option<dmc_protocol::ProtocolErrorCode> {
        match self {
            Self::Protocol(ProtocolError::Wire { code, .. }) => Some(*code),
            _ => None,
        }
    }
}
