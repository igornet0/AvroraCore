//! Ops error surfaces — sanitized messages only (no secrets / path dumps).

use thiserror::Error;

use crate::lifecycle::LifecycleState;

pub type Result<T> = std::result::Result<T, ConfigError>;
pub type LifecycleResult<T> = std::result::Result<T, LifecycleError>;
pub type LayoutResult<T> = std::result::Result<T, LayoutError>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConfigError {
    #[error("invalid config: {0}")]
    Invalid(String),
    #[error("config contains forbidden secret field or value")]
    ForbiddenSecret,
    #[error("config parse error")]
    Parse,
    #[error("config io error")]
    Io,
}

impl ConfigError {
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::Invalid(msg.into())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LifecycleError {
    #[error("invalid lifecycle transition from {from} via {action}")]
    InvalidTransition { from: String, action: String },
}

impl LifecycleError {
    pub fn invalid_transition(from: LifecycleState, action: impl Into<String>) -> Self {
        Self::InvalidTransition {
            from: from.as_str().into(),
            action: action.into(),
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LayoutError {
    #[error("invalid layout: {0}")]
    Invalid(String),
    #[error("unsupported layout_version {got} (supported {supported})")]
    UnsupportedVersion { got: u32, supported: u32 },
    #[error("layout path escapes data_root")]
    EscapesRoot,
    #[error("layout io error")]
    Io,
}

impl LayoutError {
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::Invalid(msg.into())
    }
}

pub type StartupResult<T> = std::result::Result<T, StartupError>;
pub type ShutdownResult<T> = std::result::Result<T, ShutdownError>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StartupError {
    #[error("startup config error: {0}")]
    Config(String),
    #[error("startup layout error: {0}")]
    Layout(String),
    #[error("startup provision error: {0}")]
    Provision(String),
    #[error("startup journal error: {0}")]
    Journal(String),
    #[error("startup catalog error: {0}")]
    Catalog(String),
    #[error("startup storage error: {0}")]
    Storage(String),
    #[error("startup vault error: {0}")]
    Vault(String),
    #[error("startup recovery metadata error: {0}")]
    RecoveryMetadata(String),
    #[error("startup recovery error: {0}")]
    Recovery(String),
    #[error("startup lifecycle error: {0}")]
    Lifecycle(String),
    #[error("startup io error: {0}")]
    Io(String),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ShutdownError {
    #[error("shutdown lifecycle error: {0}")]
    Lifecycle(String),
    #[error("shutdown rollback error: {0}")]
    Rollback(String),
    #[error("shutdown flush error: {0}")]
    Flush(String),
    #[error("shutdown vault error: {0}")]
    Vault(String),
}
