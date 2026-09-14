use dmc_protocol::{ProtocolError, ProtocolErrorCode, Result};

/// Production vs development deployment profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeploymentProfile {
    Development,
    Production,
}

/// Remote transport mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RemoteMode {
    /// TLS 1.3 — required for production remote access.
    Tls,
    /// Plain TCP — development only; must be explicitly opted in.
    PlainTcpDev,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteTransportPolicy {
    pub deployment: DeploymentProfile,
    pub mode: RemoteMode,
}

impl RemoteTransportPolicy {
    pub fn production_tls() -> Self {
        Self {
            deployment: DeploymentProfile::Production,
            mode: RemoteMode::Tls,
        }
    }

    pub fn development_plain_tcp() -> Self {
        Self {
            deployment: DeploymentProfile::Development,
            mode: RemoteMode::PlainTcpDev,
        }
    }

    pub fn development_tls() -> Self {
        Self {
            deployment: DeploymentProfile::Development,
            mode: RemoteMode::Tls,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.deployment == DeploymentProfile::Production
            && self.mode == RemoteMode::PlainTcpDev
        {
            return Err(ProtocolError::wire(
                ProtocolErrorCode::TransportError,
                "plaintext remote TCP is forbidden in production profile",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct RemoteBindConfig {
    pub policy: RemoteTransportPolicy,
}

#[derive(Clone, Debug)]
pub struct RemoteConnectConfig {
    pub policy: RemoteTransportPolicy,
    pub server_hostname: String,
}

impl RemoteBindConfig {
    pub fn ensure_allowed(&self) -> Result<()> {
        self.policy.validate()
    }
}

impl RemoteConnectConfig {
    pub fn ensure_allowed(&self) -> Result<()> {
        self.policy.validate()
    }
}
