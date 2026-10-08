use std::path::PathBuf;

use dmc_protocol::{SqlResult, VaultStateWire};
use dmc_remote::TlsClientConfig;

/// Where the client connects. Control/SQL API is identical for both.
#[derive(Clone, Debug)]
pub enum ConnectionTarget {
    Local {
        socket: PathBuf,
    },
    Remote {
        endpoint: std::net::SocketAddr,
        tls: RemoteTlsConfig,
    },
}

/// TLS options for remote targets. TLS itself lives in `dmc-remote`.
#[derive(Clone)]
pub struct RemoteTlsConfig {
    pub client: TlsClientConfig,
    /// When true, use development TLS policy (test / local lab).
    pub development: bool,
}

impl std::fmt::Debug for RemoteTlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteTlsConfig")
            .field("development", &self.development)
            .field("client", &"<TlsClientConfig>")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthInfo {
    pub session_id: String,
    pub identity_id: String,
}

/// Client-facing vault state (mirrors wire; no secrets).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultState {
    Locked,
    Unlocked,
}

impl From<VaultStateWire> for VaultState {
    fn from(value: VaultStateWire) -> Self {
        match value {
            VaultStateWire::Locked => Self::Locked,
            VaultStateWire::Unlocked => Self::Unlocked,
        }
    }
}

impl From<VaultState> for VaultStateWire {
    fn from(value: VaultState) -> Self {
        match value {
            VaultState::Locked => Self::Locked,
            VaultState::Unlocked => Self::Unlocked,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecuteOutcome {
    Ok,
    Rows(SqlResult),
}

/// Opaque backup listing row (Control Plane DTO — no filesystem paths).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupInfo {
    pub backup_id: String,
    pub checkpoint_sequence: u64,
    pub created_at: String,
    pub valid: bool,
    pub state: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupCreateResult {
    pub backup_id: String,
    pub checkpoint_sequence: u64,
    /// D4-E: SHA-256 (hex) of the backup's authenticated `manifest.sealed` (empty for an
    /// unencrypted backup) — what a client keeps to authorize an emergency restore.
    pub manifest_sealed_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupVerifyResult {
    pub backup_id: String,
    pub checkpoint_sequence: u64,
    pub valid: bool,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupRestoreResult {
    pub backup_id: String,
    pub target_id: String,
    pub checkpoint_sequence: u64,
    pub vault_locked: bool,
    pub sessions_invalid: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupRecoverResult {
    pub target_id: String,
    pub checkpoint_sequence: u64,
    pub state: String,
    pub vault_locked: bool,
    pub sessions_invalid: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupStatusResult {
    pub target_id: String,
    pub state: String,
    pub checkpoint_sequence: u64,
    pub vault_locked: bool,
    pub sessions_invalid: bool,
}
