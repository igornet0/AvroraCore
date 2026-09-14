use serde::{Deserialize, Serialize};

/// UI-facing connection flag. Not Core SecurityState.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionUi {
    Disconnected,
    Connected,
}

/// Cached vault observation for UI. Core remains source of truth via `vault_status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatusUi {
    Locked,
    Unlocked,
}

/// Lightweight UI mirror. Must never hold secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientUiState {
    pub connection: ConnectionUi,
    pub authenticated: bool,
    pub vault: Option<VaultStatusUi>,
}

impl Default for ClientUiState {
    fn default() -> Self {
        Self {
            connection: ConnectionUi::Disconnected,
            authenticated: false,
            vault: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub identity_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlCellDto {
    pub value: String,
    pub is_null: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlRowDto {
    pub cells: Vec<SqlCellDto>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<SqlRowDto>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupInfoUi {
    pub backup_id: String,
    pub checkpoint_sequence: u64,
    pub created_at: String,
    pub valid: bool,
    pub state: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupCreateUi {
    pub backup_id: String,
    pub checkpoint_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupVerifyUi {
    pub backup_id: String,
    pub checkpoint_sequence: u64,
    pub valid: bool,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupRestoreUi {
    pub backup_id: String,
    pub target_id: String,
    pub checkpoint_sequence: u64,
    pub vault_locked: bool,
    pub sessions_invalid: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupRecoverUi {
    pub target_id: String,
    pub checkpoint_sequence: u64,
    pub state: String,
    pub vault_locked: bool,
    pub sessions_invalid: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupStatusUi {
    pub target_id: String,
    pub state: String,
    pub checkpoint_sequence: u64,
    pub vault_locked: bool,
    pub sessions_invalid: bool,
}

/// UI-facing diagnostics snapshot (7.9.7). Mirrors Control DiagnosticsWire — no secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticsUi {
    pub version: String,
    pub process_state: String,
    pub uptime_secs: u64,
    pub liveness: String,
    pub readiness: String,
    pub vault: String,
    pub readiness_reason_code: Option<String>,
    pub journal_tip: Option<u64>,
    pub materialized_sequence: Option<u64>,
    pub journal_lag: Option<u64>,
    pub catalog: String,
    pub rowstore: String,
    pub indexes: String,
    pub statistics: String,
    pub recovery_state: Option<String>,
    pub recovery_checkpoint_sequence: Option<u64>,
    pub connections_active: u64,
    pub connections_accepted_total: u64,
    pub logging: String,
    pub metrics: String,
    pub audit: String,
}

/// Connect arguments from UI. TLS PEM stays opaque bytes/string — no rustls in TS.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ConnectRequest {
    Local {
        socket: String,
    },
    Remote {
        host: String,
        port: u16,
        ca_pem: String,
        #[serde(default)]
        server_name: Option<String>,
        #[serde(default)]
        development: bool,
    },
}
