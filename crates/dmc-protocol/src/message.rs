use serde::{Deserialize, Serialize};

use crate::error::ProtocolErrorCode;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEnvelope<T> {
    pub request_id: u64,
    pub body: T,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseStatus {
    Ok,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseEnvelope<T> {
    pub request_id: u64,
    pub status: ResponseStatus,
    pub body: Option<T>,
    pub error_code: Option<ProtocolErrorCode>,
    pub error_message: Option<String>,
}

impl<T> ResponseEnvelope<T> {
    pub fn ok(request_id: u64, body: T) -> Self {
        Self {
            request_id,
            status: ResponseStatus::Ok,
            body: Some(body),
            error_code: None,
            error_message: None,
        }
    }

    pub fn err(
        request_id: u64,
        code: ProtocolErrorCode,
        message: impl Into<String>,
    ) -> Self {
        Self {
            request_id,
            status: ResponseStatus::Error,
            body: None,
            error_code: Some(code),
            error_message: Some(crate::error::sanitize_client_message(message.into())),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeRequest {
    pub protocol_version: u16,
    pub client_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub protocol_version: u16,
    pub server_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultStateWire {
    Locked,
    Unlocked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlRequest {
    Authenticate {
        identity_name: String,
        password: String,
    },
    SessionInfo {
        session_id: String,
    },
    Health,
    /// Operational readiness (Control plane only — not Data plane).
    Readiness,
    /// Read-only operational diagnostics snapshot (7.9.7). Not a control action.
    Diagnostics,
    VaultStatus {
        session_id: String,
    },
    VaultUnlock {
        session_id: String,
        blob: crate::unlock_blob::UnlockBlob,
    },
    VaultLock {
        session_id: String,
    },
    /// Revoke AuthSession only — does not lock vault (7.6 contract).
    Logout {
        session_id: String,
    },
    /// Phase 7.8.7 — create immutable backup @ consistency barrier.
    BackupCreate {
        session_id: String,
        backup_id: String,
        #[serde(default)]
        include_rowstore: bool,
    },
    BackupVerify {
        session_id: String,
        backup_id: String,
    },
    BackupList {
        session_id: String,
    },
    BackupRestore {
        session_id: String,
        backup_id: String,
        target_id: String,
    },
    BackupRecover {
        session_id: String,
        target_id: String,
    },
    BackupStatus {
        session_id: String,
        target_id: String,
    },
}

/// Wire DTO for ControlResponse::Diagnostics (7.9.7). Sanitized; no paths/secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DiagnosticsWire {
    pub version: String,
    pub process_state: String,
    pub uptime_secs: u64,
    pub liveness: String,
    pub readiness: String,
    pub vault: String,
    #[serde(default)]
    pub readiness_reason_code: Option<String>,
    #[serde(default)]
    pub journal_tip: Option<u64>,
    #[serde(default)]
    pub materialized_sequence: Option<u64>,
    #[serde(default)]
    pub journal_lag: Option<u64>,
    pub catalog: String,
    pub rowstore: String,
    pub indexes: String,
    pub statistics: String,
    #[serde(default)]
    pub recovery_state: Option<String>,
    #[serde(default)]
    pub recovery_checkpoint_sequence: Option<u64>,
    pub connections_active: u64,
    pub connections_accepted_total: u64,
    pub logging: String,
    pub metrics: String,
    pub audit: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlResponse {
    Authenticate {
        session_id: String,
        identity_id: String,
        /// Per-session AEAD key for UnlockBlob sealing (not Master Key).
        #[serde(with = "serde_bytes")]
        unlock_binding_key: Vec<u8>,
    },
    SessionInfo {
        active: bool,
        identity_id: Option<String>,
        expires_at_ms: Option<u64>,
    },
    /// Sanitized operational axes (7.9.6). No paths / secrets / session counts.
    Health {
        liveness: String,
        readiness: String,
        vault: String,
        #[serde(default)]
        reason_code: Option<String>,
    },
    Readiness {
        readiness: String,
        #[serde(default)]
        reason_code: Option<String>,
    },
    /// Sanitized diagnostics DTO (7.9.7). No paths / secrets / session dumps.
    Diagnostics(DiagnosticsWire),
    VaultStatus {
        state: VaultStateWire,
    },
    VaultUnlock {
        state: VaultStateWire,
    },
    VaultLock {
        state: VaultStateWire,
    },
    Logout {
        ok: bool,
    },
    BackupCreate {
        backup_id: String,
        checkpoint_sequence: u64,
    },
    BackupVerify {
        backup_id: String,
        checkpoint_sequence: u64,
        valid: bool,
        errors: Vec<String>,
    },
    BackupList {
        items: Vec<BackupListItem>,
    },
    BackupRestore {
        backup_id: String,
        target_id: String,
        checkpoint_sequence: u64,
        vault_locked: bool,
        sessions_invalid: bool,
    },
    BackupRecover {
        target_id: String,
        checkpoint_sequence: u64,
        state: String,
        vault_locked: bool,
        sessions_invalid: bool,
    },
    BackupStatus {
        target_id: String,
        state: String,
        checkpoint_sequence: u64,
        vault_locked: bool,
        sessions_invalid: bool,
    },
}

/// Opaque backup listing DTO for Control Plane / Tauri (no filesystem paths).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupListItem {
    pub backup_id: String,
    pub checkpoint_sequence: u64,
    pub created_at: String,
    pub valid: bool,
    pub state: String,
}

mod serde_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        <Vec<u8>>::deserialize(d)
    }
}

impl Default for ControlResponse {
    fn default() -> Self {
        Self::Health {
            liveness: String::new(),
            readiness: String::new(),
            vault: String::new(),
            reason_code: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SqlParam {
    pub value: String,
    #[serde(default)]
    pub is_null: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataRequest {
    ExecuteSql {
        session_id: String,
        sql: String,
        #[serde(default)]
        params: Vec<SqlParam>,
    },
    Begin {
        session_id: String,
    },
    Commit {
        session_id: String,
    },
    Rollback {
        session_id: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlCell {
    pub value: String,
    pub is_null: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlRow {
    pub cells: Vec<SqlCell>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlResult {
    pub columns: Vec<String>,
    pub rows: Vec<SqlRow>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DataResponse {
    #[default]
    Ok,
    SqlResult(SqlResult),
}
