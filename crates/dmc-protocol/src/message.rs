use serde::{Deserialize, Serialize};

use crate::error::ProtocolErrorCode;
use crate::runtime::{
    CatalogColumnWire, CatalogConstraintWire, CatalogDatabaseWire, CatalogIndexWire,
    CatalogSchemaWire, CatalogSnapshotWire, CatalogTableSummaryWire, ChannelInfoWire,
    ChannelSpecWire, RuntimeEventWire, SchemaSnapshotWire, ServerCapabilities, StreamSpecWire,
    TriggerDefWire,
};

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
    /// Feature discovery — does not require a session.
    GetCapabilities,
    ChannelList {
        session_id: String,
    },
    ChannelGet {
        session_id: String,
        id: String,
    },
    ChannelConfigure {
        session_id: String,
        spec: ChannelSpecWire,
    },
    ChannelStart {
        session_id: String,
        id: String,
    },
    ChannelStop {
        session_id: String,
        id: String,
    },
    StreamList {
        session_id: String,
    },
    StreamGet {
        session_id: String,
        id: String,
    },
    StreamCreate {
        session_id: String,
        spec: StreamSpecWire,
    },
    StreamIngest {
        session_id: String,
        stream_id: String,
        path: String,
        payload: String,
    },
    TriggerList {
        session_id: String,
    },
    TriggerGet {
        session_id: String,
        id: String,
    },
    TriggerCreate {
        session_id: String,
        def: TriggerDefWire,
    },
    EventList {
        session_id: String,
        #[serde(default = "default_event_limit")]
        limit: u32,
    },
    RuntimeSchema {
        session_id: String,
    },
    CatalogList {
        session_id: String,
    },
    /// Lazy catalog: databases only.
    DatabaseList {
        session_id: String,
    },
    SchemaList {
        session_id: String,
        #[serde(default)]
        database: Option<String>,
        #[serde(default)]
        cursor: Option<String>,
        #[serde(default = "default_catalog_limit")]
        limit: u32,
        #[serde(default)]
        name_filter: Option<String>,
    },
    TableList {
        session_id: String,
        database: String,
        schema: String,
        #[serde(default)]
        cursor: Option<String>,
        #[serde(default = "default_catalog_limit")]
        limit: u32,
        #[serde(default)]
        name_filter: Option<String>,
    },
    TableGet {
        session_id: String,
        database: String,
        schema: String,
        table: String,
    },
    ColumnList {
        session_id: String,
        database: String,
        schema: String,
        table: String,
        #[serde(default)]
        cursor: Option<String>,
        #[serde(default = "default_catalog_limit")]
        limit: u32,
        #[serde(default)]
        name_filter: Option<String>,
    },
    IndexList {
        session_id: String,
        database: String,
        schema: String,
        table: String,
        #[serde(default)]
        cursor: Option<String>,
        #[serde(default = "default_catalog_limit")]
        limit: u32,
        #[serde(default)]
        name_filter: Option<String>,
    },
    ConstraintList {
        session_id: String,
        database: String,
        schema: String,
        table: String,
        #[serde(default)]
        cursor: Option<String>,
        #[serde(default = "default_catalog_limit")]
        limit: u32,
        #[serde(default)]
        name_filter: Option<String>,
    },
    CreateTable {
        session_id: String,
        database: String,
        schema: String,
        name: String,
        columns: Vec<crate::runtime::ColumnDefWire>,
    },
    DropTable {
        session_id: String,
        database: String,
        schema: String,
        table: String,
    },
    RenameTable {
        session_id: String,
        database: String,
        schema: String,
        table: String,
        new_name: String,
    },
    AddColumn {
        session_id: String,
        database: String,
        schema: String,
        table: String,
        column: crate::runtime::ColumnDefWire,
    },
    AlterColumn {
        session_id: String,
        database: String,
        schema: String,
        table: String,
        column: String,
        #[serde(default)]
        nullable: Option<bool>,
        #[serde(default)]
        data_type: Option<String>,
        #[serde(default)]
        default: Option<Option<String>>,
    },
    DropColumn {
        session_id: String,
        database: String,
        schema: String,
        table: String,
        column: String,
    },
    RenameColumn {
        session_id: String,
        database: String,
        schema: String,
        table: String,
        column: String,
        new_name: String,
    },
    CreateIndex {
        session_id: String,
        database: String,
        schema: String,
        table: String,
        name: String,
        columns: Vec<String>,
        #[serde(default)]
        unique: bool,
    },
    DropIndex {
        session_id: String,
        database: String,
        schema: String,
        table: String,
        name: String,
    },
    // ── CLIENT_OWNED key management (appended: postcard variant indices stay stable) ──
    //
    // Every field is public or already wrapped: public keys, HPKE envelopes, subject ids.
    // There is no message that carries a private key, root, recovery code or plaintext DEK.
    /// Register the caller's first (version 1) public KEM key.
    ClientKeyRegister {
        session_id: String,
        key: dmc_vault::ownership::ClientPublicKey,
    },
    /// Fetch all key versions of a subject (caller recomputes fingerprints; TOFU).
    ClientKeyGet {
        session_id: String,
        subject: dmc_vault::ownership::SubjectId,
    },
    /// Register the caller's next key bundle version; previous becomes RETIRED. `proof`
    /// carries the new auth key's possession signature and the old auth key's continuity
    /// signature (`dmc_vault::ownership::auth::rotation_statement`).
    ClientKeyRotate {
        session_id: String,
        key: dmc_vault::ownership::ClientPublicKey,
        proof: dmc_vault::ownership::auth::KeyRotationProof,
    },
    /// Store an HPKE envelope created by its owner.
    KeyEnvelopePut {
        session_id: String,
        envelope: dmc_vault::ownership::ClientKeyEnvelope,
    },
    /// Envelopes addressed to the caller (own + live delegations).
    KeyEnvelopeGet {
        session_id: String,
    },
    GrantCreate {
        session_id: String,
        grantee: dmc_vault::ownership::SubjectId,
        #[serde(default)]
        expires_at_ms: Option<u64>,
    },
    GrantList {
        session_id: String,
    },
    GrantRevoke {
        session_id: String,
        grantee: dmc_vault::ownership::SubjectId,
    },
    /// Declare a BLOB column CLIENT_OWNED: the server then rejects any value that is not a
    /// well-formed CLIENT-domain sealed record (no decryption involved).
    SealedColumnDeclare {
        session_id: String,
        schema: String,
        table: String,
        column: String,
        #[serde(default)]
        owner_column: Option<String>,
    },
    /// Operator (grant CREATE on system) issues a one-time enrollment invite. The server
    /// assigns the subject; the token is returned once.
    IdentityInviteCreate {
        session_id: String,
        name: String,
        tenant: dmc_vault::ownership::TenantId,
        ttl_ms: u64,
    },
    /// Client claims an invite: registers its key bundle (X25519 + Ed25519) and proves
    /// possession of the Ed25519 key. No session needed; no private key on the wire.
    IdentityEnroll {
        invite_id: String,
        token: Vec<u8>,
        key: dmc_vault::ownership::ClientPublicKey,
        signature: Vec<u8>,
    },
    /// CLIENT_OWNED authentication, step 1: ask for a challenge bound to this connection.
    ClientAuthBegin {
        subject: dmc_vault::ownership::SubjectId,
        tenant: dmc_vault::ownership::TenantId,
    },
    /// Step 2: Ed25519 signature over the challenge; `nonce` identifies it.
    ClientAuthFinish {
        nonce: Vec<u8>,
        signature: Vec<u8>,
    },
    /// Grant a privilege to another identity (caller needs GRANT on system; never self).
    /// DMC IPC only — not forwarded by the HTTP / control-plane adapters.
    PrivilegeGrant {
        session_id: String,
        grantee: String,
        privilege: PrivilegeWire,
    },
    PrivilegeRevoke {
        session_id: String,
        grantee: String,
        privilege: PrivilegeWire,
    },
    /// Privileges of `identity` (GRANT holders: anyone; others: only themselves).
    PrivilegeList {
        session_id: String,
        identity: String,
    },
    /// D4-A stage 5 — explicit migration of a plaintext (pre-D4) SQL store to encrypted
    /// storage. The storage keys come exactly as for `VaultUnlock` (client-side KeyPass →
    /// unlock blob bound to this session); the caller needs GRANT on system. On success
    /// the vault is unlocked and the encrypted store is open. Plaintext backups / restore
    /// targets are refused unless `purge_plaintext_backups` (they are then deleted).
    /// DMC IPC only — not forwarded by the HTTP / control-plane adapters.
    StorageMigrateEncrypt {
        session_id: String,
        blob: crate::unlock_blob::UnlockBlob,
        #[serde(default)]
        purge_plaintext_backups: bool,
    },
}

/// Resource of a privilege on the wire (mirrors `dmc_security::auth::Resource`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivilegeResourceWire {
    System,
    Database { name: String },
    Schema { database: String, name: String },
    Table { database: String, schema: String, name: String },
}

/// Action of a privilege on the wire (mirrors `dmc_security::auth::Action`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivilegeActionWire {
    Connect,
    Usage,
    Select,
    Insert,
    Update,
    Delete,
    Create,
    Drop,
    Grant,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivilegeWire {
    pub resource: PrivilegeResourceWire,
    pub action: PrivilegeActionWire,
}

/// Delegation grant as seen on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientGrantWire {
    pub owner: dmc_vault::ownership::SubjectId,
    pub grantee: dmc_vault::ownership::SubjectId,
    pub tenant: dmc_vault::ownership::TenantId,
    pub granted_at_ms: u64,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
}

fn default_event_limit() -> u32 {
    100
}

fn default_catalog_limit() -> u32 {
    500
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
        /// D4-D: generation of the open SQL storage (journal tip); 0 while sealed.
        #[serde(default)]
        generation: u64,
    },
    VaultUnlock {
        state: VaultStateWire,
        /// D4-D: generation of the storage just opened — the client's next anchor.
        #[serde(default)]
        generation: u64,
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
        /// D4-E: SHA-256 (hex) of the backup's authenticated `manifest.sealed` — what the
        /// client stores to authorize an emergency restore of exactly this artifact.
        /// Empty for an unencrypted backup.
        #[serde(default)]
        manifest_sealed_sha256: String,
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
    Capabilities(ServerCapabilities),
    ChannelList {
        items: Vec<ChannelInfoWire>,
    },
    ChannelInfo(ChannelInfoWire),
    ChannelConfigured {
        id: String,
    },
    StreamList {
        items: Vec<StreamSpecWire>,
    },
    StreamInfo(StreamSpecWire),
    StreamCreated {
        id: String,
    },
    TriggerList {
        items: Vec<TriggerDefWire>,
    },
    TriggerInfo(TriggerDefWire),
    TriggerCreated {
        id: String,
    },
    EventList {
        items: Vec<RuntimeEventWire>,
    },
    RuntimeSchema(SchemaSnapshotWire),
    CatalogList(CatalogSnapshotWire),
    DatabaseList {
        items: Vec<CatalogDatabaseWire>,
    },
    SchemaList {
        items: Vec<CatalogSchemaWire>,
        #[serde(default)]
        next_cursor: Option<String>,
        #[serde(default)]
        truncated: bool,
    },
    TableList {
        items: Vec<CatalogTableSummaryWire>,
        #[serde(default)]
        next_cursor: Option<String>,
        #[serde(default)]
        truncated: bool,
    },
    TableGet(CatalogTableSummaryWire),
    ColumnList {
        items: Vec<CatalogColumnWire>,
        #[serde(default)]
        next_cursor: Option<String>,
        #[serde(default)]
        truncated: bool,
    },
    IndexList {
        items: Vec<CatalogIndexWire>,
        #[serde(default)]
        next_cursor: Option<String>,
        #[serde(default)]
        truncated: bool,
    },
    ConstraintList {
        items: Vec<CatalogConstraintWire>,
        #[serde(default)]
        next_cursor: Option<String>,
        #[serde(default)]
        truncated: bool,
    },
    SchemaMutation(crate::runtime::SchemaMutationResultWire),
    RuntimeOk,
    // ── CLIENT_OWNED key management (appended) ──
    ClientKeyAck {
        key_id: String,
        key_version: u32,
    },
    ClientKeys {
        keys: Vec<dmc_vault::ownership::ServerStoredPublicKey>,
    },
    KeyEnvelopeAck,
    KeyEnvelopes {
        envelopes: Vec<dmc_vault::ownership::ClientKeyEnvelope>,
    },
    Grants {
        grants: Vec<ClientGrantWire>,
    },
    GrantAck {
        changed: bool,
    },
    SealedColumnAck,
    /// Invite issued: `token` is shown to the operator once (not stored by the server).
    IdentityInvite {
        invite_id: String,
        token: Vec<u8>,
        name: String,
        tenant: dmc_vault::ownership::TenantId,
        subject: dmc_vault::ownership::SubjectId,
        expires_at_ms: u64,
    },
    IdentityEnrolled {
        identity_id: String,
        subject: dmc_vault::ownership::SubjectId,
        key_id: String,
    },
    /// Challenge bytes (`dmc_vault::ownership::auth::Challenge`) to be signed.
    ClientAuthChallenge {
        challenge: Vec<u8>,
    },
    /// Session bound to this connection; carries no key material.
    ClientAuthOk {
        session_id: String,
        expires_at_ms: u64,
        key_version: u32,
    },
    PrivilegeAck {
        changed: bool,
    },
    Privileges {
        privileges: Vec<PrivilegeWire>,
    },
    StorageMigrateEncrypt {
        /// Events re-written into the encrypted journal.
        events: u64,
        /// Tables re-materialized (encrypted segments, indexes, statistics).
        tables: u64,
        /// Plaintext backup / restore artifacts deleted (only with `purge_plaintext_backups`).
        purged_artifacts: u64,
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
    /// Canonical text form (PostgreSQL text output: `apple`, `1`, `t`, `\x…`); empty for
    /// NULL. `value` keeps its existing form for DMC clients.
    #[serde(default)]
    pub text: String,
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
