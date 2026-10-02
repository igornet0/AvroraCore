//! Phase 7.7.7 — Tauri command adapter over [`dmc_client`].
//!
//! This crate must **not** depend on `dmc-server`, `dmc-storage`, `dmc-vault`,
//! `dmc-materialized`, or `dmc-sql-exec` directly. Only `dmc-client` + DTOs.
//!
//! Tauri `#[command]` wrappers live in the host app (`data-client-tauri`) so
//! `generate_handler!` can see them; this crate owns the bridge logic + tests.

mod bridge;
mod dto;
mod error;

pub use bridge::DmcBridge;
pub use dto::{
    BackupCreateUi, BackupInfoUi, BackupRecoverUi, BackupRestoreUi, BackupStatusUi, BackupVerifyUi,
    CatalogPageUi, ClientUiState, ConnectRequest, ConnectionUi, DiagnosticsUi, QueryResult,
    SessionInfo, SqlCellDto, SqlRowDto, VaultStatusUi,
};
pub use dmc_client::{
    CatalogColumnWire, CatalogConstraintKindWire, CatalogConstraintWire, CatalogDatabaseWire,
    CatalogIndexWire, CatalogSchemaWire, CatalogSnapshotWire, CatalogTableSummaryWire,
    ChannelInfoWire, ChannelKindWire, ChannelSpecWire, ColumnDefWire, RuntimeEventWire,
    SchemaMutationResultWire, SchemaSnapshotWire, ServerCapabilities, StreamDirectionWire,
    StreamSpecWire, TriggerActionWire, TriggerDefWire,
};
pub use error::{FrontendError, FrontendErrorCode, Result};
