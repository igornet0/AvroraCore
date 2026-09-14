//! Phase 7.7.1 — transport-neutral DataClient SDK.
//!
//! Thin boundary over `dmc-protocol` + `dmc-ipc` + `dmc-remote`.
//! Does **not** expose KeyTree, DEK/KEK, RowStore, Journal, or SQL AST.

mod client;
mod control;
mod error;
mod keypass;
mod session;
mod sql;
mod transport;
mod types;

pub use client::Client;
pub use control::ControlClient;
pub use error::{ClientError, Result};
pub use keypass::KeyPassHandle;
pub use session::{ConnectionPhase, SessionSnapshot};
pub use sql::SqlClient;
pub use transport::{ClientTransport, LiveTransport, Request, Response};
pub use types::{
    AuthInfo, BackupCreateResult, BackupInfo, BackupRecoverResult, BackupRestoreResult,
    BackupStatusResult, BackupVerifyResult, ConnectionTarget, ExecuteOutcome, RemoteTlsConfig,
    VaultState,
};

pub use dmc_protocol::{DiagnosticsWire, ProtocolErrorCode, SqlParam, SqlResult, SqlRow};
pub use dmc_server::{
    create_unlock_blob, KeyPassBundle, KeyPassError, KeyPassProvider, MockKeyPassProvider,
    PasswordKeyPassProvider, UnlockMaterial,
};
pub use dmc_remote::TlsClientConfig;
