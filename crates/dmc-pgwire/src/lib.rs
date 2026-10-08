//! PostgreSQL wire protocol.
//!
//! * [`sql_plane`] — **production** pgwire (D4-A): a thin adapter over the SQL plane
//!   (`CoreServerState`), authenticated with SASL `AVRORA-ED25519-V1` only; hosted by
//!   `dmc serve --pgwire`.
//! * [`legacy`] — the retired legacy engine (`dmc_sql::SqlEngine`). D4 gate reference and
//!   tests only; no production entry point serves it.

mod adapter;
mod protocol;
mod server;
pub mod sql_plane;

pub use sql_plane::{CHANNEL_PREFIX, MECHANISM, require_loopback, serve, spawn};

/// The retired legacy engine — reference / tests only (see crate docs).
pub mod legacy {
    pub use crate::adapter::{bind_sql_session, register_sql_channel};
    pub mod keyfile;
    pub use crate::server::{listen, serve, DEFAULT_ADDR};
}
