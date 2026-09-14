//! PostgreSQL Simple Query wire protocol — TCP channel adapter for `dmc-core`.

mod adapter;
mod protocol;
mod server;

pub use adapter::{bind_sql_session, register_sql_channel};
pub use server::{listen, serve, DEFAULT_ADDR};
