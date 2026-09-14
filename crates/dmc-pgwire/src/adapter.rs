use std::net::SocketAddr;

use dmc_core::{ChannelId, ChannelSpec, Result, Runtime, SessionId};
use dmc_sql::SqlEngine;

/// Register this SQL listener as a TCP channel on the core runtime.
pub async fn register_sql_channel(rt: &Runtime, addr: SocketAddr) -> Result<ChannelId> {
    let id = rt.configure_channel(ChannelSpec::tcp("pgwire", addr)).await?;
    rt.start_channel(&id).await?;
    Ok(id)
}

/// Bind a core session capability onto the SQL storage engine.
pub async fn bind_sql_session(
    rt: &Runtime,
    session: &SessionId,
    engine: &mut SqlEngine,
) -> Result<()> {
    rt.apply_session_to_storage(session, engine.storage_mut())
        .await
}
