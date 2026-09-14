use crate::control::ControlClient;
use crate::error::{ClientError, Result};
use crate::session::{ConnectionPhase, SessionSnapshot, SessionState};
use crate::sql::SqlClient;
use crate::transport::{ClientTransport, LiveTransport, Request, Response};
use crate::types::ConnectionTarget;

/// Top-level DataClient. UI talks only to `control()` / `sql()`.
pub struct Client {
    target: ConnectionTarget,
    client_id: String,
    transport: Option<LiveTransport>,
    pub(crate) session: SessionState,
}

impl Client {
    /// Create a disconnected client for `target`. Call [`connect`](Self::connect) next.
    pub fn new(target: ConnectionTarget) -> Self {
        Self::with_client_id(target, "dmc-client")
    }

    pub fn with_client_id(target: ConnectionTarget, client_id: impl Into<String>) -> Self {
        Self {
            target,
            client_id: client_id.into(),
            transport: None,
            session: SessionState::disconnected(),
        }
    }

    /// Connect + handshake. Does **not** authenticate or unlock vault.
    pub fn connect(&mut self) -> Result<()> {
        if self.transport.is_some() {
            return Err(ClientError::AlreadyConnected);
        }
        self.session.phase = ConnectionPhase::Connecting;
        match LiveTransport::connect(&self.target) {
            Ok(mut transport) => {
                transport.handshake(&self.client_id)?;
                self.transport = Some(transport);
                self.session.phase = ConnectionPhase::Connected;
                Ok(())
            }
            Err(err) => {
                self.session.phase = ConnectionPhase::Disconnected;
                Err(err)
            }
        }
    }

    /// Drop the transport. Does **not** imply AuthSession destroyed or vault locked
    /// on the server — those are Core semantics. After reconnect, call authenticate
    /// and `vault_status` again.
    pub fn disconnect(&mut self) -> Result<()> {
        if let Some(t) = self.transport.take() {
            let _ = t.shutdown();
        }
        self.session.clear_all();
        Ok(())
    }

    /// Reconnect to the same target. Clears local session cache; server state unchanged
    /// until the client re-authenticates / re-queries vault_status.
    pub fn reconnect(&mut self) -> Result<()> {
        self.disconnect()?;
        self.connect()
    }

    pub fn is_connected(&self) -> bool {
        self.transport.is_some()
            && matches!(
                self.session.phase,
                ConnectionPhase::Connected | ConnectionPhase::Authenticated
            )
    }

    pub fn snapshot(&self) -> SessionSnapshot {
        self.session.snapshot()
    }

    pub fn target(&self) -> &ConnectionTarget {
        &self.target
    }

    pub fn control(&mut self) -> ControlClient<'_> {
        ControlClient { client: self }
    }

    pub fn sql(&mut self) -> SqlClient<'_> {
        SqlClient { client: self }
    }

    pub(crate) fn transport_mut(&mut self) -> Result<&mut LiveTransport> {
        self.transport.as_mut().ok_or(ClientError::NotConnected)
    }

    pub(crate) fn request(&mut self, request: Request) -> Result<Response> {
        Ok(self.transport_mut()?.request(request)?)
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.disconnect();
    }
}
