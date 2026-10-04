use std::io::{Read, Write};

use dmc_protocol::{
    build_frame, decode_payload, encode_payload, ControlRequest, DataRequest, FramedConnection, HandshakeRequest, HandshakeResponse, MessageType,
    ProtocolError, ProtocolErrorCode, RemoteLimits, RequestEnvelope, Result,
    PROTOCOL_VERSION,
};

use crate::correlation::allocate_connection_id;
use crate::dispatch::{handle_control, handle_data};
use crate::state::CoreServerState;

#[derive(Clone, Debug)]
pub struct ConnectionLimits {
    pub requests_served: u32,
    /// Stable for the lifetime of this accepted socket; new accept → new id.
    pub connection_id: String,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            requests_served: 0,
            connection_id: allocate_connection_id(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ServeOptions {
    pub limits: RemoteLimits,
    pub max_requests_per_connection: u32,
    /// Optional metrics transport label (`local` / `remote`). Not an auth signal.
    pub metrics_transport: Option<dmc_observability::MetricTransport>,
    /// Request execution ceiling from CoreConfig (informational for transport; ms).
    pub request_timeout_ms: u64,
}

impl Default for ServeOptions {
    fn default() -> Self {
        let limits = RemoteLimits::default();
        Self {
            max_requests_per_connection: limits.max_requests_per_connection,
            request_timeout_ms: limits.frame.read_timeout_ms,
            limits,
            metrics_transport: None,
        }
    }
}

impl ServeOptions {
    /// Build from protocol RemoteLimits — preferred path is ops `RuntimeLimitPolicy`.
    pub fn from_remote_limits(limits: RemoteLimits) -> Self {
        Self {
            max_requests_per_connection: limits.max_requests_per_connection,
            request_timeout_ms: limits.frame.read_timeout_ms,
            limits,
            metrics_transport: None,
        }
    }
}

/// How the connection loop reaches server state: exclusively for the whole connection,
/// or through a mutex locked **per request** so other transports (HTTP adapter, control
/// plane) and other connections can be served in between.
pub trait StateAccess {
    fn with<R>(&mut self, f: impl FnOnce(&mut CoreServerState) -> R) -> R;
}

impl StateAccess for &mut CoreServerState {
    fn with<R>(&mut self, f: impl FnOnce(&mut CoreServerState) -> R) -> R {
        f(self)
    }
}

/// Per-request locking over a shared state.
pub struct SharedState<'a>(pub &'a std::sync::Mutex<CoreServerState>);

impl StateAccess for SharedState<'_> {
    fn with<R>(&mut self, f: impl FnOnce(&mut CoreServerState) -> R) -> R {
        let mut guard = self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&mut guard)
    }
}

pub fn serve_connection<C: Read + Write>(
    conn: &mut FramedConnection<C>,
    state: &mut CoreServerState,
    options: &ServeOptions,
    conn_limits: &mut ConnectionLimits,
) -> Result<()> {
    serve_connection_with(conn, state, options, conn_limits)
}

/// Serve one connection, locking `state` only while a request is handled.
pub fn serve_connection_shared<C: Read + Write>(
    conn: &mut FramedConnection<C>,
    state: &std::sync::Mutex<CoreServerState>,
    options: &ServeOptions,
    conn_limits: &mut ConnectionLimits,
) -> Result<()> {
    serve_connection_with(conn, SharedState(state), options, conn_limits)
}

fn serve_connection_with<C: Read + Write, S: StateAccess>(
    conn: &mut FramedConnection<C>,
    mut state: S,
    options: &ServeOptions,
    conn_limits: &mut ConnectionLimits,
) -> Result<()> {
    state.with(|s| -> Result<()> {
        s.try_admit_connection()?;
        if options.metrics_transport.is_some() {
            s.metrics_transport = options.metrics_transport;
        }
        crate::metrics_rec::connection_accepted(s);
        Ok(())
    })?;
    let result = serve_connection_loop(conn, &mut state, options, conn_limits);
    state.with(|s| {
        // D5: sessions bound to this connection end with it (no rebind protocol).
        s.auth.close_channel(&conn_limits.connection_id);
        crate::metrics_rec::connection_closed(s);
        s.release_connection();
    });
    result
}

fn serve_connection_loop<C: Read + Write, S: StateAccess>(
    conn: &mut FramedConnection<C>,
    state: &mut S,
    options: &ServeOptions,
    conn_limits: &mut ConnectionLimits,
) -> Result<()> {
    loop {
        if conn_limits.requests_served >= options.max_requests_per_connection {
            return Err(ProtocolError::wire(
                ProtocolErrorCode::InvalidRequest,
                "connection request limit exceeded",
            ));
        }

        let frame = match conn.read_frame() {
            Ok(frame) => frame,
            Err(ProtocolError::Io(msg)) if msg.contains("UnexpectedEof") => return Ok(()),
            Err(err) => return Err(err),
        };

        match frame.header.message_type {
            MessageType::HandshakeRequest => {
                let req: HandshakeRequest = decode_payload(&frame.payload)?;
                if req.protocol_version != PROTOCOL_VERSION {
                    return Err(ProtocolError::UnsupportedVersion(req.protocol_version));
                }
                let resp = HandshakeResponse {
                    protocol_version: PROTOCOL_VERSION,
                    server_id: "avrora-core".into(),
                };
                let payload = encode_payload(&resp, options.limits.protocol())?;
                conn.write_frame(&build_frame(MessageType::HandshakeResponse, payload))?;
                conn.handshaken = true;
            }
            MessageType::ControlRequest => {
                ensure_handshaken(conn)?;
                let env: RequestEnvelope<ControlRequest> = decode_payload(&frame.payload)?;
                let response = state.with(|s| handle_control(s, env, &options.limits, &conn_limits.connection_id))?;
                let payload = encode_payload(&response, options.limits.protocol())?;
                conn.write_frame(&build_frame(MessageType::ControlResponse, payload))?;
                conn_limits.requests_served += 1;
            }
            MessageType::DataRequest => {
                ensure_handshaken(conn)?;
                let env: RequestEnvelope<DataRequest> = decode_payload(&frame.payload)?;
                let response = state.with(|s| handle_data(s, env, &options.limits, &conn_limits.connection_id))?;
                let payload = encode_payload(&response, options.limits.protocol())?;
                conn.write_frame(&build_frame(MessageType::DataResponse, payload))?;
                conn_limits.requests_served += 1;
            }
            other => {
                return Err(ProtocolError::UnknownMessageType(other as u16));
            }
        }
    }
}

fn ensure_handshaken<C>(conn: &FramedConnection<C>) -> Result<()> {
    if conn.handshaken {
        Ok(())
    } else {
        Err(ProtocolError::wire(
            ProtocolErrorCode::InvalidRequest,
            "handshake required",
        ))
    }
}
