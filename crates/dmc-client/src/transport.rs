//! Transport-neutral request surface. ControlClient / SqlClient never see Local vs TLS.

use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, DataResponse, HandshakeResponse,
    ResponseEnvelope, Result as ProtoResult,
};
use dmc_protocol::RemoteLimits;
use dmc_remote::{
    tls_connect, RemoteConnectConfig, RemoteTransportPolicy, TlsConnection,
};
use dmc_server::ProtocolClient;

use crate::error::Result;
use crate::types::ConnectionTarget;

/// Unified request after handshake.
#[derive(Clone, Debug)]
pub enum Request {
    Control(ControlRequest),
    Data(DataRequest),
}

#[derive(Clone, Debug)]
pub enum Response {
    Control(ResponseEnvelope<ControlResponse>),
    Data(ResponseEnvelope<DataResponse>),
}

pub trait ClientTransport {
    fn handshake(&mut self, client_id: &str) -> ProtoResult<HandshakeResponse>;
    fn request(&mut self, request: Request) -> ProtoResult<Response>;
}

/// Concrete live transports. Callers use [`ClientTransport`], not the variants.
pub enum LiveTransport {
    #[cfg(unix)]
    Local(ProtocolClient<dmc_ipc::UnixConnection>),
    Tls(ProtocolClient<TlsConnection>),
}

impl ClientTransport for LiveTransport {
    fn handshake(&mut self, client_id: &str) -> ProtoResult<HandshakeResponse> {
        match self {
            #[cfg(unix)]
            Self::Local(c) => c.handshake(client_id),
            Self::Tls(c) => c.handshake(client_id),
        }
    }

    fn request(&mut self, request: Request) -> ProtoResult<Response> {
        match self {
            #[cfg(unix)]
            Self::Local(c) => dispatch(c, request),
            Self::Tls(c) => dispatch(c, request),
        }
    }
}

fn dispatch<C: std::io::Read + std::io::Write>(
    client: &mut ProtocolClient<C>,
    request: Request,
) -> ProtoResult<Response> {
    match request {
        Request::Control(body) => Ok(Response::Control(client.control(body)?)),
        Request::Data(body) => Ok(Response::Data(client.data(body)?)),
    }
}

impl LiveTransport {
    pub fn connect(target: &ConnectionTarget) -> Result<Self> {
        match target {
            ConnectionTarget::Local { socket } => {
                #[cfg(unix)]
                {
                    use dmc_ipc::LocalTransport;
                    let conn = dmc_ipc::UnixSocketTransport::connect(socket.as_path())?;
                    Ok(Self::Local(ProtocolClient::new(
                        conn,
                        RemoteLimits::default(),
                    )))
                }
                #[cfg(not(unix))]
                {
                    let _ = socket;
                    Err(crate::ClientError::LocalUnsupported)
                }
            }
            ConnectionTarget::Remote { endpoint, tls } => {
                let policy = if tls.development {
                    RemoteTransportPolicy::development_tls()
                } else {
                    RemoteTransportPolicy::production_tls()
                };
                RemoteConnectConfig {
                    policy,
                    server_hostname: "dmc-client".into(),
                }
                .ensure_allowed()?;
                let conn = tls_connect(*endpoint, &tls.client)?;
                Ok(Self::Tls(ProtocolClient::new(
                    conn,
                    RemoteLimits::default(),
                )))
            }
        }
    }

    pub fn shutdown(self) -> Result<()> {
        match self {
            #[cfg(unix)]
            Self::Local(c) => {
                use dmc_ipc::LocalConnection;
                c.into_inner()
                    .shutdown()
                    .map_err(dmc_protocol::ProtocolError::from)?;
                Ok(())
            }
            Self::Tls(c) => {
                c.into_inner()
                    .shutdown()
                    .map_err(dmc_protocol::ProtocolError::from)?;
                Ok(())
            }
        }
    }
}
