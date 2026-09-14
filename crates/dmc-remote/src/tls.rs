use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::version::{TLS12, TLS13};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned};

use dmc_protocol::{ProtocolError, ProtocolErrorCode, Result};

use crate::tcp::{track_connection_start, TcpConnection, TcpListener, TcpTransport};

static CRYPTO: OnceLock<()> = OnceLock::new();

pub fn ensure_crypto() {
    CRYPTO.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub fn load_pem_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut &pem[..])
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| map_tls_error(e.to_string()))
}

pub fn load_pem_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut &pem[..])
        .map_err(|e| map_tls_error(e.to_string()))?
        .ok_or_else(|| ProtocolError::wire(ProtocolErrorCode::CertificateInvalid, "missing private key"))
}

#[derive(Clone, Debug)]
pub struct TlsMaterial {
    pub ca_cert_pem: Vec<u8>,
    pub server_cert_pem: Vec<u8>,
    pub server_key_pem: Vec<u8>,
}

impl TlsMaterial {
    pub fn from_pem_files(
        ca: impl AsRef<Path>,
        cert: impl AsRef<Path>,
        key: impl AsRef<Path>,
    ) -> Result<Self> {
        Ok(Self {
            ca_cert_pem: std::fs::read(ca).map_err(ProtocolError::from)?,
            server_cert_pem: std::fs::read(cert).map_err(ProtocolError::from)?,
            server_key_pem: std::fs::read(key).map_err(ProtocolError::from)?,
        })
    }
}

#[derive(Clone)]
pub struct TlsServerConfig {
    inner: Arc<ServerConfig>,
}

impl TlsServerConfig {
    pub fn from_material(material: &TlsMaterial) -> Result<Self> {
        ensure_crypto();
        let certs = load_pem_certs(&material.server_cert_pem)?;
        let key = load_pem_key(&material.server_key_pem)?;
        let ca_certs = load_pem_certs(&material.ca_cert_pem)?;
        let mut roots = RootCertStore::empty();
        for cert in ca_certs {
            roots.add(cert).map_err(|e| map_tls_error(e.to_string()))?;
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .allow_unauthenticated()
            .build()
            .map_err(|e| map_tls_error(e.to_string()))?;
        let cfg = ServerConfig::builder_with_protocol_versions(&[&TLS13])
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| map_tls_error(e.to_string()))?;
        Ok(Self {
            inner: Arc::new(cfg),
        })
    }

    pub fn from_material_tls12(material: &TlsMaterial) -> Result<Self> {
        ensure_crypto();
        let certs = load_pem_certs(&material.server_cert_pem)?;
        let key = load_pem_key(&material.server_key_pem)?;
        let ca_certs = load_pem_certs(&material.ca_cert_pem)?;
        let mut roots = RootCertStore::empty();
        for cert in ca_certs {
            roots.add(cert).map_err(|e| map_tls_error(e.to_string()))?;
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .allow_unauthenticated()
            .build()
            .map_err(|e| map_tls_error(e.to_string()))?;
        let cfg = ServerConfig::builder_with_protocol_versions(&[&TLS12])
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| map_tls_error(e.to_string()))?;
        Ok(Self {
            inner: Arc::new(cfg),
        })
    }

    pub fn inner(&self) -> &Arc<ServerConfig> {
        &self.inner
    }
}

#[derive(Clone)]
pub struct TlsClientConfig {
    inner: Arc<ClientConfig>,
    server_name: ServerName<'static>,
}

impl TlsClientConfig {
    pub fn from_material(material: &TlsMaterial, server_hostname: &str) -> Result<Self> {
        Self::from_ca_pem(&material.ca_cert_pem, server_hostname)
    }

    pub fn from_ca_pem(ca_pem: &[u8], server_hostname: &str) -> Result<Self> {
        ensure_crypto();
        let mut roots = RootCertStore::empty();
        for cert in load_pem_certs(ca_pem)? {
            roots.add(cert).map_err(|e| map_tls_error(e.to_string()))?;
        }
        let cfg = ClientConfig::builder_with_protocol_versions(&[&TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name = ServerName::try_from(server_hostname)
            .map_err(|_| {
                ProtocolError::wire(ProtocolErrorCode::HostnameMismatch, "invalid server name")
            })?
            .to_owned();
        Ok(Self {
            inner: Arc::new(cfg),
            server_name,
        })
    }

    pub fn from_ca_pem_tls12_only(ca_pem: &[u8], server_hostname: &str) -> Result<Self> {
        ensure_crypto();
        let mut roots = RootCertStore::empty();
        for cert in load_pem_certs(ca_pem)? {
            roots.add(cert).map_err(|e| map_tls_error(e.to_string()))?;
        }
        let cfg = ClientConfig::builder_with_protocol_versions(&[&TLS12])
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name = ServerName::try_from(server_hostname)
            .map_err(|_| {
                ProtocolError::wire(ProtocolErrorCode::HostnameMismatch, "invalid server name")
            })?
            .to_owned();
        Ok(Self {
            inner: Arc::new(cfg),
            server_name,
        })
    }

    pub fn with_wrong_ca(trusted_ca_pem: &[u8], server_hostname: &str) -> Result<Self> {
        Self::from_ca_pem(trusted_ca_pem, server_hostname)
    }

    pub fn with_hostname(mut self, hostname: &str) -> Result<Self> {
        self.server_name = ServerName::try_from(hostname)
            .map_err(|_| {
                ProtocolError::wire(ProtocolErrorCode::HostnameMismatch, "invalid server name")
            })?
            .to_owned();
        Ok(self)
    }

    pub fn inner(&self) -> &Arc<ClientConfig> {
        &self.inner
    }

    pub fn server_name(&self) -> &ServerName<'static> {
        &self.server_name
    }
}

pub enum TlsConnection {
    Client(StreamOwned<ClientConnection, TcpConnection>),
    Server(StreamOwned<ServerConnection, TcpConnection>),
}

impl Read for TlsConnection {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Client(s) => s.read(buf),
            Self::Server(s) => s.read(buf),
        }
    }
}

impl Write for TlsConnection {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Client(s) => s.write(buf),
            Self::Server(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Client(s) => s.flush(),
            Self::Server(s) => s.flush(),
        }
    }
}

impl TlsConnection {
    pub fn shutdown(&mut self) -> std::io::Result<()> {
        match self {
            Self::Client(s) => s.get_mut().shutdown(),
            Self::Server(s) => s.get_mut().shutdown(),
        }
    }
}

pub struct TlsListener {
    tcp: TcpListener,
    tls: TlsServerConfig,
}

impl TlsListener {
    pub fn bind(addr: SocketAddr, tls: TlsServerConfig, max_connections: u32) -> Result<Self> {
        Ok(Self {
            tcp: TcpTransport::bind(addr, max_connections)?,
            tls,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.tcp.local_addr()
    }

    pub fn accept(&self) -> Result<TlsConnection> {
        let tcp = self.tcp.accept()?;
        let conn = ServerConnection::new(Arc::clone(self.tls.inner()))
            .map_err(|e| map_tls_error(e.to_string()))?;
        Ok(TlsConnection::Server(StreamOwned::new(conn, tcp)))
    }
}

pub fn tls_connect(addr: SocketAddr, config: &TlsClientConfig) -> Result<TlsConnection> {
    let tcp = TcpTransport::connect(addr)?;
    let conn = ClientConnection::new(Arc::clone(config.inner()), config.server_name().clone())
        .map_err(|e| map_rustls_error(&e))?;
    let mut tls = StreamOwned::new(conn, tcp);
    tls.flush().map_err(map_tls_io_error)?;
    Ok(TlsConnection::Client(tls))
}

pub fn map_rustls_error(err: &rustls::Error) -> ProtocolError {
    use rustls::CertificateError as CertErr;
    let code = match err {
        rustls::Error::InvalidCertificate(
            CertErr::Expired | CertErr::ExpiredContext { .. },
        ) => ProtocolErrorCode::CertificateExpired,
        rustls::Error::InvalidCertificate(
            CertErr::NotValidYet | CertErr::NotValidYetContext { .. },
        ) => ProtocolErrorCode::CertificateInvalid,
        rustls::Error::InvalidCertificate(
            CertErr::UnknownIssuer
            | CertErr::BadSignature
            | CertErr::UnknownRevocationStatus
            | CertErr::Revoked
            | CertErr::ExpiredRevocationList
            | CertErr::ExpiredRevocationListContext { .. },
        ) => ProtocolErrorCode::CertificateUntrusted,
        rustls::Error::InvalidCertificate(
            CertErr::NotValidForName | CertErr::NotValidForNameContext { .. },
        ) => ProtocolErrorCode::HostnameMismatch,
        rustls::Error::PeerIncompatible(_)
        | rustls::Error::InappropriateHandshakeMessage { .. }
        | rustls::Error::InappropriateMessage { .. } => ProtocolErrorCode::TlsHandshakeFailed,
        rustls::Error::AlertReceived(rustls::AlertDescription::CloseNotify) => {
            ProtocolErrorCode::ConnectionClosed
        }
        _ => ProtocolErrorCode::TlsHandshakeFailed,
    };
    ProtocolError::wire(code, sanitize_tls_message(err.to_string()))
}

pub fn map_tls_io_error(err: std::io::Error) -> ProtocolError {
    if let Some(inner) = err.get_ref() {
        if let Some(tls) = inner.downcast_ref::<rustls::Error>() {
            return map_rustls_error(tls);
        }
        return map_tls_error(inner.to_string());
    }
    map_tls_error(err.to_string())
}

pub fn map_tls_error(detail: String) -> ProtocolError {
    let lower = detail.to_lowercase();
    let code = if lower.contains("expired") {
        ProtocolErrorCode::CertificateExpired
    } else if lower.contains("not valid yet") || lower.contains("not yet valid") {
        ProtocolErrorCode::CertificateInvalid
    } else if lower.contains("unknownissuer")
        || lower.contains("unknown issuer")
        || lower.contains("untrusted")
        || lower.contains("bad signature")
        || lower.contains("invalid peer certificate")
    {
        ProtocolErrorCode::CertificateUntrusted
    } else if lower.contains("dnsname")
        || lower.contains("name mismatch")
        || lower.contains("invalid name")
        || lower.contains("notvalidforname")
        || lower.contains("certificate not valid for name")
    {
        ProtocolErrorCode::HostnameMismatch
    } else if lower.contains("closed") || lower.contains("unexpected eof") {
        ProtocolErrorCode::ConnectionClosed
    } else if lower.contains("handshake") || lower.contains("protocol version") {
        ProtocolErrorCode::TlsHandshakeFailed
    } else {
        ProtocolErrorCode::TlsHandshakeFailed
    };
    ProtocolError::wire(code, sanitize_tls_message(detail))
}

fn sanitize_tls_message(message: String) -> String {
    dmc_protocol::sanitize_client_message(message)
}

pub struct TlsRemoteServer {
    listener: TlsListener,
    options: dmc_server::ServeOptions,
}

impl TlsRemoteServer {
    pub fn bind(
        addr: SocketAddr,
        tls: TlsServerConfig,
        limits: dmc_protocol::RemoteLimits,
    ) -> Result<Self> {
        Self::bind_with_policy(addr, tls, limits, crate::mode::RemoteTransportPolicy::production_tls())
    }

    pub fn bind_dev(
        addr: SocketAddr,
        tls: TlsServerConfig,
        limits: dmc_protocol::RemoteLimits,
    ) -> Result<Self> {
        Self::bind_with_policy(
            addr,
            tls,
            limits,
            crate::mode::RemoteTransportPolicy::development_tls(),
        )
    }

    fn bind_with_policy(
        addr: SocketAddr,
        tls: TlsServerConfig,
        limits: dmc_protocol::RemoteLimits,
        policy: crate::mode::RemoteTransportPolicy,
    ) -> Result<Self> {
        crate::mode::RemoteBindConfig { policy }.ensure_allowed()?;
        let listener = TlsListener::bind(addr, tls, limits.frame.max_connections)?;
        Ok(Self {
            listener,
            options: dmc_server::ServeOptions {
                limits,
                max_requests_per_connection: limits.max_requests_per_connection,
                metrics_transport: Some(dmc_observability::MetricTransport::Remote),
                request_timeout_ms: limits.frame.read_timeout_ms,
            },
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.listener.local_addr()
    }

    pub fn accept_and_serve_one(&self, state: &mut dmc_server::CoreServerState) -> Result<()> {
        let _guard = track_connection_start(self.options.limits.frame.max_connections)?;
        let conn = self.listener.accept()?;
        let mut framed = dmc_protocol::FramedConnection::new(conn, self.options.limits.frame);
        let mut conn_limits = dmc_server::ConnectionLimits::default();
        dmc_server::serve_connection(&mut framed, state, &self.options, &mut conn_limits)
    }
}

pub struct TlsRemoteClient {
    inner: dmc_server::ProtocolClient<TlsConnection>,
}

impl TlsRemoteClient {
    pub fn connect(
        addr: SocketAddr,
        tls: TlsClientConfig,
        limits: dmc_protocol::RemoteLimits,
    ) -> Result<Self> {
        Self::connect_with_policy(
            addr,
            tls,
            limits,
            crate::mode::RemoteTransportPolicy::production_tls(),
        )
    }

    pub fn connect_dev(
        addr: SocketAddr,
        tls: TlsClientConfig,
        limits: dmc_protocol::RemoteLimits,
    ) -> Result<Self> {
        Self::connect_with_policy(
            addr,
            tls,
            limits,
            crate::mode::RemoteTransportPolicy::development_tls(),
        )
    }

    fn connect_with_policy(
        addr: SocketAddr,
        tls: TlsClientConfig,
        limits: dmc_protocol::RemoteLimits,
        policy: crate::mode::RemoteTransportPolicy,
    ) -> Result<Self> {
        crate::mode::RemoteConnectConfig {
            policy,
            server_hostname: "tls-client".into(),
        }
        .ensure_allowed()?;
        let conn = tls_connect(addr, &tls)?;
        Ok(Self {
            inner: dmc_server::ProtocolClient::new(conn, limits),
        })
    }

    pub fn handshake(
        &mut self,
        client_id: &str,
    ) -> Result<dmc_protocol::HandshakeResponse> {
        self.inner.handshake(client_id)
    }

    pub fn authenticate(
        &mut self,
        identity_name: &str,
        password: &str,
    ) -> Result<dmc_protocol::ResponseEnvelope<dmc_protocol::ControlResponse>> {
        self.inner.authenticate(identity_name, password)
    }

    pub fn control(
        &mut self,
        body: dmc_protocol::ControlRequest,
    ) -> Result<dmc_protocol::ResponseEnvelope<dmc_protocol::ControlResponse>> {
        self.inner.control(body)
    }

    pub fn data(
        &mut self,
        body: dmc_protocol::DataRequest,
    ) -> Result<dmc_protocol::ResponseEnvelope<dmc_protocol::DataResponse>> {
        self.inner.data(body)
    }

    pub fn execute_sql(
        &mut self,
        session_id: &str,
        sql: &str,
    ) -> Result<dmc_protocol::ResponseEnvelope<dmc_protocol::DataResponse>> {
        self.inner.execute_sql(session_id, sql)
    }

    pub fn close(self) -> Result<()> {
        self.inner.into_inner().shutdown().map_err(Into::into)
    }
}

#[allow(dead_code)]
pub fn supported_tls13() -> &'static rustls::SupportedProtocolVersion {
    &TLS13
}

#[allow(dead_code)]
pub fn supported_tls12() -> &'static rustls::SupportedProtocolVersion {
    &TLS12
}
