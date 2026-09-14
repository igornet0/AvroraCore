use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener as StdTcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};

use dmc_protocol::{ProtocolError, Result};

static ACTIVE_CONNECTIONS: AtomicU32 = AtomicU32::new(0);

pub struct TcpConnection(TcpStream);

impl Read for TcpConnection {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for TcpConnection {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl TcpConnection {
    pub fn shutdown(&mut self) -> std::io::Result<()> {
        self.0.shutdown(std::net::Shutdown::Both)
    }
}

pub struct TcpListener {
    inner: StdTcpListener,
    addr: SocketAddr,
}

impl TcpListener {
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn accept(&self) -> Result<TcpConnection> {
        let (stream, _) = self
            .inner
            .accept()
            .map_err(|e| ProtocolError::Io(e.to_string()))?;
        let _ = stream.set_nodelay(true);
        Ok(TcpConnection(stream))
    }
}

pub struct TcpTransport;

impl TcpTransport {
    pub fn bind(addr: SocketAddr, max_connections: u32) -> Result<TcpListener> {
        if ACTIVE_CONNECTIONS.load(Ordering::Relaxed) >= max_connections {
            return Err(ProtocolError::wire(
                dmc_protocol::ProtocolErrorCode::TransportError,
                "connection limit reached",
            ));
        }
        let inner = StdTcpListener::bind(addr).map_err(|e| ProtocolError::Io(e.to_string()))?;
        let addr = inner.local_addr().map_err(|e| ProtocolError::Io(e.to_string()))?;
        Ok(TcpListener { inner, addr })
    }

    pub fn connect(addr: SocketAddr) -> Result<TcpConnection> {
        let stream = TcpStream::connect(addr).map_err(|e| ProtocolError::Io(e.to_string()))?;
        let _ = stream.set_nodelay(true);
        Ok(TcpConnection(stream))
    }
}

pub fn track_connection_start(max_connections: u32) -> Result<ConnectionGuard> {
    loop {
        let current = ACTIVE_CONNECTIONS.load(Ordering::Relaxed);
        if current >= max_connections {
            return Err(ProtocolError::wire(
                dmc_protocol::ProtocolErrorCode::TransportError,
                "connection limit reached",
            ));
        }
        if ACTIVE_CONNECTIONS
            .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            return Ok(ConnectionGuard);
        }
    }
}

pub struct ConnectionGuard;

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
    }
}
