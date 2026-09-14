use std::io::{Read, Write};
use std::path::Path;

use dmc_protocol::{ProtocolError, Result};

use super::{LocalConnection, LocalListener, LocalTransport};

pub struct NamedPipeTransport;

pub struct StubListener;

pub struct StubConnection;

impl Read for StubConnection {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "named pipe stub",
        ))
    }
}

impl Write for StubConnection {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "named pipe stub",
        ))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "named pipe stub",
        ))
    }
}

impl LocalConnection for StubConnection {
    fn shutdown(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LocalListener for StubListener {
    type Connection = StubConnection;

    fn accept(&self) -> Result<Self::Connection> {
        Err(stub_error())
    }

    fn local_path(&self) -> Option<&Path> {
        None
    }
}

impl LocalTransport for NamedPipeTransport {
    type Listener = StubListener;
    type Connection = StubConnection;

    fn bind(_path: &Path) -> Result<Self::Listener> {
        Err(stub_error())
    }

    fn connect(_path: &Path) -> Result<Self::Connection> {
        Err(stub_error())
    }
}

fn stub_error() -> ProtocolError {
    ProtocolError::Io(
        "named pipes are only available on Windows (Phase 7.3 stub)".into(),
    )
}
