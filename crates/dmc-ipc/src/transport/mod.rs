use std::io::{Read, Write};
use std::path::Path;

use dmc_protocol::Result;

pub trait LocalConnection: Read + Write {
    fn shutdown(&mut self) -> std::io::Result<()>;
}

pub trait LocalListener {
    type Connection: LocalConnection;
    fn accept(&self) -> Result<Self::Connection>;
    fn local_path(&self) -> Option<&Path>;
}

pub trait LocalTransport {
    type Listener: LocalListener;
    type Connection: LocalConnection;

    fn bind(path: &Path) -> Result<Self::Listener>;
    fn connect(path: &Path) -> Result<Self::Connection>;
}

pub use dmc_protocol::FramedConnection;

pub mod unix;

#[cfg(windows)]
pub mod named_pipe;

#[cfg(not(windows))]
pub mod named_pipe_stub;

#[cfg(unix)]
pub use unix::UnixSocketTransport;

#[cfg(windows)]
pub use named_pipe::NamedPipeTransport;

#[cfg(not(windows))]
pub use named_pipe_stub::NamedPipeTransport;
