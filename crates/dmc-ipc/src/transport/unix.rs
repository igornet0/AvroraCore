#[cfg(unix)]
mod imp {
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};

    use dmc_protocol::{ProtocolError, Result};

    use super::super::{LocalConnection, LocalListener, LocalTransport};
    use crate::path::prepare_socket_parent;

    pub struct UnixConnection(UnixStream);

    impl Read for UnixConnection {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for UnixConnection {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush()
        }
    }

    impl LocalConnection for UnixConnection {
        fn shutdown(&mut self) -> std::io::Result<()> {
            self.0.shutdown(std::net::Shutdown::Both)
        }
    }

    pub struct UnixListenerWrapper {
        listener: UnixListener,
        path: PathBuf,
    }

    impl LocalListener for UnixListenerWrapper {
        type Connection = UnixConnection;

        fn accept(&self) -> Result<Self::Connection> {
            Ok(UnixConnection(
                self.listener
                    .accept()
                    .map_err(|e| ProtocolError::Io(e.to_string()))?
                    .0,
            ))
        }

        fn local_path(&self) -> Option<&Path> {
            Some(&self.path)
        }
    }

    pub struct UnixSocketTransport;

    impl LocalTransport for UnixSocketTransport {
        type Listener = UnixListenerWrapper;
        type Connection = UnixConnection;

        fn bind(path: &Path) -> Result<Self::Listener> {
            prepare_socket_parent(path)?;
            use std::os::unix::fs::FileTypeExt;
            if path.exists() {
                if path.symlink_metadata()?.file_type().is_socket() {
                    std::fs::remove_file(path)?;
                } else {
                    return Err(ProtocolError::InvalidFrame(
                        "socket path exists and is not a socket".into(),
                    ));
                }
            }
            let listener = UnixListener::bind(path).map_err(|e| ProtocolError::Io(e.to_string()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            }
            Ok(UnixListenerWrapper {
                listener,
                path: path.to_path_buf(),
            })
        }

        fn connect(path: &Path) -> Result<Self::Connection> {
            Ok(UnixConnection(
                UnixStream::connect(path).map_err(|e| ProtocolError::Io(e.to_string()))?,
            ))
        }
    }
}

#[cfg(unix)]
pub use imp::*;

#[cfg(not(unix))]
pub struct UnixSocketTransport;

#[cfg(not(unix))]
impl super::LocalTransport for UnixSocketTransport {
    type Listener = ();
    type Connection = ();

    fn bind(_path: &std::path::Path) -> dmc_protocol::Result<Self::Listener> {
        Err(dmc_protocol::ProtocolError::Io(
            "unix sockets unavailable on this platform".into(),
        ))
    }

    fn connect(_path: &std::path::Path) -> dmc_protocol::Result<Self::Connection> {
        Err(dmc_protocol::ProtocolError::Io(
            "unix sockets unavailable on this platform".into(),
        ))
    }
}
