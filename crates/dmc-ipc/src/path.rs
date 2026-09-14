use std::path::{Path, PathBuf};

use dmc_protocol::{ProtocolError, Result};

#[derive(Clone, Debug)]
pub struct SocketPathOptions {
    pub allow_custom_path: bool,
}

impl Default for SocketPathOptions {
    fn default() -> Self {
        Self {
            allow_custom_path: false,
        }
    }
}

pub fn default_socket_path() -> PathBuf {
    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime).join("avrora").join("avrora.sock");
    }
    std::env::temp_dir().join("avrora").join("avrora.sock")
}

pub fn prepare_socket_dir(path: &Path, options: &SocketPathOptions) -> Result<()> {
    if !options.allow_custom_path && !is_default_or_runtime_path(path) {
        return Err(ProtocolError::InvalidFrame(
            "custom socket path requires explicit opt-in".into(),
        ));
    }
    prepare_socket_parent(path)
}

pub fn prepare_socket_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| ProtocolError::InvalidFrame("socket path has no parent".into()))?;
    std::fs::create_dir_all(parent).map_err(|e| ProtocolError::Io(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    if path.exists() {
        let meta = path.symlink_metadata()?;
        if meta.file_type().is_symlink() {
            return Err(ProtocolError::InvalidFrame(
                "socket path is a symlink".into(),
            ));
        }
    }
    Ok(())
}

fn is_default_or_runtime_path(path: &Path) -> bool {
    if path == default_socket_path() {
        return true;
    }
    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
        let base = PathBuf::from(runtime).join("avrora");
        if path.starts_with(base) {
            return true;
        }
    }
    false
}
