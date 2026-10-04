//! Owner-only, crash-safe file writes for secret or security-relevant material.
//!
//! The file is created with mode `0600` *at creation time* (no write-then-chmod window in
//! which another local user could read it), written to a sibling temp file, fsynced,
//! renamed over the destination and the directory is fsynced. Readers observe either
//! the previous or the new content.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

/// Mode for secret files (owner read/write only).
pub const SECRET_FILE_MODE: u32 = 0o600;
/// Mode for directories that hold secret files.
pub const SECRET_DIR_MODE: u32 = 0o700;

/// Atomically replace `path` with `bytes`, owner-only permissions from the first byte.
pub fn write_secret_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    fs::create_dir_all(dir)?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let tmp = dir.join(format!(".{}.tmp-{}", name.to_string_lossy(), std::process::id()));
    let _ = fs::remove_file(&tmp);
    {
        let mut f = create_owner_only(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    // rename keeps the temp file's 0600 mode even if `path` existed with wider mode.
    File::open(dir)?.sync_all()
}

/// Restrict an existing directory to the owner.
pub fn restrict_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(SECRET_DIR_MODE))?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

fn create_owner_only(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(SECRET_FILE_MODE);
    }
    opts.open(path)
}

/// Permission bits of `path` (unix only; `None` elsewhere).
pub fn mode_of(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).ok().map(|m| m.permissions().mode() & 0o777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn creates_owner_only_and_tightens_existing_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/secret.txt");
        write_secret_file(&path, b"one").unwrap();
        assert_eq!(mode_of(&path), Some(0o600));
        assert_eq!(fs::read(&path).unwrap(), b"one");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_secret_file(&path, b"two").unwrap();
        assert_eq!(mode_of(&path), Some(0o600), "replacement resets wide mode");
        assert_eq!(fs::read(&path).unwrap(), b"two");
        let leftovers: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
    }
}
