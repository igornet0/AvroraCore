//! `dmc identity bootstrap-operator` — the local, one-time creation of the first
//! administrator (decision Administrator-A). See `dmc_security::auth::bootstrap`.
//!
//! Local privileged path: the invoking OS user must own the data directory; the password
//! is read from stdin (never from argv, never printed); the command refuses while a
//! server is listening on the data directory's socket (it would not see the new operator).
//! There is deliberately no `--force` / reset option.

use std::io::BufRead;
use std::path::{Path, PathBuf};

use dmc_ops::{CoreConfig, StorageLayout};

pub struct BootstrapArgs {
    pub data_dir: PathBuf,
    pub socket: PathBuf,
    pub name: String,
    pub database: String,
    pub schema: String,
}

/// Data root exactly as `dmc serve` resolves it.
pub fn data_root(data_dir: &Path) -> Result<PathBuf, String> {
    StorageLayout::from_config(&CoreConfig::local_defaults(data_dir))
        .map(|l| l.data_root().to_path_buf())
        .map_err(|e| e.to_string())
}

/// The invoking user must own the data root (checked by comparing the owner of a file we
/// just created with the owner of the directory; no extra dependencies).
#[cfg(unix)]
fn require_local_owner(root: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let probe = root.join(".bootstrap-owner-probe");
    std::fs::write(&probe, b"").map_err(|e| format!("data directory not writable: {e}"))?;
    let me = std::fs::metadata(&probe).map(|m| m.uid());
    let _ = std::fs::remove_file(&probe);
    let owner = std::fs::metadata(root).map(|m| m.uid()).map_err(|e| e.to_string())?;
    match me {
        Ok(uid) if uid == owner => Ok(()),
        _ => Err("bootstrap must be run by the owner of the data directory".into()),
    }
}

#[cfg(not(unix))]
fn require_local_owner(_root: &Path) -> Result<(), String> {
    Ok(())
}

pub fn read_password(input: &mut dyn BufRead) -> Result<zeroize::Zeroizing<String>, String> {
    let mut line = zeroize::Zeroizing::new(String::new());
    input.read_line(&mut line).map_err(|e| e.to_string())?;
    let trimmed = zeroize::Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_string());
    if trimmed.is_empty() {
        return Err("no password on stdin".into());
    }
    Ok(trimmed)
}

pub fn bootstrap_operator(args: &BootstrapArgs, input: &mut dyn BufRead) -> Result<String, String> {
    if std::os::unix::net::UnixStream::connect(&args.socket).is_ok() {
        return Err(format!(
            "a server is listening on {}: stop it before bootstrapping",
            args.socket.display()
        ));
    }
    std::fs::create_dir_all(&args.data_dir).map_err(|e| e.to_string())?;
    let root = data_root(&args.data_dir)?;
    require_local_owner(&root)?;
    let password = read_password(input)?;
    let id = dmc_security::auth::bootstrap::bootstrap_operator(
        &root.join(dmc_server::OWNERSHIP_DIR),
        &root.join(dmc_server::IDENTITIES_FILE),
        &args.name,
        &password,
        &args.database,
        &args.schema,
    )
    .map_err(|e| e.to_string())?;
    Ok(id.as_str().to_string())
}
