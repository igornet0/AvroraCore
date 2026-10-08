//! Master-key handling for the `dmc-pgwire` binary.
//!
//! The key is read from / written to an owner-only file. It is never accepted on the
//! command line (visible in `ps`, `/proc/<pid>/cmdline`, shell history) and never printed
//! (stdout of a daemon is usually a log file).

use std::path::{Path, PathBuf};

/// How the legacy SQL engine gets its master key.
#[derive(Debug, PartialEq, Eq)]
pub enum KeySource {
    /// Create a new database; write a freshly generated key to `out` (0600).
    CreateNew { out: PathBuf },
    /// Create a new database with a key that is already stored in `file` (0600).
    CreateWith { file: PathBuf },
    /// Open an existing database with the key stored in `file` (0600).
    Unlock { file: PathBuf },
}

#[derive(Debug, PartialEq, Eq)]
pub struct Args {
    pub data: PathBuf,
    pub listen: Option<String>,
    pub key: KeySource,
}

pub const USAGE: &str = "usage: dmc-pgwire --data PATH [--listen 127.0.0.1:15432] \
(--create --master-key-out FILE | --create --master-hex-file FILE | --unlock-file FILE)";

pub fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut data = PathBuf::from("data/sql.dbs.json");
    let mut listen = None;
    let mut create = false;
    let (mut out, mut hex_file, mut unlock_file) = (None, None, None);
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let mut value = |name: &str| {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{name} needs a value\n{USAGE}"))
        };
        match arg.as_str() {
            "--data" => data = PathBuf::from(value("--data")?),
            "--listen" => listen = Some(value("--listen")?),
            "--create" => create = true,
            "--master-key-out" => out = Some(PathBuf::from(value("--master-key-out")?)),
            "--master-hex-file" => hex_file = Some(PathBuf::from(value("--master-hex-file")?)),
            "--unlock-file" => unlock_file = Some(PathBuf::from(value("--unlock-file")?)),
            "--unlock" | "--master-hex" => {
                return Err(format!(
                    "{arg} took the master key on the command line (visible to other processes); \
                     it was removed — store the key in an owner-only file and use \
                     --unlock-file / --master-hex-file\n{USAGE}"
                ));
            }
            other => return Err(format!("unknown arg: {other}\n{USAGE}")),
        }
    }
    let key = match (create, out, hex_file, unlock_file) {
        (true, Some(out), None, None) => KeySource::CreateNew { out },
        (true, None, Some(file), None) => KeySource::CreateWith { file },
        (false, None, None, Some(file)) => KeySource::Unlock { file },
        _ => return Err(format!("choose exactly one key mode\n{USAGE}")),
    };
    Ok(Args { data, listen, key })
}

/// Read a hex master key from an owner-only file.
pub fn read_key_file(path: &Path) -> Result<String, String> {
    #[cfg(unix)]
    {
        let mode = dmc_vault::secure_fs::mode_of(path)
            .ok_or_else(|| format!("master key file {} not found", path.display()))?;
        if mode & 0o077 != 0 {
            return Err(format!(
                "master key file {} is accessible by group/others (mode {:o}); chmod 600 it",
                path.display(),
                mode & 0o777
            ));
        }
    }
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read master key file: {e}"))?;
    let key = raw.trim().to_string();
    if key.is_empty() {
        return Err("master key file is empty".into());
    }
    Ok(key)
}

/// Write a newly generated master key to `path` (0600 from creation). Refuses to
/// overwrite an existing file.
pub fn write_key_file(path: &Path, hex: &str) -> Result<(), String> {
    if path.exists() {
        return Err(format!("{} already exists; refusing to overwrite a master key", path.display()));
    }
    dmc_vault::secure_fs::write_secret_file(path, hex.as_bytes())
        .map_err(|e| format!("write master key file: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn argv_secrets_are_rejected() {
        for flag in ["--unlock", "--master-hex"] {
            let err = parse_args(&a(&["--data", "d", flag, "00ff"])).unwrap_err();
            assert!(err.contains("command line"), "{err}");
            assert!(!err.contains("00ff"), "error must not echo the key");
        }
    }

    #[test]
    fn exactly_one_key_mode() {
        assert!(parse_args(&a(&["--data", "d"])).is_err());
        assert!(parse_args(&a(&["--create"])).is_err(), "create without a key file");
        assert!(parse_args(&a(&["--create", "--master-key-out", "k", "--unlock-file", "k"])).is_err());
        assert_eq!(
            parse_args(&a(&["--data", "d", "--unlock-file", "k"])).unwrap().key,
            KeySource::Unlock { file: "k".into() }
        );
        assert_eq!(
            parse_args(&a(&["--create", "--master-key-out", "k"])).unwrap().key,
            KeySource::CreateNew { out: "k".into() }
        );
    }

    #[cfg(unix)]
    #[test]
    fn key_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sql.master.key");
        write_key_file(&p, "abcd").unwrap();
        assert_eq!(dmc_vault::secure_fs::mode_of(&p).unwrap() & 0o777, 0o600);
        assert_eq!(read_key_file(&p).unwrap(), "abcd");
        assert!(write_key_file(&p, "ffff").is_err(), "no overwrite");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = read_key_file(&p).unwrap_err();
        assert!(err.contains("chmod 600") && !err.contains("abcd"), "{err}");
    }
}
