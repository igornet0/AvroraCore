use std::fs;
use std::path::{Path, PathBuf};

use rand::RngCore;

use super::tls::{generate_tls_material, generate_tls_material_for_hosts};

pub struct InitResult {
    pub data_dir: PathBuf,
    pub token: String,
    pub token_path: PathBuf,
}

pub fn control_dir_next_to_db(db_path: &Path) -> PathBuf {
    db_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("control")
}

pub fn control_dir(db_path: &Path) -> PathBuf {
    if let Ok(dir) = std::env::var("AVRORA_CONTROL_DIR") {
        if !dir.trim().is_empty() {
            return PathBuf::from(dir);
        }
    }
    if let Ok(home) = std::env::var("AVRORA_HOME") {
        if !home.trim().is_empty() {
            return PathBuf::from(home).join("control");
        }
    }
    control_dir_next_to_db(db_path)
}

pub fn init_control(data_dir: &Path) -> Result<InitResult, String> {
    init_with(data_dir, None)
}

pub fn init_control_for_host(data_dir: &Path, extra_host: &str) -> Result<InitResult, String> {
    init_with(data_dir, Some(extra_host))
}

fn init_with(data_dir: &Path, extra_host: Option<&str>) -> Result<InitResult, String> {
    fs::create_dir_all(data_dir.join("tls")).map_err(|e| e.to_string())?;
    if data_dir.join("tls/server.crt").is_file() {
        return Err(format!("already initialized: {}", data_dir.display()));
    }
    match extra_host {
        Some(host) if !host.trim().is_empty() && host != "localhost" => {
            generate_tls_material_for_hosts(data_dir, &[host])?;
        }
        _ => generate_tls_material(data_dir)?,
    }
    let token = generate_bootstrap_token();
    let token_path = data_dir.join("bootstrap.token");
    write_secret_file(&token_path, token.as_bytes())?;
    crate::control::capability_rotation_config::write_default(data_dir)?;
    Ok(InitResult {
        data_dir: data_dir.to_path_buf(),
        token,
        token_path,
    })
}

pub fn read_bootstrap_token(data_dir: &Path) -> Result<String, String> {
    let path = data_dir.join("bootstrap.token");
    let raw = fs::read_to_string(&path)
        .map_err(|_| "bootstrap token already used or missing".to_string())?;
    Ok(raw.trim().to_string())
}

pub fn consume_bootstrap_token(data_dir: &Path) -> Result<(), String> {
    let path = data_dir.join("bootstrap.token");
    if path.exists() {
        fs::remove_file(&path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn generate_bootstrap_token() -> String {
    const ALPH: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    let mut parts = Vec::new();
    for _ in 0..4 {
        let mut buf = [0u8; 4];
        for b in &mut buf {
            *b = ALPH[rng.next_u32() as usize % ALPH.len()];
        }
        parts.push(String::from_utf8_lossy(&buf).into_owned());
    }
    format!("AVR-{}", parts.join("-"))
}

pub fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_writes_token_and_tls_once() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("control");
        let first = init_control(&data).unwrap();
        assert!(first.token.starts_with("AVR-"));
        assert!(first.token_path.is_file());
        assert!(data.join("tls/server.crt").is_file());
        assert!(data.join("tls/server.key").is_file());
        assert!(data.join("tls/ca.crt").is_file());
        assert!(data.join("tls/ca.key").is_file());
        assert!(data.join("capability-rotation.json").is_file());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&first.token_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        assert_eq!(read_bootstrap_token(&data).unwrap(), first.token);
        assert!(init_control(&data).is_err());

        consume_bootstrap_token(&data).unwrap();
        assert!(read_bootstrap_token(&data).is_err());
    }

    #[test]
    fn control_dir_defaults_next_to_db() {
        if std::env::var_os("AVRORA_CONTROL_DIR").is_some() {
            return;
        }
        let p = PathBuf::from("/var/lib/avrora/store.dbs.json");
        assert_eq!(control_dir(&p), PathBuf::from("/var/lib/avrora/control"));
    }
}
