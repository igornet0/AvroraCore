//! Resolve AVRORA_HOME / AVRORA_DATA / AVRORA_CONTROL_DIR and wipe local server state.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use dmc_security::ui_auth_path;
use dmc_vault::persist::default_db_path;

use super::init::control_dir_next_to_db;

#[derive(Debug, Clone)]
pub struct AvroraPaths {
    pub home: Option<PathBuf>,
    pub db_path: PathBuf,
    pub control_dir: PathBuf,
}

impl AvroraPaths {
    pub fn resolve() -> Self {
        let home = env_path("AVRORA_HOME");
        let repo_data = discover_repo_data_dir();
        let db_path = env_path("AVRORA_DATA")
            .or_else(|| home.as_ref().map(|h| h.join("avrora.dbs.json")))
            .or_else(|| repo_data.as_ref().map(|d| d.join("avrora.dbs.json")))
            .unwrap_or_else(default_db_path);
        let control_dir = env_path("AVRORA_CONTROL_DIR")
            .or_else(|| home.as_ref().map(|h| h.join("control")))
            .or_else(|| repo_data.map(|d| d.join("control")))
            .unwrap_or_else(|| control_dir_next_to_db(&db_path));
        Self {
            home,
            db_path,
            control_dir,
        }
    }

    /// Standalone auth vault for embedding RBAC in other services (`avrora-auth.dbs.json`).
    pub fn auth_db_path(&self) -> PathBuf {
        self.db_path
            .parent()
            .map(|p| p.join("avrora-auth.dbs.json"))
            .unwrap_or_else(|| PathBuf::from("avrora-auth.dbs.json"))
    }

    pub fn control_initialized(&self) -> bool {
        self.control_dir.join("tls/server.crt").is_file()
    }

    pub fn bootstrap_token_present(&self) -> bool {
        self.control_dir.join("bootstrap.token").is_file()
    }

    pub fn invite_present(&self) -> bool {
        self.control_dir.join("invite.json").is_file()
    }

    pub fn vault_exists(&self) -> bool {
        self.db_path.is_file() || dmc_journal::StorageLayout::from_db_path(&self.db_path).vault_exists()
    }
}

fn env_path(name: &str) -> Option<PathBuf> {
    env::var(name)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
}

/// When `avrora` runs from the monorepo without AVRORA_DATA, match `scripts/build/avrora-serve`.
fn discover_repo_data_dir() -> Option<PathBuf> {
    let mut starts = Vec::new();
    if let Ok(cwd) = env::current_dir() {
        starts.push(cwd);
    }
    if let Ok(exe) = env::current_exe() {
        if let Some(parent) = exe.parent() {
            starts.push(parent.to_path_buf());
        }
    }
    for start in starts {
        let mut dir = Some(start.as_path());
        while let Some(current) = dir {
            let dmc = current.join("DataModelCore");
            if dmc.is_dir() && dmc.join("Cargo.toml").is_file() {
                return Some(dmc.join("data"));
            }
            dir = current.parent();
        }
    }
    None
}

pub fn default_http_addr() -> String {
    env::var("AVRORA_ADDR").unwrap_or_else(|_| "127.0.0.1:18787".into())
}

pub fn default_control_addr() -> String {
    env::var("AVRORA_CONTROL_ADDR").unwrap_or_else(|_| "127.0.0.1:7432".into())
}

pub fn control_port_from_env() -> u16 {
    default_control_addr()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse().ok())
        .unwrap_or(7432)
}

fn is_unsafe_wipe_root(path: &Path) -> bool {
    if path == Path::new("/") {
        return true;
    }
    if let Some(home) = env::var_os("HOME").or_else(|| env::var_os("USERPROFILE")) {
        if path == Path::new(&home) {
            return true;
        }
    }
    false
}

/// Delete control plane + vault files. Requires the caller to pass `confirmed=true` (`--yes`).
pub fn reset_server_data(paths: &AvroraPaths, confirmed: bool) -> Result<Vec<PathBuf>, String> {
    if !confirmed {
        return Err("refusing to reset without --yes".into());
    }
    for p in [&paths.control_dir, paths.db_path.parent().unwrap_or(Path::new("."))] {
        if is_unsafe_wipe_root(p) {
            return Err(format!("refusing to reset unsafe path {}", p.display()));
        }
    }
    if let Some(home) = &paths.home {
        if is_unsafe_wipe_root(home) {
            return Err(format!("refusing to reset unsafe AVRORA_HOME {}", home.display()));
        }
    }

    let mut removed = Vec::new();
    if paths.control_dir.exists() {
        fs::remove_dir_all(&paths.control_dir).map_err(|e| e.to_string())?;
        removed.push(paths.control_dir.clone());
    }
    if paths.db_path.exists() {
        fs::remove_file(&paths.db_path).map_err(|e| e.to_string())?;
        removed.push(paths.db_path.clone());
    }
    let layout = dmc_journal::StorageLayout::from_db_path(&paths.db_path);
    for extra in [
        layout.base_dir(),
        layout.journal_dir(),
        layout.runtime_dir(),
        layout.legacy_backup(),
        layout.migrated_marker(),
    ] {
        if extra.is_dir() {
            fs::remove_dir_all(&extra).map_err(|e| e.to_string())?;
            removed.push(extra);
        } else if extra.is_file() {
            fs::remove_file(&extra).map_err(|e| e.to_string())?;
            removed.push(extra);
        }
    }
    let auth = ui_auth_path(&paths.db_path);
    if auth.exists() {
        fs::remove_file(&auth).map_err(|e| e.to_string())?;
        removed.push(auth);
    }
    for extra_name in [".avrora-dev-master.hex", ".avrora-dev-ui-credentials.txt"] {
        if let Some(parent) = paths.db_path.parent() {
            let p = parent.join(extra_name);
            if p.is_file() {
                fs::remove_file(&p).map_err(|e| e.to_string())?;
                removed.push(p);
            }
        }
    }
    if let Some(parent) = paths.db_path.parent() {
        if let Ok(rd) = fs::read_dir(parent) {
            for ent in rd.flatten() {
                let name = ent.file_name();
                let n = name.to_string_lossy();
                if n.ends_with(".ui-auth.json") {
                    let p = ent.path();
                    let _ = fs::remove_file(&p);
                    removed.push(p);
                }
            }
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn discover_repo_data_from_cwd() {
        let cwd = env::current_dir().unwrap();
        if cwd.join("DataModelCore/Cargo.toml").is_file()
            || cwd.join("../DataModelCore/Cargo.toml").is_file()
            || cwd.ancestors().any(|p| p.join("DataModelCore/Cargo.toml").is_file())
        {
            let paths = AvroraPaths::resolve();
            assert!(
                paths.db_path.to_string_lossy().contains("DataModelCore/data/avrora.dbs.json"),
                "db_path={}",
                paths.db_path.display()
            );
        }
    }

    #[test]
    fn auth_db_path_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let paths = AvroraPaths {
            home: None,
            db_path: dir.path().join("data/avrora.dbs.json"),
            control_dir: dir.path().join("control"),
        };
        assert_eq!(
            paths.auth_db_path(),
            dir.path().join("data/avrora-auth.dbs.json")
        );
    }

    #[test]
    fn reset_requires_yes() {
        let dir = tempfile::tempdir().unwrap();
        let paths = AvroraPaths {
            home: Some(dir.path().to_path_buf()),
            db_path: dir.path().join("avrora.dbs.json"),
            control_dir: dir.path().join("control"),
        };
        let err = reset_server_data(&paths, false).unwrap_err();
        assert!(err.contains("--yes"), "{err}");
    }

    #[test]
    fn reset_wipes_control_vault_and_auth() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("avrora.dbs.json");
        let control = dir.path().join("control");
        fs::create_dir_all(control.join("tls")).unwrap();
        fs::write(control.join("tls/server.crt"), "x").unwrap();
        fs::write(&db, "{}").unwrap();
        fs::write(dir.path().join("avrora.ui-auth.json"), "{}").unwrap();
        let paths = AvroraPaths {
            home: Some(dir.path().to_path_buf()),
            db_path: db.clone(),
            control_dir: control.clone(),
        };
        reset_server_data(&paths, true).unwrap();
        assert!(!control.exists());
        assert!(!db.exists());
        assert!(!dir.path().join("avrora.ui-auth.json").exists());
    }
}
