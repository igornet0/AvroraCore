//! Persist HTTP / control bind addresses and UI toggle (`server.json`).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::paths::default_http_addr;

pub const CONFIG_FILE: &str = "server.json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_ui_enabled")]
    pub ui_enabled: bool,
    #[serde(default)]
    pub http_addr: String,
    #[serde(default)]
    pub control_addr: String,
}

fn default_ui_enabled() -> bool {
    true
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            ui_enabled: true,
            http_addr: String::new(),
            control_addr: String::new(),
        }
    }
}

impl ServerConfig {
    pub fn config_path(control_dir: &Path) -> PathBuf {
        control_dir.join(CONFIG_FILE)
    }

    /// File values, then env `AVRORA_ADDR` / `AVRORA_CONTROL_ADDR`, then built-in defaults.
    pub fn resolve(control_dir: &Path) -> Self {
        let mut cfg = load(control_dir).unwrap_or_default();
        if let Some(v) = env_nonempty("AVRORA_ADDR") {
            cfg.http_addr = v;
        } else if cfg.http_addr.trim().is_empty() {
            cfg.http_addr = default_http_addr();
        }
        if let Some(v) = env_nonempty("AVRORA_CONTROL_ADDR") {
            cfg.control_addr = v;
        } else if cfg.control_addr.trim().is_empty() {
            cfg.control_addr = "0.0.0.0:7432".into();
        }
        cfg
    }

    pub fn display_http_url(&self) -> String {
        display_http_url(&self.http_addr)
    }
}

fn env_nonempty(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .filter(|s| !s.trim().is_empty())
}

pub fn display_http_url(http_addr: &str) -> String {
    let shown = http_addr
        .replace("0.0.0.0", "127.0.0.1")
        .replace("[::]", "127.0.0.1");
    format!("http://{shown}")
}

pub fn load(control_dir: &Path) -> Result<ServerConfig, String> {
    let path = ServerConfig::config_path(control_dir);
    if !path.is_file() {
        return Ok(ServerConfig::default());
    }
    let raw = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    serde_json::from_str(&raw).map_err(|e| format!("server.json: {e}"))
}

pub fn save(control_dir: &Path, cfg: &ServerConfig) -> Result<PathBuf, String> {
    fs::create_dir_all(control_dir).map_err(|e| e.to_string())?;
    let path = ServerConfig::config_path(control_dir);
    let body = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    fs::write(&path, body).map_err(|e| e.to_string())?;
    Ok(path)
}

/// Dev: crate `ui/dist`. Install: `AVRORA_UI_DIST` or `<prefix>/share/avrora/ui` next to the binary.
pub fn resolve_ui_dist() -> Option<PathBuf> {
    if let Ok(p) = env::var("AVRORA_UI_DIST") {
        let p = PathBuf::from(p);
        if p.is_dir() {
            return Some(p);
        }
    }
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            for rel in ["ui", "../share/avrora/ui", "../ui"] {
                let cand = dir.join(rel);
                if cand.is_dir() {
                    return Some(cand);
                }
            }
        }
    }
    let dev = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ui/dist");
    if dev.is_dir() {
        Some(dev)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ui_flag() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = ServerConfig {
            ui_enabled: false,
            http_addr: "127.0.0.1:19999".into(),
            control_addr: "127.0.0.1:17432".into(),
        };
        save(dir.path(), &cfg).unwrap();
        cfg.ui_enabled = true;
        let loaded = load(dir.path()).unwrap();
        assert!(!loaded.ui_enabled);
        assert_eq!(loaded.http_addr, "127.0.0.1:19999");
    }
}
