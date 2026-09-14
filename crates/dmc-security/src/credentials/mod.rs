//! Persisted UI credentials (access-key hash + TOTP secret). Not user tables.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::AuthError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AuthFile {
    pub version: u32,
    pub salt_hex: String,
    pub access_key_hash: String,
    pub totp_secret_b32: String,
}

pub fn ui_auth_path(db_path: &Path) -> PathBuf {
    let name = db_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("avrora.dbs.json");
    let stem = name
        .strip_suffix(".dbs.json")
        .or_else(|| name.strip_suffix(".json"))
        .unwrap_or(name);
    db_path.with_file_name(format!("{stem}.ui-auth.json"))
}

pub(crate) fn load_file(path: &Path) -> Result<Option<AuthFile>, AuthError> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path)?;
    let file: AuthFile = serde_json::from_str(&raw)
        .map_err(|e| AuthError::BadRequest(format!("corrupt auth file: {e}")))?;
    Ok(Some(file))
}

pub(crate) fn save_file(path: &Path, file: &AuthFile) -> Result<(), AuthError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let raw = serde_json::to_string_pretty(file)
        .map_err(|e| AuthError::BadRequest(e.to_string()))?;
    std::fs::write(path, raw)?;
    Ok(())
}
