//! Persisted UI credentials (access-key verifier + TOTP secret). Not user tables.
//!
//! Format v2: Argon2id verifier (shared `dmc_vault::ownership::credential` KDF).
//! Format v1 (legacy): single SHA-256(salt ‖ key) — still accepted for login and
//! upgraded to v2 on the first successful login.
//!
//! The file holds the TOTP secret in cleartext (TOTP needs it), so it is always written
//! owner-only (0600 from creation); a wider mode found on load is tightened.

use std::fmt;
use std::path::{Path, PathBuf};

use dmc_vault::ownership::{PasswordKdfParams, Verifier};
use serde::{Deserialize, Serialize};

use crate::error::AuthError;

pub(crate) const AUTH_FILE_V1_SHA256: u32 = 1;
pub(crate) const AUTH_FILE_V2_ARGON2ID: u32 = 2;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct AuthFile {
    pub version: u32,
    pub salt_hex: String,
    /// v1 only: hex SHA-256(salt ‖ access key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_key_hash: Option<String>,
    /// v2: Argon2id parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf: Option<PasswordKdfParams>,
    /// v2: Argon2id → HKDF verifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier: Option<Verifier>,
    pub totp_secret_b32: String,
}

impl fmt::Debug for AuthFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthFile")
            .field("version", &self.version)
            .field("verifier", &"[REDACTED]")
            .field("totp_secret_b32", &"[REDACTED]")
            .finish()
    }
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
    tighten_mode(path)?;
    let raw = zeroize::Zeroizing::new(std::fs::read_to_string(path)?);
    let file: AuthFile = serde_json::from_str(&raw)
        .map_err(|_| AuthError::BadRequest("corrupt auth file".into()))?;
    match file.version {
        AUTH_FILE_V1_SHA256 if file.access_key_hash.is_some() => {}
        AUTH_FILE_V2_ARGON2ID if file.kdf.is_some() && file.verifier.is_some() => {}
        _ => return Err(AuthError::BadRequest("corrupt auth file".into())),
    }
    Ok(Some(file))
}

pub(crate) fn save_file(path: &Path, file: &AuthFile) -> Result<(), AuthError> {
    let raw = zeroize::Zeroizing::new(
        serde_json::to_string_pretty(file).map_err(|e| AuthError::BadRequest(e.to_string()))?,
    );
    dmc_vault::secure_fs::write_secret_file(path, raw.as_bytes())?;
    Ok(())
}

/// Existing deployments wrote this file with the default (often 0644) mode.
fn tighten_mode(path: &Path) -> Result<(), AuthError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Some(mode) = dmc_vault::secure_fs::mode_of(path) {
            if mode & 0o077 != 0 {
                std::fs::set_permissions(
                    path,
                    std::fs::Permissions::from_mode(dmc_vault::secure_fs::SECRET_FILE_MODE),
                )?;
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
