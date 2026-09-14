//! Reject secret material in config text and structured documents.

use serde_json::Value;

use crate::config::CoreConfig;
use crate::error::{ConfigError, Result};

/// Forbidden configuration keys (exact match, case-insensitive).
pub const FORBIDDEN_CONFIG_KEYS: &[&str] = &[
    "master",
    "master_key",
    "masterkey",
    "password",
    "passwd",
    "secret",
    "dek",
    "kek",
    "unlock_material",
    "unlockmaterial",
    "unlock_blob",
    "unlockblob",
    "keypass",
    "session_token",
    "credential",
    "private_key_pem",
    "ciphertext",
    "argon2",
    "auth_session",
];

const FORBIDDEN_VALUE_MARKERS: &[&str] = &[
    "-----begin",
    "master_key",
    "unlockmaterial",
    "unlock_blob",
    "keypass",
];

fn is_forbidden_key(name: &str) -> bool {
    let lower = name.to_lowercase();
    FORBIDDEN_CONFIG_KEYS.iter().any(|f| lower == *f)
}

pub fn assert_no_secrets_in_text(text: &str) -> Result<()> {
    // Fast path for PEM bodies / obvious secret markers in values.
    let lower = text.to_lowercase();
    for marker in FORBIDDEN_VALUE_MARKERS {
        if lower.contains(marker) {
            return Err(ConfigError::ForbiddenSecret);
        }
    }

    // Detect forbidden keys in JSON (`"password":`) and TOML (`password =`).
    for key in FORBIDDEN_CONFIG_KEYS {
        let json_key = format!("\"{key}\"");
        let toml_key = format!("\n{key} ");
        let toml_key_start = format!("{key} ");
        let toml_eq = format!("\n{key}=");
        let toml_eq_start = format!("{key}=");
        if lower.contains(&json_key)
            || lower.contains(&toml_key)
            || lower.starts_with(&toml_key_start)
            || lower.contains(&toml_eq)
            || lower.starts_with(&toml_eq_start)
        {
            return Err(ConfigError::ForbiddenSecret);
        }
    }
    Ok(())
}

pub fn assert_no_secrets_in_json_value(value: &Value) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                if is_forbidden_key(k) {
                    return Err(ConfigError::ForbiddenSecret);
                }
                assert_no_secrets_in_json_value(v)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                assert_no_secrets_in_json_value(item)?;
            }
        }
        Value::String(s) => {
            let lower = s.to_lowercase();
            for marker in FORBIDDEN_VALUE_MARKERS {
                if lower.contains(marker) {
                    return Err(ConfigError::ForbiddenSecret);
                }
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn assert_no_secrets_in_config(cfg: &CoreConfig) -> Result<()> {
    let json = serde_json::to_value(cfg).map_err(|_| ConfigError::Parse)?;
    assert_no_secrets_in_json_value(&json)?;
    Ok(())
}
