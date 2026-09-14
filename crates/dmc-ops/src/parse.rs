//! Parse CoreConfig from JSON / TOML without executing startup.

use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::config::{CoreConfig, CONFIG_FORMAT_VERSION};
use crate::error::{ConfigError, Result};
use crate::secrets::{assert_no_secrets_in_json_value, assert_no_secrets_in_text};
use crate::validate::validate_config;

/// Wire/file partial document — omitted fields take defaults after merge.
#[derive(Debug, Deserialize)]
struct CoreConfigFile {
    #[serde(default = "default_format_version")]
    format_version: u32,
    #[serde(default)]
    profile: Option<crate::config::Profile>,
    data_root: std::path::PathBuf,
    #[serde(default)]
    transport: Option<crate::config::TransportConfig>,
    #[serde(default)]
    limits: Option<crate::config::LimitsConfig>,
    #[serde(default)]
    lifecycle: Option<crate::config::LifecycleConfig>,
    #[serde(default)]
    recovery: Option<crate::config::RecoveryConfig>,
    #[serde(default)]
    backup: Option<crate::config::BackupConfig>,
    #[serde(default)]
    layout: Option<crate::config::LayoutConfig>,
    #[serde(default)]
    observability: Option<crate::config::ObservabilityConfig>,
}

fn default_format_version() -> u32 {
    CONFIG_FORMAT_VERSION
}

fn merge_file(file: CoreConfigFile) -> CoreConfig {
    let mut cfg = CoreConfig::local_defaults(file.data_root);
    cfg.format_version = file.format_version;
    if let Some(p) = file.profile {
        cfg.profile = p;
    }
    if let Some(t) = file.transport {
        cfg.transport = t;
    }
    if let Some(l) = file.limits {
        cfg.limits = l;
    }
    if let Some(l) = file.lifecycle {
        cfg.lifecycle = l;
    }
    if let Some(r) = file.recovery {
        cfg.recovery = r;
    }
    if let Some(b) = file.backup {
        cfg.backup = b;
    }
    if let Some(l) = file.layout {
        cfg.layout = l;
    }
    if let Some(o) = file.observability {
        cfg.observability = o;
    }
    cfg
}

fn finish(cfg: CoreConfig) -> Result<CoreConfig> {
    validate_config(&cfg)?;
    Ok(cfg)
}

/// Parse JSON text → validated [`CoreConfig`].
pub fn parse_config_json(text: &str) -> Result<CoreConfig> {
    assert_no_secrets_in_text(text)?;
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|_| ConfigError::Parse)?;
    assert_no_secrets_in_json_value(&value)?;
    let file: CoreConfigFile =
        serde_json::from_value(value).map_err(|_| ConfigError::Parse)?;
    finish(merge_file(file))
}

/// Parse TOML text → validated [`CoreConfig`].
pub fn parse_config_toml(text: &str) -> Result<CoreConfig> {
    assert_no_secrets_in_text(text)?;
    let value: toml::Value = text.parse().map_err(|_| ConfigError::Parse)?;
    let json = serde_json::to_value(value).map_err(|_| ConfigError::Parse)?;
    assert_no_secrets_in_json_value(&json)?;
    let file: CoreConfigFile =
        serde_json::from_value(json).map_err(|_| ConfigError::Parse)?;
    finish(merge_file(file))
}

/// Auto-detect JSON vs TOML by leading non-whitespace (`{` → JSON).
pub fn parse_config_str(text: &str) -> Result<CoreConfig> {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') {
        parse_config_json(text)
    } else {
        parse_config_toml(text)
    }
}

pub fn load_config_file(path: &Path) -> Result<CoreConfig> {
    let text = fs::read_to_string(path).map_err(|_| ConfigError::Io)?;
    match path.extension().and_then(|e| e.to_str()) {
        Some("json") => parse_config_json(&text),
        Some("toml") => parse_config_toml(&text),
        _ => parse_config_str(&text),
    }
}
