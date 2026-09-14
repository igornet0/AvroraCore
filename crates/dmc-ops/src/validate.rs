//! Fail-closed validation for [`CoreConfig`].

use crate::config::{CoreConfig, Profile, TransportMode, CONFIG_FORMAT_VERSION};
use crate::error::{ConfigError, Result};
use crate::secrets::assert_no_secrets_in_config;

pub fn validate_config(cfg: &CoreConfig) -> Result<()> {
    if cfg.format_version != CONFIG_FORMAT_VERSION {
        return Err(ConfigError::invalid(format!(
            "unsupported format_version {}",
            cfg.format_version
        )));
    }

    if cfg.data_root.as_os_str().is_empty() {
        return Err(ConfigError::invalid("data_root must not be empty"));
    }

    validate_limits(cfg)?;
    validate_transport(cfg)?;
    validate_lifecycle(cfg)?;
    validate_backup(cfg)?;
    assert_no_secrets_in_config(cfg)?;
    Ok(())
}

fn validate_limits(cfg: &CoreConfig) -> Result<()> {
    crate::limits::validate_limits_config(&cfg.limits)
}

fn validate_transport(cfg: &CoreConfig) -> Result<()> {
    let t = &cfg.transport;
    let needs_remote = matches!(t.mode, TransportMode::Remote | TransportMode::Dual);

    if needs_remote {
        let listen = t
            .remote_listen
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if listen.is_none() {
            return Err(ConfigError::invalid(
                "remote_listen required for remote/dual transport",
            ));
        }
        match &t.tls {
            None => {
                let _ = cfg.profile; // production and development both require TLS for remote
                return Err(ConfigError::invalid(
                    "remote/dual transport requires tls path references",
                ));
            }
            Some(tls) => {
                if tls.ca_cert_path.as_os_str().is_empty()
                    || tls.server_cert_path.as_os_str().is_empty()
                    || tls.server_key_path.as_os_str().is_empty()
                {
                    return Err(ConfigError::invalid("tls paths must not be empty"));
                }
            }
        }
        // Production: remote without TLS already rejected above. Plaintext remote forbidden.
        if cfg.profile == Profile::Production && t.tls.is_none() {
            return Err(ConfigError::invalid(
                "production remote/dual requires tls path references",
            ));
        }
    }

    Ok(())
}

fn validate_lifecycle(cfg: &CoreConfig) -> Result<()> {
    if cfg.lifecycle.shutdown_drain_timeout_ms == 0 {
        return Err(ConfigError::invalid(
            "shutdown_drain_timeout_ms must be > 0",
        ));
    }
    Ok(())
}

fn validate_backup(cfg: &CoreConfig) -> Result<()> {
    use crate::layout::{validate_relative_component, LAYOUT_VERSION};

    validate_relative_component("backups_dirname", &cfg.backup.backups_dirname)
        .map_err(|e| ConfigError::invalid(e.to_string()))?;
    validate_relative_component("restores_dirname", &cfg.backup.restores_dirname)
        .map_err(|e| ConfigError::invalid(e.to_string()))?;
    validate_relative_component("recovery_dirname", &cfg.layout.recovery_dirname)
        .map_err(|e| ConfigError::invalid(e.to_string()))?;
    validate_relative_component("ops_dirname", &cfg.layout.ops_dirname)
        .map_err(|e| ConfigError::invalid(e.to_string()))?;
    if cfg.layout.layout_version != LAYOUT_VERSION {
        return Err(ConfigError::invalid(format!(
            "unsupported layout_version {}",
            cfg.layout.layout_version
        )));
    }
    Ok(())
}
