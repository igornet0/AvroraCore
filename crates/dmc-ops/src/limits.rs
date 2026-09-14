//! Phase 7.10.7 — Unified runtime limit policy from [`CoreConfig::limits`].
//!
//! Single production source for protocol / connection / request / SQL ceilings.
//! Does **not** invent memory accounting, CPU quotas, or adaptive rate limiting.

use serde::{Deserialize, Serialize};

use dmc_protocol::{ProtocolLimits, RemoteLimits};
use dmc_server::ServeOptions;

use crate::config::{
    CoreConfig, LimitsConfig, ABS_MAX_CONNECTIONS, ABS_MAX_FRAME_SIZE, ABS_MAX_IN_FLIGHT,
};
use crate::error::{ConfigError, Result};
use crate::validate::validate_config;

/// Protocol wire ceilings (validated before allocation — ADR-020 / 7.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolLimitGroup {
    pub max_frame_size: u32,
    pub max_unlock_blob_size: u32,
}

/// Connection admission / idle policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionLimitGroup {
    pub max_connections: u32,
    pub idle_timeout_ms: u64,
    pub read_timeout_ms: u64,
    pub write_timeout_ms: u64,
}

/// In-flight / per-connection request ceilings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestLimitGroup {
    pub max_concurrent_requests: u32,
    pub max_in_flight_requests: u32,
    pub max_requests_per_connection: u32,
    /// Request execution ceiling (ms). Transport/runtime may enforce; 0 invalid at config.
    pub request_timeout_ms: u64,
}

/// SQL statement / parameter ceilings (independent of parser internals).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlLimitGroup {
    pub max_sql_size: u32,
    pub max_params: u32,
    pub max_parameter_size: u32,
}

/// Canonical ops view of production limits — built only from [`LimitsConfig`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeLimitPolicy {
    pub protocol: ProtocolLimitGroup,
    pub connection: ConnectionLimitGroup,
    pub request: RequestLimitGroup,
    pub sql: SqlLimitGroup,
}

impl RuntimeLimitPolicy {
    /// Build from validated config. Prefer [`Self::from_validated_config`] after
    /// [`crate::validate_config`].
    pub fn from_limits(limits: &LimitsConfig) -> Self {
        Self {
            protocol: ProtocolLimitGroup {
                max_frame_size: limits.max_frame_size,
                max_unlock_blob_size: limits.max_unlock_blob_size,
            },
            connection: ConnectionLimitGroup {
                max_connections: limits.max_connections,
                idle_timeout_ms: limits.idle_timeout_ms,
                read_timeout_ms: limits.read_timeout_ms,
                write_timeout_ms: limits.write_timeout_ms,
            },
            request: RequestLimitGroup {
                max_concurrent_requests: limits.max_concurrent_requests,
                max_in_flight_requests: limits.max_in_flight_requests,
                max_requests_per_connection: limits.max_requests_per_connection,
                request_timeout_ms: limits.request_timeout_ms,
            },
            sql: SqlLimitGroup {
                max_sql_size: limits.max_sql_size,
                max_params: limits.max_params,
                max_parameter_size: limits.max_parameter_size,
            },
        }
    }

    /// Validate full config then build policy (fail-closed).
    pub fn from_config(cfg: &CoreConfig) -> Result<Self> {
        validate_config(cfg)?;
        Ok(Self::from_limits(&cfg.limits))
    }

    /// Config already validated (e.g. inside `start_core`).
    pub fn from_validated_config(cfg: &CoreConfig) -> Self {
        Self::from_limits(&cfg.limits)
    }

    pub fn to_remote_limits(&self) -> RemoteLimits {
        RemoteLimits {
            frame: ProtocolLimits {
                max_frame_size: self.protocol.max_frame_size,
                max_connections: self.connection.max_connections,
                max_concurrent_requests: self.request.max_concurrent_requests,
                read_timeout_ms: self.connection.read_timeout_ms,
                write_timeout_ms: self.connection.write_timeout_ms,
                idle_timeout_ms: self.connection.idle_timeout_ms,
            },
            max_sql_size: self.sql.max_sql_size,
            max_params: self.sql.max_params,
            max_parameter_size: self.sql.max_parameter_size,
            max_in_flight_requests: self.request.max_in_flight_requests,
            max_requests_per_connection: self.request.max_requests_per_connection,
            max_unlock_blob_size: self.protocol.max_unlock_blob_size,
        }
    }

    /// Serve options for IPC/TLS accept loops — **no** second hardcoded production table.
    pub fn to_serve_options(&self) -> ServeOptions {
        let limits = self.to_remote_limits();
        ServeOptions {
            max_requests_per_connection: limits.max_requests_per_connection,
            limits,
            metrics_transport: None,
            request_timeout_ms: self.request.request_timeout_ms,
        }
    }

    /// Effective concurrent ceiling (stricter of the two config knobs).
    pub fn max_concurrent_effective(&self) -> u32 {
        self.request
            .max_concurrent_requests
            .min(self.request.max_in_flight_requests)
    }

    pub fn snapshot(&self) -> LimitPolicySnapshot {
        LimitPolicySnapshot {
            max_frame_size: self.protocol.max_frame_size,
            max_unlock_blob_size: self.protocol.max_unlock_blob_size,
            max_connections: self.connection.max_connections,
            max_concurrent_requests: self.request.max_concurrent_requests,
            max_in_flight_requests: self.request.max_in_flight_requests,
            max_sql_size: self.sql.max_sql_size,
            max_params: self.sql.max_params,
            max_parameter_size: self.sql.max_parameter_size,
            request_timeout_ms: self.request.request_timeout_ms,
            idle_timeout_ms: self.connection.idle_timeout_ms,
        }
    }
}

/// Sanitized diagnostics view (no paths / secrets / SQL).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitPolicySnapshot {
    pub max_frame_size: u32,
    pub max_unlock_blob_size: u32,
    pub max_connections: u32,
    pub max_concurrent_requests: u32,
    pub max_in_flight_requests: u32,
    pub max_sql_size: u32,
    pub max_params: u32,
    pub max_parameter_size: u32,
    pub request_timeout_ms: u64,
    pub idle_timeout_ms: u64,
}

/// Fail-closed limit field rules (explicit zero / ceiling contract).
pub fn validate_limits_config(l: &LimitsConfig) -> Result<()> {
    for (name, value) in [
        ("max_frame_size", l.max_frame_size),
        ("max_connections", l.max_connections),
        ("max_concurrent_requests", l.max_concurrent_requests),
        ("max_sql_size", l.max_sql_size),
        ("max_params", l.max_params),
        ("max_parameter_size", l.max_parameter_size),
        ("max_in_flight_requests", l.max_in_flight_requests),
        ("max_requests_per_connection", l.max_requests_per_connection),
        ("max_unlock_blob_size", l.max_unlock_blob_size),
    ] {
        if value == 0 {
            return Err(ConfigError::invalid(format!("{name} must be > 0")));
        }
    }
    for (name, value) in [
        ("read_timeout_ms", l.read_timeout_ms),
        ("write_timeout_ms", l.write_timeout_ms),
        ("idle_timeout_ms", l.idle_timeout_ms),
        ("request_timeout_ms", l.request_timeout_ms),
    ] {
        if value == 0 {
            return Err(ConfigError::invalid(format!("{name} must be > 0")));
        }
    }
    if l.max_frame_size > ABS_MAX_FRAME_SIZE {
        return Err(ConfigError::invalid(
            "max_frame_size exceeds absolute ceiling",
        ));
    }
    if l.max_connections > ABS_MAX_CONNECTIONS {
        return Err(ConfigError::invalid(
            "max_connections exceeds absolute ceiling",
        ));
    }
    if l.max_in_flight_requests > ABS_MAX_IN_FLIGHT
        || l.max_concurrent_requests > ABS_MAX_IN_FLIGHT
    {
        return Err(ConfigError::invalid(
            "in-flight limit exceeds absolute ceiling",
        ));
    }
    if l.max_sql_size > ABS_MAX_FRAME_SIZE {
        return Err(ConfigError::invalid("max_sql_size exceeds absolute ceiling"));
    }
    if l.max_parameter_size > ABS_MAX_FRAME_SIZE {
        return Err(ConfigError::invalid(
            "max_parameter_size exceeds absolute ceiling",
        ));
    }
    if l.max_unlock_blob_size > ABS_MAX_FRAME_SIZE {
        return Err(ConfigError::invalid(
            "max_unlock_blob_size exceeds absolute ceiling",
        ));
    }
    Ok(())
}

/// Assert limit error text has no secrets / paths / full SQL dumps (tests).
pub fn assert_limit_error_clean(msg: &str) {
    let text = msg.to_lowercase();
    for needle in [
        "password",
        "master_key",
        "unlock_material",
        "\"dek\"",
        "\"kek\"",
        "keypass",
        "/var/",
        "/users/",
        "-----begin",
    ] {
        assert!(
            !text.contains(needle),
            "limit error leaked `{needle}`: {msg}"
        );
    }
}
