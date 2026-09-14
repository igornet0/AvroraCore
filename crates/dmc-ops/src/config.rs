//! Production Core configuration schema (ADR-026 §3 / 7.10.1).
//!
//! Describes *how* Core is launched. Contains **no** secrets and does **not** execute startup.

use std::path::PathBuf;

use dmc_protocol::RemoteLimits;
use serde::{Deserialize, Serialize};

/// Config format version — bump only on breaking schema changes.
pub const CONFIG_FORMAT_VERSION: u32 = 1;

/// Deployment profile. `Production` enables stricter transport/TLS rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    #[default]
    Development,
    Production,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    #[default]
    Local,
    Remote,
    Dual,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryOnStartup {
    /// Run ADR-024 recover when gate requires it, then Ready.
    #[default]
    Auto,
    /// If recover required → stay Failed/NotReady until operator recovers.
    ManualFail,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_frame_size")]
    pub max_frame_size: u32,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_max_concurrent_requests")]
    pub max_concurrent_requests: u32,
    #[serde(default = "default_max_sql_size")]
    pub max_sql_size: u32,
    #[serde(default = "default_max_params")]
    pub max_params: u32,
    #[serde(default = "default_max_parameter_size")]
    pub max_parameter_size: u32,
    #[serde(default = "default_max_in_flight_requests")]
    pub max_in_flight_requests: u32,
    #[serde(default = "default_max_requests_per_connection")]
    pub max_requests_per_connection: u32,
    #[serde(default = "default_max_unlock_blob_size")]
    pub max_unlock_blob_size: u32,
    #[serde(default = "default_read_timeout_ms")]
    pub read_timeout_ms: u64,
    #[serde(default = "default_write_timeout_ms")]
    pub write_timeout_ms: u64,
    #[serde(default = "default_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
    /// Request execution ceiling (ms). Zero is invalid (fail-closed).
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
}

fn default_max_frame_size() -> u32 {
    LimitsConfig::default().max_frame_size
}
fn default_max_connections() -> u32 {
    LimitsConfig::default().max_connections
}
fn default_max_concurrent_requests() -> u32 {
    LimitsConfig::default().max_concurrent_requests
}
fn default_max_sql_size() -> u32 {
    LimitsConfig::default().max_sql_size
}
fn default_max_params() -> u32 {
    LimitsConfig::default().max_params
}
fn default_max_parameter_size() -> u32 {
    LimitsConfig::default().max_parameter_size
}
fn default_max_in_flight_requests() -> u32 {
    LimitsConfig::default().max_in_flight_requests
}
fn default_max_requests_per_connection() -> u32 {
    LimitsConfig::default().max_requests_per_connection
}
fn default_max_unlock_blob_size() -> u32 {
    LimitsConfig::default().max_unlock_blob_size
}
fn default_read_timeout_ms() -> u64 {
    LimitsConfig::default().read_timeout_ms
}
fn default_write_timeout_ms() -> u64 {
    LimitsConfig::default().write_timeout_ms
}
fn default_idle_timeout_ms() -> u64 {
    LimitsConfig::default().idle_timeout_ms
}
fn default_request_timeout_ms() -> u64 {
    LimitsConfig::default().request_timeout_ms
}

impl Default for LimitsConfig {
    fn default() -> Self {
        let remote = RemoteLimits::default();
        let frame = remote.frame;
        Self {
            max_frame_size: frame.max_frame_size,
            max_connections: frame.max_connections,
            max_concurrent_requests: frame.max_concurrent_requests,
            max_sql_size: remote.max_sql_size,
            max_params: remote.max_params,
            max_parameter_size: remote.max_parameter_size,
            max_in_flight_requests: remote.max_in_flight_requests,
            max_requests_per_connection: remote.max_requests_per_connection,
            max_unlock_blob_size: remote.max_unlock_blob_size,
            read_timeout_ms: frame.read_timeout_ms,
            write_timeout_ms: frame.write_timeout_ms,
            idle_timeout_ms: frame.idle_timeout_ms,
            // Align with read timeout as the V1 request-execution ceiling seed.
            request_timeout_ms: frame.read_timeout_ms,
        }
    }
}

impl LimitsConfig {
    pub fn to_remote_limits(&self) -> RemoteLimits {
        crate::limits::RuntimeLimitPolicy::from_limits(self).to_remote_limits()
    }

    pub fn to_runtime_policy(&self) -> crate::limits::RuntimeLimitPolicy {
        crate::limits::RuntimeLimitPolicy::from_limits(self)
    }
}

/// TLS material is referenced by **filesystem path only** — never PEM body in config.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TlsPathsConfig {
    pub ca_cert_path: PathBuf,
    pub server_cert_path: PathBuf,
    pub server_key_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportConfig {
    pub mode: TransportMode,
    /// Optional override; empty → IPC default path resolution at start time (7.10.4).
    #[serde(default)]
    pub local_socket_path: Option<PathBuf>,
    /// `host:port` for remote listen. Required when mode is Remote or Dual.
    #[serde(default)]
    pub remote_listen: Option<String>,
    #[serde(default)]
    pub tls: Option<TlsPathsConfig>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            mode: TransportMode::Local,
            local_socket_path: None,
            remote_listen: None,
            tls: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleConfig {
    /// Drain timeout for graceful shutdown (ADR-026 §8).
    pub shutdown_drain_timeout_ms: u64,
    /// Optional recover hang ceiling (0 = disabled).
    pub startup_recover_timeout_ms: u64,
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            shutdown_drain_timeout_ms: 30_000,
            startup_recover_timeout_ms: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryConfig {
    pub on_startup: RecoveryOnStartup,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            on_startup: RecoveryOnStartup::Auto,
        }
    }
}

/// Backup/restore roots are **relative names under data_root** (opaque externally).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupConfig {
    pub backups_dirname: String,
    pub restores_dirname: String,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            backups_dirname: "backups".into(),
            restores_dirname: "restores".into(),
        }
    }
}

/// Layout version + relative ops/recovery dirnames (7.10.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayoutConfig {
    #[serde(default = "default_layout_version")]
    pub layout_version: u32,
    #[serde(default = "default_recovery_dirname")]
    pub recovery_dirname: String,
    #[serde(default = "default_ops_dirname")]
    pub ops_dirname: String,
}

fn default_layout_version() -> u32 {
    crate::layout::LAYOUT_VERSION
}

fn default_recovery_dirname() -> String {
    "recovery".into()
}

fn default_ops_dirname() -> String {
    "ops".into()
}

impl Default for LayoutConfig {
    fn default() -> Self {
        Self {
            layout_version: default_layout_version(),
            recovery_dirname: default_recovery_dirname(),
            ops_dirname: default_ops_dirname(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ObservabilityConfig {
    #[default]
    Tracing,
    Noop,
}

/// Validated production configuration document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreConfig {
    pub format_version: u32,
    pub profile: Profile,
    /// Instance data root (host path). Never echoed as absolute path on wire DTOs.
    pub data_root: PathBuf,
    #[serde(default)]
    pub transport: TransportConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub lifecycle: LifecycleConfig,
    #[serde(default)]
    pub recovery: RecoveryConfig,
    #[serde(default)]
    pub backup: BackupConfig,
    #[serde(default)]
    pub layout: LayoutConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
}

impl CoreConfig {
    /// Minimal local-dev defaults for `data_root`.
    pub fn local_defaults(data_root: impl Into<PathBuf>) -> Self {
        Self {
            format_version: CONFIG_FORMAT_VERSION,
            profile: Profile::Development,
            data_root: data_root.into(),
            transport: TransportConfig::default(),
            limits: LimitsConfig::default(),
            lifecycle: LifecycleConfig::default(),
            recovery: RecoveryConfig::default(),
            backup: BackupConfig::default(),
            layout: LayoutConfig::default(),
            observability: ObservabilityConfig::default(),
        }
    }

    pub fn production_local(data_root: impl Into<PathBuf>) -> Self {
        let mut cfg = Self::local_defaults(data_root);
        cfg.profile = Profile::Production;
        cfg
    }
}

/// Soft ceilings — values above these fail validation (abuse / misconfig).
pub const ABS_MAX_FRAME_SIZE: u32 = 64 * 1024 * 1024;
pub const ABS_MAX_CONNECTIONS: u32 = 10_000;
pub const ABS_MAX_IN_FLIGHT: u32 = 10_000;
