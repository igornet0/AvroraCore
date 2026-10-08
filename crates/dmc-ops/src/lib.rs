//! Phase 7.10 — Production operations boundary.
//!
//! * 7.10.1 — configuration contract
//! * 7.10.2 — process lifecycle state machine
//! * 7.10.3 — storage / data_root layout descriptor
//! * 7.10.4 — startup orchestration (Ready + Locked; no unlock)
//! * 7.10.5 — recovery-on-startup (ADR-024 `recover` / `RecoveryGate`; no unlock)
//! * 7.10.6 — shutdown / drain (no implicit COMMIT; vault wipe)
//! * 7.10.7 — unified runtime limits from CoreConfig
//! * 7.10.8 — failure policy classifier (RejectOnly / NotReady / Fatal)

mod config;
mod emergency;
mod error;
mod failure;
mod layout;
mod lifecycle;
mod limits;
mod migrate;
mod parse;
mod secrets;
mod shutdown;
mod startup;
mod validate;

pub use config::{
    BackupConfig, CoreConfig, LayoutConfig, LifecycleConfig, LimitsConfig, ObservabilityConfig,
    Profile, RecoveryConfig, RecoveryOnStartup, TransportConfig, TransportMode, TlsPathsConfig,
    ABS_MAX_CONNECTIONS, ABS_MAX_FRAME_SIZE, ABS_MAX_IN_FLIGHT, CONFIG_FORMAT_VERSION,
};
pub use error::{
    ConfigError, LayoutError, LayoutResult, LifecycleError, LifecycleResult, Result, ShutdownError,
    ShutdownResult, StartupError, StartupResult,
};
pub use failure::{
    apply_failure_class, apply_failure_to_started, classify_kind, classify_protocol,
    classify_shutdown, classify_startup, decision_for, failure_matrix, FailureClass,
    FailureDecision, FailureKind,
};
pub use layout::{
    names as layout_names, validate_relative_component, LayoutNames, StorageLayout,
    DATABASE_FORMAT_VERSION, LAYOUT_VERSION,
};
pub use lifecycle::{
    DrainPhase, LifecycleSnapshot, LifecycleState, ProcessLifecycle, ProjectedReadiness,
    ShutdownReason,
};
pub use limits::{
    assert_limit_error_clean, validate_limits_config, ConnectionLimitGroup, LimitPolicySnapshot,
    ProtocolLimitGroup, RequestLimitGroup, RuntimeLimitPolicy, SqlLimitGroup,
};
pub use emergency::{stage_emergency_restore, EmergencyStage};
pub use parse::{load_config_file, parse_config_json, parse_config_str, parse_config_toml};
pub use secrets::{assert_no_secrets_in_config, assert_no_secrets_in_text, FORBIDDEN_CONFIG_KEYS};
pub use shutdown::{
    assert_shutdown_invariants, shutdown_core, DrainPolicy, ShutdownCoordinator, ShutdownOptions,
    ShutdownSnapshot,
};
pub use startup::{
    assert_started_invariants, assert_startup_error_clean, start_core, StartedCore,
    ENCRYPTED_STORAGE_MARKER,
    StartupDiagnostics, StartupOptions,
};
pub use validate::validate_config;
