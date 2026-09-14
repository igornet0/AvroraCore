//! Transport-independent Core server: protocol dispatch, AuthGate, UnlockGate, SQL.

mod audit_rec;
mod backup_ops;
mod bootstrap;
mod client;
mod correlation;
mod diagnostics;
mod dispatch;
mod health;
mod metrics_rec;
mod observe;
mod serve;
mod session_gate;
mod state;
mod unlock_blob;
mod unlock_client;
mod unlock_gate;
mod vault_runtime;

pub use bootstrap::{
    bootstrap_core_state, bootstrap_core_state_locked, bootstrap_core_state_unlocked_for_test,
    dev_auth_service,
};
pub use client::{expect_ok_control, expect_ok_data, ProtocolClient};
pub use correlation::allocate_connection_id;
pub use diagnostics::{diagnostics_to_wire, evaluate_diagnostics};
pub use dispatch::{handle_control, handle_data, map_security_to_protocol};
pub use health::{evaluate_health, evaluate_readiness, liveness};
pub use serve::{serve_connection, ConnectionLimits, ServeOptions};
pub use state::{CoreLifecycle, CoreServerState, OperationalState};
pub use unlock_blob::{open_unlock_blob, seal_unlock_blob, UnlockMaterial};
pub use unlock_client::{
    authenticate_with_binding, create_unlock_blob, expect_vault_unlocked, load_keypass_bundle,
    vault_lock, vault_status, vault_unlock, KeyPassError, KeyPassProvider, MockKeyPassProvider,
    PasswordKeyPassProvider,
};
pub use unlock_gate::{SecurityState, UnlockGate, VaultState};
pub use dmc_vault::keypass::KeyPassBundle;
