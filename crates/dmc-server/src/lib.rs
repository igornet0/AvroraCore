//! Transport-independent Core server: protocol dispatch, AuthGate, UnlockGate, SQL.

mod audit_rec;
mod backup_ops;
mod bootstrap;
mod catalog_ops;
mod client;
mod correlation;
mod diagnostics;
mod dispatch;
mod ddl_ops;
mod runtime_ops;
mod health;
mod metrics_rec;
mod observe;
mod ownership_ops;
pub mod privilege_ops;
pub mod transport_policy;
mod serve;
mod session_gate;
mod state;
mod storage_migration_ops;
mod unlock_blob;
mod unlock_client;
mod unlock_gate;
mod vault_runtime;
pub use vault_runtime::{KEY_TREE_FILE, STORAGE_KEY_PATHS};

pub use bootstrap::{
    bootstrap_core_state, bootstrap_core_state_locked, bootstrap_core_state_locked_with_hub,
    bootstrap_core_state_persistent_with_hub, bootstrap_core_state_unlocked_for_test,
    bootstrap_core_state_unlocked_with_hub_for_test, dev_auth_service, dev_catalog_events,
    dev_users_table_event,
};
pub use client::{expect_ok_control, expect_ok_data, ProtocolClient};
pub use correlation::allocate_connection_id;
pub use diagnostics::{diagnostics_to_wire, evaluate_diagnostics};
pub use dispatch::{handle_control, handle_data, map_security_to_protocol};
pub use health::{evaluate_health, evaluate_readiness, liveness};
pub use serve::{serve_connection, serve_connection_shared, ConnectionLimits, ServeOptions, SharedState, StateAccess};
pub use state::{
    AuthorizedOpenError, CoreLifecycle, CoreServerState, MigrationError, MigrationReport,
    OperationalState,
    StorageOpener, CLIENT_KEYS_DIR, IDENTITIES_FILE, OWNERSHIP_DIR,
};
pub use unlock_blob::{
    open_unlock_blob, open_unlock_blob_anchored, open_unlock_blob_full, seal_unlock_blob,
    seal_unlock_blob_anchored, seal_unlock_blob_restore, OpenedUnlock, UnlockMaterial,
};
pub use unlock_client::{
    authenticate_with_binding, create_unlock_blob, create_unlock_blob_anchored,
    create_unlock_blob_restore,
    expect_vault_unlocked, load_keypass_bundle,
    vault_lock, vault_status, vault_unlock, KeyPassError, KeyPassProvider, MockKeyPassProvider,
    PasswordKeyPassProvider,
};
pub use unlock_gate::{SecurityState, UnlockGate, VaultState};
pub use dmc_vault::keypass::KeyPassBundle;
