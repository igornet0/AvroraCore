use std::path::{Path, PathBuf};
use std::sync::Arc;

use dmc_materialized::StateMaterializer;
use dmc_model::{ApplyMode, Catalog, CatalogApplier, CatalogEvent};
use dmc_security::auth::{Action, AuthService, Resource};
use dmc_sql_exec::{ExecutionContext, JournalBackend};

use dmc_runtime::RuntimeHub;

use crate::state::{CoreServerState, StorageOpener};
use crate::unlock_blob::UnlockMaterial;

/// Dev / test bootstrap (ephemeral vault): vault Locked, no Master Key / DEK in RAM, SQL
/// storage **not opened** until `VaultUnlock` and sealed with the vault's storage keys
/// (D4-F: the same deferred, encrypted path as production `start_core`).
///
/// Returns one-time master for client KeyPass wrap (caller must not put it in SecurityState).
pub fn bootstrap_core_state(root: &Path, users_table: bool) -> (CoreServerState, UnlockMaterial) {
    bootstrap_core_state_inner(root, users_table, RuntimeHub::new())
}

/// Same as [`bootstrap_core_state`] — locked vault (UnlockGate / Key Management tests).
pub fn bootstrap_core_state_locked(root: &Path, users_table: bool) -> (CoreServerState, UnlockMaterial) {
    bootstrap_core_state_inner(root, users_table, RuntimeHub::new())
}

/// Locked bootstrap that shares an existing [`RuntimeHub`] with HTTP / other adapters.
pub fn bootstrap_core_state_locked_with_hub(
    root: &Path,
    users_table: bool,
    hub: RuntimeHub,
) -> (CoreServerState, UnlockMaterial) {
    bootstrap_core_state_inner(root, users_table, hub)
}

/// Test helper for Phase 7.1–7.5 SQL / transport fixtures: vault starts Unlocked.
pub fn bootstrap_core_state_unlocked_for_test(root: &Path, users_table: bool) -> CoreServerState {
    let (mut state, master) = bootstrap_core_state_inner(root, users_table, RuntimeHub::new());
    state
        .apply_vault_unlock(&master)
        .expect("test unlock");
    state
}

/// Unlocked test bootstrap with a shared hub (HTTP + DMC same process).
pub fn bootstrap_core_state_unlocked_with_hub_for_test(
    root: &Path,
    users_table: bool,
    hub: RuntimeHub,
) -> CoreServerState {
    let (mut state, master) = bootstrap_core_state_inner(root, users_table, hub);
    state
        .apply_vault_unlock(&master)
        .expect("test unlock");
    state
}

fn bootstrap_core_state_inner(
    root: &Path,
    users_table: bool,
    hub: RuntimeHub,
) -> (CoreServerState, UnlockMaterial) {
    let (mut state, master) = CoreServerState::new_locked_with_hub(
        dev_auth_service(),
        ExecutionContext::new(),
        root.to_path_buf(),
        hub,
    )
    .expect("vault create");
    state.set_storage_opener(Box::new(DevStorageOpener::new(root, users_table)));
    (state, master)
}

/// D4-F: dev bootstrap with a **persistent** key store at `root/vault/keytree.json` (dev
/// hosts that restart on the same data root). Same deferred, encrypted storage as
/// [`bootstrap_core_state_locked_with_hub`]; the Master Key is returned only when the key
/// store was just created.
pub fn bootstrap_core_state_persistent_with_hub(
    root: &Path,
    users_table: bool,
    hub: RuntimeHub,
) -> Result<(CoreServerState, Option<UnlockMaterial>), dmc_protocol::ProtocolError> {
    let key_store = root.join("vault").join(crate::vault_runtime::KEY_TREE_FILE);
    let (mut state, master) = CoreServerState::open_persistent_with_hub(
        dev_auth_service(),
        ExecutionContext::new(),
        root.to_path_buf(),
        &key_store,
        hub,
    )?;
    state.set_storage_opener(Box::new(DevStorageOpener::new(root, users_table)));
    Ok((state, master))
}

/// D4-F: the dev / test store is opened like the production one — only on `VaultUnlock`,
/// only with the vault's storage keys (nothing is read or written while locked, everything
/// on disk is sealed). A fresh store is seeded with the default catalog (and the demo
/// `users` table) at its first opening; a plaintext store is refused by the sealed-file
/// rules (explicit migration only).
struct DevStorageOpener {
    root: PathBuf,
    users_table: bool,
}

impl DevStorageOpener {
    fn new(root: &Path, users_table: bool) -> Self {
        Self {
            root: root.to_path_buf(),
            users_table,
        }
    }
}

impl StorageOpener for DevStorageOpener {
    fn open(&self, cipher: &dmc_vault::StorageCipher) -> Result<ExecutionContext, String> {
        let mut mat = StateMaterializer::open_with_cipher(
            self.root.join("rows"),
            self.root.join("materialized_snapshot.json"),
            self.root.join("state_events.json"),
            Some(Arc::new(cipher.clone())),
        )
        .map_err(|e| e.to_string())?;
        if mat.tip_sequence() == 0 {
            for event in dev_catalog_events(self.users_table)? {
                mat.mutate_catalog(event).map_err(|e| e.to_string())?;
            }
        }
        let catalog = mat.catalog().clone();
        let mut ctx = ExecutionContext::new();
        ctx.attach_journal(JournalBackend::File(mat));
        ctx.attach_session_catalog(&catalog);
        ctx.register_materialized_tables_from_journal()
            .map_err(|e| e.to_string())?;
        Ok(ctx)
    }
}

/// Default catalog (`avrora.public`) and, optionally, the demo `users (id, name)` table.
pub fn dev_catalog_events(users_table: bool) -> Result<Vec<CatalogEvent>, String> {
    let mut catalog = Catalog::new();
    let mut events = catalog.bootstrap_default().map_err(|e| e.to_string())?;
    if users_table {
        events.push(dev_users_table_event(&mut catalog)?);
    }
    Ok(events)
}

/// The demo `users (id BIGINT PRIMARY KEY, name TEXT)` table, applied to `catalog`.
pub fn dev_users_table_event(catalog: &mut Catalog) -> Result<CatalogEvent, String> {
    let schema = catalog
        .schemas()
        .find(|s| s.name == "public")
        .ok_or("no public schema")?
        .id;
    let create = catalog
        .create_table_event(
            schema,
            "users",
            vec![
                dmc_model::ColumnDef {
                    name: "id".into(),
                    data_type: dmc_model::SqlDataType::BigInt,
                    nullable: false,
                    default: None,
                },
                dmc_model::ColumnDef {
                    name: "name".into(),
                    data_type: dmc_model::SqlDataType::Text,
                    nullable: true,
                    default: None,
                },
            ],
            Some(vec!["id".into()]),
        )
        .map_err(|e| e.to_string())?;
    catalog
        .apply(&create, ApplyMode::Live)
        .map_err(|e| e.to_string())?;
    Ok(create)
}

/// Dev/demo auth: `analyst` / `pw` with grants for the default `avrora` catalog.
pub fn dev_auth_service() -> AuthService {
    let mut auth = AuthService::new();
    let identity = auth.create_identity("analyst", "pw").expect("dev identity");
    auth.grants_mut().grant(
        identity.clone(),
        Resource::database("avrora"),
        Action::Connect,
    );
    auth.grants_mut().grant(
        identity.clone(),
        Resource::schema("avrora", "public"),
        Action::Usage,
    );
    auth.grants_mut().grant(
        identity.clone(),
        Resource::table("avrora", "public", "users"),
        Action::Select,
    );
    auth.grants_mut().grant(
        identity.clone(),
        Resource::table("avrora", "public", "items"),
        Action::Select,
    );
    auth.grants_mut().grant(
        identity.clone(),
        Resource::table("avrora", "public", "items"),
        Action::Insert,
    );
    auth.grants_mut().grant(
        identity.clone(),
        Resource::schema("avrora", "public"),
        Action::Create,
    );
    auth.grants_mut().grant(
        identity.clone(),
        Resource::schema("avrora", "public"),
        Action::Drop,
    );
    auth.grants_mut()
        .grant(identity.clone(), Resource::database("avrora"), Action::Create);
    for table in ["users", "items"] {
        for action in [Action::Create, Action::Drop] {
            auth.grants_mut().grant(
                identity.clone(),
                Resource::table("avrora", "public", table),
                action,
            );
        }
    }
    auth
}
