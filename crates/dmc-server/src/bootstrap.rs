use std::path::Path;

use dmc_materialized::StateMaterializer;
use dmc_model::{ApplyMode, Catalog, CatalogApplier};
use dmc_security::auth::{Action, AuthService, Resource};
use dmc_sql_exec::{ExecutionContext, JournalBackend};

use crate::state::CoreServerState;
use crate::unlock_blob::UnlockMaterial;

/// Production-safe startup: vault Locked, no Master Key / DEK in RAM.
///
/// Returns one-time master for client KeyPass wrap (caller must not put it in SecurityState).
pub fn bootstrap_core_state(root: &Path, users_table: bool) -> (CoreServerState, UnlockMaterial) {
    bootstrap_core_state_inner(root, users_table)
}

/// Same as [`bootstrap_core_state`] — locked vault (UnlockGate / Key Management tests).
pub fn bootstrap_core_state_locked(root: &Path, users_table: bool) -> (CoreServerState, UnlockMaterial) {
    bootstrap_core_state_inner(root, users_table)
}

/// Test helper for Phase 7.1–7.5 SQL / transport fixtures: vault starts Unlocked.
pub fn bootstrap_core_state_unlocked_for_test(root: &Path, users_table: bool) -> CoreServerState {
    let (mut state, master) = bootstrap_core_state_inner(root, users_table);
    state
        .apply_vault_unlock(&master)
        .expect("test unlock");
    state
}

fn bootstrap_core_state_inner(root: &Path, users_table: bool) -> (CoreServerState, UnlockMaterial) {
    let mut catalog = Catalog::new();
    let mut events = catalog.bootstrap_default().unwrap();
    if users_table {
        let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
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
            .unwrap();
        catalog.apply(&create, ApplyMode::Live).unwrap();
        events.push(create);
    }

    let snapshot = root.join("materialized_snapshot.json");
    let log = root.join("state_events.json");
    let rows = root.join("rows");
    let mut mat = StateMaterializer::open(rows, snapshot, log).unwrap();
    for event in &events {
        mat.mutate_catalog(event.clone()).unwrap();
    }

    let mut ctx = ExecutionContext::new();
    ctx.attach_journal(JournalBackend::File(mat));
    ctx.attach_session_catalog(&catalog);
    if users_table {
        let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
        let table_id = catalog.table_by_name(schema, "users").unwrap().id;
        ctx.insert_materialized_from_journal(table_id).unwrap();
    } else {
        ctx.register_materialized_tables_from_journal().unwrap();
    }

    let auth = dev_auth_service();

    CoreServerState::new_locked(auth, ctx, root.to_path_buf()).expect("vault create")
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
    auth.grants_mut()
        .grant(identity, Resource::database("avrora"), Action::Create);
    auth
}
