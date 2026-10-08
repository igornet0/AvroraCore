//! D4-F: the dev / test bootstrap (`dmc_server::bootstrap_core_state_*`, `dmc serve --dev`
//! via `start_core(StartupOptions::dev())`, the `dmc-core` dev co-host) runs the same
//! storage path as production: SQL storage is not opened while the vault is locked, is
//! sealed with the vault's storage keys at rest, is closed again on lock, and a plaintext
//! store is never opened or converted implicitly.

#[path = "../../dmc-materialized/tests/d4_support/mod.rs"]
mod d4;

use std::path::Path;

use dmc_ops::{CoreConfig, StartupOptions, parse_config_json, start_core};
use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, DataResponse, ProtocolErrorCode, RemoteLimits,
    RequestEnvelope,
};
use dmc_runtime::RuntimeHub;
use dmc_server::{
    CoreServerState, MockKeyPassProvider, UnlockMaterial, bootstrap_core_state_locked,
    bootstrap_core_state_persistent_with_hub, create_unlock_blob, handle_control, handle_data,
};
use dmc_vault::storage_cipher::looks_sealed;

const MARKER: &str = "D4F_DEV_BOOTSTRAP_PLAINTEXT_MARKER_31e4";

fn ctl(
    s: &mut CoreServerState,
    body: ControlRequest,
) -> dmc_protocol::ResponseEnvelope<ControlResponse> {
    handle_control(
        s,
        RequestEnvelope {
            request_id: 1,
            body,
        },
        &RemoteLimits::default(),
        "d4f",
    )
    .unwrap()
}

/// Dev identity `analyst` / `pw` → (session id, binding key).
fn login(s: &mut CoreServerState) -> (String, [u8; 32]) {
    match ctl(
        s,
        ControlRequest::Authenticate {
            identity_name: "analyst".into(),
            password: "pw".into(),
        },
    )
    .body
    .unwrap()
    {
        ControlResponse::Authenticate {
            session_id,
            unlock_binding_key,
            ..
        } => (
            session_id,
            unlock_binding_key.as_slice().try_into().unwrap(),
        ),
        other => panic!("{other:?}"),
    }
}

fn unlock(s: &mut CoreServerState, master: &UnlockMaterial) -> Result<(), ProtocolErrorCode> {
    let (sid, key) = login(s);
    let blob = create_unlock_blob(
        &sid,
        &key,
        &MockKeyPassProvider::with_material(master.clone()),
    )
    .unwrap();
    let r = ctl(
        s,
        ControlRequest::VaultUnlock {
            session_id: sid,
            blob,
        },
    );
    match r.error_code {
        None => Ok(()),
        Some(code) => Err(code),
    }
}

fn sql(s: &mut CoreServerState, q: &str) -> Result<DataResponse, ProtocolErrorCode> {
    let (sid, _) = login(s);
    let r = handle_data(
        s,
        RequestEnvelope {
            request_id: 1,
            body: DataRequest::ExecuteSql {
                session_id: sid,
                sql: q.into(),
                params: vec![],
            },
        },
        &RemoteLimits::default(),
        "d4f",
    )
    .unwrap();
    match r.error_code {
        None => Ok(r.body.unwrap_or_default()),
        Some(code) => Err(code),
    }
}

fn names(s: &mut CoreServerState) -> Vec<String> {
    match sql(s, "SELECT name FROM items ORDER BY id").unwrap() {
        DataResponse::SqlResult(r) => r
            .rows
            .into_iter()
            .map(|r| r.cells[0].text.clone())
            .collect(),
        other => panic!("{other:?}"),
    }
}

fn write_marker(s: &mut CoreServerState) {
    sql(s, "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)").unwrap();
    sql(
        s,
        &format!("INSERT INTO items (id, name) VALUES (1, '{MARKER}')"),
    )
    .unwrap();
}

/// Every non-empty file under `root` that holds SQL state is sealed, and the marker is not
/// visible in any encoding anywhere under `root`.
fn assert_sealed_at_rest(root: &Path) {
    assert!(
        d4::revealing_files(root, MARKER).is_empty(),
        "plaintext at rest: {:?}",
        d4::revealing_files(root, MARKER)
    );
    let journal = d4::walk(root)
        .into_iter()
        .find(|p| p.ends_with("state_events.json"))
        .expect("journal written");
    assert!(looks_sealed(&std::fs::read(journal).unwrap()));
}

#[test]
fn dev_bootstrap_opens_nothing_while_locked_and_seals_everything_after_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("dev");
    std::fs::create_dir_all(&root).unwrap();
    let (mut state, master) = bootstrap_core_state_locked(&root, true);

    // locked: storage not opened, nothing of the store exists, SQL refused
    assert!(state.storage_sealed());
    assert!(!root.join("state_events.json").exists());
    assert!(!root.join("rows").exists());
    assert_eq!(
        sql(&mut state, "SELECT id FROM users"),
        Err(ProtocolErrorCode::VaultLocked)
    );

    // unlock: the default catalog and the demo `users` table are seeded — sealed
    unlock(&mut state, &master).unwrap();
    assert!(sql(&mut state, "SELECT id, name FROM users").is_ok());
    write_marker(&mut state);
    assert_eq!(names(&mut state), vec![MARKER.to_string()]);
    assert_sealed_at_rest(&root);

    // lock closes storage again; unlock reopens it from the sealed files
    state.lock_vault();
    assert!(state.storage_sealed());
    assert_eq!(
        sql(&mut state, "SELECT name FROM items"),
        Err(ProtocolErrorCode::VaultLocked)
    );
    unlock(&mut state, &master).unwrap();
    assert_eq!(names(&mut state), vec![MARKER.to_string()]);
    assert_sealed_at_rest(&root);

    // negative control: the same marker in a plaintext store is found by the scanner
    let plain = dir.path().join("plain");
    d4::write_rows(&plain, None, &[MARKER]);
    assert!(!d4::revealing_files(&plain, MARKER).is_empty());
}

#[test]
fn a_wrong_key_or_a_plaintext_store_opens_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("dev");
    std::fs::create_dir_all(&root).unwrap();
    let (mut state, _master) = bootstrap_core_state_locked(&root, true);
    assert_eq!(
        unlock(&mut state, &UnlockMaterial([3; 32])),
        Err(ProtocolErrorCode::UnlockFailed)
    );
    assert!(state.storage_sealed());
    assert!(!root.join("state_events.json").exists(), "nothing written");
    drop(state);

    // a plaintext (pre-D4-F) dev store: refused with the keys, never converted implicitly
    let legacy = dir.path().join("legacy");
    d4::write_rows(&legacy, None, &[MARKER]);
    let journal = legacy.join("state_events.json");
    let before = std::fs::read(&journal).unwrap();
    let (mut state, master) = bootstrap_core_state_locked(&legacy, true);
    assert!(unlock(&mut state, &master).is_err());
    assert!(state.storage_sealed());
    assert!(!state.root_dek_present(), "vault locked again");
    assert_eq!(
        std::fs::read(&journal).unwrap(),
        before,
        "plaintext store untouched"
    );
}

#[test]
fn persistent_dev_bootstrap_survives_a_restart_with_its_key_only() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("cohost");
    std::fs::create_dir_all(&root).unwrap();
    let (mut state, master) =
        bootstrap_core_state_persistent_with_hub(&root, true, RuntimeHub::new()).unwrap();
    let master = master.expect("key store created: Master Key issued once");
    assert!(root.join("vault/keytree.json").is_file());
    unlock(&mut state, &master).unwrap();
    write_marker(&mut state);
    drop(state);

    let (mut again, issued) =
        bootstrap_core_state_persistent_with_hub(&root, true, RuntimeHub::new()).unwrap();
    assert!(issued.is_none(), "existing key store: no new Master Key");
    assert!(again.storage_sealed());
    assert_eq!(
        unlock(&mut again, &UnlockMaterial([5; 32])),
        Err(ProtocolErrorCode::UnlockFailed)
    );
    unlock(&mut again, &master).unwrap();
    assert_eq!(names(&mut again), vec![MARKER.to_string()]);
    assert_sealed_at_rest(&root);
    let key_store = std::fs::read(root.join("vault/keytree.json")).unwrap();
    assert!(!key_store.windows(32).any(|w| w == master.0));
    assert!(!String::from_utf8_lossy(&key_store).contains(&hex::encode(master.0)));
    drop(again);

    // an ephemeral bootstrap (other keys) on that root cannot read it and changes nothing
    let journal = root.join("state_events.json");
    let before = std::fs::read(&journal).unwrap();
    let (mut other, other_master) = bootstrap_core_state_locked(&root, true);
    assert!(unlock(&mut other, &other_master).is_err());
    assert!(other.storage_sealed());
    assert_eq!(std::fs::read(&journal).unwrap(), before);
}

fn dev_cfg(root: &Path) -> CoreConfig {
    parse_config_json(&format!(
        r#"{{ "data_root": "{}", "profile": "development" }}"#,
        root.display()
    ))
    .unwrap()
}

/// `dmc serve --dev` runs `start_core(StartupOptions::dev())`: production storage path
/// (persistent key store, deferred + sealed storage) plus the demo `users` table.
#[test]
fn dev_start_core_is_the_production_storage_path() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("serve-dev");
    let mut started = start_core(dev_cfg(&root), StartupOptions::dev()).unwrap();
    let master = started.unlock_material.clone().unwrap();
    *started.server.auth_mut() = dmc_server::dev_auth_service();
    assert!(started.server.storage_sealed());
    assert!(d4::revealing_files(&root, MARKER).is_empty());

    unlock(&mut started.server, &master).unwrap();
    assert!(sql(&mut started.server, "SELECT id, name FROM users").is_ok());
    write_marker(&mut started.server);
    assert_sealed_at_rest(&root);
    drop(started);

    // restart: same key store, no migration, data back only after unlock
    let mut again = start_core(dev_cfg(&root), StartupOptions::dev()).unwrap();
    assert!(again.unlock_material.is_none());
    *again.server.auth_mut() = dmc_server::dev_auth_service();
    assert!(again.server.storage_sealed());
    assert!(!again.server.storage_migration_required());
    unlock(&mut again.server, &master).unwrap();
    assert_eq!(names(&mut again.server), vec![MARKER.to_string()]);
    assert_sealed_at_rest(&root);

    // production options do not seed the demo table
    let prod = dir.path().join("prod");
    let mut p = start_core(dev_cfg(&prod), StartupOptions::production()).unwrap();
    let pm = p.unlock_material.clone().unwrap();
    *p.server.auth_mut() = dmc_server::dev_auth_service();
    unlock(&mut p.server, &pm).unwrap();
    assert!(sql(&mut p.server, "SELECT id FROM users").is_err());
}
