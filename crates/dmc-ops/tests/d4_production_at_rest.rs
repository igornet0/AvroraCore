//! D4-A final switch — acceptance through the production path (`start_core`).
//!
//! Same scanner and the same requirement as the D4 gate (no value at rest — raw, hex,
//! HEX, base64 at all alignments — in primary storage, journal, backup, restore), driven
//! through the production SQL plane: persistent key store, deferred open, real
//! control-plane SQL / backup / restore / recover, lock and restart. Plus the guards of
//! the switch: encrypted-storage marker, refusal of a missing key store, refusal of a
//! plaintext (pre-D4) data root.
//!
//! The official gate (`dmc-pgwire/tests/d4_at_rest_gate.rs`) is unchanged and stays
//! `#[ignore]`d: its harness uses the dev/test bootstrap, not this reference path.

#[path = "../../dmc-materialized/tests/d4_support/mod.rs"]
mod d4;

use std::path::Path;

use dmc_ops::{
    CoreConfig, ENCRYPTED_STORAGE_MARKER, StartedCore, StartupError, StartupOptions,
    parse_config_json, start_core,
};
use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, DataResponse, RemoteLimits, RequestEnvelope,
};
use dmc_security::auth::{Action, Resource};
use dmc_server::{
    CoreServerState, KEY_TREE_FILE, MockKeyPassProvider, UnlockMaterial, create_unlock_blob,
    handle_control, handle_data,
};

fn cfg_for(root: &Path) -> CoreConfig {
    parse_config_json(&format!(
        r#"{{ "data_root": "{}", "profile": "development" }}"#,
        root.display()
    ))
    .unwrap()
}

/// Fresh per run, never used elsewhere.
fn unique_marker() -> String {
    format!(
        "D4_PROD_AT_REST_{}",
        hex::encode_upper(&dmc_vault::KeyMaterial::random().as_bytes()[..12])
    )
}

fn ctl(s: &mut CoreServerState, body: ControlRequest) -> ControlResponse {
    let r = handle_control(
        s,
        RequestEnvelope {
            request_id: 1,
            body,
        },
        &RemoteLimits::default(),
        "d4-prod",
    )
    .unwrap();
    assert!(r.error_code.is_none(), "{:?}", r.error_message);
    r.body.unwrap()
}

fn sql(s: &mut CoreServerState, sid: &str, q: &str) -> Option<DataResponse> {
    let r = handle_data(
        s,
        RequestEnvelope {
            request_id: 1,
            body: DataRequest::ExecuteSql {
                session_id: sid.into(),
                sql: q.into(),
                params: vec![],
            },
        },
        &RemoteLimits::default(),
        "d4-prod",
    )
    .unwrap();
    assert!(r.error_code.is_none(), "{q}: {:?}", r.error_message);
    r.body
}

/// Operator with SQL rights on `d4_plane`, authenticated and unlocked with `master`.
fn login_unlock(s: &mut CoreServerState, master: &UnlockMaterial) -> String {
    if s.auth.identities().get_by_name("op").is_none() {
        let id = s.auth_mut().create_identity("op", "pw").unwrap();
        let g = s.auth_mut().grants_mut();
        g.grant(id.clone(), Resource::database("avrora"), Action::Connect);
        g.grant(id.clone(), Resource::database("avrora"), Action::Create);
        g.grant(
            id.clone(),
            Resource::schema("avrora", "public"),
            Action::Usage,
        );
        g.grant(
            id.clone(),
            Resource::schema("avrora", "public"),
            Action::Create,
        );
        for a in [Action::Create, Action::Insert, Action::Select] {
            g.grant(
                id.clone(),
                Resource::table("avrora", "public", "d4_plane"),
                a,
            );
        }
    }
    let ControlResponse::Authenticate {
        session_id,
        unlock_binding_key,
        ..
    } = ctl(
        s,
        ControlRequest::Authenticate {
            identity_name: "op".into(),
            password: "pw".into(),
        },
    )
    else {
        panic!()
    };
    let key: [u8; 32] = unlock_binding_key.as_slice().try_into().unwrap();
    let blob = create_unlock_blob(
        &session_id,
        &key,
        &MockKeyPassProvider::with_material(master.clone()),
    )
    .unwrap();
    ctl(
        s,
        ControlRequest::VaultUnlock {
            session_id: session_id.clone(),
            blob,
        },
    );
    session_id
}

fn rows(s: &mut CoreServerState, sid: &str, q: &str) -> Vec<String> {
    match sql(s, sid, q) {
        Some(DataResponse::SqlResult(r)) => r
            .rows
            .iter()
            .map(|row| row.cells[0].value.clone())
            .collect(),
        other => panic!("{other:?}"),
    }
}

fn start(root: &Path) -> StartedCore {
    start_core(cfg_for(root), StartupOptions::production()).unwrap()
}

#[test]
fn production_sql_plane_has_no_plaintext_at_rest() {
    let marker = unique_marker();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");

    let mut started = start(&root);
    let master = started.unlock_material.clone().unwrap();
    assert!(
        root.join(ENCRYPTED_STORAGE_MARKER).is_file(),
        "marker written"
    );
    let s = &mut started.server;
    let sid = login_unlock(s, &master);
    sql(
        s,
        &sid,
        "CREATE TABLE d4_plane (id BIGINT PRIMARY KEY, note TEXT)",
    );
    sql(s, &sid, "CREATE INDEX idx_d4_note ON d4_plane(note)");
    sql(
        s,
        &sid,
        &format!("INSERT INTO d4_plane (id, note) VALUES (1, '{marker}')"),
    );
    assert_eq!(
        rows(
            s,
            &sid,
            &format!("SELECT note FROM d4_plane WHERE note = '{marker}'")
        )
        .len(),
        1
    );
    // backup → restore → recover through the control plane (keys of the open storage)
    ctl(
        s,
        ControlRequest::BackupCreate {
            session_id: sid.clone(),
            backup_id: "d4".into(),
            include_rowstore: true,
        },
    );
    ctl(
        s,
        ControlRequest::BackupRestore {
            session_id: sid.clone(),
            backup_id: "d4".into(),
            target_id: "r1".into(),
        },
    );
    ctl(
        s,
        ControlRequest::BackupRecover {
            session_id: sid.clone(),
            target_id: "r1".into(),
        },
    );
    assert!(root.join("restores/r1/live/state_events.json").is_file());

    // negative control: the scanner detects the marker in a plaintext copy
    let probe = dir.path().join("probe.txt");
    std::fs::write(&probe, format!("x{marker}y")).unwrap();
    assert!(d4::reveals(&std::fs::read(&probe).unwrap(), &marker));

    // the gate's requirement, over everything the production path wrote
    let found = d4::revealing_files(&root, &marker);
    let in_backups: Vec<_> = found.iter().filter(|f| f.starts_with("backups")).collect();
    let in_restores: Vec<_> = found.iter().filter(|f| f.starts_with("restores")).collect();
    println!("production SQL plane — all files with the marker: {found:?}");
    assert!(found.is_empty(), "plaintext at rest: {found:?}");
    assert!(in_backups.is_empty() && in_restores.is_empty());

    // lock + restart: still encrypted, readable only after unlock
    ctl(
        s,
        ControlRequest::VaultLock {
            session_id: sid.clone(),
        },
    );
    assert!(s.storage_sealed());
    drop(started);
    let mut again = start(&root);
    assert!(again.unlock_material.is_none());
    assert!(again.server.storage_sealed());
    let sid = login_unlock(&mut again.server, &master);
    let notes = rows(&mut again.server, &sid, "SELECT note FROM d4_plane");
    assert!(notes.len() == 1 && notes[0].contains(&marker), "{notes:?}");
    assert!(d4::revealing_files(&root, &marker).is_empty());
}

#[test]
fn missing_key_store_is_refused_never_recreated() {
    let marker = unique_marker();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let mut started = start(&root);
    let master = started.unlock_material.clone().unwrap();
    let key_store = started.layout.vault_root().join(KEY_TREE_FILE);
    let sid = login_unlock(&mut started.server, &master);
    sql(
        &mut started.server,
        &sid,
        "CREATE TABLE d4_plane (id BIGINT PRIMARY KEY, note TEXT)",
    );
    sql(
        &mut started.server,
        &sid,
        &format!("INSERT INTO d4_plane (id, note) VALUES (1, '{marker}')"),
    );
    drop(started);
    let saved = std::fs::read(&key_store).unwrap();

    // key store deleted: refused, no new key store, no new Master Key
    std::fs::remove_file(&key_store).unwrap();
    let err = start_core(cfg_for(&root), StartupOptions::production())
        .err()
        .unwrap();
    assert!(matches!(err, StartupError::Vault(_)), "{err}");
    assert!(!key_store.exists());

    // marker deleted as well: the sealed SQL files still identify the root
    std::fs::remove_file(root.join(ENCRYPTED_STORAGE_MARKER)).unwrap();
    let err = start_core(cfg_for(&root), StartupOptions::production())
        .err()
        .unwrap();
    assert!(matches!(err, StartupError::Vault(_)), "{err}");
    assert!(!key_store.exists());

    // the original key store back: works again (and the marker is restored)
    std::fs::write(&key_store, saved).unwrap();
    let mut again = start(&root);
    assert!(root.join(ENCRYPTED_STORAGE_MARKER).is_file());
    let sid = login_unlock(&mut again.server, &master);
    let notes = rows(&mut again.server, &sid, "SELECT note FROM d4_plane");
    assert!(notes.len() == 1 && notes[0].contains(&marker), "{notes:?}");
    assert!(d4::revealing_files(&root, &marker).is_empty());
}

#[test]
fn plaintext_data_root_requires_explicit_migration() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    // a pre-D4 store at the production layout paths
    let first = start(&root);
    let layout = first.layout.clone();
    drop(first);
    std::fs::remove_file(root.join(ENCRYPTED_STORAGE_MARKER)).unwrap();
    std::fs::remove_file(layout.vault_root().join(KEY_TREE_FILE)).unwrap();
    {
        let mut mat = dmc_materialized::StateMaterializer::open(
            layout.rowstore_root(),
            layout.materialized_snapshot(),
            layout.state_event_log(),
        )
        .unwrap();
        let mut catalog = dmc_model::Catalog::new();
        for e in catalog.bootstrap_default().unwrap() {
            mat.mutate_catalog(e).unwrap();
        }
        mat.persist_snapshot_if_configured().unwrap();
    }
    let log_before = std::fs::read(layout.state_event_log()).unwrap();

    // stage 5 contract: starts Locked with `migration_required`; a plain unlock never opens
    // or converts it (only the explicit `StorageMigrateEncrypt` does —
    // `d4_explicit_migration.rs`)
    let mut started = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    assert!(started.migration_required);
    let master = started.unlock_material.clone().expect("key store for the migration");
    let err = started.server.apply_vault_unlock(&master).err().unwrap();
    assert!(format!("{err:?}").contains("storage could not be opened"), "{err:?}");
    assert!(started.server.storage_sealed() && !started.server.root_dek_present());
    // nothing converted, no marker
    assert_eq!(std::fs::read(layout.state_event_log()).unwrap(), log_before);
    assert!(!root.join(ENCRYPTED_STORAGE_MARKER).exists());
}

/// The legacy pgwire reference leaks primary-key values at rest (`sql.dbs.json` keys);
/// the SQL plane must not: a TEXT primary key (row ids, PK index) is sealed as well.
#[test]
fn primary_key_values_are_not_plaintext_at_rest() {
    let marker = unique_marker();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let mut started = start(&root);
    let master = started.unlock_material.clone().unwrap();
    let s = &mut started.server;
    let sid = login_unlock(s, &master);
    sql(s, &sid, "CREATE TABLE d4_plane (k TEXT PRIMARY KEY, note TEXT)");
    sql(
        s,
        &sid,
        &format!("INSERT INTO d4_plane (k, note) VALUES ('{marker}', 'x')"),
    );
    assert_eq!(
        rows(s, &sid, &format!("SELECT note FROM d4_plane WHERE k = '{marker}'")).len(),
        1
    );
    ctl(
        s,
        ControlRequest::BackupCreate {
            session_id: sid.clone(),
            backup_id: "pk".into(),
            include_rowstore: true,
        },
    );
    let found = d4::revealing_files(&root, &marker);
    assert!(found.is_empty(), "primary-key value at rest: {found:?}");
}

/// D4-B through the production path: a table rolled back on disk (its sealed manifest and
/// segments, consistent with each other) keeps the vault locked at the next unlock.
#[test]
fn rolled_back_table_keeps_the_vault_locked() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let mut started = start(&root);
    let master = started.unlock_material.clone().unwrap();
    let rows_dir = started.layout.rowstore_root();
    let s = &mut started.server;
    let sid = login_unlock(s, &master);
    sql(s, &sid, "CREATE TABLE d4_plane (id BIGINT PRIMARY KEY, note TEXT)");
    sql(s, &sid, "INSERT INTO d4_plane (id, note) VALUES (1, 'a')");
    let table = std::fs::read_dir(&rows_dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.file_name().unwrap().to_string_lossy().starts_with("table_"))
        .unwrap();
    let saved = dir.path().join("saved_table");
    copy_tree(&table, &saved);
    sql(s, &sid, "INSERT INTO d4_plane (id, note) VALUES (2, 'b')");
    drop(started);

    std::fs::remove_dir_all(&table).unwrap();
    copy_tree(&saved, &table);
    let mut again = start(&root);
    assert!(again.server.apply_vault_unlock(&master).is_err());
    assert!(again.server.storage_sealed() && !again.server.root_dek_present());
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        let target = to.join(e.file_name());
        if e.path().is_dir() {
            copy_tree(&e.path(), &target);
        } else {
            std::fs::copy(e.path(), target).unwrap();
        }
    }
}
