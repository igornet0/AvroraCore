//! D4-A stage 5: explicit migration of a plaintext (pre-D4) SQL store.
//!
//! * a plaintext store starts Locked with `migration_required` and never opens or
//!   converts implicitly (a plain `VaultUnlock` is refused, files untouched);
//! * `StorageMigrateEncrypt` (administrator, unlock blob as for `VaultUnlock`) builds,
//!   verifies and switches to encrypted storage: no value remains at rest, data intact;
//! * no authority / replayed blob / wrong key / nothing to migrate / plaintext backups
//!   without purge → refused, vault locked, store untouched;
//! * an interrupted migration is discarded (building) or rolled forward (switching).

#[path = "../../dmc-materialized/tests/d4_support/mod.rs"]
mod d4;

use std::path::{Path, PathBuf};

use dmc_backup::{BackupCoordinator, BackupRequest};
use dmc_materialized::StateMaterializer;
use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, CatalogEvent, ColumnDef, DataEvent, RowId, RowValue,
    SqlDataType,
};
use dmc_ops::{
    CoreConfig, ENCRYPTED_STORAGE_MARKER, LayoutNames, StartedCore, StartupOptions, StorageLayout,
    parse_config_json, start_core,
};
use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, DataResponse, ProtocolErrorCode, RemoteLimits,
    RequestEnvelope, ResponseEnvelope,
};
use dmc_security::auth::{Action, Resource};
use dmc_server::{
    CoreServerState, MockKeyPassProvider, UnlockMaterial, create_unlock_blob, handle_control,
    handle_data,
};

const MARKER_A: &str = "D4_MIGRATION_PLAINTEXT_MARKER_A_2d8e";
const MARKER_B: &str = "D4_MIGRATION_PLAINTEXT_MARKER_B_2d8e";

fn cfg_for(root: &Path) -> CoreConfig {
    parse_config_json(&format!(
        r#"{{ "data_root": "{}", "profile": "development" }}"#,
        root.display()
    ))
    .unwrap()
}

fn layout(root: &Path) -> StorageLayout {
    StorageLayout::new(root, LayoutNames::default()).unwrap()
}

/// A pre-D4 plaintext store at the production layout paths: table `d4_plane`, an index
/// on `note`, two rows.
fn legacy_store(root: &Path) -> StateMaterializer<dmc_materialized::FileStateEventLog> {
    let l = layout(root);
    std::fs::create_dir_all(l.rowstore_root()).unwrap();
    let mut mat = StateMaterializer::open(
        l.rowstore_root(),
        l.materialized_snapshot(),
        l.state_event_log(),
    )
    .unwrap();
    let mut catalog = Catalog::new();
    let mut events = catalog.bootstrap_default().unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let cols = vec![
        ColumnDef {
            name: "id".into(),
            data_type: SqlDataType::BigInt,
            nullable: false,
            default: None,
        },
        ColumnDef {
            name: "note".into(),
            data_type: SqlDataType::Text,
            nullable: true,
            default: None,
        },
    ];
    let create = catalog
        .create_table_event(schema, "d4_plane", cols, Some(vec!["id".into()]))
        .unwrap();
    catalog.apply(&create, ApplyMode::Live).unwrap();
    let table = match &create {
        CatalogEvent::CreateTable { id, .. } => *id,
        _ => unreachable!(),
    };
    events.push(create);
    let note = catalog.table(table).unwrap().columns[1].id;
    let idx = catalog
        .create_index_event(table, "idx_note", vec![note], false)
        .unwrap();
    catalog.apply(&idx, ApplyMode::Live).unwrap();
    events.push(idx);
    for e in events {
        mat.mutate_catalog(e).unwrap();
    }
    for (i, m) in [MARKER_A, MARKER_B].iter().enumerate() {
        mat.mutate_data(DataEvent::InsertRow {
            table_id: table,
            row_id: RowId::new(i as u64 + 1),
            values: vec![RowValue::Int64(i as i64 + 1), RowValue::String((*m).into())],
        })
        .unwrap();
    }
    mat.persist_snapshot_if_configured().unwrap();
    mat
}

fn start(root: &Path) -> StartedCore {
    start_core(cfg_for(root), StartupOptions::production()).unwrap()
}

fn ctl(s: &mut CoreServerState, body: ControlRequest) -> ResponseEnvelope<ControlResponse> {
    handle_control(
        s,
        RequestEnvelope {
            request_id: 1,
            body,
        },
        &RemoteLimits::default(),
        "d4-migrate",
    )
    .unwrap()
}

/// Session of `name` (created in-process; `admin` gets GRANT on system) → (sid, binding).
fn login(s: &mut CoreServerState, name: &str) -> (String, [u8; 32]) {
    if s.auth.identities().get_by_name(name).is_none() {
        let id = s.auth_mut().create_identity(name, "pw").unwrap();
        let g = s.auth_mut().grants_mut();
        g.grant(id.clone(), Resource::database("avrora"), Action::Connect);
        g.grant(
            id.clone(),
            Resource::schema("avrora", "public"),
            Action::Usage,
        );
        g.grant(
            id.clone(),
            Resource::table("avrora", "public", "d4_plane"),
            Action::Select,
        );
        if name == "admin" {
            g.grant(id.clone(), Resource::System, Action::Grant);
        }
    }
    let r = ctl(
        s,
        ControlRequest::Authenticate {
            identity_name: name.into(),
            password: "pw".into(),
        },
    );
    match r.body.unwrap() {
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

fn blob(sid: &str, key: &[u8; 32], master: &UnlockMaterial) -> dmc_protocol::UnlockBlob {
    create_unlock_blob(
        sid,
        key,
        &MockKeyPassProvider::with_material(master.clone()),
    )
    .unwrap()
}

fn migrate(
    s: &mut CoreServerState,
    sid: &str,
    b: dmc_protocol::UnlockBlob,
    purge: bool,
) -> ResponseEnvelope<ControlResponse> {
    ctl(
        s,
        ControlRequest::StorageMigrateEncrypt {
            session_id: sid.into(),
            blob: b,
            purge_plaintext_backups: purge,
        },
    )
}

fn notes(s: &mut CoreServerState, sid: &str) -> Vec<String> {
    let r = handle_data(
        s,
        RequestEnvelope {
            request_id: 1,
            body: DataRequest::ExecuteSql {
                session_id: sid.into(),
                sql: "SELECT note FROM d4_plane ORDER BY id".into(),
                params: vec![],
            },
        },
        &RemoteLimits::default(),
        "d4-migrate",
    )
    .unwrap();
    match r.body {
        Some(DataResponse::SqlResult(r)) => {
            r.rows.iter().map(|x| x.cells[0].value.clone()).collect()
        }
        other => panic!("{other:?} {:?}", r.error_message),
    }
}

fn store_files(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let l = layout(root);
    [l.journal_root(), l.storage_root()]
        .iter()
        .flat_map(|d| d4::walk(d))
        .map(|p| {
            let raw = std::fs::read(&p).unwrap();
            (p, raw)
        })
        .collect()
}

fn assert_untouched(s: &CoreServerState, root: &Path, before: &[(PathBuf, Vec<u8>)]) {
    assert!(
        s.storage_sealed() && !s.root_dek_present(),
        "vault locked, nothing open"
    );
    assert_eq!(store_files(root), before, "plaintext store untouched");
    assert!(!root.join(".migrate-d4").exists());
    assert!(!root.join(ENCRYPTED_STORAGE_MARKER).exists());
}

#[test]
fn plaintext_store_starts_locked_and_never_opens_implicitly() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    drop(legacy_store(&root));
    let before = store_files(&root);

    let mut started = start(&root);
    assert!(started.migration_required);
    let master = started.unlock_material.clone().expect("key store created");
    assert!(
        !root.join(ENCRYPTED_STORAGE_MARKER).exists(),
        "no marker before migration"
    );
    // a plain unlock does not open (or convert) plaintext storage
    assert!(started.server.apply_vault_unlock(&master).is_err());
    assert_untouched(&started.server, &root, &before);
    // restart: still pending, still no implicit conversion
    drop(started);
    let again = start(&root);
    assert!(again.migration_required && again.unlock_material.is_none());
    assert_untouched(&again.server, &root, &before);
}

#[test]
fn explicit_migration_encrypts_verifies_and_switches() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    drop(legacy_store(&root));
    assert!(
        !d4::revealing_files(&root, MARKER_A).is_empty(),
        "negative control"
    );

    let mut started = start(&root);
    let master = started.unlock_material.clone().unwrap();
    let s = &mut started.server;
    let (sid, key) = login(s, "admin");
    let r = migrate(s, &sid, blob(&sid, &key, &master), false);
    assert!(r.error_code.is_none(), "{:?}", r.error_message);
    match r.body.unwrap() {
        ControlResponse::StorageMigrateEncrypt { events, tables, .. } => {
            assert!(events > 0);
            assert_eq!(tables, 1);
        }
        other => panic!("{other:?}"),
    }
    // opened, encrypted, data intact (index too)
    assert!(!s.storage_sealed());
    let got = notes(s, &sid);
    assert!(got.len() == 2 && got[0].contains(MARKER_A) && got[1].contains(MARKER_B));
    assert!(root.join(ENCRYPTED_STORAGE_MARKER).is_file());
    assert!(
        !root.join(".migrate-d4").exists(),
        "work dir (and the old plaintext) removed"
    );
    for m in [MARKER_A, MARKER_B] {
        assert!(
            d4::revealing_files(&root, m).is_empty(),
            "plaintext left: {m}"
        );
    }
    let l = layout(&root);
    assert!(dmc_vault::storage_cipher::looks_sealed(
        &std::fs::read(l.state_event_log()).unwrap()
    ));

    // restart: a normal encrypted store
    drop(started);
    let mut again = start(&root);
    assert!(!again.migration_required);
    again.server.apply_vault_unlock(&master).unwrap();
    let (sid, _) = login(&mut again.server, "admin");
    assert_eq!(notes(&mut again.server, &sid).len(), 2);
    // nothing left to migrate
    let (sid, key) = login(&mut again.server, "admin");
    let r = migrate(&mut again.server, &sid, blob(&sid, &key, &master), false);
    assert_eq!(r.error_code, Some(ProtocolErrorCode::InvalidRequest));
}

#[test]
fn migration_is_refused_without_authority_or_with_a_bad_blob() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    drop(legacy_store(&root));
    let before = store_files(&root);
    let mut started = start(&root);
    let master = started.unlock_material.clone().unwrap();
    let s = &mut started.server;

    // not an administrator
    let (sid, key) = login(s, "analyst");
    let r = migrate(s, &sid, blob(&sid, &key, &master), false);
    assert_eq!(r.error_code, Some(ProtocolErrorCode::AuthorizationDenied));
    assert_untouched(s, &root, &before);

    // wrong key
    let (sid, key) = login(s, "admin");
    let r = migrate(s, &sid, blob(&sid, &key, &UnlockMaterial([9; 32])), false);
    assert!(r.error_code.is_some());
    assert_untouched(s, &root, &before);

    // another session's blob
    let (other_sid, other_key) = login(s, "admin");
    let r = migrate(s, &sid, blob(&other_sid, &other_key, &master), false);
    assert!(r.error_code.is_some());
    assert_untouched(s, &root, &before);

    // a blob is single use, even after a refusal
    let b = blob(&sid, &key, &UnlockMaterial([8; 32]));
    assert!(migrate(s, &sid, b.clone(), false).error_code.is_some());
    assert_eq!(
        migrate(s, &sid, b, false).error_code,
        Some(ProtocolErrorCode::UnlockBlobReplay)
    );
    assert_untouched(s, &root, &before);
}

#[test]
fn plaintext_backups_refuse_the_migration_unless_purged() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let mat = legacy_store(&root);
    let backups = layout(&root).backup_root();
    BackupCoordinator::create_and_publish(&mat, &BackupRequest::new("avrora"), &backups, "old")
        .unwrap();
    drop(mat);
    let before = store_files(&root);
    let mut started = start(&root);
    let master = started.unlock_material.clone().unwrap();
    let s = &mut started.server;
    let (sid, key) = login(s, "admin");

    let r = migrate(s, &sid, blob(&sid, &key, &master), false);
    assert_eq!(r.error_code, Some(ProtocolErrorCode::InvalidRequest));
    assert!(
        r.error_message
            .unwrap_or_default()
            .contains("unencrypted backup")
    );
    assert_untouched(s, &root, &before);
    assert!(backups.join("backup-old").is_dir());

    let (sid, key) = login(s, "admin");
    let r = migrate(s, &sid, blob(&sid, &key, &master), true);
    assert!(r.error_code.is_none(), "{:?}", r.error_message);
    match r.body.unwrap() {
        ControlResponse::StorageMigrateEncrypt {
            purged_artifacts, ..
        } => assert_eq!(purged_artifacts, 1),
        other => panic!("{other:?}"),
    }
    assert!(!backups.join("backup-old").exists());
    for m in [MARKER_A, MARKER_B] {
        assert!(
            d4::revealing_files(&root, m).is_empty(),
            "plaintext left: {m}"
        );
    }
}

#[test]
fn interrupted_migration_is_discarded_or_rolled_forward() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    drop(legacy_store(&root));
    let first = start(&root); // creates the key store
    let master = first.unlock_material.clone().unwrap();
    drop(first);
    let before = store_files(&root);

    // crash while building: the partial build is dropped, plaintext untouched
    let work = root.join(".migrate-d4");
    std::fs::create_dir_all(work.join("new/journal")).unwrap();
    std::fs::write(
        work.join("state.json"),
        br#"{"phase":"building","purge":[]}"#,
    )
    .unwrap();
    let again = start(&root);
    assert!(again.migration_required);
    assert!(!work.exists());
    assert_eq!(store_files(&root), before);
    drop(again);

    // crash while switching: rolled forward without keys. The encrypted trees come from a
    // complete migration of an identical copy (same key store).
    let twin = dir.path().join("twin");
    copy_dir(&root, &twin);
    let mut t = start(&twin);
    let (sid, key) = login(&mut t.server, "admin");
    let r = migrate(&mut t.server, &sid, blob(&sid, &key, &master), false);
    assert!(r.error_code.is_none(), "{:?}", r.error_message);
    drop(t);
    for tree in ["journal", "storage"] {
        copy_dir(&twin.join(tree), &work.join("new").join(tree));
    }
    std::fs::write(
        work.join("state.json"),
        br#"{"phase":"switching","purge":[]}"#,
    )
    .unwrap();
    // the first tree was already moved aside when the crash happened
    std::fs::create_dir_all(work.join("old")).unwrap();
    std::fs::rename(root.join("journal"), work.join("old/journal")).unwrap();

    let mut resumed = start(&root);
    assert!(!resumed.migration_required);
    assert!(!work.exists(), "old plaintext and work dir removed");
    assert!(root.join(ENCRYPTED_STORAGE_MARKER).is_file());
    resumed.server.apply_vault_unlock(&master).unwrap();
    let (sid, _) = login(&mut resumed.server, "admin");
    assert_eq!(notes(&mut resumed.server, &sid).len(), 2);
    for m in [MARKER_A, MARKER_B] {
        assert!(
            d4::revealing_files(&root, m).is_empty(),
            "plaintext left: {m}"
        );
    }
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        let target = to.join(e.file_name());
        if e.path().is_dir() {
            copy_dir(&e.path(), &target);
        } else {
            std::fs::copy(e.path(), target).unwrap();
        }
    }
}
