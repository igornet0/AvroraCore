//! D4-D: anti-rollback of the whole data root with a client-side monotonic anchor.
//!
//! The storage generation is the authenticated journal tip (grows with every committed
//! write). The unlocking client puts the highest generation it has seen inside the AEAD of
//! its unlock blob (v2); storage older than that is closed again at unlock and the vault
//! re-locked (`StorageRollbackDetected`). Without an anchor (v1 blob / lost client state)
//! there is no check — explicit, documented. Production path (`start_core`).

use std::path::Path;

use dmc_ops::{CoreConfig, StartedCore, StartupOptions, parse_config_json, start_core};
use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, ProtocolErrorCode, RemoteLimits, RequestEnvelope,
    UnlockBlob,
};
use dmc_security::auth::{Action, Resource};
use dmc_server::{
    CoreServerState, KEY_TREE_FILE, MockKeyPassProvider, UnlockMaterial, create_unlock_blob,
    create_unlock_blob_anchored, handle_control, handle_data,
};

fn cfg_for(root: &Path) -> CoreConfig {
    parse_config_json(&format!(
        r#"{{ "data_root": "{}", "profile": "development" }}"#,
        root.display()
    ))
    .unwrap()
}

fn start(root: &Path) -> StartedCore {
    start_core(cfg_for(root), StartupOptions::production()).unwrap()
}

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
        "d4d",
    )
    .unwrap()
}

/// Operator session (SQL rights on `t`, backups) → (session id, binding key).
fn login(s: &mut CoreServerState) -> (String, [u8; 32]) {
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
            g.grant(id.clone(), Resource::table("avrora", "public", "t"), a);
        }
    }
    match ctl(
        s,
        ControlRequest::Authenticate {
            identity_name: "op".into(),
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

fn anchored_blob(sid: &str, key: &[u8; 32], master: &UnlockMaterial, min: u64) -> UnlockBlob {
    create_unlock_blob_anchored(
        sid,
        key,
        &MockKeyPassProvider::with_material(master.clone()),
        min,
    )
    .unwrap()
}

/// VaultUnlock with this blob → Ok(generation) or the error code.
fn unlock_blob(
    s: &mut CoreServerState,
    sid: &str,
    blob: UnlockBlob,
) -> Result<u64, ProtocolErrorCode> {
    let r = ctl(
        s,
        ControlRequest::VaultUnlock {
            session_id: sid.into(),
            blob,
        },
    );
    match (r.error_code, r.body) {
        (None, Some(ControlResponse::VaultUnlock { generation, .. })) => Ok(generation),
        (Some(code), _) => Err(code),
        other => panic!("{other:?}"),
    }
}

/// Fresh login + anchored unlock.
fn unlock(
    s: &mut CoreServerState,
    master: &UnlockMaterial,
    min: u64,
) -> Result<u64, ProtocolErrorCode> {
    let (sid, key) = login(s);
    unlock_blob(s, &sid, anchored_blob(&sid, &key, master, min))
}

fn sql(s: &mut CoreServerState, q: &str) {
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
        "d4d",
    )
    .unwrap();
    assert!(r.error_code.is_none(), "{q}: {:?}", r.error_message);
}

fn status_generation(s: &mut CoreServerState) -> u64 {
    let (sid, _) = login(s);
    match ctl(s, ControlRequest::VaultStatus { session_id: sid })
        .body
        .unwrap()
    {
        ControlResponse::VaultStatus { generation, .. } => generation,
        other => panic!("{other:?}"),
    }
}

fn assert_locked_and_closed(s: &CoreServerState) {
    assert!(s.storage_sealed(), "storage closed again");
    assert!(!s.root_dek_present(), "vault re-locked");
}

fn copy_dir(from: &Path, to: &Path) {
    let _ = std::fs::remove_dir_all(to);
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

#[test]
fn generation_is_reported_and_the_anchor_is_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let mut started = start(&root);
    let master = started.unlock_material.clone().unwrap();
    let s = &mut started.server;

    let g0 = unlock(s, &master, 0).unwrap();
    sql(s, "CREATE TABLE t (id BIGINT PRIMARY KEY)");
    sql(s, "INSERT INTO t (id) VALUES (1)");
    let g1 = status_generation(s);
    assert!(g1 > g0, "writes advance the generation ({g0} → {g1})");

    s.lock_vault();
    assert_eq!(
        status_generation(s),
        0,
        "sealed storage reports no generation"
    );
    assert_eq!(unlock(s, &master, g1), Ok(g1), "current anchor accepted");
    s.lock_vault();
    // a client that has seen more than the server holds: refused, nothing opened
    assert_eq!(
        unlock(s, &master, g1 + 1),
        Err(ProtocolErrorCode::StorageRollbackDetected)
    );
    assert_locked_and_closed(s);
}

#[test]
fn whole_data_root_rollback_is_detected_at_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let old_root = dir.path().join("snapshot-of-root");

    let mut started = start(&root);
    let master = started.unlock_material.clone().unwrap();
    unlock(&mut started.server, &master, 0).unwrap();
    sql(
        &mut started.server,
        "CREATE TABLE t (id BIGINT PRIMARY KEY)",
    );
    sql(&mut started.server, "INSERT INTO t (id) VALUES (1)");
    let g_old = status_generation(&mut started.server);
    drop(started);
    copy_dir(&root, &old_root); // an operator's copy of the whole data root, keys included

    let mut started = start(&root);
    unlock(&mut started.server, &master, g_old).unwrap();
    sql(&mut started.server, "INSERT INTO t (id) VALUES (2)");
    sql(&mut started.server, "INSERT INTO t (id) VALUES (3)");
    let anchor = status_generation(&mut started.server); // what the client now knows
    assert!(anchor > g_old);
    drop(started);

    // the whole data root rolled back to the copy (journal, snapshot, stores, key store)
    copy_dir(&old_root, &root);
    let journal = root.join("journal/state_events.json");
    let before = std::fs::read(&journal).unwrap();
    let mut started = start(&root);
    let s = &mut started.server;
    assert_eq!(
        unlock(s, &master, anchor),
        Err(ProtocolErrorCode::StorageRollbackDetected)
    );
    assert_locked_and_closed(s);
    assert_eq!(
        std::fs::read(&journal).unwrap(),
        before,
        "nothing written to the old root"
    );

    // explicit, client-side acceptance (anchor not sent) opens the older state
    assert_eq!(unlock(s, &master, 0), Ok(g_old));
}

#[test]
fn the_anchor_cannot_be_altered_or_downgraded_in_transit() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let mut started = start(&root);
    let master = started.unlock_material.clone().unwrap();
    let s = &mut started.server;

    let (sid, key) = login(s);
    let mut tampered = anchored_blob(&sid, &key, &master, 1_000);
    let last = tampered.ciphertext.len() - 1;
    tampered.ciphertext[last] ^= 1;
    assert_eq!(
        unlock_blob(s, &sid, tampered),
        Err(ProtocolErrorCode::UnlockBlobInvalid)
    );

    let (sid, key) = login(s);
    let mut downgraded = anchored_blob(&sid, &key, &master, 1_000);
    downgraded.version = dmc_protocol::UNLOCK_BLOB_VERSION; // claim v1 (no anchor)
    assert!(
        unlock_blob(s, &sid, downgraded).is_err(),
        "AAD binds the version"
    );
    assert_locked_and_closed(s);
}

#[test]
fn a_client_without_an_anchor_is_not_protected() {
    // documented limitation: v1 blob (old client) or lost client state = no check
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let mut started = start(&root);
    let master = started.unlock_material.clone().unwrap();
    let s = &mut started.server;
    let (sid, key) = login(s);
    let v1 = create_unlock_blob(&sid, &key, &MockKeyPassProvider::with_material(master)).unwrap();
    assert!(unlock_blob(s, &sid, v1).is_ok());
}

/// Closes the D4-C residual: an older backup restored as a data root is a rollback for a
/// client that has seen the newer state — refused unless the client accepts it explicitly.
#[test]
fn an_older_restored_backup_needs_explicit_acceptance() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let mut started = start(&root);
    let master = started.unlock_material.clone().unwrap();
    let key_store = started.layout.vault_root().join(KEY_TREE_FILE);
    let s = &mut started.server;
    unlock(s, &master, 0).unwrap();
    sql(s, "CREATE TABLE t (id BIGINT PRIMARY KEY)");
    sql(s, "INSERT INTO t (id) VALUES (1)");
    let (sid, _) = login(s);
    let n = match ctl(
        s,
        ControlRequest::BackupCreate {
            session_id: sid.clone(),
            backup_id: "old".into(),
            include_rowstore: true,
        },
    )
    .body
    .unwrap()
    {
        ControlResponse::BackupCreate {
            checkpoint_sequence,
            ..
        } => checkpoint_sequence,
        other => panic!("{other:?}"),
    };
    sql(s, "INSERT INTO t (id) VALUES (2)");
    let anchor = status_generation(s);
    assert!(anchor > n);
    let (sid, _) = login(s);
    let r = ctl(
        s,
        ControlRequest::BackupRestore {
            session_id: sid,
            backup_id: "old".into(),
            target_id: "older".into(),
        },
    );
    assert!(r.error_code.is_none(), "{:?}", r.error_message);
    drop(started);

    // the restored (older) artifact becomes a data root with the installation's key store
    let target = root.join("restores/older");
    std::fs::create_dir_all(target.join("vault")).unwrap();
    std::fs::copy(&key_store, target.join("vault").join(KEY_TREE_FILE)).unwrap();
    let mut restored = start(&target);
    let s = &mut restored.server;
    assert_eq!(
        unlock(s, &master, anchor),
        Err(ProtocolErrorCode::StorageRollbackDetected)
    );
    assert_locked_and_closed(s);
    assert_eq!(
        unlock(s, &master, n),
        Ok(n),
        "accepted down to what the client allows"
    );
}
