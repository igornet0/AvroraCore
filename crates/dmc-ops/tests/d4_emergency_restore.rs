//! D4-E (variant B): emergency restore from a backup directory alone, on a host without
//! the source installation (and so without its backup registry).
//!
//! Invariant: an emergency restore succeeds **only** when the restored artifact is exactly
//! the one whose authenticated `manifest.sealed` SHA-256 the client stored (its backup
//! anchor) and sent inside the AEAD of its unlock blob (v3). Another backup of the same
//! installation — same Master Key — is refused; so is an authorization with no restore
//! pending. Every refusal keeps the vault locked and writes neither `live/` nor an
//! attestation. Production path: `BackupCreate`, `stage_emergency_restore`, `start_core`,
//! `VaultUnlock`.

#[path = "../../dmc-materialized/tests/d4_support/mod.rs"]
mod d4;

use std::path::{Path, PathBuf};

use dmc_backup::ATTESTATION_FILE;
use dmc_ops::{
    CoreConfig, StartedCore, StartupOptions, parse_config_json, stage_emergency_restore, start_core,
};
use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, DataResponse, ProtocolErrorCode, RemoteLimits,
    RequestEnvelope, UnlockBlob,
};
use dmc_security::auth::{Action, Resource};
use dmc_server::{
    CoreServerState, KEY_TREE_FILE, MockKeyPassProvider, UnlockMaterial,
    create_unlock_blob_anchored, create_unlock_blob_restore, handle_control, handle_data,
    open_unlock_blob_anchored,
};

const MARKER: &str = "D4E_EMERGENCY_PLAINTEXT_MARKER_7a90";

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
        "d4e-b",
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

fn send_unlock(
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

/// D4-D unlock (v2) with anchor `min`.
fn unlock(
    s: &mut CoreServerState,
    master: &UnlockMaterial,
    min: u64,
) -> Result<u64, ProtocolErrorCode> {
    let (sid, key) = login(s);
    let provider = MockKeyPassProvider::with_material(master.clone());
    let blob = create_unlock_blob_anchored(&sid, &key, &provider, min).unwrap();
    send_unlock(s, &sid, blob)
}

/// D4-E emergency-restore unlock (v3) authorizing `hash`, anchor `min`.
fn unlock_restore(
    s: &mut CoreServerState,
    master: &UnlockMaterial,
    min: u64,
    hash: &[u8; 32],
) -> Result<u64, ProtocolErrorCode> {
    let (sid, key) = login(s);
    let provider = MockKeyPassProvider::with_material(master.clone());
    let blob = create_unlock_blob_restore(&sid, &key, &provider, min, hash).unwrap();
    send_unlock(s, &sid, blob)
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
        "d4e-b",
    )
    .unwrap();
    match r.error_code {
        None => Ok(r.body.unwrap_or_default()),
        Some(code) => Err(code),
    }
}

fn notes(s: &mut CoreServerState) -> Vec<String> {
    match sql(s, "SELECT note FROM t ORDER BY id").unwrap() {
        DataResponse::SqlResult(r) => r
            .rows
            .into_iter()
            .map(|r| r.cells[0].text.clone())
            .collect(),
        other => panic!("{other:?}"),
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

fn sha256_file(path: &Path) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(std::fs::read(path).unwrap()).into()
}

/// A backup as the client knows it: id, checkpoint N and the hash `BackupCreate` returned.
struct Created {
    id: String,
    n: u64,
    hash: [u8; 32],
    /// Off-site copy of the published backup directory (survives the host).
    offsite: PathBuf,
}

struct Installation {
    root: PathBuf,
    master: UnlockMaterial,
    b1: Created,
    b2: Created,
    /// Highest generation the client saw on the live installation (D4-D anchor).
    anchor: u64,
}

fn backup(s: &mut CoreServerState, root: &Path, offsite: &Path, id: &str) -> Created {
    let (sid, _) = login(s);
    let r = ctl(
        s,
        ControlRequest::BackupCreate {
            session_id: sid,
            backup_id: id.into(),
            include_rowstore: true,
        },
    );
    assert!(r.error_code.is_none(), "{:?}", r.error_message);
    let (n, hex_hash) = match r.body.unwrap() {
        ControlResponse::BackupCreate {
            checkpoint_sequence,
            manifest_sealed_sha256,
            ..
        } => (checkpoint_sequence, manifest_sealed_sha256),
        other => panic!("{other:?}"),
    };
    let published = root.join(format!("backups/backup-{id}"));
    let hash: [u8; 32] = hex::decode(&hex_hash).unwrap().try_into().unwrap();
    assert_eq!(
        hash,
        sha256_file(&published.join("manifest.sealed")),
        "BackupCreate returns exactly the hash of the authenticated manifest"
    );
    let copy = offsite.join(format!("backup-{id}"));
    copy_dir(&published, &copy);
    Created {
        id: id.into(),
        n,
        hash,
        offsite: copy,
    }
}

/// Installation A: rows (MARKER), backup b1, more rows, backup b2, more rows; both backups
/// copied off-site. Then the host is gone unless `keep` is set.
fn installation(dir: &Path, keep: bool) -> Installation {
    let root = dir.join("a");
    let offsite = dir.join("offsite");
    let mut started = start(&root);
    let master = started.unlock_material.clone().unwrap();
    let s = &mut started.server;
    unlock(s, &master, 0).unwrap();
    sql(s, "CREATE TABLE t (id BIGINT PRIMARY KEY, note TEXT)").unwrap();
    sql(
        s,
        &format!("INSERT INTO t (id, note) VALUES (1, '{MARKER}')"),
    )
    .unwrap();
    let b1 = backup(s, &root, &offsite, "b1");
    sql(s, "INSERT INTO t (id, note) VALUES (2, 'second')").unwrap();
    let b2 = backup(s, &root, &offsite, "b2");
    sql(s, "INSERT INTO t (id, note) VALUES (3, 'third')").unwrap();
    let (sid, _) = login(s);
    let anchor = match ctl(s, ControlRequest::VaultStatus { session_id: sid })
        .body
        .unwrap()
    {
        ControlResponse::VaultStatus { generation, .. } => generation,
        other => panic!("{other:?}"),
    };
    assert!(b1.n < b2.n && b2.n < anchor);
    drop(started);
    if !keep {
        std::fs::remove_dir_all(&root).unwrap();
    }
    Installation {
        root,
        master,
        b1,
        b2,
        anchor,
    }
}

fn assert_refused_untouched(started: &StartedCore, root: &Path) {
    assert!(started.server.storage_sealed(), "storage not opened");
    assert!(!started.server.root_dek_present(), "vault locked");
    assert!(!root.join("live").exists(), "no live tree");
    assert!(
        !root.join(ATTESTATION_FILE).exists(),
        "no attestation written"
    );
    assert!(d4::revealing_files(root, MARKER).is_empty());
}

fn stage(dir: &Path, backup: &Created, name: &str) -> PathBuf {
    let host = dir.join(name);
    let staged = stage_emergency_restore(&backup.offsite, &host).unwrap();
    assert_eq!(staged.backup_id, backup.id);
    assert_eq!(staged.checkpoint_sequence, backup.n);
    assert_eq!(staged.manifest_sealed_sha256, hex::encode(backup.hash));
    host
}

#[test]
fn emergency_restore_opens_exactly_the_client_authorized_backup() {
    let dir = tempfile::tempdir().unwrap();
    let a = installation(dir.path(), false); // the source host is gone
    let host = stage(dir.path(), &a.b2, "clean");
    assert!(
        !host.join(ATTESTATION_FILE).exists(),
        "staging attests nothing"
    );

    let mut started = start(&host);
    assert!(started.unlock_material.is_none(), "no new installation");
    assert!(started.recovery_required);
    assert!(
        host.join("vault").join(KEY_TREE_FILE).is_file(),
        "carried key store installed"
    );
    assert_refused_untouched(&started, &host);

    // without the client's authorization the unregistered artifact does not open (D4-C)
    assert!(unlock(&mut started.server, &a.master, 0).is_err());
    assert_refused_untouched(&started, &host);

    // the client's authorization for exactly this artifact: opened at its checkpoint
    assert_eq!(
        unlock_restore(&mut started.server, &a.master, a.b2.n, &a.b2.hash),
        Ok(a.b2.n)
    );
    assert_eq!(
        notes(&mut started.server),
        vec![MARKER.to_string(), "second".into()]
    );
    assert!(host.join(ATTESTATION_FILE).is_file());
    assert!(d4::revealing_files(&host, MARKER).is_empty());
    drop(started);

    // afterwards an ordinary (anchored) unlock opens it; the old live anchor is a rollback
    let mut again = start(&host);
    assert_eq!(unlock(&mut again.server, &a.master, a.b2.n), Ok(a.b2.n));
    again.server.lock_vault();
    assert_eq!(
        unlock(&mut again.server, &a.master, a.anchor),
        Err(ProtocolErrorCode::StorageRollbackDetected)
    );
}

#[test]
fn another_backup_of_the_same_installation_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let a = installation(dir.path(), false);

    // b1 staged, b2 authorized (and the other way round): same Master Key, other artifact
    for (staged, authorized, name) in [(&a.b1, &a.b2, "older"), (&a.b2, &a.b1, "newer")] {
        let host = stage(dir.path(), staged, name);
        let mut started = start(&host);
        assert_eq!(
            unlock_restore(&mut started.server, &a.master, 0, &authorized.hash),
            Err(ProtocolErrorCode::UnlockFailed)
        );
        assert_refused_untouched(&started, &host);
    }

    // b1's content under b2's authenticated manifest (hash matches, content does not)
    let host = stage(dir.path(), &a.b1, "spliced");
    std::fs::copy(
        a.b2.offsite.join("manifest.sealed"),
        host.join("manifest.sealed"),
    )
    .unwrap();
    let mut started = start(&host);
    assert_eq!(
        unlock_restore(&mut started.server, &a.master, 0, &a.b2.hash),
        Err(ProtocolErrorCode::UnlockFailed)
    );
    assert_refused_untouched(&started, &host);
    drop(started);
    // ... with b2's plaintext manifest as well: inconsistent with b1's content already at
    // startup (no keys needed), nothing is read
    std::fs::copy(
        a.b2.offsite.join("manifest.json"),
        host.join("manifest.json"),
    )
    .unwrap();
    assert!(start_core(cfg_for(&host), StartupOptions::production()).is_err());
    assert!(!host.join("live").exists());

    // b1 relabelled as b2 on disk: still b1's manifest.sealed, so still refused for b2
    let renamed = dir.path().join("offsite/relabel/backup-b2");
    copy_dir(&a.b1.offsite, &renamed);
    let host = dir.path().join("relabel-host");
    assert!(
        stage_emergency_restore(&renamed, &host).is_err(),
        "identity check (backup id) refuses the relabelled directory"
    );

    // control: each with its own authorization opens
    let host = stage(dir.path(), &a.b1, "control");
    let mut started = start(&host);
    assert_eq!(
        unlock_restore(&mut started.server, &a.master, a.b1.n, &a.b1.hash),
        Ok(a.b1.n)
    );
    assert_eq!(notes(&mut started.server), vec![MARKER.to_string()]);
}

#[test]
fn the_authorization_cannot_be_forged_altered_or_downgraded() {
    let dir = tempfile::tempdir().unwrap();
    let a = installation(dir.path(), false);
    let host = stage(dir.path(), &a.b2, "clean");
    let mut started = start(&host);
    let s = &mut started.server;
    let provider = MockKeyPassProvider::with_material(a.master.clone());

    // a hash nobody authorized
    assert_eq!(
        unlock_restore(s, &a.master, 0, &[0x42; 32]),
        Err(ProtocolErrorCode::UnlockFailed)
    );
    // the authorization altered in transit (AEAD)
    let (sid, key) = login(s);
    let mut blob = create_unlock_blob_restore(&sid, &key, &provider, 0, &a.b2.hash).unwrap();
    let last = blob.ciphertext.len() - 1;
    blob.ciphertext[last] ^= 1;
    assert_eq!(
        send_unlock(s, &sid, blob),
        Err(ProtocolErrorCode::UnlockBlobInvalid)
    );
    // downgraded to v2 (dropping the authorization): the version is in the AAD
    let (sid, key) = login(s);
    let mut blob = create_unlock_blob_restore(&sid, &key, &provider, 0, &a.b2.hash).unwrap();
    blob.version = dmc_protocol::UNLOCK_BLOB_VERSION_ANCHORED;
    assert!(send_unlock(s, &sid, blob).is_err());
    // an anchor above the backup's checkpoint is enforced on this path — before anything
    // is restored (authenticated checkpoint)
    assert_eq!(
        unlock_restore(s, &a.master, a.b2.n + 1, &a.b2.hash),
        Err(ProtocolErrorCode::StorageRollbackDetected)
    );
    assert!(!host.join("live").exists() && !host.join(ATTESTATION_FILE).exists());
    // a wrong Master Key with the right hash
    assert_eq!(
        unlock_restore(s, &UnlockMaterial([9; 32]), 0, &a.b2.hash),
        Err(ProtocolErrorCode::UnlockFailed)
    );
    assert_refused_untouched(&started, &host);

    // operations other than VaultUnlock never accept (and so never drop) an authorization
    let (sid, key) = login(&mut started.server);
    let blob = create_unlock_blob_restore(&sid, &key, &provider, 0, &a.b2.hash).unwrap();
    assert!(open_unlock_blob_anchored(&blob, &key).is_err());
}

#[test]
fn an_authorization_without_a_pending_restore_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let a = installation(dir.path(), true); // the live installation still exists

    // on the live store: nothing to restore → refused, vault locked, storage not opened
    let mut live = start(&a.root);
    assert_eq!(
        unlock_restore(&mut live.server, &a.master, 0, &a.b2.hash),
        Err(ProtocolErrorCode::UnlockFailed)
    );
    assert!(live.server.storage_sealed());
    assert!(!live.server.root_dek_present());
    // ... also when the vault is already unlocked: locked again, nothing left open
    assert_eq!(unlock(&mut live.server, &a.master, a.anchor), Ok(a.anchor));
    assert_eq!(
        unlock_restore(&mut live.server, &a.master, 0, &a.b2.hash),
        Err(ProtocolErrorCode::UnlockFailed)
    );
    assert!(live.server.storage_sealed());
    assert!(!live.server.root_dek_present());
    drop(live);

    // on a target already recovered: refused as well; an ordinary unlock still opens it
    let host = stage(dir.path(), &a.b2, "clean");
    let mut started = start(&host);
    unlock_restore(&mut started.server, &a.master, a.b2.n, &a.b2.hash).unwrap();
    drop(started);
    let mut again = start(&host);
    assert_eq!(
        unlock_restore(&mut again.server, &a.master, a.b2.n, &a.b2.hash),
        Err(ProtocolErrorCode::UnlockFailed)
    );
    assert!(again.server.storage_sealed());
    assert_eq!(unlock(&mut again.server, &a.master, a.b2.n), Ok(a.b2.n));
}

#[test]
fn staging_refuses_what_cannot_be_authorized_and_never_replaces_a_key_store() {
    let dir = tempfile::tempdir().unwrap();
    let a = installation(dir.path(), false);

    // not an empty data root (e.g. one with its own key store): refused, nothing replaced
    let host = dir.path().join("occupied");
    std::fs::create_dir_all(host.join("vault")).unwrap();
    std::fs::write(host.join("vault").join(KEY_TREE_FILE), b"existing").unwrap();
    assert!(stage_emergency_restore(&a.b2.offsite, &host).is_err());
    assert_eq!(
        std::fs::read(host.join("vault").join(KEY_TREE_FILE)).unwrap(),
        b"existing"
    );

    // a backup without its key store (e.g. made before D4-E): cannot be restored here
    let no_ks = dir.path().join("offsite/no-ks/backup-b2");
    copy_dir(&a.b2.offsite, &no_ks);
    std::fs::remove_dir_all(no_ks.join("keystore")).unwrap();
    let path = no_ks.join("manifest.json");
    let mut m: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    m["files"]
        .as_array_mut()
        .unwrap()
        .retain(|f| f["role"] != "key_store");
    std::fs::write(&path, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
    let host = dir.path().join("no-ks-host");
    let err = stage_emergency_restore(&no_ks, &host).unwrap_err();
    assert!(err.contains("key store"), "{err}");
    assert!(!host.exists() || std::fs::read_dir(&host).unwrap().next().is_none());

    // a backup claiming to be plaintext: refused
    let plain = dir.path().join("offsite/plain/backup-b2");
    copy_dir(&a.b2.offsite, &plain);
    let path = plain.join("manifest.json");
    let mut m: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    m["encrypted"] = false.into();
    std::fs::write(&path, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
    assert!(stage_emergency_restore(&plain, &dir.path().join("plain-host")).is_err());

    // the key store carried by the staged backup is never written over an existing one
    let host = stage(dir.path(), &a.b2, "clean");
    std::fs::create_dir_all(host.join("vault")).unwrap();
    std::fs::write(host.join("vault").join(KEY_TREE_FILE), b"{}").unwrap();
    assert!(start_core(cfg_for(&host), StartupOptions::production()).is_err());
    assert_eq!(
        std::fs::read(host.join("vault").join(KEY_TREE_FILE)).unwrap(),
        b"{}"
    );
}
