//! D4-E: the installation's key store travels with an encrypted backup (production path:
//! `BackupCreate` / `BackupRestore` control ops, `start_core`, `VaultUnlock`).
//!
//! The carried `keystore/keytree.json` is the wrapped key tree only (salt, unlock proof,
//! wrapped DEKs): a registered restore target becomes a self-contained data root that
//! opens on any host with the client's Master Key — and with nothing else. No Master Key,
//! KEK or DEK appears in the backup in any encoding; a foreign, altered or substituted key
//! store is refused and the vault stays locked with no live tree.

#[path = "../../dmc-materialized/tests/d4_support/mod.rs"]
mod d4;

use std::path::{Path, PathBuf};

use base64::Engine;
use dmc_ops::{CoreConfig, StartedCore, StartupOptions, parse_config_json, start_core};
use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, DataResponse, ProtocolErrorCode, RemoteLimits,
    RequestEnvelope,
};
use dmc_security::auth::{Action, Resource};
use dmc_server::{
    CoreServerState, KEY_TREE_FILE, MockKeyPassProvider, STORAGE_KEY_PATHS, UnlockMaterial,
    create_unlock_blob_anchored, handle_control, handle_data,
};
use dmc_vault::{KeyMaterial, KeyPath, KeyTree};

const MARKER: &str = "D4E_PORTABLE_PLAINTEXT_MARKER_5c21";
const CARRIED: &str = "keystore/keytree.json";

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
        "d4e",
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

/// `VaultUnlock` with `master` (no anchor) → Ok(generation) or the error code.
fn unlock(s: &mut CoreServerState, master: &UnlockMaterial) -> Result<u64, ProtocolErrorCode> {
    let (sid, key) = login(s);
    let blob = create_unlock_blob_anchored(
        &sid,
        &key,
        &MockKeyPassProvider::with_material(master.clone()),
        0,
    )
    .unwrap();
    let r = ctl(
        s,
        ControlRequest::VaultUnlock {
            session_id: sid,
            blob,
        },
    );
    match (r.error_code, r.body) {
        (None, Some(ControlResponse::VaultUnlock { generation, .. })) => Ok(generation),
        (Some(code), _) => Err(code),
        other => panic!("{other:?}"),
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
        "d4e",
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

fn ok_body(r: dmc_protocol::ResponseEnvelope<ControlResponse>) -> ControlResponse {
    assert!(r.error_code.is_none(), "{:?}", r.error_message);
    r.body.unwrap()
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

struct Installation {
    master: UnlockMaterial,
    key_store: Vec<u8>,
    backup: PathBuf,
    /// Registered restore target of the backup (made by the installation itself).
    restored: PathBuf,
    /// Master Key, every storage DEK and every KEK on the way (root included).
    secrets: Vec<Vec<u8>>,
    n: u64,
}

/// Installation A at `dir/name`: SQL data with `MARKER`, a backup through `BackupCreate`
/// and its registered restore through `BackupRestore`.
fn installation(dir: &Path, name: &str) -> Installation {
    let root = dir.join(name);
    let mut started = start(&root);
    let master = started.unlock_material.clone().unwrap();
    let key_store_path = started.layout.vault_root().join(KEY_TREE_FILE);
    let s = &mut started.server;
    unlock(s, &master).unwrap();
    sql(s, "CREATE TABLE t (id BIGINT PRIMARY KEY, note TEXT)").unwrap();
    sql(
        s,
        &format!("INSERT INTO t (id, note) VALUES (1, '{MARKER}')"),
    )
    .unwrap();
    sql(s, "INSERT INTO t (id, note) VALUES (2, 'second')").unwrap();
    let (sid, _) = login(s);
    let n = match ok_body(ctl(
        s,
        ControlRequest::BackupCreate {
            session_id: sid.clone(),
            backup_id: "b1".into(),
            include_rowstore: true,
        },
    )) {
        ControlResponse::BackupCreate {
            checkpoint_sequence,
            ..
        } => checkpoint_sequence,
        other => panic!("{other:?}"),
    };
    ok_body(ctl(
        s,
        ControlRequest::BackupRestore {
            session_id: sid,
            backup_id: "b1".into(),
            target_id: "r1".into(),
        },
    ));
    drop(started);

    let key_store = std::fs::read(&key_store_path).unwrap();
    let locked = dmc_vault::parse_locked_key_tree(&key_store).unwrap();
    let mut tree = KeyTree::unlock(
        &KeyMaterial::from_bytes(master.0),
        *locked.salt(),
        locked.unlock_proof().clone(),
        locked.export_meta(),
    )
    .unwrap();
    let mut secrets = vec![master.0.to_vec()];
    let mut paths = vec![KeyPath::root()];
    paths.extend(STORAGE_KEY_PATHS.iter().map(|p| KeyPath::parse(p).unwrap()));
    for p in &paths {
        secrets.push(tree.dek(p).unwrap().as_bytes().to_vec());
        secrets.push(tree.derive_kek(p).unwrap().as_bytes().to_vec());
    }
    Installation {
        master,
        key_store,
        backup: root.join("backups/backup-b1"),
        restored: root.join("restores/r1"),
        secrets,
        n,
    }
}

/// `secret` raw / hex / HEX / base64 (standard and URL-safe, padded or not, every
/// alignment) — the encodings a key could be stored in.
fn encodings(secret: &[u8]) -> Vec<Vec<u8>> {
    let mut out = vec![
        secret.to_vec(),
        hex::encode(secret).into_bytes(),
        hex::encode_upper(secret).into_bytes(),
    ];
    for engine in [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::URL_SAFE,
    ] {
        for pad in 0..3usize {
            let mut buf = vec![0u8; pad];
            buf.extend_from_slice(secret);
            let e = engine.encode(&buf);
            let start = if pad == 0 { 0 } else { 4 };
            out.push(e.as_bytes()[start..e.len() - 4].to_vec());
        }
    }
    out
}

fn files_revealing(root: &Path, secrets: &[Vec<u8>]) -> Vec<String> {
    let needles: Vec<Vec<u8>> = secrets.iter().flat_map(|s| encodings(s)).collect();
    d4::walk(root)
        .into_iter()
        .filter(|f| {
            let raw = std::fs::read(f).unwrap_or_default();
            needles
                .iter()
                .any(|n| raw.windows(n.len()).any(|w| w == n.as_slice()))
        })
        .map(|f| f.strip_prefix(root).unwrap().display().to_string())
        .collect()
}

/// A copy of the registered restore target on a host that has nothing else of A.
fn clean_host(dir: &Path, inst: &Installation, name: &str) -> PathBuf {
    let host = dir.join(name);
    copy_dir(&inst.restored, &host);
    host
}

fn assert_locked_without_live(started: &StartedCore, root: &Path) {
    assert!(started.server.storage_sealed(), "storage not opened");
    assert!(!started.server.root_dek_present(), "vault locked");
    assert!(!root.join("live").exists(), "no live tree");
    assert!(d4::revealing_files(root, MARKER).is_empty());
}

/// Recompute the plaintext manifest's listing of the carried key store (what an attacker
/// without keys can do); `manifest.sealed` is left as it is.
fn relist_carried(root: &Path) {
    let carried = std::fs::read(root.join(CARRIED)).unwrap();
    let path = root.join("manifest.json");
    let mut m: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for f in m["files"].as_array_mut().unwrap() {
        if f["relative_path"] == CARRIED {
            f["size"] = (carried.len() as u64).into();
            f["checksum_sha256"] = hex::encode(sha256(&carried)).into();
        }
    }
    std::fs::write(&path, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(data).into()
}

/// Same key tree, different bytes (re-serialized compactly): still opens with A's Master Key.
fn reserialized(key_store: &[u8]) -> Vec<u8> {
    let v: serde_json::Value = serde_json::from_slice(key_store).unwrap();
    let out = serde_json::to_vec(&v).unwrap();
    assert_ne!(out, key_store);
    out
}

#[test]
fn the_backup_carries_the_wrapped_key_store_and_no_key_in_any_encoding() {
    let dir = tempfile::tempdir().unwrap();
    let a = installation(dir.path(), "a");

    // the key store travels, byte-identical, listed (and so authenticated) in the manifest
    assert_eq!(std::fs::read(a.backup.join(CARRIED)).unwrap(), a.key_store);
    assert_eq!(
        std::fs::read(a.restored.join(CARRIED)).unwrap(),
        a.key_store
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(a.backup.join("manifest.json")).unwrap()).unwrap();
    let listed: Vec<_> = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["role"] == "key_store")
        .collect();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["relative_path"], CARRIED);
    assert_eq!(manifest["encrypted"], true);

    // no Master Key / DEK / KEK in any encoding, no plaintext SQL value
    assert_eq!(a.secrets.len(), 1 + 2 * (1 + STORAGE_KEY_PATHS.len()));
    for root in [&a.backup, &a.restored] {
        assert!(
            files_revealing(root, &a.secrets).is_empty(),
            "key material in {}: {:?}",
            root.display(),
            files_revealing(root, &a.secrets)
        );
        assert!(d4::revealing_files(root, MARKER).is_empty());
    }
    // negative control: the scanner finds a DEK written in any of those encodings
    let probe = dir.path().join("probe");
    for (i, enc) in encodings(&a.secrets[1]).into_iter().enumerate() {
        std::fs::create_dir_all(&probe).unwrap();
        let mut raw = b"prefix ".to_vec();
        raw.extend_from_slice(&enc);
        std::fs::write(probe.join("f"), raw).unwrap();
        assert_eq!(
            files_revealing(&probe, &a.secrets),
            vec!["f".to_string()],
            "encoding #{i} detected"
        );
    }
}

#[test]
fn backup_and_master_key_restore_on_a_clean_host() {
    let dir = tempfile::tempdir().unwrap();
    let a = installation(dir.path(), "a");
    let host = clean_host(dir.path(), &a, "clean");
    std::fs::remove_dir_all(dir.path().join("a")).unwrap(); // the source host is gone

    // locked start: the carried key store is installed, nothing is read or recovered
    let mut started = start(&host);
    assert!(
        started.unlock_material.is_none(),
        "no new installation / Master Key"
    );
    assert!(started.recovery_required);
    assert_eq!(
        std::fs::read(host.join("vault").join(KEY_TREE_FILE)).unwrap(),
        a.key_store
    );
    assert_locked_without_live(&started, &host);
    assert_eq!(
        sql(&mut started.server, "SELECT note FROM t"),
        Err(ProtocolErrorCode::VaultLocked)
    );

    // the client's Master Key: authenticated recovery, data readable, stored sealed
    assert_eq!(unlock(&mut started.server, &a.master), Ok(a.n));
    assert_eq!(
        notes(&mut started.server),
        vec![MARKER.to_string(), "second".into()]
    );
    assert!(d4::revealing_files(&host, MARKER).is_empty());
    assert!(files_revealing(&host, &a.secrets).is_empty());
    drop(started);

    // and again after a restart (only after unlock)
    let mut again = start(&host);
    assert!(!again.recovery_required);
    assert!(again.server.storage_sealed());
    unlock(&mut again.server, &a.master).unwrap();
    assert_eq!(notes(&mut again.server).len(), 2);
}

#[test]
fn without_the_master_key_the_carried_key_store_opens_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let a = installation(dir.path(), "a");
    let b = installation(dir.path(), "b");
    let host = clean_host(dir.path(), &a, "clean");
    let mut started = start(&host);
    for wrong in [UnlockMaterial([7; 32]), b.master.clone()] {
        assert_eq!(
            unlock(&mut started.server, &wrong),
            Err(ProtocolErrorCode::UnlockFailed)
        );
        assert_locked_without_live(&started, &host);
    }
    assert_eq!(
        sql(&mut started.server, "SELECT note FROM t"),
        Err(ProtocolErrorCode::VaultLocked)
    );
}

#[test]
fn a_foreign_or_altered_key_store_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let a = installation(dir.path(), "a");
    let b = installation(dir.path(), "b");

    // 1. B's key store carried in A's restore target (listing recomputed without keys):
    //    A's Master Key does not open it; B's opens it but cannot authenticate A's backup
    let host = clean_host(dir.path(), &a, "foreign");
    std::fs::write(host.join(CARRIED), &b.key_store).unwrap();
    relist_carried(&host);
    let mut started = start(&host);
    assert_eq!(
        unlock(&mut started.server, &a.master),
        Err(ProtocolErrorCode::UnlockFailed)
    );
    assert_locked_without_live(&started, &host);
    assert!(unlock(&mut started.server, &b.master).is_err());
    assert_locked_without_live(&started, &host);
    drop(started);

    // 2. a wrapped DEK altered (JSON still valid, listing recomputed): refused at unlock
    let host = clean_host(dir.path(), &a, "altered");
    let mut tree: serde_json::Value = serde_json::from_slice(&a.key_store).unwrap();
    let node = tree["nodes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|n| n["path"] == format!("/{}", STORAGE_KEY_PATHS[0]))
        .unwrap();
    let ct = node["wrapped_dek"]["ciphertext"]
        .as_str()
        .unwrap()
        .to_string();
    let flipped = if ct.starts_with('0') { "1" } else { "0" };
    node["wrapped_dek"]["ciphertext"] = format!("{flipped}{}", &ct[1..]).into();
    std::fs::write(
        host.join(CARRIED),
        serde_json::to_vec_pretty(&tree).unwrap(),
    )
    .unwrap();
    relist_carried(&host);
    let mut started = start(&host);
    assert!(unlock(&mut started.server, &a.master).is_err());
    assert_locked_without_live(&started, &host);
    drop(started);

    // 3. carried copy does not match the plaintext listing: refused at startup, no key
    //    store installed
    let host = clean_host(dir.path(), &a, "mismatch");
    std::fs::write(host.join(CARRIED), &b.key_store).unwrap();
    let err = start_core(cfg_for(&host), StartupOptions::production()).expect_err("refused");
    assert!(err.to_string().contains("key store"), "{err}");
    assert!(!host.join("vault").join(KEY_TREE_FILE).exists());
    assert!(!host.join("live").exists());

    // 4. the same key tree re-serialized, carried and installed, listing recomputed: it
    //    opens with A's Master Key, but its digest is not the authenticated one
    let host = clean_host(dir.path(), &a, "relisted");
    let same_tree = reserialized(&a.key_store);
    std::fs::write(host.join(CARRIED), &same_tree).unwrap();
    relist_carried(&host);
    let mut started = start(&host);
    assert!(unlock(&mut started.server, &a.master).is_err());
    assert_locked_without_live(&started, &host);
    drop(started);

    // 5. a different key store installed in the vault than the one carried (same tree,
    //    other bytes): the installed one must be exactly the authenticated copy
    let host = clean_host(dir.path(), &a, "installed");
    std::fs::create_dir_all(host.join("vault")).unwrap();
    std::fs::write(host.join("vault").join(KEY_TREE_FILE), &same_tree).unwrap();
    let mut started = start(&host);
    assert!(unlock(&mut started.server, &a.master).is_err());
    assert_locked_without_live(&started, &host);
    drop(started);

    // 6. unlisted content next to the carried key store: refused at recovery
    let host = clean_host(dir.path(), &a, "unlisted");
    std::fs::write(host.join("keystore/extra.json"), b"{}").unwrap();
    let mut started = start(&host);
    assert!(unlock(&mut started.server, &a.master).is_err());
    assert_locked_without_live(&started, &host);
    drop(started);

    // control: the untouched copy opens
    let host = clean_host(dir.path(), &a, "control");
    let mut started = start(&host);
    assert_eq!(unlock(&mut started.server, &a.master), Ok(a.n));
}

/// The D4-C boundary is unchanged: a backup that the installation did not restore through
/// its registry (no sealed restore attestation) is not accepted on a clean host either,
/// even though it carries the key store (disaster restore without the source registry is
/// an open decision — see the security doc).
#[test]
fn an_unregistered_restore_is_still_refused_on_a_clean_host() {
    let dir = tempfile::tempdir().unwrap();
    let a = installation(dir.path(), "a");
    let host = dir.path().join("clean");
    dmc_backup::restore_backup(&a.backup, &host).unwrap(); // keyless copy, no attestation
    std::fs::remove_dir_all(dir.path().join("a")).unwrap();
    assert!(host.join(CARRIED).is_file());
    let mut started = start(&host);
    assert!(unlock(&mut started.server, &a.master).is_err());
    assert_locked_without_live(&started, &host);
}
