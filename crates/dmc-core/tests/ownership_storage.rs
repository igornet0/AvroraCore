//! Cryptographic ownership through the real event-plane persistence path:
//! WAL segments (with rotation + compaction), base snapshot, runtime snapshots,
//! local backup, BackupSAS archive payload, restore → recover → unlock.
//!
//! Every check scans raw bytes on disk — not API results.

use std::fs;
use std::path::{Path, PathBuf};

use dmc_core::backup::{
    archive, backup_dir, backups_root, create_backup, create_backup_with_sections,
    recover_into_empty, restore_backup, restores_root,
};
use dmc_core::runtime::{DbStatus, Runtime};
use dmc_journal::{StorageLayout, set_test_segment_max_bytes};
use dmc_security::auth::{AuthService, Credential, SessionManager};
use dmc_security::ownership::KeyManager;
use dmc_security::{Error as SecError, SessionId};
use dmc_vault::ownership::{SubjectId, TenantId};

const SECRET: &[u8] = b"VERY_SECRET_TEST_PAYLOAD";

struct SmallSegments;

impl SmallSegments {
    fn enable() -> Self {
        set_test_segment_max_bytes(Some(900));
        Self
    }
}

impl Drop for SmallSegments {
    fn drop(&mut self) {
        set_test_segment_max_bytes(None);
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Fail if any persistent file (incl. temp / staging / archived) under `root` holds the secret.
fn assert_no_plaintext(root: &Path, what: &str) -> usize {
    let files = walk(root);
    assert!(!files.is_empty(), "{what}: nothing on disk under {}", root.display());
    for f in &files {
        let bytes = fs::read(f).unwrap();
        assert!(
            !contains(&bytes, SECRET),
            "{what}: plaintext payload found in {}",
            f.display()
        );
    }
    files.len()
}

fn files_named(root: &Path, pred: impl Fn(&str) -> bool) -> Vec<PathBuf> {
    walk(root)
        .into_iter()
        .filter(|p| pred(&p.to_string_lossy()))
        .collect()
}

fn owned_path(subject: SubjectId, object: &str) -> String {
    format!("owned/{subject}/{object}")
}

fn login(auth: &mut AuthService, keys: &mut KeyManager, name: &str, pw: &str) -> SessionId {
    let (identity, unlock) = auth
        .authenticate_with_key_unlock(&Credential::Password {
            identity_name: name.into(),
            password: pw.into(),
        })
        .unwrap();
    let session = auth.create_session(identity.identity_id).unwrap();
    keys.open_session(auth, &session.id, unlock).unwrap();
    session.id.clone()
}

#[tokio::test]
async fn owned_data_stays_ciphertext_through_wal_snapshot_backup_restore() {
    let _seg = SmallSegments::enable();
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db/store.dbs.json");
    fs::create_dir_all(db_path.parent().unwrap()).unwrap();
    let layout = StorageLayout::from_db_path(&db_path);

    // ── 1. create encrypted data ─────────────────────────────────────────────
    let rt = Runtime::at_path(&db_path);
    let (master_hex, _) = rt.create_dev(false).await.unwrap();
    let admin = rt.admin_session().await.unwrap(); // cap_root: full database privileges

    let mut auth = AuthService::new();
    let mut keys = KeyManager::open(layout.keyring_dir()).unwrap();
    let acme = TenantId::new("acme").unwrap();
    let (alice_id, alice, unlock) = auth.enroll_owner("alice", "alice-password", acme.clone()).unwrap();
    keys.enroll(&auth, &alice_id, unlock).unwrap();
    let (bob_id, _bob, unlock) = auth.enroll_owner("bob", "bob-password", acme.clone()).unwrap();
    keys.enroll(&auth, &bob_id, unlock).unwrap();
    auth.save_identities(&layout.identities_file()).unwrap();

    let sa = login(&mut auth, &mut keys, "alice", "alice-password");
    for i in 0..40u64 {
        let object = format!("note-{i}");
        let sealed = keys.seal(&auth, &sa, alice, &object, 1, SECRET).unwrap();
        rt.put_data(&admin, &owned_path(alice, &object), &sealed)
            .await
            .unwrap();
    }
    // key rotation mid-stream: later records use v2
    keys.rotate_data_key(&auth, &sa).unwrap();
    let sealed = keys.seal(&auth, &sa, alice, "after-rotation", 1, SECRET).unwrap();
    rt.put_data(&admin, &owned_path(alice, "after-rotation"), &sealed)
        .await
        .unwrap();

    // WAL: segments rotated, possibly compacted
    let segments = files_named(&layout.journal_dir(), |p| p.ends_with(".jnl"));
    assert!(segments.len() > 1, "expected WAL segment rotation");
    if let Ok(artifact) = rt.compact_journal().await {
        rt.publish_compaction(artifact).await.unwrap();
    }
    assert_no_plaintext(&layout.journal_dir(), "WAL / journal segments");

    // snapshots
    rt.force_snapshot().await.unwrap();
    rt.persist().await.unwrap();
    assert_no_plaintext(&layout.base_dir(), "base snapshot");
    assert_no_plaintext(&layout.runtime_dir(), "runtime snapshots + keyrings");

    // privileged DB API returns ciphertext only
    let raw = rt.get_data(&admin, &owned_path(alice, "note-0")).await.unwrap();
    assert!(!contains(&raw, SECRET));
    assert_eq!(keys.open_sealed(&auth, &sa, alice, "note-0", &raw).unwrap(), SECRET);

    // ── 2. backup ────────────────────────────────────────────────────────────
    create_backup(&rt, "full-1", true).await.unwrap();
    let backups = backups_root(&layout.data_dir);
    let published = backup_dir(&backups, "full-1");
    let n = assert_no_plaintext(&published, "local backup");
    assert!(n > 3);
    // BackupSAS payload (what leaves the host before BackupSAS's own encryption)
    let payload = archive::pack_dir(&published).unwrap();
    assert!(!contains(&payload, SECRET), "remote backup archive payload");
    // keyring travelled with the backup (runtime section)
    assert!(!files_named(&published, |p| p.ends_with(".keyring.json")).is_empty());

    // whole data dir, incl. any staging / tmp files left behind
    assert_no_plaintext(&layout.data_dir, "entire data directory");

    // ── 3. remove original storage (simulated host loss) ─────────────────────
    let offsite = tmp.path().join("offsite");
    fs::create_dir_all(&offsite).unwrap();
    copy_dir(&published, &offsite.join("backup-full-1"));
    drop(keys);
    drop(rt);
    fs::remove_dir_all(db_path.parent().unwrap()).unwrap();

    // ── 4. restore on a new host ─────────────────────────────────────────────
    let new_db = tmp.path().join("new-host/store.dbs.json");
    fs::create_dir_all(new_db.parent().unwrap()).unwrap();
    let new_layout = StorageLayout::from_db_path(&new_db);
    let new_backups = backups_root(&new_layout.data_dir);
    fs::create_dir_all(&new_backups).unwrap();
    copy_dir(&offsite.join("backup-full-1"), &backup_dir(&new_backups, "full-1"));
    let new_restores = restores_root(&new_layout.data_dir);
    restore_backup(&new_backups, &new_restores, "full-1", "t1").unwrap();
    let fresh = Runtime::at_path(&new_db);
    recover_into_empty(&fresh, &new_restores, "t1").await.unwrap();
    drop(fresh);

    // ── 5. still encrypted after restore ─────────────────────────────────────
    assert_no_plaintext(&new_layout.data_dir, "restored data directory");

    // Backup operator: holds the backup AND the vault Master Key, unlocks the DB,
    // and uses cap_root. Gets only ciphertext.
    let rt = Runtime::at_path(&new_db);
    assert_eq!(rt.status().await, DbStatus::Locked);
    rt.unlock(&master_hex).await.unwrap();
    let operator = rt.admin_session().await.unwrap();
    let raw_old = rt.get_data(&operator, &owned_path(alice, "note-7")).await.unwrap();
    let raw_new = rt.get_data(&operator, &owned_path(alice, "after-rotation")).await.unwrap();
    assert!(!contains(&raw_old, SECRET) && !contains(&raw_new, SECRET));

    // ── 6. authorized user can decrypt (old + rotated key versions) ──────────
    let mut auth = AuthService::new();
    auth.load_identities(&new_layout.identities_file()).unwrap();
    let mut keys = KeyManager::open(new_layout.keyring_dir()).unwrap();
    let sa = login(&mut auth, &mut keys, "alice", "alice-password");
    assert_eq!(keys.open_sealed(&auth, &sa, alice, "note-7", &raw_old).unwrap(), SECRET);
    assert_eq!(
        keys.open_sealed(&auth, &sa, alice, "after-rotation", &raw_new).unwrap(),
        SECRET
    );
    assert_eq!(keys.active_key_version(&sa).unwrap(), 2, "rotation survived restore");

    // ── 7. unauthorized principals cannot ────────────────────────────────────
    let sb = login(&mut auth, &mut keys, "bob", "bob-password");
    let err = keys.open_sealed(&auth, &sb, alice, "note-7", &raw_old).unwrap_err();
    assert!(matches!(err, SecError::KeyAccessDenied(_)), "{err}");
    // operator with a valid session but no credential unlock → no crypto session
    let (_, _) = (operator, ());
    let operator_session = auth.create_session(bob_id).unwrap();
    assert!(keys
        .open_sealed(&auth, &operator_session.id, alice, "note-7", &raw_old)
        .is_err());
}

#[tokio::test]
async fn backup_without_keyrings_restores_ciphertext_and_fails_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db/store.dbs.json");
    fs::create_dir_all(db_path.parent().unwrap()).unwrap();
    let layout = StorageLayout::from_db_path(&db_path);
    let rt = Runtime::at_path(&db_path);
    let (master_hex, _) = rt.create_dev(false).await.unwrap();
    let admin = rt.admin_session().await.unwrap();

    let mut auth = AuthService::new();
    let mut keys = KeyManager::open(layout.keyring_dir()).unwrap();
    let (id, alice, unlock) = auth
        .enroll_owner("alice", "alice-password", TenantId::new("acme").unwrap())
        .unwrap();
    keys.enroll(&auth, &id, unlock).unwrap();
    auth.save_identities(&layout.identities_file()).unwrap();
    let sa = login(&mut auth, &mut keys, "alice", "alice-password");
    let sealed = keys.seal(&auth, &sa, alice, "doc", 1, SECRET).unwrap();
    rt.put_data(&admin, &owned_path(alice, "doc"), &sealed).await.unwrap();

    // Data-only backup (no `runtime` section → no keyrings).
    create_backup_with_sections(&rt, "data-only", &["base".into(), "journal".into()])
        .await
        .unwrap();
    let backups = backups_root(&layout.data_dir);
    assert!(files_named(&backup_dir(&backups, "data-only"), |p| p.contains("keyring")).is_empty());
    let restores = restores_root(&layout.data_dir);
    restore_backup(&backups, &restores, "data-only", "r").unwrap();
    drop(keys);
    rt.lock().await.unwrap();
    dmc_core::backup::recover_backup(&rt, &restores, "r").await.unwrap();
    drop(rt);

    let rt = Runtime::at_path(&db_path);
    rt.unlock(&master_hex).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    let raw = rt.get_data(&admin, &owned_path(alice, "doc")).await.unwrap();
    assert!(!contains(&raw, SECRET));

    // NO KEY → NO DECRYPTION → NO PLAINTEXT. No key is generated in its place.
    let mut keys = KeyManager::open(layout.keyring_dir()).unwrap();
    let (identity, unlock) = auth
        .authenticate_with_key_unlock(&Credential::Password {
            identity_name: "alice".into(),
            password: "alice-password".into(),
        })
        .unwrap();
    let s = auth.create_session(identity.identity_id).unwrap();
    let err = keys.open_session(&auth, &s.id, unlock).unwrap_err();
    assert!(
        matches!(
            err,
            SecError::Ownership(dmc_vault::ownership::Error::KeyringNotFound(_))
        ),
        "{err}"
    );
    assert!(files_named(&layout.keyring_dir(), |p| p.ends_with(".keyring.json")).is_empty());
}

fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for e in fs::read_dir(src).unwrap().flatten() {
        let to = dst.join(e.file_name());
        if e.path().is_dir() {
            copy_dir(&e.path(), &to);
        } else {
            fs::copy(e.path(), to).unwrap();
        }
    }
}
