//! CLIENT_OWNED data through the real event-plane persistence path, against the
//! strongest server-side attacker: database files + backups + vault Master Key + cap_root.
//!
//! The "client" half of this test uses only `dmc-client-crypto`; the "server" half uses
//! only AvroraCore crates (Runtime, AuthService, ClientKeyDirectory, EncryptedStorage,
//! KeyManager). Plaintext and client keys never flow from the client half to the server half.

use std::fs;
use std::path::{Path, PathBuf};

use dmc_client_crypto::{ClientIdentity, ClientKeyring, ClientState, RecoveryCode};
use dmc_core::backup::{
    archive, backup_dir, backups_root, create_backup, recover_into_empty, restore_backup,
    restores_root,
};
use dmc_core::runtime::{DbStatus, Runtime};
use dmc_core::SessionId as CoreSessionId;
use dmc_journal::{StorageLayout, set_test_segment_max_bytes};
use dmc_security::auth::{AuthService, Credential, IdentityId, SessionManager};
use dmc_security::ownership::{
    ClientKeyDirectory, EncryptedStorage, KeyManager, KeyOp, RecordBackend, storage_key,
};
use dmc_security::SessionId;
use dmc_vault::ownership::{ClientKeyEnvelope, RecordHeader, SubjectId, TenantId};

const SECRET: &str = "VERY_SECRET_CLIENT_PAYLOAD";

// ── server-side storage adapter: EncryptedStorage → Runtime (WAL/snapshots/backups) ──

struct RuntimeBackend {
    rt: Runtime,
    storage_session: CoreSessionId,
}

impl RuntimeBackend {
    fn block<F: std::future::Future>(&self, f: F) -> F::Output {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
    }
}

impl RecordBackend for RuntimeBackend {
    fn put(&mut self, key: &str, sealed: &[u8]) -> dmc_security::Result<()> {
        let path = format!("owned/{key}");
        self.block(self.rt.put_data(&self.storage_session, &path, sealed))
            .map_err(|e| dmc_security::Error::Conflict(e.to_string()))
    }

    fn get(&self, key: &str) -> dmc_security::Result<Option<Vec<u8>>> {
        let path = format!("owned/{key}");
        Ok(self.block(self.rt.get_data(&self.storage_session, &path)).ok())
    }

    fn keys(&self) -> dmc_security::Result<Vec<String>> {
        Ok(self
            .block(self.rt.list_overlays("owned"))
            .into_iter()
            .filter(|p| !p.deleted)
            .filter_map(|p| p.path.strip_prefix("owned/").map(str::to_string))
            .collect())
    }
}

// ── helpers ─────────────────────────────────────────────────────────────────

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

fn contains(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}

/// Root secret hex embedded in a recovery code (test-only knowledge of the client secret).
fn root_hex(code: &RecoveryCode) -> String {
    let parts: Vec<&str> = code.as_str().split('-').collect();
    parts[1..9].concat()
}

/// No server file contains plaintext, any client root secret (raw or hex) or a password.
fn assert_server_blind(root: &Path, client_secrets: &[String], passwords: &[&str], what: &str) {
    let files = walk(root);
    assert!(!files.is_empty(), "{what}: nothing on disk");
    for f in &files {
        let bytes = fs::read(f).unwrap_or_default();
        let lossy = String::from_utf8_lossy(&bytes).to_lowercase();
        assert!(!contains(&bytes, SECRET.as_bytes()), "{what}: plaintext in {}", f.display());
        for s in client_secrets {
            assert!(!lossy.contains(s), "{what}: client root (hex) in {}", f.display());
            let raw = hex::decode(s).unwrap();
            assert!(!contains(&bytes, &raw), "{what}: client root (raw) in {}", f.display());
        }
        for p in passwords {
            assert!(!contains(&bytes, p.as_bytes()), "{what}: password in {}", f.display());
        }
    }
}

struct ClientUser {
    name: &'static str,
    password: &'static str,
    subject: SubjectId,
    identity_id: IdentityId,
    code: RecoveryCode,
    device: PathBuf,
}

impl ClientUser {
    fn identity(&self) -> ClientIdentity {
        ClientIdentity::load(&self.device.join("identity.json")).unwrap()
    }

    fn state(&self) -> ClientState {
        ClientState::open(self.device.join("state.json")).unwrap()
    }
}

/// Server creates a password-less CLIENT_OWNED identity (enrollment itself is covered by
/// `test/tests/client_owned_auth.rs`); the device generates the key root locally.
fn enroll(
    auth: &mut AuthService,
    devices: &Path,
    tenant: &TenantId,
    name: &'static str,
    password: &'static str,
) -> ClientUser {
    let subject = SubjectId::random();
    let identity_id = auth.create_client_identity(name, tenant.clone(), subject).unwrap();
    let device = devices.join(name);
    let (id, code) = ClientIdentity::generate(subject, tenant.clone());
    id.save(&device.join("identity.json")).unwrap();
    ClientUser {
        name,
        password,
        subject,
        identity_id,
        code,
        device,
    }
}

/// In-process session (this test is about storage; network authentication is Ed25519
/// challenge–response, `client_owned_auth.rs`). The server learns nothing that derives
/// client keys either way.
fn login(auth: &mut AuthService, u: &ClientUser) -> SessionId {
    auth.create_session(u.identity_id.clone()).unwrap().id.clone()
}

/// Client loads its keyring from server-held envelopes (HPKE-sealed to its public key).
fn client_ring(dir: &ClientKeyDirectory, auth: &AuthService, s: &SessionId, u: &ClientUser) -> ClientKeyring {
    let envs: Vec<ClientKeyEnvelope> = dir.envelopes_for(auth, s).unwrap();
    ClientKeyring::load(u.identity(), &envs, &mut u.state()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_owned_data_is_opaque_to_database_backup_master_key_and_cap_root() {
    set_test_segment_max_bytes(Some(900));
    let tmp = tempfile::tempdir().unwrap();
    let devices = tmp.path().join("devices"); // client side — never inside the server tree
    let db_path = tmp.path().join("server/db/store.dbs.json");
    fs::create_dir_all(db_path.parent().unwrap()).unwrap();
    let layout = StorageLayout::from_db_path(&db_path);
    let server_root = tmp.path().join("server");

    // ── server boot ──────────────────────────────────────────────────────────
    let rt = Runtime::at_path(&db_path);
    let (master_hex, _) = rt.create_dev(false).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    let mut auth = AuthService::new();
    let client_dir_path = layout.ownership_dir().join("client");
    let mut directory = ClientKeyDirectory::open(&client_dir_path).unwrap();
    let mut store = EncryptedStorage::new(RuntimeBackend {
        rt: rt.clone(),
        storage_session: admin.clone(),
    });
    let tenant = TenantId::new("acme").unwrap();

    let alice = enroll(&mut auth, &devices, &tenant, "alice", "alice-password");
    let bob = enroll(&mut auth, &devices, &tenant, "bob", "bob-password");
    let charlie = enroll(&mut auth, &devices, &tenant, "charlie", "charlie-password");
    auth.save_identities(&layout.identities_file()).unwrap();

    // each client registers its public key and its own DEK v1 envelope
    let mut sessions = Vec::new();
    for u in [&alice, &bob, &charlie] {
        let s = login(&mut auth, u);
        let mut st = u.state();
        let (ring, env) = ClientKeyring::create(u.identity(), &mut st).unwrap();
        directory.register_public_key(&auth, &s, ring.public_key()).unwrap();
        directory.put_envelope(&auth, &s, env).unwrap();
        sessions.push(s);
    }
    let (sa, sb, sc) = (sessions[0].clone(), sessions[1].clone(), sessions[2].clone());

    // ── Alice writes (client seals, server stores ciphertext) ────────────────
    let mut a_ring = client_ring(&directory, &auth, &sa, &alice);
    for i in 0..30u32 {
        let oid = format!("note-{i}");
        let sealed = a_ring.seal(&oid, 1, format!("{SECRET}-{i}").as_bytes()).unwrap();
        store.put_sealed(&auth, &sa, alice.subject, &oid, &sealed).unwrap();
    }
    // server-side validation without plaintext: wrong domain / foreign owner / replay refused
    let replay = a_ring.seal("note-0", 1, b"replay").unwrap();
    assert!(store.put_sealed(&auth, &sa, alice.subject, "note-0", &replay).is_err());
    assert!(store.put_sealed(&auth, &sb, alice.subject, "note-x", &replay).is_err());
    // Charlie's own data
    let c_ring = client_ring(&directory, &auth, &sc, &charlie);
    let c_sealed = c_ring.seal("diary", 1, b"charlie private").unwrap();
    store.put_sealed(&auth, &sc, charlie.subject, "diary", &c_sealed).unwrap();

    // ── rotation: new DEK v2 on the client; re-encrypt one record client-side ──
    let mut st = alice.state();
    let env2 = a_ring.new_data_key(&mut st).unwrap();
    directory.put_envelope(&auth, &sa, env2).unwrap();
    let old = store.get_sealed(&auth, &sa, alice.subject, "note-0", &directory).unwrap();
    let re = a_ring.reencrypt("note-0", &old).unwrap();
    store.put_sealed(&auth, &sa, alice.subject, "note-0", &re).unwrap();
    let fresh = a_ring.seal("note-new", 1, format!("{SECRET}-new").as_bytes()).unwrap();
    store.put_sealed(&auth, &sa, alice.subject, "note-new", &fresh).unwrap();

    // ── asynchronous delegation: Alice → Bob and Charlie, both offline ───────
    for (u, s_grantee) in [(&bob, &sb), (&charlie, &sc)] {
        let _ = s_grantee;
        let pk = directory.public_key(&auth, &sa, u.subject).unwrap();
        directory.grant(&auth, &sa, u.subject, None).unwrap();
        let mut st = alice.state();
        for env in a_ring.delegate_to(&pk, &mut st).unwrap() {
            directory.put_envelope(&auth, &sa, env).unwrap();
        }
    }
    drop(a_ring); // Alice goes offline

    // ── persistence: WAL rotation/compaction, snapshot, backup, archive ──────
    if let Ok(artifact) = rt.compact_journal().await {
        rt.publish_compaction(artifact).await.unwrap();
    }
    rt.force_snapshot().await.unwrap();
    rt.persist().await.unwrap();
    create_backup(&rt, "full-1", true).await.unwrap();
    let published = backup_dir(&backups_root(&layout.data_dir), "full-1");
    let payload = archive::pack_dir(&published).unwrap();
    assert!(!contains(&payload, SECRET.as_bytes()), "BackupSAS payload");
    assert!(
        walk(&published).iter().any(|p| p.ends_with("client-directory.json")),
        "client key directory travels with the backup"
    );

    let roots: Vec<String> = [&alice, &bob, &charlie].iter().map(|u| root_hex(&u.code)).collect();
    let pws = ["alice-password", "bob-password", "charlie-password"];
    assert_server_blind(&server_root, &roots, &pws, "live server + local backup");

    // ── host compromise: server-side key holders have nothing for CLIENT_OWNED ─
    let mut keys = KeyManager::open(layout.keyring_dir()).unwrap();
    assert!(
        walk(&layout.keyring_dir()).iter().all(|p| !p.to_string_lossy().ends_with(".keyring.json")),
        "no server keyring exists for client-custody subjects"
    );
    for u in [&alice, &bob, &charlie] {
        // a CLIENT_OWNED identity has no password at all: nothing password-derived exists
        // that the server could feed into its KeyManager, and password login is refused
        assert!(auth
            .authenticate_with_key_unlock(&Credential::Password {
                identity_name: u.name.into(),
                password: u.password.into(),
            })
            .is_err());
        let s = login(&mut auth, u);
        assert!(keys.authorize(&auth, &s, u.subject, KeyOp::Read).is_err());
    }
    assert_eq!(keys.open_session_count(), 0);
    let server_debug = format!("{auth:?} {directory:?} {keys:?}");
    assert!(!server_debug.contains(SECRET));
    for r in &roots {
        assert!(!server_debug.to_lowercase().contains(r));
    }

    // ── host loss → restore on a new host (attacker == backup operator here) ──
    let offsite = tmp.path().join("offsite/backup-full-1");
    copy_dir(&published, &offsite);
    drop(store);
    drop(directory);
    drop(rt);
    fs::remove_dir_all(&server_root).unwrap();

    let new_root = tmp.path().join("new-host");
    let new_db = new_root.join("db/store.dbs.json");
    fs::create_dir_all(new_db.parent().unwrap()).unwrap();
    let nl = StorageLayout::from_db_path(&new_db);
    copy_dir(&offsite, &backup_dir(&backups_root(&nl.data_dir), "full-1"));
    let restores = restores_root(&nl.data_dir);
    restore_backup(&backups_root(&nl.data_dir), &restores, "full-1", "t1").unwrap();
    recover_into_empty(&Runtime::at_path(&new_db), &restores, "t1").await.unwrap();

    // Attacker: restored DB + backup + Master Key + cap_root.
    let rt = Runtime::at_path(&new_db);
    assert_eq!(rt.status().await, DbStatus::Locked);
    rt.unlock(&master_hex).await.unwrap();
    let root_cap = rt.admin_session().await.unwrap();
    for i in [0u32, 7, 29] {
        let raw = rt
            .get_data(&root_cap, &format!("owned/{}", storage_key(alice.subject, &format!("note-{i}"))))
            .await
            .unwrap();
        assert!(!contains(&raw, SECRET.as_bytes()));
        assert_eq!(RecordHeader::parse(&raw).unwrap().domain, dmc_vault::ownership::KeyDomain::Client);
    }
    assert_server_blind(&new_root, &roots, &pws, "restored host");

    // ── authorized clients after restore (server restart + client restart) ───
    let mut auth = AuthService::new();
    auth.load_identities(&nl.identities_file()).unwrap();
    let directory = ClientKeyDirectory::open(nl.ownership_dir().join("client")).unwrap();
    let store = EncryptedStorage::new(RuntimeBackend {
        rt: rt.clone(),
        storage_session: root_cap.clone(),
    });
    let sa = login(&mut auth, &alice);
    let a_ring = client_ring(&directory, &auth, &sa, &alice);
    assert_eq!(a_ring.active_version().unwrap(), 2, "key version persisted");
    for oid in ["note-0", "note-7", "note-new"] {
        let sealed = store.get_sealed(&auth, &sa, alice.subject, oid, &directory).unwrap();
        let plain = String::from_utf8(a_ring.open(alice.subject, oid, &sealed).unwrap()).unwrap();
        assert!(plain.starts_with(SECRET));
    }
    // mixed versions after rotation
    let v_old = RecordHeader::parse(&store.get_sealed(&auth, &sa, alice.subject, "note-7", &directory).unwrap()).unwrap();
    let v_new = RecordHeader::parse(&store.get_sealed(&auth, &sa, alice.subject, "note-0", &directory).unwrap()).unwrap();
    assert_eq!((v_old.key_version, v_new.key_version), (1, 2));

    // Bob (delegated while offline) reads Alice's data; cannot read Charlie's
    let sb = login(&mut auth, &bob);
    let b_ring = client_ring(&directory, &auth, &sb, &bob);
    let a7 = store.get_sealed(&auth, &sb, alice.subject, "note-7", &directory).unwrap();
    assert!(String::from_utf8(b_ring.open(alice.subject, "note-7", &a7).unwrap()).unwrap().starts_with(SECRET));
    assert!(store.get_sealed(&auth, &sb, charlie.subject, "diary", &directory).is_err());
    let c_raw = rt
        .get_data(&root_cap, &format!("owned/{}", storage_key(charlie.subject, "diary")))
        .await
        .unwrap();
    assert!(b_ring.open(charlie.subject, "diary", &c_raw).is_err(), "Bob has no key for Charlie");

    // Revocation: Alice revokes Bob → server stops serving envelopes and ciphertext.
    let mut directory = directory;
    directory.revoke(&auth, &sa, bob.subject).unwrap();
    assert!(store.get_sealed(&auth, &sb, alice.subject, "note-7", &directory).is_err());
    assert!(ClientKeyring::load(bob.identity(), &directory.envelopes_for(&auth, &sb).unwrap(), &mut bob.state())
        .unwrap()
        .open(alice.subject, "note-7", &a7)
        .is_err());
    // Documented limit: a key Bob already downloaded still opens ciphertext he already
    // holds — revocation is not retroactive. Rotation protects *new* data:
    assert!(b_ring.open(alice.subject, "note-7", &a7).is_ok());
    let mut a_ring = a_ring;
    let mut st = alice.state();
    let env3 = a_ring.new_data_key(&mut st).unwrap();
    directory.put_envelope(&auth, &sa, env3).unwrap();
    let after = a_ring.seal("post-revoke", 1, b"not for bob").unwrap();
    assert!(b_ring.open(alice.subject, "post-revoke", &after).is_err());
    // Charlie's delegation is unaffected
    let sc = login(&mut auth, &charlie);
    let c2 = client_ring(&directory, &auth, &sc, &charlie);
    assert!(c2.open(alice.subject, "note-7", &a7).is_ok());

    set_test_segment_max_bytes(None);
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
