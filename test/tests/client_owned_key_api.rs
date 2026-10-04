//! CLIENT_OWNED key management over the real DMC IPC transport (reference path).
//!
//! All traffic (register / get / rotate keys, upload / download envelopes, grants,
//! revoke, SQL write / read, backup) passes through a byte-capturing proxy. The capture,
//! every server file and the server's log/audit sinks are scanned for *known secret byte
//! sequences* computed independently in this test (client roots, every X25519 private
//! key version, every DEK, recovery codes, plaintext) — raw and hex. A plaintext negative
//! control proves the scanner would see a leak.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use dmc_client::{Client, ConnectionTarget, MockKeyPassProvider};
use dmc_client_crypto::{
    ClientIdentity, ClientKeyring, ClientState, Error as CErr, RecoveryCode, TrustDecision,
    parse_sql_blob_cell, sql_blob_literal, sql_client_object_id,
};
use dmc_ipc::{CoreServer, SocketPathOptions};
use dmc_observability::{Audit, MemoryAuditSink, MemorySink, Observability};
use dmc_security::auth::{Action, AuthService, IdentityId, Resource};
use dmc_server::{CoreServerState, bootstrap_core_state_locked};
use dmc_vault::ownership::{ClientKeyEnvelope, PublicKeyStatus, SubjectId, TenantId};

const SECRET: &str = "VERY_SECRET_PLAINTEXT_CLIENT";
const CONTROL: &str = "VERY_PLAIN_NEGATIVE_CONTROL";

// ── capture proxy ─────────────────────────────────────────────────────────────

type Capture = Arc<Mutex<Vec<u8>>>;

fn pump(mut from: UnixStream, mut to: UnixStream, cap: Capture) {
    let mut buf = [0u8; 8192];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => {
                let _ = to.shutdown(std::net::Shutdown::Both);
                break;
            }
            Ok(n) => {
                cap.lock().unwrap().extend_from_slice(&buf[..n]);
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
}

fn spawn_capture_proxy(listen: PathBuf, upstream: PathBuf, cap: Capture) {
    let listener = UnixListener::bind(&listen).unwrap();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(client) = conn else { break };
            let server = UnixStream::connect(&upstream).unwrap();
            let (c1, c2) = (cap.clone(), cap.clone());
            let (cr, sr) = (client.try_clone().unwrap(), server.try_clone().unwrap());
            thread::spawn(move || pump(client, server, c1));
            thread::spawn(move || pump(sr, cr, c2));
        }
    });
}

/// Like `dmc serve`: connections served one at a time, state locked per request (so the
/// test can act as the in-process operator between connections).
fn spawn_server(state: CoreServerState, socket: PathBuf) -> Arc<Mutex<CoreServerState>> {
    let state = Arc::new(Mutex::new(state));
    let shared = state.clone();
    thread::spawn(move || {
        let server = CoreServer::bind(&socket, &SocketPathOptions { allow_custom_path: true }).unwrap();
        loop {
            let _ = server.accept_and_serve_shared(&shared);
        }
    });
    thread::sleep(Duration::from_millis(50));
    state
}

// ── independent secret derivation (mirrors the documented KDF, not the client API) ──

fn root_of(code: &RecoveryCode) -> [u8; 32] {
    let parts: Vec<&str> = code.as_str().split('-').collect();
    hex::decode(parts[1..9].concat()).unwrap().try_into().unwrap()
}

fn private_key_bytes(root: &[u8; 32], version: u32) -> Vec<u8> {
    use hpke::{Kem, Serializable};
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, root);
    let info = if version == 1 {
        b"avrora/client-kem/v1".to_vec()
    } else {
        format!("avrora/client-kem/v1/kv{version}").into_bytes()
    };
    let mut ikm = [0u8; 32];
    hk.expand(&info, &mut ikm).unwrap();
    let (sk, _) = hpke::kem::X25519HkdfSha256::derive_keypair(&ikm);
    sk.to_bytes().to_vec()
}

/// Ed25519 auth key seed (= private key) of `version`, derived independently.
fn auth_seed_bytes(root: &[u8; 32], version: u32) -> Vec<u8> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, root);
    let mut seed = [0u8; 32];
    hk.expand(format!("avrora/client-owned/ed25519/v1/kv{version}").as_bytes(), &mut seed)
        .unwrap();
    seed.to_vec()
}

fn dek_from(env: &ClientKeyEnvelope, root: &[u8; 32], kem_version: u32) -> Vec<u8> {
    use hpke::{Deserializable, OpModeR};
    type K = hpke::kem::X25519HkdfSha256;
    let sk = <K as hpke::Kem>::PrivateKey::from_bytes(&private_key_bytes(root, kem_version)).unwrap();
    let enc = <K as hpke::Kem>::EncappedKey::from_bytes(&env.enc).unwrap();
    let b = env.binding();
    hpke::single_shot_open::<hpke::aead::AesGcm256, hpke::kdf::HkdfSha256, K>(
        &OpModeR::Base, &sk, &enc, &b, &env.ciphertext, &b,
    )
    .unwrap()
}

#[derive(Default)]
struct Secrets(Vec<(String, Vec<u8>)>);

impl Secrets {
    fn add(&mut self, label: &str, bytes: &[u8]) {
        self.0.push((format!("{label}(raw)"), bytes.to_vec()));
        self.0.push((format!("{label}(hex)"), hex::encode(bytes).into_bytes()));
        self.0.push((format!("{label}(HEX)"), hex::encode_upper(bytes).into_bytes()));
    }

    fn add_text(&mut self, label: &str, s: &str) {
        self.0.push((label.to_string(), s.as_bytes().to_vec()));
    }

    fn find_in(&self, hay: &[u8]) -> Vec<String> {
        self.0
            .iter()
            .filter(|(_, n)| hay.windows(n.len()).any(|w| w == n.as_slice()))
            .map(|(l, _)| l.clone())
            .collect()
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
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

fn count(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

// ── users ─────────────────────────────────────────────────────────────────────

struct User {
    name: &'static str,
    subject: SubjectId,
    identity_id: IdentityId,
    code: RecoveryCode,
    device: PathBuf,
}

impl User {
    fn identity(&self) -> ClientIdentity {
        ClientIdentity::load(&self.device.join("identity.json")).unwrap()
    }

    fn state(&self) -> ClientState {
        ClientState::open(self.device.join("state.json")).unwrap()
    }
}

fn grant_sql(auth: &mut AuthService, id: &IdentityId) {
    auth.grants_mut().grant(id.clone(), Resource::database("avrora"), Action::Connect);
    auth.grants_mut().grant(id.clone(), Resource::database("avrora"), Action::Create);
    auth.grants_mut().grant(id.clone(), Resource::schema("avrora", "public"), Action::Usage);
    auth.grants_mut().grant(id.clone(), Resource::schema("avrora", "public"), Action::Create);
    for table in ["notes", "plain_control"] {
        for a in [Action::Create, Action::Insert, Action::Select, Action::Update] {
            auth.grants_mut().grant(id.clone(), Resource::table("avrora", "public", table), a);
        }
    }
}

/// Distinctive so that its occurrences on the wire can be counted exactly.
const OPERATOR_PASSWORD: &str = "operator-password-Q7z9";

/// CLIENT_OWNED login: Ed25519 challenge–response, session bound to this connection.
fn connect(sock: &Path, u: &User) -> Client {
    let mut c = Client::with_client_id(ConnectionTarget::Local { socket: sock.to_path_buf() }, u.name);
    c.connect().unwrap();
    let id = u.identity();
    c.control()
        .client_authenticate(u.subject, id.tenant().clone(), |challenge| id.sign_challenge(challenge))
        .unwrap();
    c
}

/// Operator (server-custody `analyst`) password login.
fn connect_operator(sock: &Path, auths: &mut usize) -> Client {
    let mut c = Client::with_client_id(ConnectionTarget::Local { socket: sock.to_path_buf() }, "operator");
    c.connect().unwrap();
    c.control().authenticate("analyst", OPERATOR_PASSWORD).unwrap();
    *auths += 1;
    c
}

fn active_key(c: &mut Client, subject: SubjectId) -> dmc_vault::ownership::ClientPublicKey {
    c.control()
        .client_key_get(subject)
        .unwrap()
        .into_iter()
        .find(|k| k.status == PublicKeyStatus::Active)
        .unwrap()
        .key
}

fn ring_from_server(c: &mut Client, u: &User) -> ClientKeyring {
    let envs = c.control().key_envelope_get().unwrap();
    ClientKeyring::load(u.identity(), &envs, &mut u.state()).unwrap()
}

#[test]
fn key_management_and_client_owned_sql_over_dmc_ipc_reveal_no_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let data_root = dir.path().join("server");
    std::fs::create_dir_all(&data_root).unwrap();
    let devices = dir.path().join("devices");
    let tenant = TenantId::new("acme").unwrap();

    // ── server: operator `analyst` may issue invites (CREATE on system) ─────
    let (mut state, master) = bootstrap_core_state_locked(&data_root, false);
    let logs = MemorySink::new();
    let audit = MemoryAuditSink::new();
    state.set_observability(Observability::memory(logs.clone()));
    state.set_audit(Audit::memory(audit.clone()));
    let analyst = state.auth.identities().get_by_name("analyst").unwrap().id.clone();
    state.auth_mut().configure_credential("analyst", OPERATOR_PASSWORD);
    state.auth_mut().grants_mut().grant(analyst.clone(), Resource::System, Action::Create);
    grant_sql(state.auth_mut(), &analyst);
    let socket = data_root.join("dmc.sock");
    let shared = spawn_server(state, socket.clone());
    let capture: Capture = Arc::new(Mutex::new(Vec::new()));
    let proxy = dir.path().join("proxy.sock");
    spawn_capture_proxy(proxy.clone(), socket.clone(), capture.clone());
    let mut auths = 0usize;
    let mut secrets = Secrets::default();
    let mut invite_tokens: Vec<Vec<u8>> = Vec::new();
    let mut all_envs: Vec<(ClientKeyEnvelope, usize)> = Vec::new(); // (env, user index)

    // The server serves one connection at a time (as `dmc serve` does): every step
    // below opens its own connection and drops it before the next one.

    // ── operator: unlock, SQL schema, CLIENT_OWNED column, enrollment invites ─
    let invites: Vec<_> = {
        let mut ops = connect_operator(&proxy, &mut auths);
        ops.control()
            .vault_unlock(&MockKeyPassProvider::with_material(master.clone()))
            .unwrap();
        ops.sql()
            .execute("CREATE TABLE notes (id BIGINT PRIMARY KEY, owner TEXT, body BLOB)")
            .unwrap();
        ops.sql()
            .execute("CREATE TABLE plain_control (id BIGINT PRIMARY KEY, note TEXT)")
            .unwrap();
        ops.control()
            .sealed_column_declare("public", "notes", "body", Some("owner"))
            .unwrap();
        ["alice", "bob", "charlie"]
            .into_iter()
            .map(|name| (name, ops.control().identity_invite_create(name, tenant.clone(), 600_000).unwrap()))
            .collect()
    };

    // ── each user enrolls from its own device: key generated locally, PoP signed ─
    let mut users = Vec::new();
    for (i, (name, invite)) in invites.into_iter().enumerate() {
        let device = devices.join(name);
        let (id, code) = ClientIdentity::generate(invite.subject, invite.tenant.clone());
        id.save(&device.join("identity.json")).unwrap();
        let sig = id.sign_enrollment(&invite.invite_id, &invite.token, name).unwrap();
        let mut c = Client::with_client_id(ConnectionTarget::Local { socket: proxy.clone() }, name);
        c.connect().unwrap();
        let (identity_id, subject) = c
            .control()
            .identity_enroll(&invite.invite_id, &invite.token, id.public_key(), sig.clone())
            .unwrap();
        assert_eq!(subject, invite.subject);
        // the same invite cannot be used twice
        assert!(c
            .control()
            .identity_enroll(&invite.invite_id, &invite.token, id.public_key(), sig)
            .is_err());
        drop(c);
        invite_tokens.push(invite.token.clone());
        let identity_id = IdentityId::new(identity_id);
        // SQL grants have no network API yet: the operator grants in-process (documented gap)
        grant_sql(shared.lock().unwrap().auth_mut(), &identity_id);
        let u = User { name, subject, identity_id, code, device };
        // own DEK envelope; a different key cannot replace the enrolled one
        let mut c = connect(&proxy, &u);
        let mut st = u.state();
        let (_ring, env) = ClientKeyring::create(u.identity(), &mut st).unwrap();
        let (other, _) = ClientIdentity::generate(u.subject, tenant.clone());
        assert!(c.control().client_key_register(other.public_key()).is_err());
        c.control().key_envelope_put(env.clone()).unwrap();
        all_envs.push((env, i));
        drop(c);
        users.push(u);
    }
    let (alice, bob, charlie) = (&users[0], &users[1], &users[2]);

    // ── Alice: TOFU + out-of-band fingerprint, grants, offline delegation ────
    let mut a = connect(&proxy, alice);
    let mut a_state = alice.state();
    let a_ring = ring_from_server(&mut a, alice);
    for target in [bob, charlie] {
        let pk = active_key(&mut a, target.subject);
        // server-supplied fingerprint is not trusted: recompute locally + compare out of band
        let oob = target.identity().public_key().fingerprint_display();
        assert_eq!(a_state.check_or_pin(&pk).unwrap(), TrustDecision::PinnedOnFirstUse);
        a_state.pin_verified(&pk, &oob).unwrap();
        a.control().grant_create(target.subject, None).unwrap();
        for env in a_ring.delegate_to(&pk, &mut a_state).unwrap() {
            a.control().key_envelope_put(env.clone()).unwrap();
            all_envs.push((env, 0));
        }
    }
    assert_eq!(a.control().grant_list().unwrap().len(), 2);

    // client-owned writes: plaintext → seal (client) → X'…' → server
    for id in 1..=6u64 {
        let oid = sql_client_object_id("notes", &id.to_string(), "body");
        let sealed = a_ring.seal(&oid, 1, format!("{SECRET}-{id}").as_bytes()).unwrap();
        a.sql()
            .execute(&format!(
                "INSERT INTO notes (id, owner, body) VALUES ({id}, '{}', {})",
                alice.subject.to_hex(),
                sql_blob_literal(&sealed)
            ))
            .unwrap();
    }
    // plaintext-injection defense: arbitrary BLOB and wrong-owner sealed value rejected
    let raw_plain = sql_blob_literal(b"VERY_PLAIN_BLOB_INJECTION_ATTEMPT_____________________________");
    let err = a
        .sql()
        .execute(&format!(
            "INSERT INTO notes (id, owner, body) VALUES (90, '{}', {raw_plain})",
            alice.subject.to_hex()
        ))
        .unwrap_err();
    assert!(err.to_string().to_lowercase().contains("sealed") || err.to_string().contains("onstraint"), "{err}");
    let alice_sealed = a_ring.seal("sqlc/notes/91/body", 1, b"x").unwrap();
    assert!(a
        .sql()
        .execute(&format!(
            "INSERT INTO notes (id, owner, body) VALUES (91, '{}', {})",
            bob.subject.to_hex(),
            sql_blob_literal(&alice_sealed)
        ))
        .is_err());
    // negative control: an unprotected value crosses the wire in plaintext
    a.sql()
        .execute(&format!("INSERT INTO plain_control (id, note) VALUES (1, '{CONTROL}')"))
        .unwrap();
    // Alice goes offline
    drop(a_ring);
    drop(a);

    // ── Bob later: downloads envelopes, decrypts locally ─────────────────────
    let mut b = connect(&proxy, bob);
    let b_ring_old = ring_from_server(&mut b, bob); // "Bob has old DEK"
    let row3 = parse_sql_blob_cell(
        &b.sql().query("SELECT body FROM notes WHERE id = 3").unwrap().rows[0].cells[0].value,
    )
    .unwrap();
    let oid3 = sql_client_object_id("notes", "3", "body");
    assert_eq!(b_ring_old.open(alice.subject, &oid3, &row3).unwrap(), format!("{SECRET}-3").into_bytes());
    drop(b);

    // Charlie writes private data; Bob cannot read it
    let mut c = connect(&proxy, charlie);
    let c_ring = ring_from_server(&mut c, charlie);
    let c_oid = sql_client_object_id("notes", "50", "body");
    let c_sealed = c_ring.seal(&c_oid, 1, b"charlie private").unwrap();
    c.sql()
        .execute(&format!(
            "INSERT INTO notes (id, owner, body) VALUES (50, '{}', {})",
            charlie.subject.to_hex(),
            sql_blob_literal(&c_sealed)
        ))
        .unwrap();
    drop(c);
    let mut b = connect(&proxy, bob);
    let row50 = parse_sql_blob_cell(
        &b.sql().query("SELECT body FROM notes WHERE id = 50").unwrap().rows[0].cells[0].value,
    )
    .unwrap();
    assert!(b_ring_old.open(charlie.subject, &c_oid, &row50).is_err());
    drop(b);

    // ── revocation: Alice revokes Bob; rotates DEK; re-delegates to Charlie ──
    let mut a = connect(&proxy, alice);
    let mut a_ring = ring_from_server(&mut a, alice);
    assert!(a.control().grant_revoke(bob.subject).unwrap());
    let env_v2 = a_ring.new_data_key(&mut a_state).unwrap();
    a.control().key_envelope_put(env_v2.clone()).unwrap();
    all_envs.push((env_v2, 0));
    let charlie_pk = active_key(&mut a, charlie.subject);
    for env in a_ring.delegate_to(&charlie_pk, &mut a_state).unwrap() {
        if env.key_version == 2 {
            a.control().key_envelope_put(env.clone()).unwrap();
            all_envs.push((env, 0));
        }
    }
    let new_oid = sql_client_object_id("notes", "7", "body");
    let new_sealed = a_ring.seal(&new_oid, 1, format!("{SECRET}-7").as_bytes()).unwrap();
    a.sql()
        .execute(&format!(
            "INSERT INTO notes (id, owner, body) VALUES (7, '{}', {})",
            alice.subject.to_hex(),
            sql_blob_literal(&new_sealed)
        ))
        .unwrap();
    drop(a);
    let mut b = connect(&proxy, bob);
    let b_ring_new = ring_from_server(&mut b, bob);
    drop(b);
    assert!(b_ring_new.open(alice.subject, &oid3, &row3).is_err(), "no envelope after revoke");
    // documented limit: the DEK Bob already holds still opens what he already has
    assert!(b_ring_old.open(alice.subject, &oid3, &row3).is_ok());
    assert!(b_ring_old.open(alice.subject, &new_oid, &new_sealed).is_err(), "new DEK version not shared");
    let mut c = connect(&proxy, charlie);
    let c_ring2 = ring_from_server(&mut c, charlie);
    assert!(c_ring2.open(alice.subject, &new_oid, &new_sealed).is_ok());

    // ── KEM key rotation over the network; TOFU KEY_CHANGED / rollback ───────
    let mut c_state = charlie.state();
    let alice_v1 = active_key(&mut c, alice.subject);
    c_state.check_or_pin(&alice_v1).unwrap();
    drop(c);
    let mut a = connect(&proxy, alice);
    let (alice_v2, proof, resealed) = a_ring.rotate_identity_key().unwrap();
    a.control().client_key_rotate(alice_v2.clone(), proof).unwrap();
    for env in resealed {
        a.control().key_envelope_put(env.clone()).unwrap();
        all_envs.push((env, 0));
    }
    // persist the rotated identity on Alice's device
    a_ring.identity().save(&alice.device.join("identity.json")).unwrap();
    drop(a);
    let mut c = connect(&proxy, charlie);
    let keys = c.control().client_key_get(alice.subject).unwrap();
    assert_eq!(keys.len(), 2);
    let fetched_v2 = keys.iter().find(|k| k.status == PublicKeyStatus::Active).unwrap().key.clone();
    assert!(matches!(c_state.check_or_pin(&fetched_v2), Err(CErr::KeyChanged { .. })), "no auto-accept");
    c_state.pin_verified(&fetched_v2, &alice_v2.fingerprint_display()).unwrap();
    assert!(matches!(c_state.check_or_pin(&alice_v1), Err(CErr::KeyRollback { .. })), "downgrade refused");
    drop(c);
    let mut a = connect(&proxy, alice);
    // old envelopes (sealed to Alice's v1 KEM key) remain valid after rotation
    let a_reloaded = ring_from_server(&mut a, alice);
    assert_eq!(a_reloaded.open(alice.subject, &oid3, &row3).unwrap(), format!("{SECRET}-3").into_bytes());
    // malicious server hides DEK v2 → Alice refuses to load (rollback floor)
    let hidden: Vec<_> = a.control().key_envelope_get().unwrap().into_iter().filter(|e| e.key_version < 2).collect();
    assert!(matches!(
        ClientKeyring::load(alice.identity(), &hidden, &mut alice.state()),
        Err(CErr::Rollback { .. })
    ));

    // ── backup over the network ──────────────────────────────────────────────
    a.control().backup_create("kb1", true).unwrap();
    drop(a);

    // ── secrets: independently derived ───────────────────────────────────────
    for (i, u) in users.iter().enumerate() {
        let root = root_of(&u.code);
        secrets.add(&format!("{}-root", u.name), &root);
        secrets.add_text(&format!("{}-recovery-code", u.name), u.code.as_str());
        let versions = if i == 0 { 2 } else { 1 };
        for v in 1..=versions {
            secrets.add(&format!("{}-private-key-v{v}", u.name), &private_key_bytes(&root, v));
            secrets.add(&format!("{}-auth-key-v{v}", u.name), &auth_seed_bytes(&root, v));
        }
    }
    for (env, _) in &all_envs {
        let recipient = users.iter().find(|u| u.subject == env.recipient).unwrap();
        let root = root_of(&recipient.code);
        let kv = (1..=2)
            .find(|v| {
                let id = ClientIdentity::from_recovery_at_version(recipient.subject, tenant.clone(), &recipient.code, *v).unwrap();
                id.public_key().fingerprint() == env.recipient_key_fingerprint
            })
            .unwrap();
        secrets.add(&format!("dek-{}-v{}", env.owner, env.key_version), &dek_from(env, &root, kv));
    }
    secrets.add_text("plaintext", SECRET);

    // ── assertions: wire ─────────────────────────────────────────────────────
    let wire = capture.lock().unwrap().clone();
    assert!(count(&wire, CONTROL.as_bytes()) >= 1, "negative control must be visible");
    let leaked = secrets.find_in(&wire);
    assert!(leaked.is_empty(), "secrets on the wire: {leaked:?}");
    // CLIENT_OWNED users have no password; the operator password appears only inside its
    // Authenticate frames
    assert_eq!(count(&wire, OPERATOR_PASSWORD.as_bytes()), auths, "operator password outside Authenticate");
    assert!(count(&wire, sql_blob_literal(&new_sealed)[2..50].as_bytes()) >= 1, "ciphertext visible");

    // ── assertions: server files (incl. backup), logs, audit ─────────────────
    let files = walk(&data_root);
    assert!(files.iter().any(|p| p.ends_with("client-directory.json")));
    assert!(files.iter().any(|p| p.to_string_lossy().contains("backups") && p.to_string_lossy().contains("ownership")));
    for f in &files {
        let bytes = std::fs::read(f).unwrap_or_default();
        let leaked = secrets.find_in(&bytes);
        assert!(leaked.is_empty(), "secrets in server file {}: {leaked:?}", f.display());
        // invite tokens are stored only as hashes
        for t in &invite_tokens {
            assert!(count(&bytes, t).max(count(&bytes, hex::encode(t).as_bytes())) == 0, "invite token in {}", f.display());
        }
    }
    assert!(files.iter().any(|p| p.ends_with("invites.json")));
    assert!(files.iter().any(|p| p.ends_with("identities.json")), "enrollment persists identities");
    let server_logs = format!("{:?} {:?}", logs.snapshot(), audit.snapshot());
    let leaked = secrets.find_in(server_logs.as_bytes());
    assert!(leaked.is_empty(), "secrets in server logs: {leaked:?}");
    for t in &invite_tokens {
        assert!(!server_logs.contains(&hex::encode(t)));
    }

    // ── new host: restore + recover, attacker with full SQL access + Master ──
    let backup_path = data_root.join("backups/backup-kb1");
    assert!(backup_path.is_dir(), "{}", backup_path.display());
    let restored = dir.path().join("new-host/restore");
    dmc_backup::restore_backup(&backup_path, &restored).unwrap();
    dmc_backup::recover(&restored).unwrap();
    let live = restored.join(dmc_backup::LIVE_DIR);
    assert!(live.join("ownership/client/client-directory.json").is_file());
    assert!(live.join("rows/sealed_columns.json").is_file());

    let mat = dmc_materialized::StateMaterializer::open_recovered(
        live.join("rows"),
        live.join("materialized_snapshot.json"),
        live.join("state_events.json"),
    )
    .unwrap();
    let catalog = mat.catalog().clone();
    let mut ctx = dmc_sql_exec::ExecutionContext::new();
    ctx.attach_journal(dmc_sql_exec::JournalBackend::File(mat));
    ctx.attach_session_catalog(&catalog);
    ctx.register_materialized_tables_from_journal().unwrap();
    // Identities (hashed credentials, subject ids) come from the backup's ownership
    // component; SQL grants are not persisted by the SQL server today, so the new host's
    // operator re-issues them (documented limitation).
    let mut restored_ids = AuthService::new();
    restored_ids.load_identities(&live.join("ownership/identities.json")).unwrap();
    for u in &users {
        let identity = restored_ids.identities().get(&u.identity_id).unwrap().clone();
        assert_eq!(identity.subject_id, Some(u.subject));
        assert_eq!(identity.custody, dmc_security::auth::KeyCustody::Client);
    }
    let analyst = restored_ids.identities().get_by_name("analyst").unwrap().id.clone();
    for u in &users {
        grant_sql(&mut restored_ids, &u.identity_id);
    }
    grant_sql(&mut restored_ids, &analyst);
    let (state2, master2) =
        CoreServerState::new_locked_with_hub(restored_ids, ctx, live.clone(), dmc_runtime::RuntimeHub::new()).unwrap();
    let socket2 = dir.path().join("new-host/dmc.sock");
    spawn_server(state2, socket2.clone());
    let capture2: Capture = Arc::new(Mutex::new(Vec::new()));
    let proxy2 = dir.path().join("new-host/proxy.sock");
    spawn_capture_proxy(proxy2.clone(), socket2.clone(), capture2.clone());

    // operator: Master (vault gate) + full SQL grants → ciphertext only
    let mut op = connect_operator(&proxy2, &mut auths);
    op.control()
        .vault_unlock(&MockKeyPassProvider::with_material(master2.clone()))
        .unwrap();
    let all = op.sql().query("SELECT body FROM notes").unwrap();
    assert!(all.rows.len() >= 8);
    for row in &all.rows {
        let bytes = parse_sql_blob_cell(&row.cells[0].value).unwrap();
        assert!(secrets.find_in(&bytes).is_empty());
    }
    drop(op);
    // KEY_CHANGED is not reported for the operator's random subject: operator has no
    // client identity at all → nothing to decrypt with.

    // Alice on the new host: envelopes from the restored directory → plaintext locally
    // Alice logs in on the new host with her (rotated, v2) Ed25519 key
    let mut a2 = connect(&proxy2, alice);
    let a2_ring = ring_from_server(&mut a2, alice);
    for (id, oid) in [(3u64, oid3.clone()), (7, new_oid.clone())] {
        let cell = a2
            .sql()
            .query(&format!("SELECT body FROM notes WHERE id = {id}"))
            .unwrap()
            .rows[0]
            .cells[0]
            .value
            .clone();
        let sealed = parse_sql_blob_cell(&cell).unwrap();
        assert_eq!(a2_ring.open(alice.subject, &oid, &sealed).unwrap(), format!("{SECRET}-{id}").into_bytes());
    }
    // sealed-column rule survived the restore
    assert!(a2
        .sql()
        .execute(&format!(
            "INSERT INTO notes (id, owner, body) VALUES (99, '{}', {raw_plain})",
            alice.subject.to_hex()
        ))
        .is_err());

    let wire2 = capture2.lock().unwrap().clone();
    assert!(secrets.find_in(&wire2).is_empty(), "new-host wire");
    for f in walk(&restored) {
        let leaked = secrets.find_in(&std::fs::read(&f).unwrap_or_default());
        assert!(leaked.is_empty(), "secrets in restored file {}: {leaked:?}", f.display());
    }
}
