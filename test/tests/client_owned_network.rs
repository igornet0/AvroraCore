//! Reference network path for CLIENT_OWNED data:
//!
//! ```text
//! AvroraClient (dmc-client + dmc-client-crypto) ──[capturing proxy]── DMC IPC ── AvroraCore SQL
//! ```
//!
//! Every byte crossing the transport in either direction is recorded and scanned, as are
//! all server-side files (rows, state events, statistics, indexes, backups, restores)
//! and the server's observability/audit sinks. The client seals before sending and
//! opens after receiving; the server only ever handles `X'…'` ciphertext.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use dmc_client::{Client, ConnectionTarget, ExecuteOutcome, MockKeyPassProvider};
use dmc_client_crypto::{
    ClientIdentity, ClientKeyring, ClientState, parse_sql_blob_cell, sql_blob_literal,
    sql_client_object_id,
};
use dmc_ipc::{CoreServer, SocketPathOptions};
use dmc_observability::{Audit, MemoryAuditSink, MemorySink, Observability};
use dmc_server::bootstrap_core_state_locked;
use dmc_vault::ownership::{RecordHeader, SubjectId, TenantId};

const SECRET: &str = "VERY_SECRET_CLIENT_PAYLOAD";
const CONTROL: &str = "VERY_PLAIN_NEGATIVE_CONTROL";

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

/// Transparent proxy: client ↔ proxy ↔ server, recording both directions.
fn spawn_capture_proxy(listen: PathBuf, upstream: PathBuf) -> Capture {
    let cap: Capture = Arc::new(Mutex::new(Vec::new()));
    let listener = UnixListener::bind(&listen).unwrap();
    let c = cap.clone();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(client) = conn else { break };
            let server = UnixStream::connect(&upstream).unwrap();
            let (c1, c2) = (c.clone(), c.clone());
            let (cr, sr) = (client.try_clone().unwrap(), server.try_clone().unwrap());
            thread::spawn(move || pump(client, server, c1));
            thread::spawn(move || pump(sr, cr, c2));
        }
    });
    cap
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

fn contains(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}

#[test]
fn client_owned_sql_values_never_cross_the_wire_or_reach_server_storage_in_plaintext() {
    // ── server (untrusted) ───────────────────────────────────────────────────
    let dir = tempfile::tempdir().unwrap();
    let data_root = dir.path().join("server");
    std::fs::create_dir_all(&data_root).unwrap();
    let (mut state, master) = bootstrap_core_state_locked(&data_root, false);
    let logs = MemorySink::new();
    let audit = MemoryAuditSink::new();
    state.set_observability(Observability::memory(logs.clone()));
    state.set_audit(Audit::memory(audit.clone()));
    {
        use dmc_security::auth::{Action, Resource};
        let auth = state.auth_mut();
        let analyst = auth.identities().get_by_name("analyst").unwrap().id.clone();
        for table in ["notes", "plain_control"] {
            for action in [Action::Create, Action::Insert, Action::Select, Action::Update] {
                auth.grants_mut()
                    .grant(analyst.clone(), Resource::table("avrora", "public", table), action);
            }
        }
    }
    let socket = data_root.join("dmc.sock");
    let state = Arc::new(Mutex::new(state));
    {
        let socket = socket.clone();
        thread::spawn(move || {
            let server = CoreServer::bind(&socket, &SocketPathOptions { allow_custom_path: true }).unwrap();
            loop {
                let mut g = state.lock().unwrap();
                if server.accept_and_serve_one(&mut g).is_err() {
                    break;
                }
            }
        });
    }
    thread::sleep(Duration::from_millis(50));
    let proxy = dir.path().join("proxy.sock");
    let capture = spawn_capture_proxy(proxy.clone(), socket.clone());

    // ── client (trusted) ─────────────────────────────────────────────────────
    let client_dir = dir.path().join("alice-device");
    let tenant = TenantId::new("acme").unwrap();
    let (identity, code) = ClientIdentity::generate(SubjectId::random(), tenant.clone());
    identity.save(&client_dir.join("identity.json")).unwrap();
    let mut cstate = ClientState::open(client_dir.join("state.json")).unwrap();
    let (mut ring, env1) = ClientKeyring::create(identity, &mut cstate).unwrap();
    let me = ring.subject();

    let mut client = Client::with_client_id(ConnectionTarget::Local { socket: proxy.clone() }, "alice");
    client.connect().unwrap();
    client.control().authenticate("analyst", "pw").unwrap();
    client
        .control()
        .vault_unlock(&MockKeyPassProvider::with_material(master.clone()))
        .unwrap();
    client
        .sql()
        .execute("CREATE TABLE notes (id BIGINT PRIMARY KEY, owner TEXT, body BLOB)")
        .unwrap();
    client
        .sql()
        .execute("CREATE TABLE plain_control (id BIGINT PRIMARY KEY, note TEXT)")
        .unwrap();

    // write: plaintext → seal (client) → X'…' → wire → server
    for id in 1..=12u64 {
        let oid = sql_client_object_id("notes", &id.to_string(), "body");
        let sealed = ring.seal(&oid, 1, format!("{SECRET}-{id}").as_bytes()).unwrap();
        let sql = format!(
            "INSERT INTO notes (id, owner, body) VALUES ({id}, '{}', {})",
            me.to_hex(),
            sql_blob_literal(&sealed)
        );
        assert!(matches!(client.sql().execute(&sql).unwrap(), ExecuteOutcome::Ok));
    }
    // negative control: an unprotected value travels in plaintext (proves the capture works)
    client
        .sql()
        .execute(&format!("INSERT INTO plain_control (id, note) VALUES (1, '{CONTROL}')"))
        .unwrap();

    // client-side rotation + re-encryption of row 1; server never sees plaintext
    let env2 = ring.new_data_key(&mut cstate).unwrap();
    let oid1 = sql_client_object_id("notes", "1", "body");
    let rows = client.sql().query("SELECT body FROM notes WHERE id = 1").unwrap();
    let old = parse_sql_blob_cell(&rows.rows[0].cells[0].value).unwrap();
    let re = ring.reencrypt(&oid1, &old).unwrap();
    client
        .sql()
        .execute(&format!("UPDATE notes SET body = {} WHERE id = 1", sql_blob_literal(&re)))
        .unwrap();

    // read: wire → ciphertext → open (client)
    let check = |client: &mut Client, ring: &ClientKeyring, id: u64, expect_version: u32| {
        let rows = client
            .sql()
            .query(&format!("SELECT body FROM notes WHERE id = {id}"))
            .unwrap();
        let sealed = parse_sql_blob_cell(&rows.rows[0].cells[0].value).unwrap();
        assert_eq!(RecordHeader::parse(&sealed).unwrap().key_version, expect_version);
        let oid = sql_client_object_id("notes", &id.to_string(), "body");
        assert_eq!(ring.open(me, &oid, &sealed).unwrap(), format!("{SECRET}-{id}").into_bytes());
        // value swapped onto another row's context fails
        let other = sql_client_object_id("notes", &(id + 100).to_string(), "body");
        assert!(ring.open(me, &other, &sealed).is_err());
    };
    check(&mut client, &ring, 1, 2);
    check(&mut client, &ring, 7, 1);

    // backup → restore → recover over the same transport
    client.control().backup_create("cb1", true).unwrap();
    client.control().backup_restore("cb1", "r1").unwrap();
    client.control().backup_recover("r1").unwrap();

    // ── assertions ───────────────────────────────────────────────────────────
    let wire = capture.lock().unwrap().clone();
    assert!(contains(&wire, CONTROL.as_bytes()), "capture must see plaintext control value");
    assert!(!contains(&wire, SECRET.as_bytes()), "CLIENT_OWNED plaintext crossed the wire");
    let lit = sql_blob_literal(&re);
    assert!(contains(&wire, lit[2..42].as_bytes()), "capture must see the ciphertext");

    let files = walk(&data_root);
    assert!(files.iter().any(|p| p.to_string_lossy().contains("backups")), "backup exists");
    assert!(files.iter().any(|p| p.to_string_lossy().contains("restores")), "restore exists");
    for f in &files {
        let bytes = std::fs::read(f).unwrap_or_default();
        assert!(!contains(&bytes, SECRET.as_bytes()), "plaintext in server file {}", f.display());
    }
    let server_logs = format!("{:?} {:?}", logs.snapshot(), audit.snapshot());
    assert!(!server_logs.contains(SECRET), "plaintext in server logs/audit");

    // client restart from device file + envelopes (kept by the client here; the key
    // directory network API is not wired yet): reads still work
    drop(ring);
    let mut cstate = ClientState::open(client_dir.join("state.json")).unwrap();
    let identity = ClientIdentity::load(&client_dir.join("identity.json")).unwrap();
    let ring = ClientKeyring::load(identity, &[env1, env2], &mut cstate).unwrap();
    check(&mut client, &ring, 1, 2);
    check(&mut client, &ring, 12, 1);
    let _ = code;
}
