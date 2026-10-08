//! D4 security gate: encryption at rest, legacy pgwire path vs. SQL plane.
//!
//! A unique plaintext marker (random per run, never used by other tests) is written
//! through each path; then every byte the path leaves on disk is searched for the marker
//! — raw, lowercase/uppercase hex and base64 at all three alignments.
//!
//! * `d4_reference_legacy_pgwire_encrypts_at_rest` drives the **real legacy pgwire
//!   process** (`dmc-pgwire-legacy-reference`: the pre-D4 engine, kept only as this
//!   baseline; key file, Simple Query protocol) and requires: marker NOT FOUND.
//! * `d4_gate_sql_plane_at_rest_equivalence` writes the same through the SQL plane
//!   (the engine pgwire would move to under D4-A) and requires the same property for
//!   primary storage, journal, backup and restore. Its expectation must not be changed to
//!   make it pass.
//!
//! D4-A stage 6: the SQL-plane harness runs the **production reference path**
//! (`dmc_ops::start_core`: persistent key store, storage opened on `VaultUnlock`,
//! encrypted-only), not the dev/test bootstrap; recovery uses the storage keys of the
//! unlocked installation (`recover_with`), as the production `BackupRecover` does.
//!
//! * `d4_gate_production_pgwire_at_rest_equivalence` (D4: pgwire on the SQL plane) writes
//!   the same — plus the marker as a **primary-key** value, which legacy leaks — through the
//!   **production pgwire adapter** (PostgreSQL wire protocol, SASL `AVRORA-ED25519-V1`) and
//!   requires the same property for storage, journal, backup, restore and every file the
//!   run left behind.
//!
//! All tests first prove the scanner itself detects the marker (negative control).

#[path = "pg_support/mod.rs"]
mod pg_support;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

// ── marker + scanner ──────────────────────────────────────────────────────────

fn unique_marker() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "PGWIRE_AT_REST_CONFIDENTIALITY_MARKER_{:x}_{:x}",
        std::process::id(),
        nanos
    )
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            }
        }
    }
    out
}

/// Encodings of `marker` that would reveal it inside a larger encoded blob.
fn needles(marker: &str) -> Vec<(String, Vec<u8>)> {
    let m = marker.as_bytes();
    let mut v = vec![
        ("raw".to_string(), m.to_vec()),
        ("hex".to_string(), hex(m).into_bytes()),
        ("HEX".to_string(), hex(m).to_uppercase().into_bytes()),
    ];
    for pad in 0..3usize {
        // base64 of marker preceded by `pad` unknown bytes: drop the chars touched by them
        let mut buf = vec![0u8; pad];
        buf.extend_from_slice(m);
        let enc = b64(&buf);
        let skip = if pad == 0 { 0 } else { 4 };
        let stable = &enc[skip..enc.len() - 4];
        v.push((format!("base64+{pad}"), stable.as_bytes().to_vec()));
    }
    v
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
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

/// (file, encoding) for every occurrence of the marker under `dir`.
fn scan(dir: &Path, marker: &str) -> Vec<(String, String)> {
    let needles = needles(marker);
    let mut found = Vec::new();
    for f in walk(dir) {
        let bytes = std::fs::read(&f).unwrap_or_default();
        for (enc, n) in &needles {
            if bytes.windows(n.len()).any(|w| w == n.as_slice()) {
                found.push((
                    f.strip_prefix(dir).unwrap_or(&f).display().to_string(),
                    enc.clone(),
                ));
            }
        }
    }
    found
}

/// Negative control: the scanner must find the marker in every encoding it claims.
fn assert_scanner_detects(marker: &str) {
    let dir = tempfile::tempdir().unwrap();
    let m = marker.as_bytes();
    std::fs::write(
        dir.path().join("raw.bin"),
        [b"xx".as_slice(), m, b"yy"].concat(),
    )
    .unwrap();
    std::fs::write(dir.path().join("hex.txt"), format!("..{}..", hex(m))).unwrap();
    for pad in 0..3 {
        let mut buf = vec![7u8; pad];
        buf.extend_from_slice(m);
        buf.extend_from_slice(b"tail");
        std::fs::write(dir.path().join(format!("b64-{pad}.txt")), b64(&buf)).unwrap();
    }
    let found = scan(dir.path(), marker);
    for expect in ["raw", "hex", "base64+0", "base64+1", "base64+2"] {
        assert!(
            found.iter().any(|(_, e)| e == expect),
            "scanner misses {expect}: {found:?}"
        );
    }
}

// ── legacy path: the real dmc-pgwire binary ──────────────────────────────────

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start_pgwire(args: &[&str]) -> Server {
    let child = Command::new(env!("CARGO_BIN_EXE_dmc-pgwire-legacy-reference"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    Server(child)
}

fn connect(port: u16) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
            return s;
        }
        assert!(Instant::now() < deadline, "dmc-pgwire did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn pg_message(tag: Option<u8>, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::new();
    if let Some(t) = tag {
        m.push(t);
    }
    m.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
    m.extend_from_slice(body);
    m
}

fn read_until_ready(s: &mut TcpStream) -> Vec<u8> {
    let mut all = Vec::new();
    loop {
        let mut head = [0u8; 5];
        s.read_exact(&mut head).unwrap();
        let len = i32::from_be_bytes(head[1..5].try_into().unwrap()) as usize;
        let mut body = vec![0u8; len - 4];
        s.read_exact(&mut body).unwrap();
        all.extend_from_slice(&head);
        all.extend_from_slice(&body);
        if head[0] == b'Z' {
            return all;
        }
    }
}

fn pg_session(port: u16) -> TcpStream {
    let mut s = connect(port);
    let mut body = 196608i32.to_be_bytes().to_vec();
    body.extend_from_slice(b"user\0dbs\0database\0main\0\0");
    s.write_all(&pg_message(None, &body)).unwrap();
    read_until_ready(&mut s);
    s
}

fn pg_query(s: &mut TcpStream, sql: &str) -> Vec<u8> {
    let mut body = sql.as_bytes().to_vec();
    body.push(0);
    s.write_all(&pg_message(Some(b'Q'), &body)).unwrap();
    let reply = read_until_ready(s);
    assert!(
        !reply.contains(&b'E') || !String::from_utf8_lossy(&reply).contains("ERROR"),
        "{}",
        String::from_utf8_lossy(&reply)
    );
    reply
}

#[test]
fn d4_reference_legacy_pgwire_encrypts_at_rest() {
    let marker = unique_marker();
    assert_scanner_detects(&marker);
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let db = data.join("sql.dbs.json");
    let key = dir.path().join("keys/sql.master.key");
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");

    let mut server = start_pgwire(&[
        "--data",
        db.to_str().unwrap(),
        "--listen",
        &listen,
        "--create",
        "--master-key-out",
        key.to_str().unwrap(),
    ]);
    let mut s = pg_session(port);
    pg_query(
        &mut s,
        "CREATE TABLE d4_legacy (id INT PRIMARY KEY, note TEXT);",
    );
    pg_query(
        &mut s,
        &format!("INSERT INTO d4_legacy (id, note) VALUES (1, '{marker}');"),
    );
    // baseline precision: a marker used as a PRIMARY KEY value (the legacy row id is built
    // from primary-key values and stored as a plaintext entry path) — reported, not hidden
    let pk_marker = format!("{}_PK", unique_marker());
    pg_query(
        &mut s,
        "CREATE TABLE d4_legacy_pk (k TEXT PRIMARY KEY, v INT);",
    );
    pg_query(
        &mut s,
        &format!("INSERT INTO d4_legacy_pk (k, v) VALUES ('{pk_marker}', 1);"),
    );
    // functional sanity: the marker really is stored and readable through pgwire
    let rows = pg_query(&mut s, "SELECT note FROM d4_legacy WHERE id = 1;");
    assert!(
        String::from_utf8_lossy(&rows).contains(&marker),
        "write did not happen"
    );
    drop(s);
    drop(server);

    // restart from disk (key file) and read again: data persisted, still encrypted
    let port2 = free_port();
    server = start_pgwire(&[
        "--data",
        db.to_str().unwrap(),
        "--listen",
        &format!("127.0.0.1:{port2}"),
        "--unlock-file",
        key.to_str().unwrap(),
    ]);
    let mut s = pg_session(port2);
    assert!(
        String::from_utf8_lossy(&pg_query(
            &mut s,
            "SELECT note FROM d4_legacy WHERE id = 1;"
        ))
        .contains(&marker)
    );
    drop(s);
    let mut out = String::new();
    let mut err = String::new();
    let _ = server.0.kill();
    if let Some(mut o) = server.0.stdout.take() {
        let _ = o.read_to_string(&mut out);
    }
    if let Some(mut e) = server.0.stderr.take() {
        let _ = e.read_to_string(&mut err);
    }
    drop(server);

    let files = walk(&data);
    assert!(
        files.iter().any(|p| p == &db),
        "legacy database file exists: {files:?}"
    );
    // the legacy engine has no backup tool: a backup is a copy of these files
    let backup = dir.path().join("backup-copy");
    std::fs::create_dir_all(&backup).unwrap();
    for f in &files {
        std::fs::copy(f, backup.join(f.file_name().unwrap())).unwrap();
    }
    let found = [scan(&data, &marker), scan(&backup, &marker)].concat();
    let pk_found = scan(&data, &pk_marker);
    println!("legacy baseline — primary-key value at rest: {pk_found:?}");
    println!(
        "legacy files: {:?}",
        files
            .iter()
            .map(|p| p.strip_prefix(&data).unwrap().display().to_string())
            .collect::<Vec<_>>()
    );
    assert!(
        found.is_empty(),
        "plaintext marker at rest on the legacy path: {found:?}"
    );
    for (label, log) in [("stdout", &out), ("stderr", &err)] {
        assert!(!log.contains(&marker), "marker in pgwire {label}");
    }
}

// ── SQL plane (the engine pgwire would migrate to) ───────────────────────────

mod sql_plane {
    use super::*;
    use dmc_protocol::{
        ControlRequest, ControlResponse, DataRequest, RemoteLimits, RequestEnvelope,
    };
    use dmc_server::{
        CoreServerState, MockKeyPassProvider, create_unlock_blob, handle_control, handle_data,
    };

    fn ctl(s: &mut CoreServerState, body: ControlRequest) -> ControlResponse {
        let r = handle_control(
            s,
            RequestEnvelope {
                request_id: 1,
                body,
            },
            &RemoteLimits::default(),
            "d4",
        )
        .unwrap();
        assert!(r.error_code.is_none(), "{:?}", r.error_message);
        r.body.unwrap()
    }

    fn sql(s: &mut CoreServerState, sid: &str, q: &str) {
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
            "d4",
        )
        .unwrap();
        assert!(r.error_code.is_none(), "{q}: {:?}", r.error_message);
    }

    /// Writes the marker through the SQL plane; returns where it was found
    /// (primary storage / journal, backup, restore).
    /// (file, encoding) occurrences of the marker.
    pub type Findings = Vec<(String, String)>;

    pub fn evidence(marker: &str) -> (Findings, Findings, Findings) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("server");
        std::fs::create_dir_all(&root).unwrap();
        // production reference path: Ready + Locked, Master Key issued once
        let cfg = dmc_ops::parse_config_json(&format!(
            r#"{{ "data_root": "{}", "profile": "development" }}"#,
            root.display()
        ))
        .unwrap();
        let started =
            dmc_ops::start_core(cfg, dmc_ops::StartupOptions::production()).unwrap();
        let master = started.unlock_material.clone().unwrap();
        let mut st = started.server;
        // an SQL user with the usual rights on the test table (in-process, as before)
        let analyst = st.auth_mut().create_identity("analyst", "pw").unwrap();
        {
            use dmc_security::auth::{Action, Resource};
            let g = st.auth_mut().grants_mut();
            g.grant(
                analyst.clone(),
                Resource::database("avrora"),
                Action::Connect,
            );
            g.grant(
                analyst.clone(),
                Resource::schema("avrora", "public"),
                Action::Usage,
            );
            g.grant(
                analyst.clone(),
                Resource::database("avrora"),
                Action::Create,
            );
            g.grant(
                analyst.clone(),
                Resource::schema("avrora", "public"),
                Action::Create,
            );
            for a in [Action::Create, Action::Insert, Action::Select] {
                g.grant(
                    analyst.clone(),
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
            &mut st,
            ControlRequest::Authenticate {
                identity_name: "analyst".into(),
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
            &MockKeyPassProvider::with_material(master),
        )
        .unwrap();
        ctl(
            &mut st,
            ControlRequest::VaultUnlock {
                session_id: session_id.clone(),
                blob,
            },
        );
        sql(
            &mut st,
            &session_id,
            "CREATE TABLE d4_plane (id BIGINT PRIMARY KEY, note TEXT)",
        );
        sql(
            &mut st,
            &session_id,
            &format!("INSERT INTO d4_plane (id, note) VALUES (1, '{marker}')"),
        );
        ctl(
            &mut st,
            ControlRequest::BackupCreate {
                session_id: session_id.clone(),
                backup_id: "d4".into(),
                include_rowstore: true,
            },
        );
        let backups = root.join("backups");
        let live: Vec<_> = scan(&root, marker)
            .into_iter()
            .filter(|(f, _)| !f.starts_with("backups"))
            .collect();
        let in_backup = scan(&backups, marker);
        let restored = dir.path().join("restore");
        dmc_backup::restore_backup(&backups.join("backup-d4"), &restored).unwrap();
        // recovery needs the installation's storage keys (D4-A 4.5/4.6)
        let keys = std::sync::Arc::new(st.unlock_gate.storage_cipher().unwrap());
        dmc_backup::recover_with(&restored, Some(keys)).unwrap();
        (live, in_backup, scan(&restored, marker))
    }
}

#[test]
fn d4_gate_sql_plane_at_rest_equivalence() {
    let marker = unique_marker();
    assert_scanner_detects(&marker);
    let (live, backup, restored) = sql_plane::evidence(&marker);
    println!(
        "SQL plane — primary storage/journal: {live:?}\nSQL plane — backup: {backup:?}\nSQL plane — restore: {restored:?}"
    );
    // Same requirement as the legacy reference: no plaintext at rest anywhere.
    assert!(
        live.is_empty(),
        "plaintext marker in SQL-plane storage/journal: {live:?}"
    );
    assert!(
        backup.is_empty(),
        "plaintext marker in SQL-plane backup: {backup:?}"
    );
    assert!(
        restored.is_empty(),
        "plaintext marker in SQL-plane restore: {restored:?}"
    );
}

#[test]
fn d4_gate_production_pgwire_at_rest_equivalence() {
    use dmc_security::auth::Action;
    let marker = unique_marker();
    assert_scanner_detects(&marker);

    let srv = pg_support::Server::start();
    srv.unlock();
    let user = srv.enroll("analyst");
    srv.grant_sql(
        &user,
        &["d4_plane", "d4_pk"],
        &[Action::Create, Action::Insert, Action::Select],
    );
    let mut pg = srv.connect(&user);
    for sql in [
        "CREATE TABLE d4_plane (id BIGINT PRIMARY KEY, note TEXT)".to_string(),
        format!("INSERT INTO d4_plane (id, note) VALUES (1, '{marker}')"),
        "CREATE TABLE d4_pk (k TEXT PRIMARY KEY, n BIGINT)".to_string(),
        format!("INSERT INTO d4_pk (k, n) VALUES ('{marker}', 1)"),
    ] {
        let r = pg.query(&sql);
        assert!(r.ok(), "{sql}: {:?}", r.error);
    }
    // really written: read back over pgwire
    let r = pg.query("SELECT note FROM d4_plane");
    assert_eq!(r.rows, vec![vec![Some(marker.clone())]]);
    pg.terminate();

    // backup by the operator plane, restore + recover with the installation's keys
    srv.backup("d4");
    let backups = srv.root.join("backups");
    let restored = srv.dir.path().join("restore");
    dmc_backup::restore_backup(&backups.join("backup-d4"), &restored).unwrap();
    let keys = std::sync::Arc::new(srv.core.lock().unwrap().unlock_gate.storage_cipher().unwrap());
    dmc_backup::recover_with(&restored, Some(keys)).unwrap();

    let live: Vec<_> = scan(&srv.root, &marker)
        .into_iter()
        .filter(|(f, _)| !f.starts_with("backups"))
        .collect();
    let in_backup = scan(&backups, &marker);
    let in_restore = scan(&restored, &marker);
    // everything the run left on disk (data root, backups, restore, temporaries)
    let anywhere = scan(srv.dir.path(), &marker);
    println!(
        "production pgwire — primary storage/journal: {live:?}\nbackup: {in_backup:?}\nrestore: {in_restore:?}\nanywhere: {anywhere:?}"
    );
    assert!(live.is_empty(), "plaintext marker in pgwire storage/journal: {live:?}");
    assert!(in_backup.is_empty(), "plaintext marker in pgwire backup: {in_backup:?}");
    assert!(in_restore.is_empty(), "plaintext marker in pgwire restore: {in_restore:?}");
    assert!(anywhere.is_empty(), "plaintext marker anywhere on disk: {anywhere:?}");
}
