//! Production pgwire over the SQL plane (D4-A): functionality, authentication,
//! authorization, transactions, lifecycle, error paths — and that it is the very same
//! encrypted reference path as DMC IPC.

#[path = "pg_support/mod.rs"]
mod pg_support;

use dmc_protocol::{DataRequest, DataResponse, RemoteLimits, RequestEnvelope};
use dmc_security::auth::Action;
use pg_support::{Pg, Server, User, msg, sasl_initial, walk};

const ALL: &[Action] = &[
    Action::Create,
    Action::Drop,
    Action::Select,
    Action::Insert,
    Action::Update,
    Action::Delete,
];

fn setup() -> (Server, User) {
    let srv = Server::start();
    srv.unlock();
    let alice = srv.enroll("alice");
    srv.grant_sql(&alice, &["items", "orders", "tmp"], ALL);
    (srv, alice)
}

fn ok(pg: &mut Pg, sql: &str) -> pg_support::Reply {
    let r = pg.query(sql);
    assert!(r.ok(), "{sql}: {:?}", r.error);
    r
}

fn col(r: &pg_support::Reply, i: usize) -> Vec<String> {
    r.rows
        .iter()
        .map(|row| row[i].clone().unwrap_or_default())
        .collect()
}

#[test]
fn sql_statements_over_pgwire() {
    let (srv, alice) = setup();
    // DROP INDEX is authorized on the schema
    srv.grant(
        &alice,
        dmc_security::auth::Resource::schema("avrora", "public"),
        &[Action::Drop],
    );
    let mut pg = srv.connect(&alice);

    // DDL
    let r = ok(
        &mut pg,
        "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT, qty BIGINT)",
    );
    assert_eq!(r.tag.as_deref(), Some("CREATE TABLE"));
    ok(&mut pg, "CREATE INDEX idx_items_name ON items(name)");
    // DML
    for (id, name, qty) in [(1, "apple", 3), (2, "pear", 5), (3, "plum", 7)] {
        let r = ok(
            &mut pg,
            &format!("INSERT INTO items (id, name, qty) VALUES ({id}, '{name}', {qty})"),
        );
        assert_eq!(r.tag.as_deref(), Some("INSERT"));
    }
    let r = ok(&mut pg, "SELECT name, qty FROM items ORDER BY id");
    assert_eq!(r.tag.as_deref(), Some("SELECT 3"));
    assert_eq!(col(&r, 0), ["apple", "pear", "plum"]);
    assert_eq!(col(&r, 1), ["3", "5", "7"]);
    // index-backed lookup
    let r = ok(&mut pg, "SELECT id FROM items WHERE name = 'pear'");
    assert_eq!(col(&r, 0), ["2"]);
    ok(&mut pg, "UPDATE items SET qty = 50 WHERE id = 2");
    let r = ok(&mut pg, "SELECT qty FROM items WHERE id = 2");
    assert_eq!(col(&r, 0), ["50"]);
    ok(&mut pg, "DELETE FROM items WHERE id = 3");
    let r = ok(&mut pg, "SELECT id FROM items ORDER BY id");
    assert_eq!(col(&r, 0), ["1", "2"]);
    // primary key enforced
    let r = pg.query("INSERT INTO items (id, name, qty) VALUES (1, 'dup', 1)");
    assert_eq!(r.sqlstate(), "23000", "{:?}", r.error);
    assert_eq!(r.ready, b'I');
    // NULLs travel as SQL NULL
    ok(
        &mut pg,
        "INSERT INTO items (id, name, qty) VALUES (4, NULL, 1)",
    );
    let r = ok(&mut pg, "SELECT name FROM items WHERE id = 4");
    assert_eq!(r.rows, vec![vec![None]]);
    // DROP INDEX / DROP TABLE
    ok(&mut pg, "DROP INDEX idx_items_name");
    ok(&mut pg, "CREATE TABLE tmp (id BIGINT PRIMARY KEY)");
    ok(&mut pg, "DROP TABLE tmp");
    assert!(!pg.query("SELECT id FROM tmp").ok());

    // not in the SQL plane grammar: refused cleanly (the session stays usable)
    for sql in [
        "ALTER TABLE items ADD COLUMN extra TEXT",
        "CREATE TABLE orders (id BIGINT PRIMARY KEY, item BIGINT REFERENCES items(id))",
    ] {
        let r = pg.query(sql);
        assert!(!r.ok(), "{sql} must be refused");
        assert_eq!(r.ready, b'I');
    }
    // syntax error, unknown table
    assert_eq!(pg.query("SELEC 1").sqlstate(), "42601");
    assert!(!pg.query("SELECT * FROM no_such_table").ok());
    // empty query
    let r = pg.query("   ");
    assert!(r.ok() && r.ready == b'I');
    assert_eq!(
        col(&ok(&mut pg, "SELECT id FROM items ORDER BY id"), 0),
        ["1", "2", "4"]
    );
    pg.terminate();
}

#[test]
fn transactions_rollback_and_isolation() {
    let (srv, alice) = setup();
    let bob = srv.enroll("bob");
    srv.grant_sql(&bob, &["items"], ALL);
    let mut a = srv.connect(&alice);
    let mut b = srv.connect(&bob);
    ok(
        &mut a,
        "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)",
    );

    // rollback
    assert_eq!(ok(&mut a, "BEGIN").ready, b'T');
    ok(&mut a, "INSERT INTO items (id, name) VALUES (1, 'draft')");
    // isolation: nobody else sees (or touches) an open transaction's data
    let r = b.query("SELECT id FROM items");
    assert_eq!(r.sqlstate(), "40001", "{:?}", r.error);
    assert_eq!(r.ready, b'I', "bob is not in a transaction");
    // (a SELECT inside an open transaction does not see its own buffered writes — an
    // existing SQL-plane limitation on every transport, reported separately)
    assert_eq!(ok(&mut a, "ROLLBACK").ready, b'I');
    assert!(ok(&mut b, "SELECT id FROM items").rows.is_empty());

    // commit
    ok(&mut a, "BEGIN");
    ok(&mut a, "INSERT INTO items (id, name) VALUES (2, 'kept')");
    ok(&mut a, "COMMIT");
    assert_eq!(col(&ok(&mut b, "SELECT id FROM items"), 0), ["2"]);

    // disconnect inside a transaction: rolled back, never committed; others proceed
    ok(&mut a, "BEGIN");
    ok(&mut a, "INSERT INTO items (id, name) VALUES (3, 'orphan')");
    drop(a);
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert_eq!(
        col(&ok(&mut b, "SELECT id FROM items ORDER BY id"), 0),
        ["2"]
    );
    assert_eq!(ok(&mut b, "BEGIN").ready, b'T', "transaction slot freed");
    ok(&mut b, "ROLLBACK");
}

#[test]
fn authorization_is_per_identity() {
    let (srv, alice) = setup();
    let reader = srv.enroll("reader");
    srv.grant(
        &reader,
        dmc_security::auth::Resource::database("avrora"),
        &[Action::Connect],
    );
    srv.grant(
        &reader,
        dmc_security::auth::Resource::schema("avrora", "public"),
        &[Action::Usage],
    );
    srv.grant(
        &reader,
        dmc_security::auth::Resource::table("avrora", "public", "items"),
        &[Action::Select],
    );
    let nobody = srv.enroll("nobody");
    let mut a = srv.connect(&alice);
    ok(
        &mut a,
        "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)",
    );
    ok(&mut a, "INSERT INTO items (id, name) VALUES (1, 'x')");

    let mut r = srv.connect(&reader);
    assert_eq!(col(&ok(&mut r, "SELECT id FROM items"), 0), ["1"]);
    for sql in [
        "INSERT INTO items (id, name) VALUES (2, 'y')",
        "UPDATE items SET name = 'z' WHERE id = 1",
        "DELETE FROM items WHERE id = 1",
        "DROP TABLE items",
        "CREATE TABLE tmp (id BIGINT PRIMARY KEY)",
    ] {
        assert_eq!(r.query(sql).sqlstate(), "42501", "{sql}");
    }
    let mut n = srv.connect(&nobody);
    assert_eq!(n.query("SELECT id FROM items").sqlstate(), "42501");
    assert_eq!(
        col(&ok(&mut a, "SELECT name FROM items"), 0),
        ["x"],
        "nothing changed"
    );
}

#[test]
fn authentication_is_avrora_ed25519_only() {
    let (srv, alice) = setup();
    let mallory = srv.enroll("mallory");

    // only the AVRORA mechanism is offered
    let mut pg = Pg::open(srv.addr);
    assert_eq!(
        pg.startup().unwrap(),
        vec![dmc_pgwire::MECHANISM.to_string()]
    );

    let refused = |f: &dyn Fn(&mut Pg)| {
        let mut pg = Pg::open(srv.addr);
        pg.startup().unwrap();
        f(&mut pg);
        let r = pg.collect();
        assert_eq!(r.sqlstate(), "28000", "{:?}", r.error);
        assert!(
            pg.read().is_none(),
            "connection closed after a failed authentication"
        );
    };
    // other SASL mechanisms (SCRAM) and plain password messages
    refused(&|pg| pg.send(&sasl_initial("SCRAM-SHA-256", b"n,,n=alice,r=abc")));
    refused(&|pg| pg.send(&msg(b'p', b"password\0")));
    // a query instead of authentication
    refused(&|pg| pg.send(&msg(b'Q', b"SELECT 1\0")));
    // a signature by a key that is not alice's registered key (attacker-generated key for
    // alice's subject), and by another enrolled user's key
    {
        let (forged, _) = dmc_client_crypto::ClientIdentity::generate(
            alice.id.subject(),
            alice.id.tenant().clone(),
        );
        assert_eq!(
            Pg::authenticate(srv.addr, &forged).err().unwrap().0,
            "28000"
        );
        let mut pg = Pg::open(srv.addr);
        pg.startup().unwrap();
        pg.begin(&mallory.id).unwrap();
        let mut pg2 = Pg::open(srv.addr);
        pg2.startup().unwrap();
        let alice_challenge = pg2.begin(&alice.id).unwrap();
        // mallory cannot produce alice's signature; a signature mallory can make (over her
        // own challenge) is useless for alice's
        let mut mc = Pg::open(srv.addr);
        mc.startup().unwrap();
        let mallory_challenge = mc.begin(&mallory.id).unwrap();
        let sig = mallory.id.sign_challenge(&mallory_challenge).unwrap();
        assert_eq!(pg2.finish(&sig).unwrap_err().0, "28000");
        let _ = (pg, alice_challenge);
    }
    // tampered signature
    {
        let mut pg = Pg::open(srv.addr);
        pg.startup().unwrap();
        let challenge = pg.begin(&alice.id).unwrap();
        let mut sig = alice.id.sign_challenge(&challenge).unwrap();
        sig[5] ^= 1;
        assert_eq!(pg.finish(&sig).unwrap_err().0, "28000");
    }
    // relay: a valid signature for connection A's challenge used on connection B
    {
        let mut a = Pg::open(srv.addr);
        a.startup().unwrap();
        let challenge_a = a.begin(&alice.id).unwrap();
        let sig_a = alice.id.sign_challenge(&challenge_a).unwrap();
        let mut b = Pg::open(srv.addr);
        b.startup().unwrap();
        b.begin(&alice.id).unwrap();
        assert_eq!(b.finish(&sig_a).unwrap_err().0, "28000");
        // and A's challenge was not consumed by B: A itself still works once
        a.finish(&sig_a).unwrap();
    }
    // replay of a completed authentication on a new connection
    {
        let mut a = Pg::open(srv.addr);
        a.startup().unwrap();
        let ch = a.begin(&alice.id).unwrap();
        let sig = alice.id.sign_challenge(&ch).unwrap();
        a.finish(&sig).unwrap();
        let mut b = Pg::open(srv.addr);
        b.startup().unwrap();
        b.begin(&alice.id).unwrap();
        assert_eq!(b.finish(&sig).unwrap_err().0, "28000");
    }
    // unknown subject: same refusal, no oracle
    {
        let (stranger, _) = dmc_client_crypto::ClientIdentity::generate(
            dmc_vault::ownership::SubjectId::random(),
            dmc_vault::ownership::TenantId::new("acme").unwrap(),
        );
        assert_eq!(
            Pg::authenticate(srv.addr, &stranger).err().unwrap().0,
            "28000"
        );
    }
    // the genuine key works
    let mut good = srv.connect(&alice);
    good.query("CREATE TABLE items (id BIGINT PRIMARY KEY)");
    assert!(good.query("SELECT id FROM items").ok());
}

#[test]
fn lifecycle_and_error_paths() {
    let srv = Server::start(); // vault Locked
    let alice = srv.enroll("alice");
    srv.grant_sql(&alice, &["items"], ALL);
    let mut pg = srv.connect(&alice); // authentication needs no unlock
    assert_eq!(
        pg.query("SELECT 1").sqlstate(),
        "55000",
        "vault locked → no SQL"
    );
    srv.unlock();
    ok(&mut pg, "CREATE TABLE items (id BIGINT PRIMARY KEY)");
    srv.lock();
    assert_eq!(pg.query("SELECT id FROM items").sqlstate(), "55000");
    srv.unlock();
    assert!(ok(&mut pg, "SELECT id FROM items").rows.is_empty());

    // extended query protocol: refused, connection stays usable
    pg.send(&msg(b'P', b"\0SELECT 1\0\0\0"));
    let r = pg.collect();
    assert_eq!(r.sqlstate(), "0A000");
    pg.send(&msg(b'S', &[]));
    assert_eq!(pg.collect().ready, b'I');
    ok(&mut pg, "SELECT id FROM items");

    // oversized / malformed message: that connection is closed, the server keeps serving
    let mut bad = srv.connect(&alice);
    let mut huge = vec![b'Q'];
    huge.extend_from_slice(&(i32::MAX).to_be_bytes());
    bad.send(&huge);
    assert!(bad.read().is_none());
    let mut bad2 = Pg::open(srv.addr);
    bad2.send(&(-5i32).to_be_bytes());
    assert!(bad2.read().is_none());
    ok(&mut pg, "SELECT id FROM items");

    // disconnect ends the session (no rebind: a new connection authenticates again)
    pg.terminate();
    let mut again = srv.connect(&alice);
    ok(&mut again, "SELECT id FROM items");
}

#[test]
fn pgwire_is_the_dmc_reference_path() {
    let (srv, alice) = setup();
    let mut pg = srv.connect(&alice);
    ok(
        &mut pg,
        "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)",
    );
    ok(
        &mut pg,
        "INSERT INTO items (id, name) VALUES (1, 'via-pgwire')",
    );

    // the same data through the DMC dispatcher with a DMC session of another user
    let bob = srv.enroll("bob");
    srv.grant_sql(&bob, &["items"], ALL);
    let sid = {
        // DMC-side authentication of bob on a DMC channel
        let ch = "dmc-test";
        let mut s = srv.core.lock().unwrap();
        let r = dmc_server::handle_control(
            &mut s,
            RequestEnvelope {
                request_id: 1,
                body: dmc_protocol::ControlRequest::ClientAuthBegin {
                    subject: bob.id.subject(),
                    tenant: bob.id.tenant().clone(),
                },
            },
            &RemoteLimits::default(),
            ch,
        )
        .unwrap();
        let Some(dmc_protocol::ControlResponse::ClientAuthChallenge { challenge }) = r.body else {
            panic!()
        };
        let nonce = dmc_vault::ownership::auth::Challenge::parse(&challenge)
            .unwrap()
            .nonce
            .to_vec();
        let r = dmc_server::handle_control(
            &mut s,
            RequestEnvelope {
                request_id: 2,
                body: dmc_protocol::ControlRequest::ClientAuthFinish {
                    nonce,
                    signature: bob.id.sign_challenge(&challenge).unwrap(),
                },
            },
            &RemoteLimits::default(),
            ch,
        )
        .unwrap();
        let Some(dmc_protocol::ControlResponse::ClientAuthOk { session_id, .. }) = r.body else {
            panic!()
        };
        session_id
    };
    let dmc_sql = |sql: &str| {
        let mut s = srv.core.lock().unwrap();
        dmc_server::handle_data(
            &mut s,
            RequestEnvelope {
                request_id: 3,
                body: DataRequest::ExecuteSql {
                    session_id: sid.clone(),
                    sql: sql.into(),
                    params: vec![],
                },
            },
            &RemoteLimits::default(),
            "dmc-test",
        )
        .unwrap()
    };
    match dmc_sql("SELECT name FROM items").body {
        Some(DataResponse::SqlResult(r)) => assert_eq!(r.rows[0].cells[0].text, "via-pgwire"),
        other => panic!("{other:?}"),
    }
    assert!(
        dmc_sql("INSERT INTO items (id, name) VALUES (2, 'via-dmc')")
            .error_code
            .is_none()
    );
    assert_eq!(
        col(&ok(&mut pg, "SELECT name FROM items ORDER BY id"), 0),
        ["via-pgwire", "via-dmc"]
    );

    // a pgwire session id is not usable from the DMC side, and vice versa (D5 channels)
    // (pgwire never exposes its session id; a DMC session on a pgwire channel is
    // impossible because pgwire never accepts a session id from the client.)

    // one store: encrypted SQL-plane files, no legacy engine file anywhere
    let files = walk(&srv.root);
    assert!(
        files.iter().all(|f| !f.ends_with("sql.dbs.json")),
        "no legacy store"
    );
    let log = files
        .iter()
        .find(|f| f.ends_with("state_events.json"))
        .expect("SQL-plane journal");
    assert!(dmc_vault::storage_cipher::looks_sealed(
        &std::fs::read(log).unwrap()
    ));
    assert!(srv.root.join(dmc_ops::ENCRYPTED_STORAGE_MARKER).is_file());
}

#[test]
fn listener_is_loopback_only() {
    let srv = Server::start();
    let err = dmc_pgwire::spawn("0.0.0.0:0".parse().unwrap(), srv.core.clone()).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn production_binary_never_serves_the_legacy_engine() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let key = dir.path().join("master.key");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_dmc-pgwire"))
        .args([
            "--data",
            data.to_str().unwrap(),
            "--listen",
            &format!("127.0.0.1:{port}"),
            // exactly the legacy invocation (create a database + master key file)
            "--create",
            "--master-key-out",
            key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("dmc serve --pgwire"));
    assert!(
        !data.exists() && !key.exists(),
        "no storage and no key file created"
    );
    assert!(
        std::net::TcpStream::connect(("127.0.0.1", port)).is_err(),
        "nothing listens"
    );
}

#[test]
fn pgwire_is_bound_by_the_client_owned_policy() {
    let (srv, alice) = setup();
    srv.grant_sql(&alice, &["notes"], ALL);
    let mut pg = srv.connect(&alice);
    ok(
        &mut pg,
        "CREATE TABLE notes (id BIGINT PRIMARY KEY, owner TEXT, body BLOB)",
    );
    srv.declare_sealed("notes", "body", "owner");
    // a plaintext value for a sealed column is refused, whatever the transport
    let subject = alice.id.subject().to_string();
    let r = pg.query(&format!(
        "INSERT INTO notes (id, owner, body) VALUES (1, '{subject}', X'706C61696E')"
    ));
    assert!(
        !r.ok(),
        "plaintext into a CLIENT_OWNED sealed column must be refused"
    );
    assert!(ok(&mut pg, "SELECT id FROM notes").rows.is_empty());
}

#[test]
fn multi_statement_queries_are_refused_whole() {
    let (srv, alice) = setup();
    let mut pg = srv.connect(&alice);
    ok(&mut pg, "CREATE TABLE items (id BIGINT PRIMARY KEY)");
    let r = pg.query("INSERT INTO items (id) VALUES (1); INSERT INTO items (id) VALUES (2)");
    assert_eq!(r.sqlstate(), "42601");
    assert!(
        ok(&mut pg, "SELECT id FROM items").rows.is_empty(),
        "nothing partially executed"
    );
    ok(&mut pg, "SELECT id FROM items;");
}
