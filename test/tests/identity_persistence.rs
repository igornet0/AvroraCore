//! Identity persistence, first-administrator bootstrap and network privilege
//! administration on the **production startup path** (`dmc_ops::start_core`).
//!
//! fresh data root → one-time bootstrap → start → operator grants over DMC IPC →
//! enrolled CLIENT_OWNED user works without any in-process grant → restart (state from
//! disk only) → identities, keys, grants survive → network revoke → restart → revocation
//! survives → re-bootstrap refused → identity file lost ⇒ startup refuses to come up empty.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use dmc_client::{Client, ConnectionTarget, MockKeyPassProvider};
use dmc_client_crypto::ClientIdentity;
use dmc_ipc::{CoreServer, SocketPathOptions};
use dmc_observability::{Audit, AuditEventKind, AuditResult, MemoryAuditSink};
use dmc_ops::{CoreConfig, StartupError, StartupOptions, start_core};
use dmc_protocol::{ControlRequest, PrivilegeActionWire as A, PrivilegeResourceWire as R, PrivilegeWire};
use dmc_vault::ownership::TenantId;

fn fresh_passphrase() -> String {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    format!("op-{:x}-{:x}", std::process::id(), nanos)
}

fn privilege(resource: R, action: A) -> PrivilegeWire {
    PrivilegeWire { resource, action }
}

fn table(name: &str) -> R {
    R::Table { database: "avrora".into(), schema: "public".into(), name: name.into() }
}

struct Running {
    socket: PathBuf,
    /// Master Key: issued only by the start that created the key store (D4-A).
    master: Option<dmc_server::UnlockMaterial>,
    audit: MemoryAuditSink,
}

/// One "process start": state comes from disk only.
fn start(root: &Path, socket: PathBuf) -> Running {
    let started = start_core(CoreConfig::local_defaults(root), StartupOptions::production()).unwrap_or_else(|e| panic!("start: {e}"));
    let mut server = started.server;
    let audit = MemoryAuditSink::new();
    server.set_audit(Audit::memory(audit.clone()));
    let state = Arc::new(Mutex::new(server));
    let s = socket.clone();
    thread::spawn(move || {
        let ipc = CoreServer::bind(&s, &SocketPathOptions { allow_custom_path: true }).unwrap();
        let _ = ipc.serve_forever_shared(&state, |_| {});
    });
    thread::sleep(Duration::from_millis(50));
    Running { socket, master: started.unlock_material, audit }
}

fn operator(run: &Running, pass: &str) -> Client {
    let mut c = Client::with_client_id(ConnectionTarget::Local { socket: run.socket.clone() }, "operator");
    c.connect().unwrap();
    c.control().authenticate("root-op", pass).unwrap();
    c
}

fn user(run: &Running, device: &Path) -> Client {
    let id = ClientIdentity::load(&device.join("identity.json")).unwrap();
    let mut c = Client::with_client_id(ConnectionTarget::Local { socket: run.socket.clone() }, "alice");
    c.connect().unwrap();
    c.control()
        .client_authenticate(id.subject(), id.tenant().clone(), |ch| id.sign_challenge(ch))
        .unwrap();
    c
}

fn unlock(run: &Running, pass: &str, master: &dmc_server::UnlockMaterial) {
    operator(run, pass)
        .control()
        .vault_unlock(&MockKeyPassProvider::with_material(master.clone()))
        .unwrap();
}

#[test]
fn bootstrap_grants_and_identities_survive_restart() {
    let pass = fresh_passphrase();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    std::fs::create_dir_all(&root).unwrap();
    let ownership = root.join(dmc_server::OWNERSHIP_DIR);
    let identities = root.join(dmc_server::IDENTITIES_FILE);
    let device = dir.path().join("devices/alice");
    let acme = TenantId::new("acme").unwrap();

    // fresh installation: nobody can log in
    let run0 = start(&root, dir.path().join("s0.sock"));
    let master = run0.master.clone().expect("the first start creates the key store and issues the Master Key");
    let mut c = Client::with_client_id(ConnectionTarget::Local { socket: run0.socket.clone() }, "x");
    c.connect().unwrap();
    assert!(c.control().authenticate("root-op", &pass).is_err());
    drop(c);

    // one-time local bootstrap (the CLI calls exactly this; see dmc-cli tests)
    dmc_security::auth::bootstrap::bootstrap_operator(&ownership, &identities, "root-op", &pass, "avrora", "public").unwrap();

    // ── start #1 ─────────────────────────────────────────────────────────────
    let run1 = start(&root, dir.path().join("s1.sock"));
    assert!(run1.master.is_none(), "restarts never issue a new Master Key");
    unlock(&run1, &pass, &master);
    let invite = {
        let mut op = operator(&run1, &pass);
        op.sql().execute("CREATE TABLE notes (id BIGINT PRIMARY KEY, body TEXT)").unwrap();
        // the operator has no data access of its own and cannot grant itself any
        assert!(op.sql().query("SELECT id FROM notes").is_err());
        assert!(op.control().privilege_grant("root-op", privilege(table("notes"), A::Select)).is_err());
        op.control().identity_invite_create("alice", acme.clone(), 600_000).unwrap()
    };
    {
        let (id, _code) = ClientIdentity::generate(invite.subject, acme.clone());
        id.save(&device.join("identity.json")).unwrap();
        let sig = id.sign_enrollment(&invite.invite_id, &invite.token, "alice").unwrap();
        let mut c = Client::with_client_id(ConnectionTarget::Local { socket: run1.socket.clone() }, "alice");
        c.connect().unwrap();
        c.control().identity_enroll(&invite.invite_id, &invite.token, id.public_key(), sig).unwrap();
    }
    // network GRANT (no in-process grants anywhere in this test)
    {
        let mut op = operator(&run1, &pass);
        for p in [
            privilege(R::Database { name: "avrora".into() }, A::Connect),
            privilege(R::Schema { database: "avrora".into(), name: "public".into() }, A::Usage),
            privilege(table("notes"), A::Insert),
            privilege(table("notes"), A::Select),
        ] {
            assert!(op.control().privilege_grant("alice", p).unwrap());
        }
    }
    {
        let mut a = user(&run1, &device);
        a.sql().execute("INSERT INTO notes (id, body) VALUES (1, 'persisted')").unwrap();
        assert_eq!(a.sql().query("SELECT body FROM notes").unwrap().rows.len(), 1);
        // a user without GRANT authority cannot give itself or others anything
        assert!(a.control().privilege_grant("alice", privilege(R::System, A::Grant)).is_err());
        assert!(a.control().privilege_grant("root-op", privilege(table("notes"), A::Select)).is_err());
        assert_eq!(a.control().privilege_list("alice").unwrap().len(), 4, "own privileges visible");
        assert!(a.control().privilege_list("root-op").is_err());
    }
    // audit: every grant recorded (who → whom, what); refusals recorded as denials
    let events = run1.audit.snapshot();
    let granted: Vec<_> = events.iter().filter(|e| e.kind == AuditEventKind::PrivilegeGranted).collect();
    assert_eq!(granted.len(), 4);
    assert!(granted.iter().all(|e| e.principal_id.is_some() && e.target_id.is_some() && e.privilege.is_some()));
    assert!(granted.iter().any(|e| e.privilege.as_deref() == Some("SELECT table:avrora.public.notes")));
    let denied = events
        .iter()
        .filter(|e| e.kind == AuditEventKind::AuthorizationDenied && e.result == AuditResult::Denied && e.privilege.is_some())
        .count();
    assert!(denied >= 3, "self-grant and non-admin attempts audited ({denied})");
    assert!(format!("{events:?}").find(&pass).is_none(), "no secret in audit");

    // ── restart #2: everything from disk ─────────────────────────────────────
    let run2 = start(&root, dir.path().join("s2.sock"));
    assert!(run2.master.is_none(), "restarts never issue a new Master Key");
    unlock(&run2, &pass, &master);
    {
        let mut a = user(&run2, &device);
        let rows = a.sql().query("SELECT body FROM notes").unwrap();
        assert_eq!(rows.rows.len(), 1, "identity, key and grants survived the restart");
    }
    {
        let mut op = operator(&run2, &pass);
        assert!(op.control().privilege_revoke("alice", privilege(table("notes"), A::Select)).unwrap());
    }
    assert!(user(&run2, &device).sql().query("SELECT body FROM notes").is_err());
    assert!(run2.audit.snapshot().iter().any(|e| e.kind == AuditEventKind::PrivilegeRevoked));

    // ── restart #3: the revocation survives ──────────────────────────────────
    let run3 = start(&root, dir.path().join("s3.sock"));
    assert!(run3.master.is_none(), "restarts never issue a new Master Key");
    unlock(&run3, &pass, &master);
    {
        let mut a = user(&run3, &device);
        assert!(a.sql().query("SELECT body FROM notes").is_err());
        a.sql().execute("INSERT INTO notes (id, body) VALUES (2, 'still allowed')").unwrap();
    }

    // re-bootstrap is refused forever
    assert!(
        dmc_security::auth::bootstrap::bootstrap_operator(&ownership, &identities, "evil-op", &fresh_passphrase(), "avrora", "public")
            .is_err()
    );
    // privilege administration is not forwarded by the HTTP / control-plane adapters
    for req in [
        ControlRequest::PrivilegeGrant { session_id: "s".into(), grantee: "x".into(), privilege: privilege(R::System, A::Grant) },
        ControlRequest::PrivilegeList { session_id: "s".into(), identity: "x".into() },
    ] {
        assert!(!dmc_server::transport_policy::client_owned_session_request(&req));
        assert!(!dmc_server::transport_policy::client_owned_preauth_request(&req));
    }

    // identity directory lost after bootstrap → refuse to start empty
    std::fs::remove_file(&identities).unwrap();
    match start_core(CoreConfig::local_defaults(&root), StartupOptions::production()) {
        Err(StartupError::Identity(msg)) => assert!(msg.contains("restore"), "{msg}"),
        Err(other) => panic!("unexpected error {other}"),
        Ok(_) => panic!("started with an empty identity directory after bootstrap"),
    }
}
