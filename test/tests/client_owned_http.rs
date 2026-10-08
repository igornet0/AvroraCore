//! CLIENT_OWNED over the HTTP adapter (D3): positive flow, attacks and confidentiality.
//!
//! One `CoreServerState` is shared by the DMC IPC server (operator: vault, schema,
//! invites, backup) and the loopback HTTP adapter (CLIENT_OWNED users). All HTTP bytes
//! pass through a capturing TCP proxy. Secrets are derived independently of the client
//! code (`common/secrets.rs`) and searched in raw/hex form in the HTTP capture, every
//! server file (incl. backup and restore), logs, audit and every HTTP error body. A
//! plaintext negative control proves the capture would show a leak.

#[path = "common/secrets.rs"]
mod secrets;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use dmc_client::{Client, ConnectionTarget, MockKeyPassProvider};
use dmc_client_crypto::{
    ClientIdentity, ClientKeyring, ClientState, Error as CErr, TrustDecision, parse_sql_blob_cell,
    sql_blob_literal, sql_client_object_id,
};
use dmc_http_co::{
    AuthBeginReply, AuthFinishReply, HEADER_SEQ, HEADER_SESSION, HEADER_SIGNATURE, PATH_CONTROL,
    PATH_DATA,
};
use dmc_ipc::{CoreServer, SocketPathOptions};
use dmc_observability::{Audit, MemoryAuditSink, MemorySink, Observability};
use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, DataResponse, ProtocolErrorCode, ResponseEnvelope,
};
use dmc_security::auth::{Action, AuthService, IdentityId, Resource};
use dmc_server::{CoreServerState, bootstrap_core_state_locked};
use dmc_vault::ownership::{
    ClientKeyEnvelope, ClientPublicKey, PublicKeyStatus, SubjectId, TenantId,
};
use secrets::{Secrets, count, dek_from, root_of, walk};

const SECRET: &str = "VERY_SECRET_HTTP_PLAINTEXT";
const CONTROL: &str = "VERY_PLAIN_HTTP_NEGATIVE_CONTROL";
const OPERATOR_PASSWORD: &str = "operator-password-H7x2";

type Capture = Arc<Mutex<Vec<u8>>>;

// ── servers ───────────────────────────────────────────────────────────────────

fn spawn_dmc(state: Arc<Mutex<CoreServerState>>, socket: PathBuf) {
    thread::spawn(move || {
        let server = CoreServer::bind(
            &socket,
            &SocketPathOptions {
                allow_custom_path: true,
            },
        )
        .unwrap();
        loop {
            let _ = server.accept_and_serve_shared(&state);
        }
    });
    thread::sleep(Duration::from_millis(50));
}

fn spawn_http(state: Arc<Mutex<CoreServerState>>) -> SocketAddr {
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let listener = dmc_http_co::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            tx.send(listener.local_addr().unwrap()).unwrap();
            dmc_http_co::serve(listener, state).await.unwrap();
        });
    });
    rx.recv().unwrap()
}

fn pump<R: Read, W: Write>(mut from: R, mut to: W, cap: Capture) {
    let mut buf = [0u8; 8192];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                cap.lock().unwrap().extend_from_slice(&buf[..n]);
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
}

/// Transparent TCP proxy in front of the HTTP adapter, recording both directions.
fn spawn_tcp_capture(upstream: SocketAddr, cap: Capture) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(client) = conn else { break };
            let server = TcpStream::connect(upstream).unwrap();
            let (c1, c2) = (cap.clone(), cap.clone());
            let (cr, sr) = (client.try_clone().unwrap(), server.try_clone().unwrap());
            thread::spawn(move || {
                pump(&client, &server, c1);
                let _ = server.shutdown(std::net::Shutdown::Write);
            });
            thread::spawn(move || {
                pump(&sr, &cr, c2);
                let _ = cr.shutdown(std::net::Shutdown::Both);
            });
        }
    });
    addr
}

fn spawn_unix_capture(listen: PathBuf, upstream: PathBuf, cap: Capture) {
    let listener = UnixListener::bind(&listen).unwrap();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(client) = conn else { break };
            let server = UnixStream::connect(&upstream).unwrap();
            let (c1, c2) = (cap.clone(), cap.clone());
            let (cr, sr) = (client.try_clone().unwrap(), server.try_clone().unwrap());
            thread::spawn(move || {
                pump(&client, &server, c1);
                let _ = server.shutdown(std::net::Shutdown::Both);
            });
            thread::spawn(move || {
                pump(&sr, &cr, c2);
                let _ = cr.shutdown(std::net::Shutdown::Both);
            });
        }
    });
}

// ── minimal HTTP/1.1 client ───────────────────────────────────────────────────

struct HttpReply {
    status: u16,
    head: String,
    body: Vec<u8>,
}

fn http_post(addr: SocketAddr, path: &str, headers: &[(&str, String)], body: &[u8]) -> HttpReply {
    let mut s = TcpStream::connect(addr).unwrap();
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nOrigin: http://evil.example\r\n",
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    HttpReply {
        status,
        head,
        body: raw[split + 4..].to_vec(),
    }
}

/// A CLIENT_OWNED HTTP session: every request signed by the device's Ed25519 key.
struct HttpSession {
    addr: SocketAddr,
    identity: ClientIdentity,
    session: String,
    seq: u64,
    bodies: Arc<Mutex<Vec<u8>>>,
}

impl HttpSession {
    fn login(addr: SocketAddr, identity: ClientIdentity, bodies: Arc<Mutex<Vec<u8>>>) -> Self {
        let begin = serde_json::to_vec(&serde_json::json!({
            "subject": identity.subject(),
            "tenant": identity.tenant(),
        }))
        .unwrap();
        let r = http_post(addr, "/v1/auth/begin", &[], &begin);
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let b: AuthBeginReply = serde_json::from_slice(&r.body).unwrap();
        let challenge = hex::decode(&b.challenge_hex).unwrap();
        let sig = identity.sign_challenge(&challenge).unwrap();
        let nonce = dmc_vault::ownership::auth::Challenge::parse(&challenge)
            .unwrap()
            .nonce;
        let finish = serde_json::to_vec(&serde_json::json!({
            "channel_id": b.channel_id,
            "nonce_hex": hex::encode(nonce),
            "signature_hex": hex::encode(sig),
        }))
        .unwrap();
        let r = http_post(addr, "/v1/auth/finish", &[], &finish);
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let f: AuthFinishReply = serde_json::from_slice(&r.body).unwrap();
        Self {
            addr,
            identity,
            session: f.session_id,
            seq: 0,
            bodies,
        }
    }

    fn signed_raw(&mut self, path: &str, body: &[u8]) -> HttpReply {
        self.seq += 1;
        let sig = self
            .identity
            .sign_http_request(&self.session, self.seq, "POST", path, body)
            .unwrap();
        let r = http_post(
            self.addr,
            path,
            &[
                (HEADER_SESSION, self.session.clone()),
                (HEADER_SEQ, self.seq.to_string()),
                (HEADER_SIGNATURE, hex::encode(sig)),
            ],
            body,
        );
        self.bodies.lock().unwrap().extend_from_slice(&r.body);
        r
    }

    fn control(&mut self, req: ControlRequest) -> ResponseEnvelope<ControlResponse> {
        let r = self.signed_raw(PATH_CONTROL, &serde_json::to_vec(&req).unwrap());
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        serde_json::from_slice(&r.body).unwrap()
    }

    fn ok(&mut self, req: ControlRequest) -> ControlResponse {
        let r = self.control(req);
        assert!(r.error_code.is_none(), "{:?}", r.error_message);
        r.body.unwrap()
    }

    fn sql(&mut self, sql: &str) -> ResponseEnvelope<DataResponse> {
        let req = DataRequest::ExecuteSql {
            session_id: self.session.clone(),
            sql: sql.into(),
            params: Vec::new(),
        };
        let r = self.signed_raw(PATH_DATA, &serde_json::to_vec(&req).unwrap());
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        serde_json::from_slice(&r.body).unwrap()
    }

    fn rows(&mut self, sql: &str) -> Vec<String> {
        match self.sql(sql).body {
            Some(DataResponse::SqlResult(r)) => r
                .rows
                .into_iter()
                .map(|row| row.cells[0].value.clone())
                .collect(),
            other => panic!("{other:?}"),
        }
    }
}

fn grant_sql(auth: &mut AuthService, id: &IdentityId) {
    auth.grants_mut()
        .grant(id.clone(), Resource::database("avrora"), Action::Connect);
    auth.grants_mut()
        .grant(id.clone(), Resource::database("avrora"), Action::Create);
    auth.grants_mut().grant(
        id.clone(),
        Resource::schema("avrora", "public"),
        Action::Usage,
    );
    auth.grants_mut().grant(
        id.clone(),
        Resource::schema("avrora", "public"),
        Action::Create,
    );
    for t in ["notes", "plain_control"] {
        for a in [
            Action::Create,
            Action::Insert,
            Action::Select,
            Action::Update,
        ] {
            auth.grants_mut()
                .grant(id.clone(), Resource::table("avrora", "public", t), a);
        }
    }
}

fn active_key(s: &mut HttpSession, subject: SubjectId) -> ClientPublicKey {
    match s.ok(ControlRequest::ClientKeyGet {
        session_id: s.session.clone(),
        subject,
    }) {
        ControlResponse::ClientKeys { keys } => {
            keys.into_iter()
                .find(|k| k.status == PublicKeyStatus::Active)
                .unwrap()
                .key
        }
        other => panic!("{other:?}"),
    }
}

fn envelopes(s: &mut HttpSession) -> Vec<ClientKeyEnvelope> {
    match s.ok(ControlRequest::KeyEnvelopeGet {
        session_id: s.session.clone(),
    }) {
        ControlResponse::KeyEnvelopes { envelopes } => envelopes,
        other => panic!("{other:?}"),
    }
}

struct Dev {
    name: &'static str,
    dir: PathBuf,
    code: dmc_client_crypto::RecoveryCode,
    subject: SubjectId,
}

impl Dev {
    fn identity(&self) -> ClientIdentity {
        ClientIdentity::load(&self.dir.join("identity.json")).unwrap()
    }
    fn state(&self) -> ClientState {
        ClientState::open(self.dir.join("state.json")).unwrap()
    }
}

fn operator(sock: &Path) -> Client {
    let mut c = Client::with_client_id(
        ConnectionTarget::Local {
            socket: sock.to_path_buf(),
        },
        "operator",
    );
    c.connect().unwrap();
    c.control()
        .authenticate("analyst", OPERATOR_PASSWORD)
        .unwrap();
    c
}

#[test]
fn client_owned_over_http_adapter() {
    let dir = tempfile::tempdir().unwrap();
    let data_root = dir.path().join("server");
    std::fs::create_dir_all(&data_root).unwrap();
    let acme = TenantId::new("acme").unwrap();

    // non-loopback bind is refused (no TLS in the adapter)
    let rt = tokio::runtime::Runtime::new().unwrap();
    assert!(
        rt.block_on(dmc_http_co::bind("0.0.0.0:0".parse().unwrap()))
            .is_err()
    );

    let (mut state, master) = bootstrap_core_state_locked(&data_root, false);
    let logs = MemorySink::new();
    let audit = MemoryAuditSink::new();
    state.set_observability(Observability::memory(logs.clone()));
    state.set_audit(Audit::memory(audit.clone()));
    let analyst = state
        .auth
        .identities()
        .get_by_name("analyst")
        .unwrap()
        .id
        .clone();
    state
        .auth_mut()
        .configure_credential("analyst", OPERATOR_PASSWORD);
    state
        .auth_mut()
        .grants_mut()
        .grant(analyst.clone(), Resource::System, Action::Create);
    grant_sql(state.auth_mut(), &analyst);
    let core = Arc::new(Mutex::new(state));
    let socket = data_root.join("dmc.sock");
    spawn_dmc(core.clone(), socket.clone());
    let http_cap: Capture = Arc::new(Mutex::new(Vec::new()));
    let dmc_cap: Capture = Arc::new(Mutex::new(Vec::new()));
    let http = spawn_tcp_capture(spawn_http(core.clone()), http_cap.clone());
    let op_sock = dir.path().join("op.sock");
    spawn_unix_capture(op_sock.clone(), socket.clone(), dmc_cap.clone());
    let bodies: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let mut secrets = Secrets::default();
    let mut tokens: Vec<Vec<u8>> = Vec::new();

    // ── operator (DMC IPC): vault, schema, sealed column, invites ────────────
    let invites: Vec<_> = {
        let mut op = operator(&op_sock);
        op.control()
            .vault_unlock(&MockKeyPassProvider::with_material(master.clone()))
            .unwrap();
        op.sql()
            .execute("CREATE TABLE notes (id BIGINT PRIMARY KEY, owner TEXT, body BLOB)")
            .unwrap();
        op.sql()
            .execute("CREATE TABLE plain_control (id BIGINT PRIMARY KEY, note TEXT)")
            .unwrap();
        op.control()
            .sealed_column_declare("public", "notes", "body", Some("owner"))
            .unwrap();
        ["alice", "bob"]
            .into_iter()
            .map(|n| {
                (
                    n,
                    op.control()
                        .identity_invite_create(n, acme.clone(), 600_000)
                        .unwrap(),
                )
            })
            .collect()
    };

    // ── enrollment over HTTP (proof of possession; no session) ───────────────
    let mut devs = Vec::new();
    for (name, inv) in invites {
        let d = Dev {
            name,
            dir: dir.path().join("devices").join(name),
            code: {
                let (id, code) = ClientIdentity::generate(inv.subject, inv.tenant.clone());
                id.save(&dir.path().join("devices").join(name).join("identity.json"))
                    .unwrap();
                code
            },
            subject: inv.subject,
        };
        let id = d.identity();
        let req = ControlRequest::IdentityEnroll {
            invite_id: inv.invite_id.clone(),
            token: inv.token.clone(),
            key: id.public_key(),
            signature: id
                .sign_enrollment(&inv.invite_id, &inv.token, name)
                .unwrap(),
        };
        let r = http_post(http, "/v1/enroll", &[], &serde_json::to_vec(&req).unwrap());
        let env: ResponseEnvelope<ControlResponse> = serde_json::from_slice(&r.body).unwrap();
        let Some(ControlResponse::IdentityEnrolled { identity_id, .. }) = env.body else {
            panic!("{:?}", env.error_message)
        };
        // second use of the invite over HTTP is refused
        let again: ResponseEnvelope<ControlResponse> = serde_json::from_slice(
            &http_post(http, "/v1/enroll", &[], &serde_json::to_vec(&req).unwrap()).body,
        )
        .unwrap();
        assert_eq!(
            again.error_code,
            Some(ProtocolErrorCode::AuthenticationFailed)
        );
        grant_sql(
            core.lock().unwrap().auth_mut(),
            &IdentityId::new(identity_id),
        );
        tokens.push(inv.token);
        devs.push(d);
    }
    let (alice_d, bob_d) = (&devs[0], &devs[1]);

    // ── positive flow over HTTP ──────────────────────────────────────────────
    let mut alice = HttpSession::login(http, alice_d.identity(), bodies.clone());
    let mut bob = HttpSession::login(http, bob_d.identity(), bodies.clone());
    let mut a_state = alice_d.state();
    let (a_ring, a_env) = ClientKeyring::create(alice_d.identity(), &mut a_state).unwrap();
    alice.ok(ControlRequest::KeyEnvelopePut {
        session_id: alice.session.clone(),
        envelope: a_env.clone(),
    });
    let (_b_ring, b_env) = ClientKeyring::create(bob_d.identity(), &mut bob_d.state()).unwrap();
    bob.ok(ControlRequest::KeyEnvelopePut {
        session_id: bob.session.clone(),
        envelope: b_env.clone(),
    });
    let mut all_envs = vec![a_env, b_env];
    // TOFU + out-of-band fingerprint, grant, delegation
    let bob_pk = active_key(&mut alice, bob_d.subject);
    assert_eq!(
        a_state.check_or_pin(&bob_pk).unwrap(),
        TrustDecision::PinnedOnFirstUse
    );
    a_state
        .pin_verified(
            &bob_pk,
            &bob_d.identity().public_key().fingerprint_display(),
        )
        .unwrap();
    alice.ok(ControlRequest::GrantCreate {
        session_id: alice.session.clone(),
        grantee: bob_d.subject,
        expires_at_ms: None,
    });
    for env in a_ring.delegate_to(&bob_pk, &mut a_state).unwrap() {
        alice.ok(ControlRequest::KeyEnvelopePut {
            session_id: alice.session.clone(),
            envelope: env.clone(),
        });
        all_envs.push(env);
    }
    // sealed SQL writes (ciphertext only) + negative control
    for id in 1..=4u64 {
        let oid = sql_client_object_id("notes", &id.to_string(), "body");
        let sealed = a_ring
            .seal(&oid, 1, format!("{SECRET}-{id}").as_bytes())
            .unwrap();
        let r = alice.sql(&format!(
            "INSERT INTO notes (id, owner, body) VALUES ({id}, '{}', {})",
            alice_d.subject.to_hex(),
            sql_blob_literal(&sealed)
        ));
        assert!(r.error_code.is_none(), "{:?}", r.error_message);
    }
    assert!(
        alice
            .sql(&format!(
                "INSERT INTO plain_control (id, note) VALUES (1, '{CONTROL}')"
            ))
            .error_code
            .is_none()
    );
    // Bob reads + decrypts locally
    let b_envs = envelopes(&mut bob);
    let b_ring = ClientKeyring::load(bob_d.identity(), &b_envs, &mut bob_d.state()).unwrap();
    let cell = bob.rows("SELECT body FROM notes WHERE id = 2").remove(0);
    let oid2 = sql_client_object_id("notes", "2", "body");
    assert_eq!(
        b_ring
            .open(alice_d.subject, &oid2, &parse_sql_blob_cell(&cell).unwrap())
            .unwrap(),
        format!("{SECRET}-2").into_bytes()
    );

    // ── HTTP attacks ─────────────────────────────────────────────────────────
    let mut matrix: Vec<String> = Vec::new();
    let mut row =
        |id: &str, what: &str, got: String| matrix.push(format!("{id:<4} {what:<58} {got}"));
    let get_env = serde_json::to_vec(&ControlRequest::KeyEnvelopeGet {
        session_id: alice.session.clone(),
    })
    .unwrap();
    // H1 no signature headers (bearer use of a session id)
    let r = http_post(
        http,
        PATH_CONTROL,
        &[(HEADER_SESSION, alice.session.clone())],
        &get_env,
    );
    assert_eq!(r.status, 401);
    row(
        "H1",
        "session id without request signature",
        r.status.to_string(),
    );
    // H2 invalid signature
    let r = http_post(
        http,
        PATH_CONTROL,
        &[
            (HEADER_SESSION, alice.session.clone()),
            (HEADER_SEQ, "999".into()),
            (HEADER_SIGNATURE, hex::encode([1u8; 64])),
        ],
        &get_env,
    );
    assert_eq!(r.status, 401);
    row("H2", "forged request signature", r.status.to_string());
    // H3 replay of a signed request; H4 lower sequence number
    alice.seq += 1;
    let sig = alice
        .identity
        .sign_http_request(&alice.session, alice.seq, "POST", PATH_CONTROL, &get_env)
        .unwrap();
    let hdr = [
        (HEADER_SESSION, alice.session.clone()),
        (HEADER_SEQ, alice.seq.to_string()),
        (HEADER_SIGNATURE, hex::encode(&sig)),
    ];
    assert_eq!(http_post(http, PATH_CONTROL, &hdr, &get_env).status, 200);
    let r = http_post(http, PATH_CONTROL, &hdr, &get_env);
    assert_eq!(r.status, 401);
    row("H3", "replay of a signed request", r.status.to_string());
    let low = alice.seq - 1;
    let sig = alice
        .identity
        .sign_http_request(&alice.session, low, "POST", PATH_CONTROL, &get_env)
        .unwrap();
    let r = http_post(
        http,
        PATH_CONTROL,
        &[
            (HEADER_SESSION, alice.session.clone()),
            (HEADER_SEQ, low.to_string()),
            (HEADER_SIGNATURE, hex::encode(sig)),
        ],
        &get_env,
    );
    assert_eq!(r.status, 401);
    row(
        "H4",
        "out-of-order (lower) sequence number",
        r.status.to_string(),
    );
    // H5 tampered body (signature over another body)
    alice.seq += 1;
    let sig = alice
        .identity
        .sign_http_request(&alice.session, alice.seq, "POST", PATH_CONTROL, &get_env)
        .unwrap();
    let other = serde_json::to_vec(&ControlRequest::GrantRevoke {
        session_id: alice.session.clone(),
        grantee: bob_d.subject,
    })
    .unwrap();
    let r = http_post(
        http,
        PATH_CONTROL,
        &[
            (HEADER_SESSION, alice.session.clone()),
            (HEADER_SEQ, alice.seq.to_string()),
            (HEADER_SIGNATURE, hex::encode(sig)),
        ],
        &other,
    );
    assert_eq!(r.status, 401);
    row(
        "H5",
        "body swapped under a valid signature",
        r.status.to_string(),
    );
    // H6 Bob signs with his key but uses Alice's session id
    bob.seq += 1;
    let sig = bob
        .identity
        .sign_http_request(&alice.session, bob.seq, "POST", PATH_CONTROL, &get_env)
        .unwrap();
    let r = http_post(
        http,
        PATH_CONTROL,
        &[
            (HEADER_SESSION, alice.session.clone()),
            (HEADER_SEQ, (alice.seq + 10).to_string()),
            (HEADER_SIGNATURE, hex::encode(sig)),
        ],
        &get_env,
    );
    assert_eq!(r.status, 401);
    row(
        "H6",
        "Alice's session driven with Bob's key",
        r.status.to_string(),
    );
    // H7 HTTP session id presented on DMC IPC (another channel)
    let r = dmc_server::handle_control(
        &mut core.lock().unwrap(),
        dmc_protocol::RequestEnvelope {
            request_id: 1,
            body: ControlRequest::KeyEnvelopeGet {
                session_id: alice.session.clone(),
            },
        },
        &dmc_protocol::RemoteLimits::default(),
        "dmc-conn-x",
    )
    .unwrap();
    assert_eq!(r.error_code, Some(ProtocolErrorCode::SessionInvalid));
    row(
        "H7",
        "HTTP session id used on DMC IPC",
        format!("{:?}", r.error_code.unwrap()),
    );
    // H8 requests not available over HTTP (password login, vault, backup)
    for (label, req) in [
        (
            "password Authenticate",
            ControlRequest::Authenticate {
                identity_name: "analyst".into(),
                password: OPERATOR_PASSWORD.into(),
            },
        ),
        (
            "VaultStatus",
            ControlRequest::VaultStatus {
                session_id: alice.session.clone(),
            },
        ),
        (
            "BackupCreate",
            ControlRequest::BackupCreate {
                session_id: alice.session.clone(),
                backup_id: "x".into(),
                include_rowstore: true,
            },
        ),
    ] {
        let r = alice.signed_raw(PATH_CONTROL, &serde_json::to_vec(&req).unwrap());
        assert_eq!(r.status, 403, "{label}");
        row("H8", &format!("{label} over HTTP"), r.status.to_string());
    }
    // H9 wrong key at login (challenge signed by a different identity with the same subject)
    let (impostor, _) = ClientIdentity::generate(alice_d.subject, acme.clone());
    let begin =
        serde_json::to_vec(&serde_json::json!({"subject": alice_d.subject, "tenant": acme}))
            .unwrap();
    let b: AuthBeginReply =
        serde_json::from_slice(&http_post(http, "/v1/auth/begin", &[], &begin).body).unwrap();
    let ch = hex::decode(&b.challenge_hex).unwrap();
    let nonce = dmc_vault::ownership::auth::Challenge::parse(&ch)
        .unwrap()
        .nonce;
    let fin = serde_json::json!({"channel_id": b.channel_id, "nonce_hex": hex::encode(nonce), "signature_hex": hex::encode(impostor.sign_challenge(&ch).unwrap())});
    let r = http_post(
        http,
        "/v1/auth/finish",
        &[],
        &serde_json::to_vec(&fin).unwrap(),
    );
    assert_eq!(r.status, 401);
    row(
        "H9",
        "login with a non-registered key",
        r.status.to_string(),
    );
    // H10 forged envelope / grant, unauthorized write, plaintext injection (over HTTP)
    let forged = bob
        .identity
        .seal_dek_to(
            &bob_pk,
            alice_d.subject,
            9,
            &dmc_vault::KeyMaterial::random(),
        )
        .unwrap();
    let r = bob.control(ControlRequest::KeyEnvelopePut {
        session_id: bob.session.clone(),
        envelope: forged,
    });
    assert_eq!(r.error_code, Some(ProtocolErrorCode::AuthorizationDenied));
    row(
        "H10",
        "Bob uploads an envelope claiming owner = Alice",
        format!("{:?}", r.error_code.unwrap()),
    );
    // revocation is scoped to the caller as owner: Bob cannot touch Alice's grant to him,
    // and "revoking himself" is refused (it would have deleted his own DEK envelopes — F9)
    let r = bob.control(ControlRequest::GrantRevoke {
        session_id: bob.session.clone(),
        grantee: bob_d.subject,
    });
    assert_eq!(r.error_code, Some(ProtocolErrorCode::InvalidRequest));
    let still = match alice.ok(ControlRequest::GrantList {
        session_id: alice.session.clone(),
    }) {
        ControlResponse::Grants { grants } => grants.iter().any(|g| g.grantee == bob_d.subject),
        other => panic!("{other:?}"),
    };
    assert!(still, "Alice's grant to Bob untouched");
    assert!(
        envelopes(&mut bob).iter().any(|e| e.owner == bob_d.subject),
        "Bob's own envelope survives"
    );
    row(
        "H10",
        "Bob revokes grants as if he were Alice / revokes himself",
        "InvalidRequest; nothing deleted".into(),
    );
    let r = alice.sql(&format!(
        "INSERT INTO notes (id, owner, body) VALUES (50, '{}', {})",
        alice_d.subject.to_hex(),
        sql_blob_literal(b"VERY_PLAIN_HTTP_INJECTION________________________")
    ));
    assert_eq!(r.error_code, Some(ProtocolErrorCode::ConstraintViolation));
    row(
        "H11",
        "plaintext into a CLIENT_OWNED column over HTTP",
        format!("{:?}", r.error_code.unwrap()),
    );
    let r = bob.sql(&format!(
        "UPDATE notes SET owner = '{}' WHERE id = 1",
        bob_d.subject.to_hex()
    ));
    assert!(r.error_code.is_some());
    row(
        "H11",
        "Bob re-assigns Alice's sealed row to himself",
        format!("{:?}", r.error_code.unwrap()),
    );
    // H12 no CORS headers even with an Origin header
    let r = alice.signed_raw(PATH_CONTROL, &get_env_for(&alice.session));
    assert!(
        !r.head
            .to_ascii_lowercase()
            .contains("access-control-allow-origin")
    );
    row(
        "H12",
        "cross-origin request (Origin: evil.example)",
        "no CORS headers".into(),
    );

    // ── rotation over HTTP; TOFU KeyChanged / KeyRollback; retired key ──────
    let mut a_ring2 = ClientKeyring::load(
        alice_d.identity(),
        &envelopes(&mut alice),
        &mut alice_d.state(),
    )
    .unwrap();
    let alice_v1 = a_ring2.public_key();
    let (alice_v2, proof, resealed) = a_ring2.rotate_identity_key().unwrap();
    alice.ok(ControlRequest::ClientKeyRotate {
        session_id: alice.session.clone(),
        key: alice_v2.clone(),
        proof,
    });
    a_ring2
        .identity()
        .save(&alice_d.dir.join("identity.json"))
        .unwrap();
    // from now on this session is driven by the v2 key; keep the v1 key as "stolen"
    let alice_v1_key = std::mem::replace(&mut alice.identity, alice_d.identity());
    for env in resealed {
        alice.ok(ControlRequest::KeyEnvelopePut {
            session_id: alice.session.clone(),
            envelope: env.clone(),
        });
        all_envs.push(env);
    }
    let mut b_state = bob_d.state();
    b_state.check_or_pin(&alice_v1).unwrap();
    let fetched = active_key(&mut bob, alice_d.subject);
    assert!(matches!(
        b_state.check_or_pin(&fetched),
        Err(CErr::KeyChanged { .. })
    ));
    row(
        "H13",
        "key changed after rotation (fetched over HTTP)",
        "client: KeyChanged".into(),
    );
    b_state
        .pin_verified(&fetched, &alice_v2.fingerprint_display())
        .unwrap();
    assert!(matches!(
        b_state.check_or_pin(&alice_v1),
        Err(CErr::KeyRollback { .. })
    ));
    row(
        "H13",
        "server offers the old key again",
        "client: KeyRollback".into(),
    );
    // a request signed with the rotated-out v1 key is refused, the v2 key works
    alice.seq += 1;
    let body = get_env_for(&alice.session);
    let sig = alice_v1_key
        .sign_http_request(&alice.session, alice.seq, "POST", PATH_CONTROL, &body)
        .unwrap();
    let r = http_post(
        http,
        PATH_CONTROL,
        &[
            (HEADER_SESSION, alice.session.clone()),
            (HEADER_SEQ, alice.seq.to_string()),
            (HEADER_SIGNATURE, hex::encode(sig)),
        ],
        &body,
    );
    assert_eq!(r.status, 401);
    row(
        "H14",
        "HTTP request signed with a rotated-out key",
        r.status.to_string(),
    );
    assert!(!envelopes(&mut alice).is_empty());
    let mut fresh = HttpSession::login(http, alice_d.identity(), bodies.clone());
    assert!(!envelopes(&mut fresh).is_empty(), "v2 login over HTTP");
    // H15 disabled identity: the next signed request fails
    let bob_identity_id = core
        .lock()
        .unwrap()
        .auth
        .identities()
        .get_by_subject(bob_d.subject)
        .unwrap()
        .id
        .clone();
    core.lock()
        .unwrap()
        .auth_mut()
        .disable_identity(&bob_identity_id)
        .unwrap();
    let r = bob.signed_raw(PATH_CONTROL, &get_env_for(&bob.session));
    assert_eq!(r.status, 401);
    row(
        "H15",
        "disabled identity keeps using its HTTP session",
        r.status.to_string(),
    );

    // ── backup (operator, DMC) ───────────────────────────────────────────────
    operator(&op_sock)
        .control()
        .backup_create("hb1", true)
        .unwrap();

    // ── confidentiality ──────────────────────────────────────────────────────
    secrets.add_identity("alice", &alice_d.code, 2);
    secrets.add_identity("bob", &bob_d.code, 1);
    for env in &all_envs {
        let d = if env.recipient == alice_d.subject {
            alice_d
        } else {
            bob_d
        };
        let root = root_of(&d.code);
        let kv = (1..=2)
            .find(|v| {
                ClientIdentity::from_recovery_at_version(d.subject, acme.clone(), &d.code, *v)
                    .unwrap()
                    .public_key()
                    .fingerprint()
                    == env.recipient_key_fingerprint
            })
            .unwrap();
        secrets.add(
            &format!("dek-{}-v{}", d.name, env.key_version),
            &dek_from(env, &root, kv),
        );
    }
    secrets.add_text("plaintext", SECRET);
    let wire = http_cap.lock().unwrap().clone();
    assert!(
        count(&wire, CONTROL.as_bytes()) >= 1,
        "negative control must be visible on HTTP"
    );
    assert!(
        secrets.find_in(&wire).is_empty(),
        "HTTP wire: {:?}",
        secrets.find_in(&wire)
    );
    let dmc_wire = dmc_cap.lock().unwrap().clone();
    assert!(
        secrets.find_in(&dmc_wire).is_empty(),
        "DMC wire: {:?}",
        secrets.find_in(&dmc_wire)
    );
    let error_bodies = bodies.lock().unwrap().clone();
    assert!(
        secrets.find_in(&error_bodies).is_empty(),
        "HTTP response bodies"
    );
    for f in walk(&data_root) {
        let bytes = std::fs::read(&f).unwrap_or_default();
        assert!(
            secrets.find_in(&bytes).is_empty(),
            "server file {}: {:?}",
            f.display(),
            secrets.find_in(&bytes)
        );
        for t in &tokens {
            assert_eq!(
                count(&bytes, hex::encode(t).as_bytes()),
                0,
                "invite token in {}",
                f.display()
            );
        }
    }
    let server_logs = format!("{:?} {:?}", logs.snapshot(), audit.snapshot());
    assert!(
        secrets.find_in(server_logs.as_bytes()).is_empty(),
        "server logs"
    );
    // restore on a new host: still ciphertext only
    let restored = dir.path().join("new-host/restore");
    // D4-F: the backup is sealed with the installation's storage keys as well (the
    // operator's Master Key yields them; CLIENT_OWNED values stay ciphertext regardless)
    let storage_keys = Arc::new(core.lock().unwrap().unlock_gate.storage_cipher().unwrap());
    dmc_backup::restore_backup(&data_root.join("backups/backup-hb1"), &restored).unwrap();
    dmc_backup::recover_with(&restored, Some(storage_keys)).unwrap();
    for f in walk(&restored) {
        let bytes = std::fs::read(&f).unwrap_or_default();
        assert!(
            secrets.find_in(&bytes).is_empty(),
            "restored file {}",
            f.display()
        );
    }
    println!(
        "\nCLIENT_OWNED HTTP attack rows ({})\n{}",
        matrix.len(),
        matrix.join("\n")
    );
}

fn get_env_for(session: &str) -> Vec<u8> {
    serde_json::to_vec(&ControlRequest::KeyEnvelopeGet {
        session_id: session.into(),
    })
    .unwrap()
}
