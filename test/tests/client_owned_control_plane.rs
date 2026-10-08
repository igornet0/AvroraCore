//! CLIENT_OWNED over the control plane (D3): TLS control-plane listener with the
//! AvroraCore tunnel to the shared `CoreServerState`.
//!
//! The adversary is the server, which sees decrypted frames — so the confidentiality
//! capture records every *decrypted application frame* in both directions (not TLS
//! ciphertext), plus all server files, logs and audit. Secrets are derived
//! independently of the client code (`common/secrets.rs`); a plaintext negative control
//! proves the capture would show a leak.

#[path = "common/secrets.rs"]
mod secrets;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use dmc_client_crypto::{
    ClientIdentity, ClientKeyring, ClientState, parse_sql_blob_cell, sql_blob_literal,
    sql_client_object_id,
};
use dmc_core::control;
use dmc_core::control::core_tunnel::{CoreFrame, CoreFrameReply};
use dmc_core::control::sessions::ControlSessions;
use dmc_core::runtime::Runtime;
use dmc_observability::{Audit, MemoryAuditSink, MemorySink, Observability};
use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, DataResponse, ProtocolErrorCode, RemoteLimits,
    RequestEnvelope, ResponseEnvelope,
};
use dmc_security::auth::{Action, IdentityId, Resource};
use dmc_security::{AuthManager, ISSUER, UI_OPERATOR, ui_auth_path};
use dmc_server::{CoreServerState, bootstrap_core_state_locked, handle_control};
use dmc_vault::ownership::auth::Challenge;
use dmc_vault::ownership::{SubjectId, TenantId};
use secrets::{Secrets, count, dek_from, root_of, walk};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// Sealed client-side before it leaves the device: the scanner must NOT find it anywhere.
const KNOWN_PLAINTEXT_MARKER: &str = "KNOWN_PLAINTEXT_MARKER_CONTROL_PLANE_7c1e";
/// Written unprotected on purpose: the scanner MUST find it (proves the scan works).
const NEGATIVE_CONTROL_MARKER: &str = "NEGATIVE_CONTROL_MARKER_CONTROL_PLANE_3b9d";

type Frames = Arc<Mutex<Vec<u8>>>;

/// One TLS connection to the control plane (server-auth TLS, no device certificate).
struct Conn {
    tls: TlsStream<tokio::net::TcpStream>,
    frames: Frames,
}

impl Conn {
    async fn open(addr: SocketAddr, ca_pem: &[u8], frames: Frames) -> Self {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut &ca_pem[..]) {
            roots.add(cert.unwrap()).unwrap();
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let tls = TlsConnector::from(Arc::new(config))
            .connect(
                rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                tcp,
            )
            .await
            .unwrap();
        Self { tls, frames }
    }

    async fn raw(&mut self, body: &[u8]) -> Vec<u8> {
        self.frames.lock().unwrap().extend_from_slice(body);
        self.tls
            .write_all(&(body.len() as u32).to_be_bytes())
            .await
            .unwrap();
        self.tls.write_all(body).await.unwrap();
        self.tls.flush().await.unwrap();
        let mut len = [0u8; 4];
        self.tls.read_exact(&mut len).await.unwrap();
        let mut reply = vec![0u8; u32::from_be_bytes(len) as usize];
        self.tls.read_exact(&mut reply).await.unwrap();
        self.frames.lock().unwrap().extend_from_slice(&reply);
        reply
    }

    async fn frame(&mut self, frame: CoreFrame) -> CoreFrameReply {
        serde_json::from_slice(&self.raw(&serde_json::to_vec(&frame).unwrap()).await).unwrap()
    }

    async fn control(&mut self, req: ControlRequest) -> ResponseEnvelope<ControlResponse> {
        match self.frame(CoreFrame::CoreControl(req)).await {
            CoreFrameReply::CoreControlReply(r) => r,
            other => panic!("{other:?}"),
        }
    }

    async fn ok(&mut self, req: ControlRequest) -> ControlResponse {
        let r = self.control(req).await;
        assert!(r.error_code.is_none(), "{:?}", r.error_message);
        r.body.unwrap()
    }

    async fn sql(&mut self, session: &str, sql: &str) -> ResponseEnvelope<DataResponse> {
        match self
            .frame(CoreFrame::CoreData(DataRequest::ExecuteSql {
                session_id: session.into(),
                sql: sql.into(),
                params: Vec::new(),
            }))
            .await
        {
            CoreFrameReply::CoreDataReply(r) => r,
            other => panic!("{other:?}"),
        }
    }

    /// D1: Ed25519 challenge–response inside the tunnel.
    async fn login(&mut self, id: &ClientIdentity) -> String {
        let ControlResponse::ClientAuthChallenge { challenge } = self
            .ok(ControlRequest::ClientAuthBegin {
                subject: id.subject(),
                tenant: id.tenant().clone(),
            })
            .await
        else {
            panic!()
        };
        let nonce = Challenge::parse(&challenge).unwrap().nonce.to_vec();
        let signature = id.sign_challenge(&challenge).unwrap();
        match self
            .ok(ControlRequest::ClientAuthFinish { nonce, signature })
            .await
        {
            ControlResponse::ClientAuthOk { session_id, .. } => session_id,
            other => panic!("{other:?}"),
        }
    }
}

fn grant_sql(core: &Arc<Mutex<CoreServerState>>, id: &IdentityId) {
    let mut s = core.lock().unwrap();
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
    for t in ["notes", "plain_control"] {
        for a in [
            Action::Create,
            Action::Insert,
            Action::Select,
            Action::Update,
        ] {
            g.grant(id.clone(), Resource::table("avrora", "public", t), a);
        }
    }
}

/// In-process operator (server custody, password) on the shared core.
fn op(
    core: &Arc<Mutex<CoreServerState>>,
    sid: Option<&str>,
    body: ControlRequest,
) -> ResponseEnvelope<ControlResponse> {
    let _ = sid;
    handle_control(
        &mut core.lock().unwrap(),
        RequestEnvelope {
            request_id: 1,
            body,
        },
        &RemoteLimits::default(),
        "op-local",
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_owned_over_control_plane_tunnel() {
    let dir = tempfile::tempdir().unwrap();
    let control_dir = dir.path().join("control");
    control::init_control(&control_dir).unwrap();
    let ca_pem = std::fs::read(control_dir.join("tls/ca.crt")).unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let ui_auth = AuthManager::open(ui_auth_path(&dir.path().join("store.dbs.json")));
    let acme = TenantId::new("acme").unwrap();

    // shared SQL core (same state DMC IPC / HTTP would serve)
    let data_root = dir.path().join("server");
    std::fs::create_dir_all(&data_root).unwrap();
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
        .grants_mut()
        .grant(analyst.clone(), Resource::System, Action::Create);
    let core = Arc::new(Mutex::new(state));
    grant_sql(&core, &analyst);

    let (addr, serve) = control::bind_with_core(
        "127.0.0.1:0".parse().unwrap(),
        control_dir.clone(),
        rt.clone(),
        ui_auth.clone(),
        ControlSessions::new(),
        core.clone(),
    )
    .await
    .unwrap();
    tokio::spawn(serve);
    let frames: Frames = Arc::new(Mutex::new(Vec::new()));

    // ── operator (in process): unlock, schema, sealed column, invites ────────
    let op_sid = match op(
        &core,
        None,
        ControlRequest::Authenticate {
            identity_name: "analyst".into(),
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
        } => {
            let key: [u8; 32] = unlock_binding_key.as_slice().try_into().unwrap();
            let blob = dmc_server::create_unlock_blob(
                &session_id,
                &key,
                &dmc_server::MockKeyPassProvider::with_material(master),
            )
            .unwrap();
            assert!(
                op(
                    &core,
                    None,
                    ControlRequest::VaultUnlock {
                        session_id: session_id.clone(),
                        blob
                    }
                )
                .error_code
                .is_none()
            );
            session_id
        }
        other => panic!("{other:?}"),
    };
    let ddl = |sql: &str| {
        let r = dmc_server::handle_data(
            &mut core.lock().unwrap(),
            RequestEnvelope {
                request_id: 1,
                body: DataRequest::ExecuteSql {
                    session_id: op_sid.clone(),
                    sql: sql.into(),
                    params: vec![],
                },
            },
            &RemoteLimits::default(),
            "op-local",
        )
        .unwrap();
        assert!(r.error_code.is_none(), "{:?}", r.error_message);
    };
    ddl("CREATE TABLE notes (id BIGINT PRIMARY KEY, owner TEXT, body BLOB)");
    ddl("CREATE TABLE plain_control (id BIGINT PRIMARY KEY, note TEXT)");
    assert!(
        op(
            &core,
            None,
            ControlRequest::SealedColumnDeclare {
                session_id: op_sid.clone(),
                schema: "public".into(),
                table: "notes".into(),
                column: "body".into(),
                owner_column: Some("owner".into()),
            }
        )
        .error_code
        .is_none()
    );
    let invite = |name: &str| match op(
        &core,
        None,
        ControlRequest::IdentityInviteCreate {
            session_id: op_sid.clone(),
            name: name.into(),
            tenant: acme.clone(),
            ttl_ms: 600_000,
        },
    )
    .body
    .unwrap()
    {
        ControlResponse::IdentityInvite {
            invite_id,
            token,
            subject,
            ..
        } => (invite_id, token, subject),
        other => panic!("{other:?}"),
    };

    // ── users enroll + authenticate through the tunnel ───────────────────────
    let mut users = Vec::new();
    let mut tokens = Vec::new();
    for name in ["alice", "bob"] {
        let (iid, token, subject) = invite(name);
        let (id, code) = ClientIdentity::generate(subject, acme.clone());
        let device = dir.path().join("devices").join(name);
        id.save(&device.join("identity.json")).unwrap();
        let mut c = Conn::open(addr, &ca_pem, frames.clone()).await;
        let r = c
            .ok(ControlRequest::IdentityEnroll {
                invite_id: iid.clone(),
                token: token.clone(),
                key: id.public_key(),
                signature: id.sign_enrollment(&iid, &token, name).unwrap(),
            })
            .await;
        let ControlResponse::IdentityEnrolled { identity_id, .. } = r else {
            panic!()
        };
        grant_sql(&core, &IdentityId::new(identity_id));
        tokens.push(token);
        users.push((name, subject, code, device));
    }
    let load = |i: usize| ClientIdentity::load(&users[i].3.join("identity.json")).unwrap();
    let (alice_id, bob_id) = (load(0), load(1));

    let mut a = Conn::open(addr, &ca_pem, frames.clone()).await;
    let a_sid = a.login(&alice_id).await;
    let mut b = Conn::open(addr, &ca_pem, frames.clone()).await;
    let b_sid = b.login(&bob_id).await;
    let mut a_state = ClientState::open(users[0].3.join("state.json")).unwrap();
    let (a_ring, a_env) = ClientKeyring::create(load(0), &mut a_state).unwrap();
    a.ok(ControlRequest::KeyEnvelopePut {
        session_id: a_sid.clone(),
        envelope: a_env.clone(),
    })
    .await;
    let mut all_envs = vec![a_env];
    let ControlResponse::ClientKeys { keys } = a
        .ok(ControlRequest::ClientKeyGet {
            session_id: a_sid.clone(),
            subject: users[1].1,
        })
        .await
    else {
        panic!()
    };
    let bob_pk = keys[0].key.clone();
    a_state
        .pin_verified(&bob_pk, &bob_id.public_key().fingerprint_display())
        .unwrap();
    a.ok(ControlRequest::GrantCreate {
        session_id: a_sid.clone(),
        grantee: users[1].1,
        expires_at_ms: None,
    })
    .await;
    for env in a_ring.delegate_to(&bob_pk, &mut a_state).unwrap() {
        a.ok(ControlRequest::KeyEnvelopePut {
            session_id: a_sid.clone(),
            envelope: env.clone(),
        })
        .await;
        all_envs.push(env);
    }
    for id in 1..=3u64 {
        let oid = sql_client_object_id("notes", &id.to_string(), "body");
        let sealed = a_ring
            .seal(&oid, 1, format!("{KNOWN_PLAINTEXT_MARKER}-{id}").as_bytes())
            .unwrap();
        let r = a
            .sql(
                &a_sid,
                &format!(
                    "INSERT INTO notes (id, owner, body) VALUES ({id}, '{}', {})",
                    users[0].1.to_hex(),
                    sql_blob_literal(&sealed)
                ),
            )
            .await;
        assert!(r.error_code.is_none(), "{:?}", r.error_message);
    }
    assert!(
        a.sql(
            &a_sid,
            &format!(
                "INSERT INTO plain_control (id, note) VALUES (1, '{NEGATIVE_CONTROL_MARKER}')"
            )
        )
        .await
        .error_code
        .is_none()
    );
    // Bob: delegated envelopes + ciphertext through the tunnel, decrypts locally
    let ControlResponse::KeyEnvelopes { envelopes } = b
        .ok(ControlRequest::KeyEnvelopeGet {
            session_id: b_sid.clone(),
        })
        .await
    else {
        panic!()
    };
    let b_ring = ClientKeyring::load(
        load(1),
        &envelopes,
        &mut ClientState::open(users[1].3.join("state.json")).unwrap(),
    )
    .unwrap();
    let Some(DataResponse::SqlResult(rows)) = b
        .sql(&b_sid, "SELECT body FROM notes WHERE id = 2")
        .await
        .body
    else {
        panic!()
    };
    let sealed = parse_sql_blob_cell(&rows.rows[0].cells[0].value).unwrap();
    assert_eq!(
        b_ring
            .open(
                users[0].1,
                &sql_client_object_id("notes", "2", "body"),
                &sealed
            )
            .unwrap(),
        format!("{KNOWN_PLAINTEXT_MARKER}-2").into_bytes()
    );

    // ── control-plane attacks ────────────────────────────────────────────────
    let mut matrix: Vec<String> = Vec::new();
    let mut row =
        |id: &str, what: &str, got: String| matrix.push(format!("{id:<4} {what:<62} {got}"));
    // P1 operator: access key + TOTP control token, event-plane admin session and the
    //    SQL operator session are not CLIENT_OWNED sessions on this channel
    let setup = ui_auth.begin_setup("operator-access-key").await.unwrap();
    let totp = totp_rs::Builder::new()
        .with_secret(totp_rs::Secret::try_from_base32(&setup.totp_secret).unwrap())
        .with_account_name(UI_OPERATOR)
        .with_issuer(Some(ISSUER))
        .build()
        .unwrap();
    let op_token = ui_auth
        .confirm_setup("operator-access-key", &totp.generate_current().to_string())
        .await
        .unwrap();
    let admin_rt = rt.admin_session().await;
    let mut probe = Conn::open(addr, &ca_pem, frames.clone()).await;
    let mut candidates = vec![
        ("operator access-key/TOTP token", op_token.clone()),
        ("SQL operator session (other channel)", op_sid.clone()),
    ];
    if let Ok(s) = admin_rt {
        candidates.push(("event-plane admin runtime session", s.to_string()));
    }
    for (label, sid) in candidates {
        let r = probe
            .control(ControlRequest::KeyEnvelopeGet { session_id: sid })
            .await;
        assert_eq!(
            r.error_code,
            Some(ProtocolErrorCode::SessionInvalid),
            "{label}"
        );
        row(
            "P1",
            &format!("{label} used as CLIENT_OWNED session"),
            format!("{:?}", r.error_code.unwrap()),
        );
    }
    // P2 operator-only requests are not forwarded by the tunnel
    for (label, req) in [
        (
            "password Authenticate",
            ControlRequest::Authenticate {
                identity_name: "analyst".into(),
                password: "pw".into(),
            },
        ),
        (
            "IdentityInviteCreate",
            ControlRequest::IdentityInviteCreate {
                session_id: a_sid.clone(),
                name: "x".into(),
                tenant: acme.clone(),
                ttl_ms: 1000,
            },
        ),
        (
            "VaultStatus",
            ControlRequest::VaultStatus {
                session_id: a_sid.clone(),
            },
        ),
        (
            "BackupCreate",
            ControlRequest::BackupCreate {
                session_id: a_sid.clone(),
                backup_id: "x".into(),
                include_rowstore: true,
            },
        ),
    ] {
        let r = a.frame(CoreFrame::CoreControl(req)).await;
        assert!(matches!(r, CoreFrameReply::CoreRefused(_)), "{label}");
        row(
            "P2",
            &format!("{label} through the tunnel"),
            "refused".into(),
        );
    }
    // P3 D5: Alice's tunnel session on another TLS connection
    let r = probe
        .control(ControlRequest::KeyEnvelopeGet {
            session_id: a_sid.clone(),
        })
        .await;
    assert_eq!(r.error_code, Some(ProtocolErrorCode::SessionInvalid));
    row(
        "P3",
        "tunnel session id used on another TLS connection",
        format!("{:?}", r.error_code.unwrap()),
    );
    // P4 challenge from connection A answered on connection B
    let ControlResponse::ClientAuthChallenge { challenge } = a
        .ok(ControlRequest::ClientAuthBegin {
            subject: users[0].1,
            tenant: acme.clone(),
        })
        .await
    else {
        panic!()
    };
    let r = probe
        .control(ControlRequest::ClientAuthFinish {
            nonce: Challenge::parse(&challenge).unwrap().nonce.to_vec(),
            signature: alice_id.sign_challenge(&challenge).unwrap(),
        })
        .await;
    assert_eq!(r.error_code, Some(ProtocolErrorCode::AuthenticationFailed));
    row(
        "P4",
        "challenge signature relayed to another TLS connection",
        format!("{:?}", r.error_code.unwrap()),
    );
    // P5 forged envelope, plaintext injection, transaction of another session
    let forged = bob_id
        .seal_dek_to(&bob_pk, users[0].1, 9, &dmc_vault::KeyMaterial::random())
        .unwrap();
    let r = b
        .control(ControlRequest::KeyEnvelopePut {
            session_id: b_sid.clone(),
            envelope: forged,
        })
        .await;
    assert_eq!(r.error_code, Some(ProtocolErrorCode::AuthorizationDenied));
    row(
        "P5",
        "Bob uploads an envelope claiming owner = Alice",
        format!("{:?}", r.error_code.unwrap()),
    );
    let r = a
        .sql(
            &a_sid,
            &format!(
                "INSERT INTO notes (id, owner, body) VALUES (40, '{}', {})",
                users[0].1.to_hex(),
                sql_blob_literal(b"VERY_PLAIN_TUNNEL_INJECTION_____________________")
            ),
        )
        .await;
    assert_eq!(r.error_code, Some(ProtocolErrorCode::ConstraintViolation));
    row(
        "P5",
        "plaintext into a CLIENT_OWNED column through the tunnel",
        format!("{:?}", r.error_code.unwrap()),
    );
    assert!(
        a.frame(CoreFrame::CoreData(DataRequest::Begin {
            session_id: a_sid.clone()
        }))
        .await
        .is_ok_reply()
    );
    let r = b.sql(&b_sid, "SELECT id FROM notes").await;
    assert_eq!(r.error_code, Some(ProtocolErrorCode::TransactionConflict));
    row(
        "P5",
        "read while another session's transaction is open",
        format!("{:?}", r.error_code.unwrap()),
    );
    let v = sql_blob_literal(&a_ring.seal("sqlc/notes/41/body", 1, b"orphan").unwrap());
    assert!(
        a.sql(
            &a_sid,
            &format!(
                "INSERT INTO notes (id, owner, body) VALUES (41, '{}', {v})",
                users[0].1.to_hex()
            )
        )
        .await
        .error_code
        .is_none()
    );
    // P6 D5: closing Alice's TLS connection ends her session and rolls back her transaction
    drop(a);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let Some(DataResponse::SqlResult(rows)) = b
        .sql(&b_sid, "SELECT id FROM notes WHERE id = 41")
        .await
        .body
    else {
        panic!()
    };
    assert!(rows.rows.is_empty());
    let r = probe
        .control(ControlRequest::KeyEnvelopeGet {
            session_id: a_sid.clone(),
        })
        .await;
    assert_eq!(r.error_code, Some(ProtocolErrorCode::SessionInvalid));
    row(
        "P6",
        "connection closed mid-transaction",
        "session gone; transaction rolled back".into(),
    );
    // P7 regular control-plane messages still work next to the tunnel
    let reply = probe
        .raw(br#"{"type":"AuthLogin","body":{"access_key":"wrong-key-123","totp_code":"000000"}}"#)
        .await;
    assert!(String::from_utf8_lossy(&reply).contains("Error"));
    row(
        "P7",
        "regular ControlMsg on the same listener",
        "handled by the operator plane".into(),
    );

    // ── control plane without a core: tunnel refuses ─────────────────────────
    let (addr2, serve2) = control::bind(
        "127.0.0.1:0".parse().unwrap(),
        control_dir.clone(),
        rt.clone(),
        ui_auth.clone(),
        ControlSessions::new(),
    )
    .await
    .unwrap();
    tokio::spawn(serve2);
    let mut no_core = Conn::open(addr2, &ca_pem, frames.clone()).await;
    let r = no_core
        .frame(CoreFrame::CoreControl(ControlRequest::ClientAuthBegin {
            subject: SubjectId::random(),
            tenant: acme.clone(),
        }))
        .await;
    assert!(matches!(r, CoreFrameReply::CoreRefused(_)));
    row(
        "P8",
        "tunnel frame on a control plane without CLIENT_OWNED",
        "refused".into(),
    );

    // ── confidentiality ──────────────────────────────────────────────────────
    let mut secrets = Secrets::default();
    secrets.add_identity("alice", &users[0].2, 1);
    secrets.add_identity("bob", &users[1].2, 1);
    for env in &all_envs {
        let i = if env.recipient == users[0].1 { 0 } else { 1 };
        secrets.add(
            &format!("dek-{}", env.key_version),
            &dek_from(env, &root_of(&users[i].2), 1),
        );
    }
    secrets.add_text("plaintext", KNOWN_PLAINTEXT_MARKER);
    let seen = frames.lock().unwrap().clone();
    assert!(
        count(&seen, NEGATIVE_CONTROL_MARKER.as_bytes()) >= 1,
        "negative control visible to the server"
    );
    assert!(
        secrets.find_in(&seen).is_empty(),
        "frames: {:?}",
        secrets.find_in(&seen)
    );
    for f in walk(dir.path())
        .into_iter()
        .filter(|p| !p.starts_with(dir.path().join("devices")))
    {
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
    assert!(secrets.find_in(server_logs.as_bytes()).is_empty());
    println!(
        "\nCLIENT_OWNED control-plane rows ({})\n{}",
        matrix.len(),
        matrix.join("\n")
    );
}

trait OkReply {
    fn is_ok_reply(&self) -> bool;
}

impl OkReply for CoreFrameReply {
    fn is_ok_reply(&self) -> bool {
        matches!(self, CoreFrameReply::CoreDataReply(r) if r.error_code.is_none())
            || matches!(self, CoreFrameReply::CoreControlReply(r) if r.error_code.is_none())
    }
}
