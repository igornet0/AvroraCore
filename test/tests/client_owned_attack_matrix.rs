//! CLIENT_OWNED attack matrix (key-management API + sealed SQL columns).
//!
//! Every row is an attack attempted through the server's request dispatcher
//! (`handle_control` / `handle_data` — the same code the DMC IPC transport runs; the
//! transport itself is covered by `client_owned_key_api.rs`). Each row asserts the exact
//! refusal and, where relevant, that server state did not change. Rows marked
//! "client-side" are attacks by a malicious *server*; they are detected by
//! `dmc-client-crypto`, not by the server.

use dmc_client::MockKeyPassProvider;
use dmc_client_crypto::{
    ClientIdentity, ClientKeyring, ClientState, Error as CErr, sql_blob_literal,
};
use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, ProtocolErrorCode, RemoteLimits, RequestEnvelope,
    ResponseEnvelope,
};
use dmc_security::auth::{Action, AuthService, IdentityId, Resource, SessionManager};
use dmc_server::{
    CoreServerState, bootstrap_core_state_locked, create_unlock_blob, handle_control, handle_data,
};
use dmc_vault::KeyMaterial;
use dmc_vault::ownership::auth::{Challenge, KeyRotationProof};
use dmc_vault::ownership::{
    ClientKeyEnvelope, ClientPublicKey, RecordContext, SubjectId, TenantId, seal_record,
};

const CONN: &str = "attack-matrix";

fn bad_proof() -> KeyRotationProof {
    KeyRotationProof {
        old_signature: None,
        new_signature: vec![0; 64],
    }
}

struct Srv {
    state: CoreServerState,
    next: u64,
}

impl Srv {
    fn ctl(&mut self, body: ControlRequest) -> ResponseEnvelope<ControlResponse> {
        self.next += 1;
        handle_control(
            &mut self.state,
            RequestEnvelope {
                request_id: self.next,
                body,
            },
            &RemoteLimits::default(),
            CONN,
        )
        .unwrap()
    }

    fn sql(&mut self, session_id: &str, sql: &str) -> Option<ProtocolErrorCode> {
        self.sql_full(session_id, sql).error_code
    }

    fn sql_on(
        &mut self,
        connection: &str,
        session_id: &str,
        sql: &str,
    ) -> Option<ProtocolErrorCode> {
        self.next += 1;
        handle_data(
            &mut self.state,
            RequestEnvelope {
                request_id: self.next,
                body: DataRequest::ExecuteSql {
                    session_id: session_id.into(),
                    sql: sql.into(),
                    params: Vec::new(),
                },
            },
            &RemoteLimits::default(),
            connection,
        )
        .unwrap()
        .error_code
    }

    fn row_count(&mut self, session_id: &str, sql: &str) -> usize {
        match self.sql_full(session_id, sql).body {
            Some(dmc_protocol::DataResponse::SqlResult(r)) => r.rows.len(),
            other => panic!("{other:?}"),
        }
    }

    fn sql_full(
        &mut self,
        session_id: &str,
        sql: &str,
    ) -> ResponseEnvelope<dmc_protocol::DataResponse> {
        self.next += 1;
        handle_data(
            &mut self.state,
            RequestEnvelope {
                request_id: self.next,
                body: DataRequest::ExecuteSql {
                    session_id: session_id.into(),
                    sql: sql.into(),
                    params: Vec::new(),
                },
            },
            &RemoteLimits::default(),
            CONN,
        )
        .unwrap()
    }

    fn login(&mut self, name: &str, password: &str) -> (String, [u8; 32]) {
        match self
            .ctl(ControlRequest::Authenticate {
                identity_name: name.into(),
                password: password.into(),
            })
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

    /// Request on another transport connection (D5 channel tests).
    fn ctl_on(
        &mut self,
        connection: &str,
        body: ControlRequest,
    ) -> ResponseEnvelope<ControlResponse> {
        self.next += 1;
        handle_control(
            &mut self.state,
            RequestEnvelope {
                request_id: self.next,
                body,
            },
            &RemoteLimits::default(),
            connection,
        )
        .unwrap()
    }

    fn challenge(&mut self, connection: &str, subject: SubjectId, tenant: &TenantId) -> Vec<u8> {
        match self
            .ctl_on(
                connection,
                ControlRequest::ClientAuthBegin {
                    subject,
                    tenant: tenant.clone(),
                },
            )
            .body
            .unwrap()
        {
            ControlResponse::ClientAuthChallenge { challenge } => challenge,
            other => panic!("{other:?}"),
        }
    }

    fn finish(
        &mut self,
        connection: &str,
        challenge: &[u8],
        signature: Vec<u8>,
    ) -> ResponseEnvelope<ControlResponse> {
        let nonce = Challenge::parse(challenge).unwrap().nonce.to_vec();
        self.ctl_on(
            connection,
            ControlRequest::ClientAuthFinish { nonce, signature },
        )
    }

    /// Ed25519 challenge–response login on this test's connection.
    fn client_login(&mut self, identity: &ClientIdentity) -> String {
        let c = self.challenge(CONN, identity.subject(), identity.tenant());
        let sig = identity.sign_challenge(&c).unwrap();
        match self.finish(CONN, &c, sig).body.unwrap() {
            ControlResponse::ClientAuthOk { session_id, .. } => session_id,
            other => panic!("{other:?}"),
        }
    }

    fn ok(&mut self, body: ControlRequest) -> ControlResponse {
        let resp = self.ctl(body);
        assert!(resp.error_code.is_none(), "{:?}", resp.error_message);
        resp.body.unwrap()
    }

    fn denied(&mut self, body: ControlRequest) -> ProtocolErrorCode {
        let resp = self.ctl(body);
        resp.error_code.expect("attack must be refused")
    }

    fn directory_bytes(&self) -> Vec<u8> {
        std::fs::read(
            self.state
                .data_root
                .join("ownership/client/client-directory.json"),
        )
        .unwrap_or_default()
    }
}

struct U {
    sid: String,
    subject: SubjectId,
    identity: ClientIdentity,
    device: std::path::PathBuf,
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
    for a in [
        Action::Create,
        Action::Insert,
        Action::Select,
        Action::Update,
    ] {
        auth.grants_mut()
            .grant(id.clone(), Resource::table("avrora", "public", "notes"), a);
    }
}

fn register(srv: &mut Srv, u: &U) -> ClientKeyEnvelope {
    let mut st = ClientState::open(u.state_path()).unwrap();
    let (ring, env) = ClientKeyring::create(u.identity_clone(), &mut st).unwrap();
    srv.ok(ControlRequest::ClientKeyRegister {
        session_id: u.sid.clone(),
        key: ring.public_key(),
    });
    srv.ok(ControlRequest::KeyEnvelopePut {
        session_id: u.sid.clone(),
        envelope: env.clone(),
    });
    env
}

impl U {
    fn state_path(&self) -> std::path::PathBuf {
        self.device.join("state.json")
    }

    /// Fresh instance of the device identity (as after an app restart).
    fn identity_clone(&self) -> ClientIdentity {
        ClientIdentity::load(&self.device.join("identity.json")).unwrap()
    }

    fn pk(&self) -> ClientPublicKey {
        self.identity.public_key()
    }
}

#[test]
fn client_owned_attack_matrix() {
    let dir = tempfile::tempdir().unwrap();
    let (state, master) = bootstrap_core_state_locked(dir.path(), false);
    let mut srv = Srv { state, next: 0 };
    let acme = TenantId::new("acme").unwrap();
    let evil = TenantId::new("evil").unwrap();
    // operator: server-custody identity with full SQL rights + Master + invites
    let analyst = srv
        .state
        .auth
        .identities()
        .get_by_name("analyst")
        .unwrap()
        .id
        .clone();
    grant_sql(srv.state.auth_mut(), &analyst);
    srv.state
        .auth_mut()
        .grants_mut()
        .grant(analyst.clone(), Resource::System, Action::Create);
    let (op_sid, op_bind) = srv.login("analyst", "pw");
    let blob = create_unlock_blob(
        &op_sid,
        &op_bind,
        &MockKeyPassProvider::with_material(master),
    )
    .unwrap();
    srv.ok(ControlRequest::VaultUnlock {
        session_id: op_sid.clone(),
        blob,
    });
    // CLIENT_OWNED users: operator invite → device-generated keys → PoP enrollment → Ed25519 login
    let mk = |srv: &mut Srv, name: &str, tenant: &TenantId| {
        let ControlResponse::IdentityInvite {
            invite_id,
            token,
            subject,
            ..
        } = srv.ok(ControlRequest::IdentityInviteCreate {
            session_id: op_sid.clone(),
            name: name.into(),
            tenant: tenant.clone(),
            ttl_ms: 600_000,
        })
        else {
            panic!("invite")
        };
        let (identity, _code) = ClientIdentity::generate(subject, tenant.clone());
        let device = dir.path().join("devices").join(name);
        identity.save(&device.join("identity.json")).unwrap();
        let signature = identity.sign_enrollment(&invite_id, &token, name).unwrap();
        let ControlResponse::IdentityEnrolled { identity_id, .. } =
            srv.ok(ControlRequest::IdentityEnroll {
                invite_id,
                token,
                key: identity.public_key(),
                signature,
            })
        else {
            panic!("enroll")
        };
        grant_sql(srv.state.auth_mut(), &IdentityId::new(identity_id));
        let sid = srv.client_login(&identity);
        U {
            sid,
            subject,
            identity,
            device,
        }
    };
    let alice = mk(&mut srv, "alice", &acme);
    let bob = mk(&mut srv, "bob", &acme);
    let mallory = mk(&mut srv, "mallory", &evil);
    let dave = mk(&mut srv, "dave", &acme); // disabled later (A5)
    // carol: a CLIENT_OWNED identity that never enrolled a key (cannot be produced over
    // the network any more — enrollment registers the key atomically). Created in-process
    // with a session bound to this test's channel, only to exercise registry rules.
    let carol = {
        let subject = SubjectId::random();
        let id = srv
            .state
            .auth_mut()
            .create_client_identity("carol", acme.clone(), subject)
            .unwrap();
        srv.state.auth_mut().begin_request(CONN);
        let sid = srv
            .state
            .auth_mut()
            .create_session(id)
            .unwrap()
            .id
            .as_str()
            .to_string();
        srv.state.auth_mut().end_request();
        let (identity, _) = ClientIdentity::generate(subject, acme.clone());
        let device = dir.path().join("devices").join("carol");
        identity.save(&device.join("identity.json")).unwrap();
        U {
            sid,
            subject,
            identity,
            device,
        }
    };

    let mut rows: Vec<String> = Vec::new();
    let mut row = |id: &str, attack: &str, outcome: String| {
        rows.push(format!("{id:<4} {attack:<62} {outcome}"))
    };

    let alice_env = register(&mut srv, &alice);
    register(&mut srv, &bob);
    register(&mut srv, &mallory);
    let dek = KeyMaterial::random();

    // ── A: sessions / identities ──────────────────────────────────────────────
    let code = srv.denied(ControlRequest::KeyEnvelopeGet {
        session_id: "forged-session".into(),
    });
    assert_eq!(code, ProtocolErrorCode::SessionInvalid);
    row(
        "A1",
        "forged session id fetches envelopes",
        format!("{code:?}"),
    );

    let stale = srv.client_login(&alice.identity);
    srv.ok(ControlRequest::Logout {
        session_id: stale.clone(),
    });
    let code = srv.denied(ControlRequest::KeyEnvelopeGet { session_id: stale });
    assert_eq!(code, ProtocolErrorCode::SessionInvalid);
    row(
        "A2",
        "logged-out session fetches envelopes",
        format!("{code:?}"),
    );

    let code = srv.denied(ControlRequest::KeyEnvelopeGet {
        session_id: op_sid.clone(),
    });
    assert_eq!(code, ProtocolErrorCode::AuthorizationDenied);
    row(
        "A3",
        "operator (server custody + Master) fetches envelopes",
        format!("{code:?}"),
    );
    let code = srv.denied(ControlRequest::ClientKeyRegister {
        session_id: op_sid.clone(),
        key: alice.pk(),
    });
    assert_eq!(code, ProtocolErrorCode::AuthorizationDenied);
    row("A4", "operator registers a public key", format!("{code:?}"));

    // ── B: public-key registry ────────────────────────────────────────────────
    let before = srv.directory_bytes();
    let (fake_alice, _) = ClientIdentity::generate(alice.subject, acme.clone());
    let code = srv.denied(ControlRequest::ClientKeyRegister {
        session_id: bob.sid.clone(),
        key: fake_alice.public_key(),
    });
    assert_eq!(code, ProtocolErrorCode::AuthorizationDenied);
    row(
        "B1",
        "Bob registers a key under Alice's subject",
        format!("{code:?}"),
    );
    let code = srv.denied(ControlRequest::ClientKeyRegister {
        session_id: alice.sid.clone(),
        key: fake_alice.public_key(),
    });
    assert_eq!(code, ProtocolErrorCode::InvalidRequest);
    row(
        "B2",
        "silent key replacement via re-register",
        format!("{code:?}"),
    );
    let (carol_tmp, _) = ClientIdentity::generate(carol.subject, acme.clone());
    let mut v2_first = carol_tmp.public_key();
    v2_first.key_version = 2;
    let code = srv.denied(ControlRequest::ClientKeyRegister {
        session_id: carol.sid.clone(),
        key: v2_first,
    });
    assert_eq!(code, ProtocolErrorCode::InvalidRequest);
    row(
        "B3",
        "first registration claims key version 2",
        format!("{code:?}"),
    );
    let mut skip = fake_alice.public_key();
    skip.key_version = 3;
    let code = srv.denied(ControlRequest::ClientKeyRotate {
        session_id: alice.sid.clone(),
        key: skip,
        proof: bad_proof(),
    });
    assert_eq!(code, ProtocolErrorCode::InvalidRequest);
    row(
        "B4",
        "rotation skips a version (1 → 3)",
        format!("{code:?}"),
    );
    let mut same = alice.pk();
    same.key_version = 2;
    let code = srv.denied(ControlRequest::ClientKeyRotate {
        session_id: alice.sid.clone(),
        key: same,
        proof: bad_proof(),
    });
    assert_eq!(code, ProtocolErrorCode::InvalidRequest);
    row(
        "B5",
        "rotation re-uses the same key material",
        format!("{code:?}"),
    );
    let mut bobs_rotation = fake_alice.public_key();
    bobs_rotation.key_version = 2;
    let code = srv.denied(ControlRequest::ClientKeyRotate {
        session_id: bob.sid.clone(),
        key: bobs_rotation,
        proof: bad_proof(),
    });
    assert_eq!(code, ProtocolErrorCode::AuthorizationDenied);
    row("B6", "Bob rotates Alice's key", format!("{code:?}"));
    let code = srv.denied(ControlRequest::ClientKeyGet {
        session_id: mallory.sid.clone(),
        subject: alice.subject,
    });
    assert_eq!(code, ProtocolErrorCode::AuthorizationDenied);
    row("B7", "cross-tenant public key lookup", format!("{code:?}"));
    assert_eq!(
        srv.directory_bytes(),
        before,
        "refused key operations changed nothing"
    );

    // ── C: envelopes and grants ───────────────────────────────────────────────
    let forged = bob
        .identity
        .seal_dek_to(&alice.pk(), alice.subject, 7, &dek)
        .unwrap();
    let code = srv.denied(ControlRequest::KeyEnvelopePut {
        session_id: bob.sid.clone(),
        envelope: forged,
    });
    assert_eq!(code, ProtocolErrorCode::AuthorizationDenied);
    row(
        "C1",
        "Bob plants an envelope claiming owner = Alice",
        format!("{code:?}"),
    );
    let to_bob = alice
        .identity
        .seal_dek_to(&bob.pk(), alice.subject, 1, &dek)
        .unwrap();
    let code = srv.denied(ControlRequest::KeyEnvelopePut {
        session_id: alice.sid.clone(),
        envelope: to_bob.clone(),
    });
    assert_eq!(code, ProtocolErrorCode::AuthorizationDenied);
    row(
        "C2",
        "delegated envelope without a grant",
        format!("{code:?}"),
    );
    srv.ok(ControlRequest::GrantCreate {
        session_id: alice.sid.clone(),
        grantee: bob.subject,
        expires_at_ms: None,
    });
    let (bob_impostor, _) = ClientIdentity::generate(bob.subject, acme.clone());
    let to_impostor = alice
        .identity
        .seal_dek_to(&bob_impostor.public_key(), alice.subject, 1, &dek)
        .unwrap();
    let code = srv.denied(ControlRequest::KeyEnvelopePut {
        session_id: alice.sid.clone(),
        envelope: to_impostor,
    });
    assert_eq!(code, ProtocolErrorCode::AuthorizationDenied);
    row(
        "C3",
        "envelope sealed to a key that is not Bob's registered key",
        format!("{code:?}"),
    );
    srv.ok(ControlRequest::KeyEnvelopePut {
        session_id: alice.sid.clone(),
        envelope: to_bob.clone(),
    });
    let code = srv.denied(ControlRequest::KeyEnvelopePut {
        session_id: alice.sid.clone(),
        envelope: to_bob.clone(),
    });
    assert_eq!(code, ProtocolErrorCode::InvalidRequest);
    row(
        "C4",
        "replay / overwrite of a stored envelope version",
        format!("{code:?}"),
    );
    for (grantee, label) in [
        (alice.subject, "self"),
        (carol.subject, "subject without key"),
        (mallory.subject, "other tenant"),
    ] {
        let code = srv.denied(ControlRequest::GrantCreate {
            session_id: alice.sid.clone(),
            grantee,
            expires_at_ms: None,
        });
        assert_eq!(code, ProtocolErrorCode::AuthorizationDenied);
        row("C5", &format!("grant to {label}"), format!("{code:?}"));
    }
    let mallory_view = match srv.ok(ControlRequest::KeyEnvelopeGet {
        session_id: mallory.sid.clone(),
    }) {
        ControlResponse::KeyEnvelopes { envelopes } => envelopes,
        other => panic!("{other:?}"),
    };
    assert!(mallory_view.iter().all(|e| e.recipient == mallory.subject));
    row(
        "C6",
        "Mallory lists envelopes (only her own returned)",
        "FILTERED".into(),
    );
    // expired grant: envelope stays on the server but is no longer served
    srv.ok(ControlRequest::GrantCreate {
        session_id: alice.sid.clone(),
        grantee: bob.subject,
        expires_at_ms: Some(1),
    });
    let bob_view = |srv: &mut Srv| match srv.ok(ControlRequest::KeyEnvelopeGet {
        session_id: bob.sid.clone(),
    }) {
        ControlResponse::KeyEnvelopes { envelopes } => envelopes
            .into_iter()
            .filter(|e| e.owner == alice.subject)
            .count(),
        other => panic!("{other:?}"),
    };
    assert_eq!(bob_view(&mut srv), 0);
    row(
        "C7",
        "grantee fetches after grant expiry",
        "NOT SERVED".into(),
    );
    let to_bob_v2 = alice
        .identity
        .seal_dek_to(&bob.pk(), alice.subject, 2, &dek)
        .unwrap();
    let code = srv.denied(ControlRequest::KeyEnvelopePut {
        session_id: alice.sid.clone(),
        envelope: to_bob_v2,
    });
    assert_eq!(code, ProtocolErrorCode::AuthorizationDenied);
    row(
        "C8",
        "delegated upload under an expired grant",
        format!("{code:?}"),
    );
    let revoked = match srv.ok(ControlRequest::GrantRevoke {
        session_id: alice.sid.clone(),
        grantee: bob.subject,
    }) {
        ControlResponse::GrantAck { changed } => changed,
        other => panic!("{other:?}"),
    };
    assert!(revoked);
    let again = srv.ok(ControlRequest::GrantRevoke {
        session_id: alice.sid.clone(),
        grantee: bob.subject,
    });
    assert!(matches!(
        again,
        ControlResponse::GrantAck { changed: false }
    ));
    let code = srv.denied(ControlRequest::GrantRevoke {
        session_id: op_sid.clone(),
        grantee: bob.subject,
    });
    assert_eq!(code, ProtocolErrorCode::AuthorizationDenied);
    row(
        "C9",
        "operator revokes / manages grants",
        format!("{code:?}"),
    );

    // ── D: malicious server (detected client-side) ────────────────────────────
    let mut ast = ClientState::open(dir.path().join("alice-d.json")).unwrap();
    for (label, tamper) in [
        ("flipped HPKE ciphertext byte", 0usize),
        ("changed key_version (binding)", 1),
        ("swapped owner (binding)", 2),
    ] {
        let mut env = alice_env.clone();
        match tamper {
            0 => env.ciphertext[0] ^= 1,
            1 => env.key_version = 9,
            _ => env.owner = bob.subject,
        }
        let mut envs = vec![env];
        if tamper == 2 {
            envs.push(alice_env.clone());
        }
        let err = ClientKeyring::load(alice.identity_clone(), &envs, &mut ast).unwrap_err();
        assert!(
            matches!(err, CErr::Hpke | CErr::NotForThisKey | CErr::Ownership(_)),
            "{err:?}"
        );
        row(
            "D1",
            &format!("server serves envelope with {label}"),
            format!("client: {err:?}").chars().take(40).collect(),
        );
    }
    let mut bst = ClientState::open(dir.path().join("bob-d.json")).unwrap();
    bst.check_or_pin(&alice.pk()).unwrap();
    let err = bst.check_or_pin(&fake_alice.public_key()).unwrap_err();
    assert!(matches!(err, CErr::KeyChanged { .. }));
    row(
        "D2",
        "server substitutes Alice's public key after first contact",
        "client: KeyChanged".into(),
    );

    // ── E: sealed SQL column (plaintext-injection defence) ────────────────────
    assert!(
        srv.sql(
            &alice.sid,
            "CREATE TABLE notes (id BIGINT PRIMARY KEY, owner TEXT, body BLOB, tag TEXT)"
        )
        .is_none()
    );
    let code = srv.denied(ControlRequest::SealedColumnDeclare {
        session_id: alice.sid.clone(),
        schema: "public".into(),
        table: "notes".into(),
        column: "tag".into(),
        owner_column: Some("owner".into()),
    });
    assert_eq!(code, ProtocolErrorCode::ConstraintViolation);
    row(
        "E1",
        "declare CLIENT_OWNED on a non-BLOB column",
        format!("{code:?}"),
    );
    let code = srv.denied(ControlRequest::SealedColumnDeclare {
        session_id: alice.sid.clone(),
        schema: "public".into(),
        table: "notes".into(),
        column: "id".into(),
        owner_column: None,
    });
    assert_eq!(code, ProtocolErrorCode::ConstraintViolation);
    row(
        "E2",
        "declare CLIENT_OWNED on the primary key",
        format!("{code:?}"),
    );
    srv.ok(ControlRequest::SealedColumnDeclare {
        session_id: alice.sid.clone(),
        schema: "public".into(),
        table: "notes".into(),
        column: "body".into(),
        owner_column: Some("owner".into()),
    });
    let mut ring_state = ClientState::open(dir.path().join("alice-e.json")).unwrap();
    let ring = ClientKeyring::load(
        alice.identity_clone(),
        std::slice::from_ref(&alice_env),
        &mut ring_state,
    )
    .unwrap();
    let a = alice.subject.to_hex();
    let ok_val = sql_blob_literal(&ring.seal("sqlc/notes/1/body", 1, b"fine").unwrap());
    assert!(
        srv.sql(
            &alice.sid,
            &format!("INSERT INTO notes (id, owner, body, tag) VALUES (1, '{a}', {ok_val}, 't')")
        )
        .is_none()
    );
    assert!(
        srv.sql(
            &alice.sid,
            &format!("INSERT INTO notes (id, owner, body, tag) VALUES (2, '{a}', NULL, 't')")
        )
        .is_none()
    );

    let server_v1 = seal_record(
        &KeyMaterial::random(),
        1,
        &RecordContext {
            tenant: acme.clone(),
            owner: alice.subject,
            object_id: "sqlc/notes/3/body".into(),
            record_version: 1,
        },
        b"server-domain record",
    )
    .unwrap();
    let mut truncated = ring.seal("sqlc/notes/3/body", 1, b"x").unwrap();
    truncated.truncate(20);
    let attacks: Vec<(&str, String, String)> = vec![
        (
            "plaintext BLOB",
            a.clone(),
            sql_blob_literal(b"VERY_PLAIN_TEXT_IN_A_SEALED_COLUMN_______________"),
        ),
        (
            "sealed value whose header names another owner",
            bob.subject.to_hex(),
            ok_val.clone(),
        ),
        (
            "SERVER-domain (v1) sealed record",
            a.clone(),
            sql_blob_literal(&server_v1),
        ),
        (
            "truncated sealed record",
            a.clone(),
            sql_blob_literal(&truncated),
        ),
        (
            "TEXT literal instead of BLOB",
            a.clone(),
            "'plain text'".into(),
        ),
    ];
    for (i, (label, owner, value)) in attacks.into_iter().enumerate() {
        let id = 10 + i;
        let code = srv.sql(
            &alice.sid,
            &format!(
                "INSERT INTO notes (id, owner, body, tag) VALUES ({id}, '{owner}', {value}, 't')"
            ),
        );
        assert!(code.is_some(), "{label} accepted");
        row(
            "E3",
            &format!("INSERT {label}"),
            format!("{:?}", code.unwrap()),
        );
    }
    let code = srv.sql(
        &alice.sid,
        &format!(
            "UPDATE notes SET body = {} WHERE id = 1",
            sql_blob_literal(b"VERY_PLAIN_UPDATE_____________________________")
        ),
    );
    assert!(code.is_some());
    row(
        "E4",
        "UPDATE sealed column to plaintext",
        format!("{:?}", code.unwrap()),
    );
    let code = srv.sql(
        &op_sid,
        &format!(
            "UPDATE notes SET owner = '{}' WHERE id = 1",
            bob.subject.to_hex()
        ),
    );
    assert!(code.is_some());
    row(
        "E5",
        "operator re-assigns owner column of a sealed row",
        format!("{:?}", code.unwrap()),
    );
    // inside an explicit transaction the guard runs at COMMIT
    assert!(srv.sql(&alice.sid, "BEGIN").is_none());
    let at_insert = srv.sql(
        &alice.sid,
        &format!(
            "INSERT INTO notes (id, owner, body, tag) VALUES (30, '{a}', {}, 't')",
            sql_blob_literal(b"VERY_PLAIN_IN_TXN_______________________________")
        ),
    );
    let at_commit = srv.sql(&alice.sid, "COMMIT");
    if srv.state.ctx.in_transaction() {
        let _ = srv.sql(&alice.sid, "ROLLBACK");
    }
    let refused = match (at_insert, at_commit) {
        (Some(c), _) => format!("{c:?} at INSERT"),
        (None, Some(c)) => format!("{c:?} at COMMIT"),
        (None, None) => panic!("plaintext committed inside a transaction"),
    };
    row("E7", "plaintext INSERT inside BEGIN … COMMIT", refused);

    // after all refusals the table is intact and still writable
    assert!(
        srv.sql(&alice.sid, "UPDATE notes SET tag = 'u' WHERE id = 1")
            .is_none()
    );
    assert_eq!(
        srv.row_count(&alice.sid, "SELECT id FROM notes WHERE id = 30"),
        0,
        "refused txn left no row"
    );
    assert_eq!(
        srv.row_count(&alice.sid, "SELECT id FROM notes WHERE id = 1"),
        1
    );

    // E6 — documented limitation, asserted as such: the guard checks format/domain/owner
    // only (the server holds no key, so it cannot verify the AEAD tag), and it does not
    // bind the owner column to the writing session. Another user can therefore store a
    // row *attributed* to Alice with a well-formed header and garbage body. It reveals
    // nothing and Alice detects it: her AEAD open fails.
    let genuine = ring.seal("sqlc/notes/40/body", 1, b"genuine").unwrap();
    let mut forged = genuine[..dmc_vault::ownership::record::HEADER_LEN_V2].to_vec();
    forged.extend_from_slice(&[0x41; 48]);
    let code = srv.sql(
        &bob.sid,
        &format!(
            "INSERT INTO notes (id, owner, body, tag) VALUES (40, '{a}', {}, 'spoof')",
            sql_blob_literal(&forged)
        ),
    );
    assert!(
        code.is_none(),
        "format-valid spoof is accepted by the server (limitation)"
    );
    assert!(
        ring.open(alice.subject, "sqlc/notes/40/body", &forged)
            .is_err()
    );
    row(
        "E6",
        "Bob stores well-formed fake attributed to Alice",
        "ACCEPTED; Alice's AEAD open fails".into(),
    );

    // ── F: authentication, enrollment, session binding (D1, D2, D5) ───────────
    let fail = |r: &ResponseEnvelope<ControlResponse>| r.error_code;
    // F1: a CLIENT_OWNED identity never authenticates with a password (even if one is set)
    srv.state
        .auth_mut()
        .configure_credential("bob", "bob-password-123456");
    let r = srv.ctl(ControlRequest::Authenticate {
        identity_name: "bob".into(),
        password: "bob-password-123456".into(),
    });
    assert_eq!(fail(&r), Some(ProtocolErrorCode::AuthenticationFailed));
    row(
        "F1",
        "password login as a CLIENT_OWNED identity",
        format!("{:?}", fail(&r).unwrap()),
    );
    // F2: operator / attacker signs Alice's challenge with a key that is not hers
    let c = srv.challenge(CONN, alice.subject, &acme);
    let sig = fake_alice.sign_challenge(&c).unwrap();
    let r = srv.finish(CONN, &c, sig);
    assert_eq!(fail(&r), Some(ProtocolErrorCode::AuthenticationFailed));
    row(
        "F2",
        "session for Alice via a signature by a non-registered key",
        format!("{:?}", fail(&r).unwrap()),
    );
    // F3: replay of an accepted (nonce, signature)
    let c = srv.challenge(CONN, alice.subject, &acme);
    let sig = alice.identity.sign_challenge(&c).unwrap();
    assert!(fail(&srv.finish(CONN, &c, sig.clone())).is_none());
    let r = srv.finish(CONN, &c, sig);
    assert_eq!(fail(&r), Some(ProtocolErrorCode::AuthenticationFailed));
    row(
        "F3",
        "replay of an accepted challenge signature",
        format!("{:?}", fail(&r).unwrap()),
    );
    // F4: expired challenge
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    srv.state.auth_mut().set_clock_ms(Some(now));
    let c = srv.challenge(CONN, alice.subject, &acme);
    let sig = alice.identity.sign_challenge(&c).unwrap();
    srv.state.auth_mut().set_clock_ms(Some(now + 31_000));
    let r = srv.finish(CONN, &c, sig);
    srv.state.auth_mut().set_clock_ms(None);
    assert_eq!(fail(&r), Some(ProtocolErrorCode::AuthenticationFailed));
    row(
        "F4",
        "challenge answered after expiry",
        format!("{:?}", fail(&r).unwrap()),
    );
    // F5: challenge from connection A answered on connection B (transport/channel binding)
    let c = srv.challenge("conn-A", alice.subject, &acme);
    let sig = alice.identity.sign_challenge(&c).unwrap();
    let r = srv.finish("conn-B", &c, sig);
    assert_eq!(fail(&r), Some(ProtocolErrorCode::AuthenticationFailed));
    row(
        "F5",
        "challenge signature relayed to another connection",
        format!("{:?}", fail(&r).unwrap()),
    );
    // F6: unknown subject — a challenge of the same shape, which can never succeed
    let real = srv.challenge(CONN, alice.subject, &acme);
    let ghost = srv.challenge(CONN, SubjectId::random(), &acme);
    assert_eq!(real.len(), ghost.len(), "no enumeration oracle");
    let r = srv.finish(CONN, &ghost, vec![7; 64]);
    assert_eq!(fail(&r), Some(ProtocolErrorCode::AuthenticationFailed));
    row(
        "F6",
        "authenticate as an unknown subject",
        format!("{:?} (same-shape challenge)", fail(&r).unwrap()),
    );
    // F7 (D5): Alice's session used from another connection
    let r = srv.ctl_on(
        "other-connection",
        ControlRequest::KeyEnvelopeGet {
            session_id: alice.sid.clone(),
        },
    );
    assert_eq!(fail(&r), Some(ProtocolErrorCode::SessionInvalid));
    row(
        "F7",
        "session id stolen and used on another connection",
        format!("{:?}", fail(&r).unwrap()),
    );
    let r = srv.sql_on("other-connection", &alice.sid, "SELECT id FROM notes");
    assert_eq!(r, Some(ProtocolErrorCode::SessionInvalid));
    row(
        "F7",
        "stolen session id runs SQL on another connection",
        format!("{:?}", r.unwrap()),
    );
    // F8 (D5): connection closed → its sessions are gone (no rebind)
    let c = srv.challenge("conn-close", alice.subject, &acme);
    let sig = alice.identity.sign_challenge(&c).unwrap();
    let ControlResponse::ClientAuthOk {
        session_id: closed, ..
    } = srv.finish("conn-close", &c, sig).body.unwrap()
    else {
        panic!()
    };
    srv.state.auth_mut().close_channel("conn-close");
    let r = srv.ctl_on(
        "conn-close",
        ControlRequest::KeyEnvelopeGet { session_id: closed },
    );
    assert_eq!(fail(&r), Some(ProtocolErrorCode::SessionInvalid));
    row(
        "F8",
        "session reused after its connection closed",
        format!("{:?}", fail(&r).unwrap()),
    );
    // F9: enrollment attacks
    let invite = |srv: &mut Srv, name: &str, ttl_ms: u64| match srv.ok(
        ControlRequest::IdentityInviteCreate {
            session_id: op_sid.clone(),
            name: name.into(),
            tenant: acme.clone(),
            ttl_ms,
        },
    ) {
        ControlResponse::IdentityInvite {
            invite_id,
            token,
            subject,
            ..
        } => (invite_id, token, subject),
        other => panic!("{other:?}"),
    };
    let enroll =
        |srv: &mut Srv, id: &str, token: &[u8], key: ClientPublicKey, signature: Vec<u8>| {
            srv.ctl(ControlRequest::IdentityEnroll {
                invite_id: id.into(),
                token: token.to_vec(),
                key,
                signature,
            })
            .error_code
        };
    let code = srv.denied(ControlRequest::IdentityInviteCreate {
        session_id: bob.sid.clone(),
        name: "x".into(),
        tenant: acme.clone(),
        ttl_ms: 60_000,
    });
    assert_eq!(code, ProtocolErrorCode::AuthorizationDenied);
    row(
        "F9",
        "CLIENT_OWNED user (no CREATE on system) issues an invite",
        format!("{code:?}"),
    );
    let (iid, tok, subj) = invite(&mut srv, "eve", 600_000);
    let (eve, _) = ClientIdentity::generate(subj, acme.clone());
    let mut wrong_tok = tok.clone();
    wrong_tok[0] ^= 1;
    let sig = eve.sign_enrollment(&iid, &tok, "eve").unwrap();
    assert_eq!(
        enroll(&mut srv, &iid, &wrong_tok, eve.public_key(), sig.clone()),
        Some(ProtocolErrorCode::AuthenticationFailed)
    );
    row(
        "F9",
        "enroll with a wrong invite token",
        "AuthenticationFailed".into(),
    );
    let (other_subject, _) = ClientIdentity::generate(SubjectId::random(), acme.clone());
    let other_sig = other_subject.sign_enrollment(&iid, &tok, "eve").unwrap();
    assert!(enroll(&mut srv, &iid, &tok, other_subject.public_key(), other_sig).is_some());
    row(
        "F9",
        "invite claimed for a different subject than assigned",
        "AuthenticationFailed".into(),
    );
    let (eve_twin, _) = ClientIdentity::generate(subj, acme.clone());
    let twin_sig = eve_twin.sign_enrollment(&iid, &tok, "eve").unwrap();
    assert!(enroll(&mut srv, &iid, &tok, eve.public_key(), twin_sig).is_some());
    row(
        "F9",
        "proof of possession by a key not in the bundle",
        "AuthenticationFailed".into(),
    );
    assert!(enroll(&mut srv, &iid, &tok, eve.public_key(), sig.clone()).is_none());
    assert!(enroll(&mut srv, &iid, &tok, eve.public_key(), sig).is_some());
    row(
        "F9",
        "invite reused after a successful enrollment",
        "AuthenticationFailed".into(),
    );
    let (iid2, tok2, subj2) = invite(&mut srv, "frank", 1);
    std::thread::sleep(std::time::Duration::from_millis(5));
    let (frank, _) = ClientIdentity::generate(subj2, acme.clone());
    let fsig = frank.sign_enrollment(&iid2, &tok2, "frank").unwrap();
    assert!(enroll(&mut srv, &iid2, &tok2, frank.public_key(), fsig).is_some());
    row("F9", "expired invite", "AuthenticationFailed".into());
    let (iid3, tok3, subj3) = invite(&mut srv, "gina", 600_000);
    let (gina, _) = ClientIdentity::generate(subj3, acme.clone());
    for _ in 0..5 {
        assert!(enroll(&mut srv, &iid3, &tok3, gina.public_key(), vec![0; 64]).is_some());
    }
    let gsig = gina.sign_enrollment(&iid3, &tok3, "gina").unwrap();
    assert!(enroll(&mut srv, &iid3, &tok3, gina.public_key(), gsig).is_some());
    row(
        "F9",
        "invite after 5 bad proofs (burned), then a valid proof",
        "AuthenticationFailed".into(),
    );
    // F10: rotation without proof of possession / continuity; stolen retired key
    let mut bob_dev = ClientIdentity::load(&bob.device.join("identity.json")).unwrap();
    let (bob_v2, good) = bob_dev.rotate_keys().unwrap();
    let mut forged = good.clone();
    forged.new_signature[0] ^= 1;
    let code = srv.denied(ControlRequest::ClientKeyRotate {
        session_id: bob.sid.clone(),
        key: bob_v2.clone(),
        proof: forged,
    });
    assert_eq!(code, ProtocolErrorCode::AuthorizationDenied);
    row(
        "F10",
        "rotation without possession of the new auth key",
        format!("{code:?}"),
    );
    let no_continuity = KeyRotationProof {
        old_signature: None,
        ..good.clone()
    };
    let code = srv.denied(ControlRequest::ClientKeyRotate {
        session_id: bob.sid.clone(),
        key: bob_v2.clone(),
        proof: no_continuity,
    });
    assert_eq!(code, ProtocolErrorCode::AuthorizationDenied);
    row(
        "F10",
        "rotation not signed by the current auth key",
        format!("{code:?}"),
    );
    srv.ok(ControlRequest::ClientKeyRotate {
        session_id: bob.sid.clone(),
        key: bob_v2,
        proof: good,
    });
    // attacker holding Bob's *retired* v1 auth key signs a fresh challenge
    let root: [u8; 32] = {
        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(bob.device.join("identity.json")).unwrap())
                .unwrap();
        hex::decode(raw["root_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, &root);
    let mut seed = [0u8; 32];
    hk.expand(b"avrora/client-owned/ed25519/v1/kv1", &mut seed)
        .unwrap();
    let retired = ed25519_dalek::SigningKey::from_bytes(&seed);
    let c = srv.challenge(CONN, bob.subject, &acme);
    use ed25519_dalek::Signer;
    let r = srv.finish(CONN, &c, retired.sign(&c).to_bytes().to_vec());
    assert_eq!(fail(&r), Some(ProtocolErrorCode::AuthenticationFailed));
    row(
        "F10",
        "login with a stolen RETIRED auth key",
        format!("{:?}", fail(&r).unwrap()),
    );
    // the new key works
    let c = srv.challenge(CONN, bob.subject, &acme);
    assert!(fail(&srv.finish(CONN, &c, bob_dev.sign_challenge(&c).unwrap())).is_none());

    // C10 — regression F9: "revoke myself" must not delete the caller's own DEK envelopes
    let code = srv.denied(ControlRequest::GrantRevoke {
        session_id: alice.sid.clone(),
        grantee: alice.subject,
    });
    assert_eq!(code, ProtocolErrorCode::InvalidRequest);
    let own_left = match srv.ok(ControlRequest::KeyEnvelopeGet {
        session_id: alice.sid.clone(),
    }) {
        ControlResponse::KeyEnvelopes { envelopes } => envelopes
            .iter()
            .filter(|e| e.owner == alice.subject && e.recipient == alice.subject)
            .count(),
        other => panic!("{other:?}"),
    };
    assert!(own_left >= 1);
    row(
        "C10",
        "owner revokes a grant to itself (own envelopes)",
        format!("{code:?}; own envelopes kept"),
    );

    // ── G: SQL transaction abuse (regression F8: transactions had no owner) ───
    assert!(srv.sql(&alice.sid, "BEGIN").is_none());
    let a_hex = alice.subject.to_hex();
    let txn_val = sql_blob_literal(&ring.seal("sqlc/notes/60/body", 1, b"in-flight").unwrap());
    assert!(
        srv.sql(
            &alice.sid,
            &format!(
                "INSERT INTO notes (id, owner, body, tag) VALUES (60, '{a_hex}', {txn_val}, 'txn')"
            )
        )
        .is_none()
    );
    for (label, stmt) in [
        ("COMMIT of another session's transaction", "COMMIT"),
        ("ROLLBACK of another session's transaction", "ROLLBACK"),
        (
            "dirty read of another session's uncommitted row",
            "SELECT id FROM notes WHERE id = 60",
        ),
        (
            "write into another session's open transaction",
            "UPDATE notes SET tag = 'hijack' WHERE id = 1",
        ),
    ] {
        let code = srv.sql(&bob.sid, stmt);
        assert_eq!(
            code,
            Some(ProtocolErrorCode::TransactionConflict),
            "{label}"
        );
        row("G1", label, format!("{:?}", code.unwrap()));
    }
    // the owner's transaction is intact and commits normally
    assert!(srv.sql(&alice.sid, "COMMIT").is_none());
    assert_eq!(
        srv.row_count(&bob.sid, "SELECT id FROM notes WHERE id = 60"),
        1
    );
    assert_eq!(
        srv.row_count(&bob.sid, "SELECT id FROM notes WHERE tag = 'hijack'"),
        0
    );
    // owner's session ends mid-transaction → rolled back, never committed
    let c = srv.challenge("conn-txn", alice.subject, &acme);
    let ControlResponse::ClientAuthOk {
        session_id: tx_sid, ..
    } = srv
        .finish("conn-txn", &c, alice.identity.sign_challenge(&c).unwrap())
        .body
        .unwrap()
    else {
        panic!()
    };
    assert!(srv.sql_on("conn-txn", &tx_sid, "BEGIN").is_none());
    let v = sql_blob_literal(&ring.seal("sqlc/notes/61/body", 1, b"orphan").unwrap());
    assert!(
        srv.sql_on(
            "conn-txn",
            &tx_sid,
            &format!("INSERT INTO notes (id, owner, body, tag) VALUES (61, '{a_hex}', {v}, 'o')")
        )
        .is_none()
    );
    srv.state.auth_mut().close_channel("conn-txn");
    assert_eq!(
        srv.row_count(&bob.sid, "SELECT id FROM notes WHERE id = 61"),
        0
    );
    row(
        "G2",
        "transaction of a closed connection",
        "rolled back".into(),
    );

    // A5 — regression F7: a session issued before the identity was disabled must stop
    // working on the SQL path too (not only on the key-directory path).
    assert!(srv.sql(&dave.sid, "SELECT id FROM notes").is_none());
    let dave_id = srv
        .state
        .auth
        .identities()
        .get_by_name("dave")
        .unwrap()
        .id
        .clone();
    srv.state.auth_mut().disable_identity(&dave_id).unwrap();
    let code = srv.sql(&dave.sid, "SELECT id FROM notes");
    assert!(
        code.is_some(),
        "disabled identity's live session still runs SQL"
    );
    row(
        "A5",
        "disabled identity keeps using an earlier SQL session",
        format!("{:?}", code.unwrap()),
    );
    let code = srv.denied(ControlRequest::KeyEnvelopeGet {
        session_id: dave.sid.clone(),
    });
    row(
        "A5",
        "disabled identity keeps using an earlier key-API session",
        format!("{code:?}"),
    );

    println!(
        "\nCLIENT_OWNED attack matrix ({} rows)\n{}",
        rows.len(),
        rows.join("\n")
    );
}
