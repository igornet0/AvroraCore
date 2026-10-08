//! Test support for production pgwire (SQL plane): a production `start_core` with the
//! pgwire adapter, CLIENT_OWNED users enrolled by invite, and a minimal PostgreSQL wire
//! frontend implementing SASL `AVRORA-ED25519-V1` with the user's device key.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dmc_client_crypto::ClientIdentity;
use dmc_protocol::{ControlRequest, ControlResponse, RemoteLimits, RequestEnvelope};
use dmc_security::auth::{Action, IdentityId, Resource};
use dmc_server::{CoreServerState, UnlockMaterial, handle_control};
use dmc_vault::ownership::TenantId;

pub struct Server {
    pub dir: tempfile::TempDir,
    pub root: PathBuf,
    pub core: Arc<Mutex<CoreServerState>>,
    pub master: UnlockMaterial,
    pub addr: SocketAddr,
    op_sid: String,
    op_id: IdentityId,
}

pub struct User {
    pub id: ClientIdentity,
    pub identity_id: IdentityId,
}

fn op(core: &Arc<Mutex<CoreServerState>>, body: ControlRequest) -> ControlResponse {
    let r = handle_control(
        &mut core.lock().unwrap(),
        RequestEnvelope {
            request_id: 1,
            body,
        },
        &RemoteLimits::default(),
        "op-local",
    )
    .unwrap();
    assert!(r.error_code.is_none(), "{:?}", r.error_message);
    r.body.unwrap()
}

impl Server {
    /// Production `start_core` (encrypted-only) + the pgwire adapter on loopback, exactly as
    /// `dmc serve --pgwire` wires it. The vault starts Locked.
    pub fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("data");
        let cfg = dmc_ops::parse_config_json(&format!(
            r#"{{ "data_root": "{}", "profile": "development" }}"#,
            root.display()
        ))
        .unwrap();
        let mut started = dmc_ops::start_core(cfg, dmc_ops::StartupOptions::production()).unwrap();
        let master = started.unlock_material.clone().unwrap();
        // in-process operator (DMC IPC in production): invites, grants, unlock, backup
        let op_id = started
            .server
            .auth_mut()
            .create_identity("op", "pw")
            .unwrap();
        started.server.auth_mut().grants_mut().grant(
            op_id.clone(),
            Resource::System,
            Action::Create,
        );
        let core = Arc::new(Mutex::new(started.server));
        let ControlResponse::Authenticate { session_id, .. } = op(
            &core,
            ControlRequest::Authenticate {
                identity_name: "op".into(),
                password: "pw".into(),
            },
        ) else {
            panic!()
        };
        let (addr, _) = dmc_pgwire::spawn("127.0.0.1:0".parse().unwrap(), core.clone()).unwrap();
        Self {
            dir,
            root,
            core,
            master,
            addr,
            op_sid: session_id,
            op_id,
        }
    }

    pub fn unlock(&self) {
        self.core
            .lock()
            .unwrap()
            .apply_vault_unlock(&self.master)
            .unwrap();
    }

    pub fn lock(&self) {
        self.core.lock().unwrap().lock_vault();
    }

    pub fn control(&self, body: ControlRequest) -> ControlResponse {
        op(&self.core, body)
    }

    /// Operator declares `table.column` CLIENT_OWNED sealed (owner in `owner_column`).
    pub fn declare_sealed(&self, table: &str, column: &str, owner_column: &str) {
        {
            let mut s = self.core.lock().unwrap();
            let g = s.auth_mut().grants_mut();
            g.grant(
                self.op_id.clone(),
                Resource::database("avrora"),
                Action::Connect,
            );
            g.grant(
                self.op_id.clone(),
                Resource::schema("avrora", "public"),
                Action::Usage,
            );
            g.grant(
                self.op_id.clone(),
                Resource::table("avrora", "public", table),
                Action::Create,
            );
        }
        self.control(ControlRequest::SealedColumnDeclare {
            session_id: self.op_sid.clone(),
            schema: "public".into(),
            table: table.into(),
            column: column.into(),
            owner_column: Some(owner_column.into()),
        });
    }

    /// `BackupCreate` by the operator (DMC IPC in production), rowstore included.
    pub fn backup(&self, backup_id: &str) {
        self.control(ControlRequest::BackupCreate {
            session_id: self.op_sid.clone(),
            backup_id: backup_id.into(),
            include_rowstore: true,
        });
    }

    /// Enroll a CLIENT_OWNED user by operator invite (D2); device key stays client-side.
    pub fn enroll(&self, name: &str) -> User {
        let tenant = TenantId::new("acme").unwrap();
        let ControlResponse::IdentityInvite {
            invite_id,
            token,
            subject,
            ..
        } = self.control(ControlRequest::IdentityInviteCreate {
            session_id: self.op_sid.clone(),
            name: name.into(),
            tenant: tenant.clone(),
            ttl_ms: 600_000,
        })
        else {
            panic!()
        };
        let (id, _) = ClientIdentity::generate(subject, tenant);
        let ControlResponse::IdentityEnrolled { identity_id, .. } =
            self.control(ControlRequest::IdentityEnroll {
                invite_id: invite_id.clone(),
                token: token.clone(),
                key: id.public_key(),
                signature: id.sign_enrollment(&invite_id, &token, name).unwrap(),
            })
        else {
            panic!()
        };
        User {
            id,
            identity_id: IdentityId::new(identity_id),
        }
    }

    pub fn grant(&self, user: &User, resource: Resource, actions: &[Action]) {
        let mut s = self.core.lock().unwrap();
        for a in actions {
            s.auth_mut()
                .grants_mut()
                .grant(user.identity_id.clone(), resource.clone(), *a);
        }
    }

    /// The usual SQL rights on `tables` (+ database / schema).
    pub fn grant_sql(&self, user: &User, tables: &[&str], actions: &[Action]) {
        self.grant(
            user,
            Resource::database("avrora"),
            &[Action::Connect, Action::Create],
        );
        self.grant(
            user,
            Resource::schema("avrora", "public"),
            &[Action::Usage, Action::Create],
        );
        for t in tables {
            self.grant(user, Resource::table("avrora", "public", *t), actions);
        }
    }

    pub fn connect(&self, user: &User) -> Pg {
        Pg::authenticate(self.addr, &user.id).expect("authenticated")
    }
}

// ── minimal PostgreSQL frontend ──────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct Reply {
    pub rows: Vec<Vec<Option<String>>>,
    pub tag: Option<String>,
    pub error: Option<(String, String)>,
    pub ready: u8,
}

impl Reply {
    pub fn ok(&self) -> bool {
        self.error.is_none()
    }

    pub fn sqlstate(&self) -> &str {
        self.error.as_ref().map(|e| e.0.as_str()).unwrap_or("")
    }
}

pub struct Pg {
    pub s: TcpStream,
}

pub fn msg(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

pub fn startup_packet(user: &str) -> Vec<u8> {
    let mut body = 196608i32.to_be_bytes().to_vec();
    for (k, v) in [("user", user), ("database", "avrora")] {
        body.extend_from_slice(k.as_bytes());
        body.push(0);
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut out = ((body.len() + 4) as i32).to_be_bytes().to_vec();
    out.extend(body);
    out
}

pub fn sasl_initial(mechanism: &str, data: &[u8]) -> Vec<u8> {
    let mut body = mechanism.as_bytes().to_vec();
    body.push(0);
    body.extend_from_slice(&(data.len() as i32).to_be_bytes());
    body.extend_from_slice(data);
    msg(b'p', &body)
}

pub fn client_first(id: &ClientIdentity) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "subject": id.subject(), "tenant": id.tenant() }))
        .unwrap()
}

fn error_fields(body: &[u8]) -> (String, String) {
    let (mut code, mut text) = (String::new(), String::new());
    for f in body.split(|b| *b == 0) {
        match f.first() {
            Some(b'C') => code = String::from_utf8_lossy(&f[1..]).into(),
            Some(b'M') => text = String::from_utf8_lossy(&f[1..]).into(),
            _ => {}
        }
    }
    (code, text)
}

impl Pg {
    pub fn open(addr: SocketAddr) -> Self {
        let s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        Self { s }
    }

    pub fn send(&mut self, bytes: &[u8]) {
        self.s.write_all(bytes).unwrap();
    }

    /// Next backend message; `None` when the server closed the connection.
    pub fn read(&mut self) -> Option<(u8, Vec<u8>)> {
        let mut tag = [0u8; 1];
        self.s.read_exact(&mut tag).ok()?;
        let mut len = [0u8; 4];
        self.s.read_exact(&mut len).ok()?;
        let mut body = vec![0u8; i32::from_be_bytes(len) as usize - 4];
        self.s.read_exact(&mut body).ok()?;
        Some((tag[0], body))
    }

    /// Startup → the offered SASL mechanisms (or the error if none).
    pub fn startup(&mut self) -> Result<Vec<String>, (String, String)> {
        self.send(&startup_packet("pgwire-user"));
        match self.read() {
            Some((b'R', body)) if body[..4] == 10i32.to_be_bytes() => Ok(body[4..]
                .split(|b| *b == 0)
                .filter(|m| !m.is_empty())
                .map(|m| String::from_utf8_lossy(m).into())
                .collect()),
            Some((b'E', body)) => Err(error_fields(&body)),
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Step 1: client-first → the server's challenge.
    pub fn begin(&mut self, id: &ClientIdentity) -> Result<Vec<u8>, (String, String)> {
        self.send(&sasl_initial(dmc_pgwire::MECHANISM, &client_first(id)));
        match self.read() {
            Some((b'R', body)) if body[..4] == 11i32.to_be_bytes() => Ok(body[4..].to_vec()),
            Some((b'E', body)) => Err(error_fields(&body)),
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Step 2: signature → authenticated (reads up to the first ReadyForQuery).
    pub fn finish(&mut self, signature: &[u8]) -> Result<(), (String, String)> {
        self.send(&msg(b'p', signature));
        let mut sasl_final = false;
        loop {
            match self.read() {
                Some((b'R', body)) if body[..4] == 12i32.to_be_bytes() => sasl_final = true,
                Some((b'R', body)) if body[..4] == 0i32.to_be_bytes() => {
                    assert!(sasl_final, "AuthenticationOk only after SASLFinal");
                }
                Some((b'S' | b'K', _)) => {}
                Some((b'Z', _)) => return Ok(()),
                Some((b'E', body)) => return Err(error_fields(&body)),
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    pub fn authenticate(addr: SocketAddr, id: &ClientIdentity) -> Result<Self, (String, String)> {
        let mut pg = Self::open(addr);
        pg.startup()?;
        let challenge = pg.begin(id)?;
        let signature = id.sign_challenge(&challenge).unwrap();
        pg.finish(&signature)?;
        Ok(pg)
    }

    pub fn query(&mut self, sql: &str) -> Reply {
        let mut body = sql.as_bytes().to_vec();
        body.push(0);
        self.send(&msg(b'Q', &body));
        self.collect()
    }

    /// Read until ReadyForQuery (or connection close: `ready == 0`).
    pub fn collect(&mut self) -> Reply {
        let mut r = Reply::default();
        loop {
            match self.read() {
                Some((b'T', _)) | Some((b'I', _)) => {}
                Some((b'D', body)) => {
                    let n = i16::from_be_bytes([body[0], body[1]]) as usize;
                    let mut at = 2;
                    let mut row = Vec::with_capacity(n);
                    for _ in 0..n {
                        let len = i32::from_be_bytes(body[at..at + 4].try_into().unwrap());
                        at += 4;
                        if len < 0 {
                            row.push(None);
                        } else {
                            let v = String::from_utf8_lossy(&body[at..at + len as usize]).into();
                            at += len as usize;
                            row.push(Some(v));
                        }
                    }
                    r.rows.push(row);
                }
                Some((b'C', body)) => {
                    r.tag = Some(String::from_utf8_lossy(&body[..body.len() - 1]).into())
                }
                Some((b'E', body)) => r.error = Some(error_fields(&body)),
                Some((b'Z', body)) => {
                    r.ready = body[0];
                    return r;
                }
                Some(_) => {}
                None => return r,
            }
        }
    }

    pub fn terminate(mut self) {
        self.send(&msg(b'X', &[]));
    }
}

/// Every file under `dir`.
pub fn walk(dir: &Path) -> Vec<PathBuf> {
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
