//! Production pgwire (D4-A): the PostgreSQL wire protocol as a **thin adapter over the SQL
//! plane** — the same `CoreServerState`, `AuthService`, SQL authorization, CLIENT_OWNED
//! policy and encrypted storage as DMC IPC (the reference path proven by the D4 gate).
//!
//! What a pgwire connection can do — and nothing else:
//!
//! * **Authenticate** with the SASL mechanism [`MECHANISM`] (`AVRORA-ED25519-V1`) only:
//!   `ClientAuthBegin` → the D1 challenge (bound to this connection's channel) → the
//!   client's Ed25519 signature → `ClientAuthFinish`. No password, no SCRAM, no
//!   `AuthenticationOk` without that check (contract D4, §6A.6). Failures are one
//!   indistinguishable `28000`.
//! * **Run SQL** of the session it authenticated (`ExecuteSql` through `handle_data`):
//!   vault gate, per-identity SQL grants, F8 transaction ownership, sealed-column policy —
//!   all enforced by the dispatcher, not here. The client never supplies a session id.
//!
//! The connection is the channel (D5): `pgwire:<random>`; when it closes, its sessions end
//! and an open transaction is rolled back. Vault, backup, privilege, identity and runtime
//! administration are not reachable (they stay on DMC IPC). Listens on loopback only: the
//! adapter has no TLS, and a challenge relay is only excluded where no one can sit between
//! client and server (same rule as the HTTP adapter, D3). Writes nothing to disk itself.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

use dmc_protocol::{
    ControlRequest, ControlResponse, DataRequest, DataResponse, ProtocolErrorCode, RemoteLimits,
    RequestEnvelope, SqlResult,
};
use dmc_server::{CoreServerState, handle_control, handle_data};
use dmc_vault::ownership::auth::Challenge;
use dmc_vault::ownership::{SubjectId, TenantId};
use serde::Deserialize;

/// The only authentication mechanism offered.
pub const MECHANISM: &str = "AVRORA-ED25519-V1";
/// Channel prefix of pgwire connections (D5).
pub const CHANNEL_PREFIX: &str = "pgwire:";

pub type SharedCore = Arc<Mutex<CoreServerState>>;

const SSL_REQUEST: i32 = 80877103;
const GSSENC_REQUEST: i32 = 80877104;
const CANCEL_REQUEST: i32 = 80877102;
const PROTOCOL_V3: i32 = 196608;
const MAX_STARTUP: usize = 10_000;
const AUTH_TIMEOUT: Duration = Duration::from_secs(60);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Text type OID (results are sent in text format).
const TEXT_OID: i32 = 25;

/// First SASL message of [`MECHANISM`]: who wants to authenticate.
#[derive(Deserialize)]
pub struct ClientFirst {
    pub subject: SubjectId,
    pub tenant: TenantId,
}

/// Refuse any non-loopback listen address (no TLS in this adapter).
pub fn require_loopback(addr: &SocketAddr) -> io::Result<()> {
    if addr.ip().is_loopback() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "pgwire listens on loopback only (no TLS in this adapter)",
        ))
    }
}

/// Bind on a loopback address and serve in a background thread.
pub fn spawn(addr: SocketAddr, core: SharedCore) -> io::Result<(SocketAddr, JoinHandle<()>)> {
    require_loopback(&addr)?;
    let listener = TcpListener::bind(addr)?;
    let local = listener.local_addr()?;
    require_loopback(&local)?;
    let handle = std::thread::spawn(move || {
        let _ = serve(listener, core);
    });
    Ok((local, handle))
}

/// Accept loop: one thread per connection, state locked per request.
pub fn serve(listener: TcpListener, core: SharedCore) -> io::Result<()> {
    require_loopback(&listener.local_addr()?)?;
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let core = Arc::clone(&core);
        std::thread::spawn(move || handle_connection(stream, core));
    }
    Ok(())
}

fn lock(core: &SharedCore) -> MutexGuard<'_, CoreServerState> {
    core.lock().unwrap_or_else(|p| p.into_inner())
}

fn new_channel() -> String {
    let id = dmc_vault::KeyMaterial::random();
    format!("{CHANNEL_PREFIX}{}", hex::encode(&id.as_bytes()[..16]))
}

/// One connection: admit → authenticate → queries; on any exit its sessions end and an
/// open transaction is rolled back (never committed).
pub fn handle_connection(mut stream: TcpStream, core: SharedCore) {
    if !stream.peer_addr().is_ok_and(|p| p.ip().is_loopback()) {
        return;
    }
    if lock(&core).try_admit_connection().is_err() {
        let _ = stream.write_all(&error_response("53300", "too many connections"));
        return;
    }
    let channel = new_channel();
    let _ = run(&mut stream, &core, &channel);
    let mut s = lock(&core);
    s.auth.close_channel(&channel);
    s.reap_orphan_transaction();
    s.release_connection();
}

fn run(stream: &mut TcpStream, core: &SharedCore, channel: &str) -> io::Result<()> {
    stream.set_read_timeout(Some(AUTH_TIMEOUT))?;
    if !startup(stream)? {
        return Ok(());
    }
    let Some(session_id) = authenticate(stream, core, channel)? else {
        stream.write_all(&error_response("28000", "authentication failed"))?;
        return Ok(());
    };
    let mut out = auth_ok();
    for (k, v) in [
        ("server_version", "16.0"),
        ("server_encoding", "UTF8"),
        ("client_encoding", "UTF8"),
        ("DateStyle", "ISO, MDY"),
        ("integer_datetimes", "on"),
    ] {
        out.extend(parameter_status(k, v));
    }
    out.extend(backend_key_data());
    out.extend(ready(core, &session_id));
    stream.write_all(&out)?;
    stream.set_read_timeout(Some(IDLE_TIMEOUT))?;
    queries(stream, core, channel, &session_id)
}

/// Startup packet (SSL / GSSENC requests are declined). `false`: the client went away or
/// sent something other than a v3 startup.
fn startup(stream: &mut TcpStream) -> io::Result<bool> {
    loop {
        let len = match read_i32(stream) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
            Err(e) => return Err(e),
        };
        if !(8..=MAX_STARTUP as i32).contains(&len) {
            return Ok(false);
        }
        let code = read_i32(stream)?;
        if code == SSL_REQUEST || code == GSSENC_REQUEST {
            stream.write_all(b"N")?;
            continue;
        }
        if code == CANCEL_REQUEST || code != PROTOCOL_V3 {
            return Ok(false);
        }
        let mut params = vec![0u8; len as usize - 8];
        stream.read_exact(&mut params)?;
        return Ok(true);
    }
}

/// SASL `AVRORA-ED25519-V1`. `None`: refused (one indistinguishable outcome).
fn authenticate(
    stream: &mut TcpStream,
    core: &SharedCore,
    channel: &str,
) -> io::Result<Option<String>> {
    // AuthenticationSASL: the only mechanism offered
    let mut body = 10i32.to_be_bytes().to_vec();
    body.extend_from_slice(MECHANISM.as_bytes());
    body.extend_from_slice(&[0, 0]);
    stream.write_all(&message(b'R', &body))?;

    // SASLInitialResponse: mechanism, client-first (subject, tenant)
    let Some((b'p', payload)) = read_message(stream, MAX_STARTUP)? else {
        return Ok(None);
    };
    let Some((mechanism, data)) = split_initial_response(&payload) else {
        return Ok(None);
    };
    if mechanism != MECHANISM {
        return Ok(None);
    }
    let Ok(first) = serde_json::from_slice::<ClientFirst>(data) else {
        return Ok(None);
    };
    let challenge = match control(
        core,
        channel,
        ControlRequest::ClientAuthBegin {
            subject: first.subject,
            tenant: first.tenant,
        },
    ) {
        Some(ControlResponse::ClientAuthChallenge { challenge }) => challenge,
        _ => return Ok(None),
    };
    let Ok(parsed) = Challenge::parse(&challenge) else {
        return Ok(None);
    };
    let mut body = 11i32.to_be_bytes().to_vec();
    body.extend_from_slice(&challenge);
    stream.write_all(&message(b'R', &body))?;

    // SASLResponse: the signature over exactly that challenge
    let Some((b'p', signature)) = read_message(stream, MAX_STARTUP)? else {
        return Ok(None);
    };
    match control(
        core,
        channel,
        ControlRequest::ClientAuthFinish {
            nonce: parsed.nonce.to_vec(),
            signature,
        },
    ) {
        Some(ControlResponse::ClientAuthOk { session_id, .. }) => {
            // AuthenticationSASLFinal (no server data)
            stream.write_all(&message(b'R', &12i32.to_be_bytes()))?;
            Ok(Some(session_id))
        }
        _ => Ok(None),
    }
}

fn split_initial_response(payload: &[u8]) -> Option<(&str, &[u8])> {
    let end = payload.iter().position(|b| *b == 0)?;
    let mechanism = std::str::from_utf8(&payload[..end]).ok()?;
    let rest = &payload[end + 1..];
    let len = i32::from_be_bytes(rest.get(..4)?.try_into().ok()?);
    let data = rest.get(4..)?;
    (len >= 0 && len as usize == data.len()).then_some((mechanism, data))
}

fn control(core: &SharedCore, channel: &str, body: ControlRequest) -> Option<ControlResponse> {
    let mut s = lock(core);
    let r = handle_control(
        &mut s,
        RequestEnvelope {
            request_id: 0,
            body,
        },
        &RemoteLimits::default(),
        channel,
    )
    .ok()?;
    if r.error_code.is_some() {
        return None;
    }
    r.body
}

fn queries(
    stream: &mut TcpStream,
    core: &SharedCore,
    channel: &str,
    session_id: &str,
) -> io::Result<()> {
    let max = RemoteLimits::default().max_sql_size as usize + 1024;
    loop {
        let Some((tag, payload)) = read_message(stream, max)? else {
            return Ok(());
        };
        let mut out = Vec::new();
        match tag {
            b'X' => return Ok(()),
            b'Q' => {
                let sql = cstr(&payload);
                if sql.trim().is_empty() {
                    out.extend(message(b'I', &[]));
                } else {
                    let (reply, session_gone) = execute(core, channel, session_id, &sql);
                    out.extend(reply);
                    if session_gone {
                        stream.write_all(&out)?;
                        return Ok(());
                    }
                }
                out.extend(ready(core, session_id));
            }
            b'S' => out.extend(ready(core, session_id)),
            b'H' => {}
            _ => {
                out.extend(error_response(
                    "0A000",
                    "only the simple query protocol is supported",
                ));
                out.extend(ready(core, session_id));
            }
        }
        stream.write_all(&out)?;
    }
}

/// Run one statement on the session; returns the reply and whether the session is gone.
fn execute(core: &SharedCore, channel: &str, session_id: &str, sql: &str) -> (Vec<u8>, bool) {
    let mut s = lock(core);
    let r = handle_data(
        &mut s,
        RequestEnvelope {
            request_id: 0,
            body: DataRequest::ExecuteSql {
                session_id: session_id.to_string(),
                sql: sql.to_string(),
                params: Vec::new(),
            },
        },
        &RemoteLimits::default(),
        channel,
    );
    match r {
        Ok(env) => match (env.error_code, env.body) {
            (None, Some(DataResponse::SqlResult(result))) => (encode_result(sql, &result), false),
            (None, _) => (command_complete(&tag_for(sql, 0)), false),
            (Some(code), _) => {
                let msg = env
                    .error_message
                    .unwrap_or_else(|| "request failed".to_string());
                (
                    error_response(sqlstate(code), &msg),
                    code == ProtocolErrorCode::SessionInvalid,
                )
            }
        },
        Err(_) => (error_response("08P01", "malformed request"), false),
    }
}

/// SQLSTATE for a dispatcher error code.
pub fn sqlstate(code: ProtocolErrorCode) -> &'static str {
    match code {
        ProtocolErrorCode::AuthenticationFailed => "28000",
        ProtocolErrorCode::SessionInvalid => "08006",
        ProtocolErrorCode::AuthorizationDenied => "42501",
        ProtocolErrorCode::VaultLocked => "55000",
        ProtocolErrorCode::InvalidSql => "42601",
        ProtocolErrorCode::ConstraintViolation => "23000",
        ProtocolErrorCode::TransactionConflict => "40001",
        ProtocolErrorCode::ResourceNotFound => "42P01",
        ProtocolErrorCode::Unsupported => "0A000",
        ProtocolErrorCode::InvalidRequest => "22023",
        ProtocolErrorCode::ExecutionError => "22000",
        _ => "XX000",
    }
}

fn tag_for(sql: &str, rows: usize) -> String {
    let words: Vec<String> = sql
        .split_whitespace()
        .take(2)
        .map(|w| w.trim_end_matches(';').to_ascii_uppercase())
        .collect();
    match words.first().map(String::as_str) {
        Some("SELECT") => format!("SELECT {rows}"),
        Some("CREATE" | "DROP") => words.join(" "),
        Some(w) => w.to_string(),
        None => "OK".into(),
    }
}

fn encode_result(sql: &str, r: &SqlResult) -> Vec<u8> {
    let mut out = Vec::new();
    if !r.columns.is_empty() {
        let mut body = (r.columns.len() as i16).to_be_bytes().to_vec();
        for (i, name) in r.columns.iter().enumerate() {
            body.extend_from_slice(name.as_bytes());
            body.push(0);
            body.extend_from_slice(&0i32.to_be_bytes());
            body.extend_from_slice(&((i as i16) + 1).to_be_bytes());
            body.extend_from_slice(&TEXT_OID.to_be_bytes());
            body.extend_from_slice(&(-1i16).to_be_bytes());
            body.extend_from_slice(&(-1i32).to_be_bytes());
            body.extend_from_slice(&0i16.to_be_bytes());
        }
        out.extend(message(b'T', &body));
        for row in &r.rows {
            let mut body = (row.cells.len() as i16).to_be_bytes().to_vec();
            for cell in &row.cells {
                if cell.is_null {
                    body.extend_from_slice(&(-1i32).to_be_bytes());
                } else {
                    body.extend_from_slice(&(cell.text.len() as i32).to_be_bytes());
                    body.extend_from_slice(cell.text.as_bytes());
                }
            }
            out.extend(message(b'D', &body));
        }
    }
    out.extend(command_complete(&tag_for(sql, r.rows.len())));
    out
}

fn ready(core: &SharedCore, session_id: &str) -> Vec<u8> {
    let in_txn = lock(core).transaction_owned_by(session_id);
    message(b'Z', &[if in_txn { b'T' } else { b'I' }])
}

fn auth_ok() -> Vec<u8> {
    message(b'R', &0i32.to_be_bytes())
}

fn parameter_status(name: &str, value: &str) -> Vec<u8> {
    let mut body = name.as_bytes().to_vec();
    body.push(0);
    body.extend_from_slice(value.as_bytes());
    body.push(0);
    message(b'S', &body)
}

fn backend_key_data() -> Vec<u8> {
    let k = dmc_vault::KeyMaterial::random();
    message(b'K', &k.as_bytes()[..8])
}

fn command_complete(tag: &str) -> Vec<u8> {
    let mut body = tag.as_bytes().to_vec();
    body.push(0);
    message(b'C', &body)
}

fn error_response(sqlstate: &str, msg: &str) -> Vec<u8> {
    let mut body = Vec::new();
    for (field, value) in [
        (b'S', "ERROR"),
        (b'V', "ERROR"),
        (b'C', sqlstate),
        (b'M', msg),
    ] {
        body.push(field);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    }
    body.push(0);
    message(b'E', &body)
}

fn message(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + body.len());
    out.push(tag);
    out.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// One frontend message; `None` on EOF. Oversized or malformed lengths close the
/// connection (no unbounded allocation).
fn read_message(stream: &mut TcpStream, max: usize) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut tag = [0u8; 1];
    match stream.read_exact(&mut tag) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = read_i32(stream)?;
    if len < 4 || (len as usize - 4) > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message length"));
    }
    let mut payload = vec![0u8; len as usize - 4];
    stream.read_exact(&mut payload)?;
    Ok(Some((tag[0], payload)))
}

fn read_i32(stream: &mut TcpStream) -> io::Result<i32> {
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf)?;
    Ok(i32::from_be_bytes(buf))
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
