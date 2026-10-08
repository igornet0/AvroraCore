//! CLIENT_OWNED HTTP adapter (D3): a thin transport over the same `CoreServerState`,
//! `AuthService`, key directory, SQL authorization and CLIENT_OWNED policy as DMC IPC.
//!
//! * **Loopback only.** [`serve`] refuses a non-loopback address, and every request's
//!   peer address is checked again. There is no TLS in this adapter, so it is never
//!   exposed beyond the host. No CORS headers are sent (no cross-origin browser access).
//! * **No bearer tokens.** HTTP has no connection to bind a session to (D5), so after
//!   Ed25519 challenge–response (`/v1/auth/*`) every request is signed by the session's
//!   auth key over method, path, body hash and a strictly increasing sequence number
//!   (`dmc_security::auth::AuthService::verify_http_request`). A stolen session id is
//!   useless without the device's private key; a replayed request is refused.
//! * **Same dispatcher, allowlist.** Signed requests are handed to
//!   `dmc_server::handle_control` / `handle_data` with the session's HTTP channel as the
//!   connection id. Only key-directory, envelope, grant, sealed-column and SQL requests
//!   are accepted; password authentication, vault, backup and runtime administration are
//!   not reachable here.
//! * The adapter never sees a private key, DEK or CLIENT_OWNED plaintext: requests carry
//!   public keys, envelopes, signatures and SQL with `X'…'` ciphertext only.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use dmc_protocol::{ControlRequest, ControlResponse, DataRequest, RemoteLimits, RequestEnvelope};
use dmc_security::auth::client_auth::HTTP_CHANNEL_PREFIX;
use dmc_server::{CoreServerState, handle_control, handle_data};
use dmc_vault::ownership::{SubjectId, TenantId};
use serde::{Deserialize, Serialize};

pub const HEADER_SESSION: &str = "x-avrora-session";
pub const HEADER_SEQ: &str = "x-avrora-seq";
pub const HEADER_SIGNATURE: &str = "x-avrora-signature";
pub const PATH_CONTROL: &str = "/v1/control";
pub const PATH_DATA: &str = "/v1/data";

pub type SharedCore = Arc<Mutex<CoreServerState>>;

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthBeginBody {
    pub subject: SubjectId,
    pub tenant: TenantId,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthBeginReply {
    pub channel_id: String,
    pub challenge_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthFinishBody {
    pub channel_id: String,
    pub nonce_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthFinishReply {
    pub session_id: String,
    pub expires_at_ms: u64,
}

/// Error body: a code and a fixed, secret-free message.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorReply {
    pub error: String,
}

fn err(status: StatusCode, msg: &str) -> Response {
    (
        status,
        Json(ErrorReply {
            error: msg.to_string(),
        }),
    )
        .into_response()
}

fn refuse() -> Response {
    err(StatusCode::UNAUTHORIZED, "authentication failed")
}

fn http_channel(channel_id: &str) -> Option<String> {
    let ok = channel_id.len() == 32 && channel_id.bytes().all(|b| b.is_ascii_hexdigit());
    ok.then(|| format!("{HTTP_CHANNEL_PREFIX}{channel_id}"))
}

fn lock(core: &SharedCore) -> std::sync::MutexGuard<'_, CoreServerState> {
    core.lock().unwrap_or_else(|p| p.into_inner())
}

/// Requests reachable over HTTP (shared policy with the control-plane tunnel).
pub fn control_allowed(req: &ControlRequest) -> bool {
    dmc_server::transport_policy::client_owned_session_request(req)
}

/// `Some(403)` unless the peer is on the loopback interface.
fn refuse_non_loopback(peer: &SocketAddr) -> Option<Response> {
    (!peer.ip().is_loopback()).then(|| err(StatusCode::FORBIDDEN, "loopback only"))
}

async fn on_core<T: Send + 'static>(
    core: &SharedCore,
    f: impl FnOnce(&mut CoreServerState) -> T + Send + 'static,
) -> T {
    let core = core.clone();
    tokio::task::spawn_blocking(move || f(&mut lock(&core)))
        .await
        .expect("core task")
}

async fn auth_begin(
    State(core): State<SharedCore>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<AuthBeginBody>,
) -> Response {
    if let Some(r) = refuse_non_loopback(&peer) {
        return r;
    }
    let mut id = [0u8; 16];
    getrandom_fill(&mut id);
    let channel_id = hex::encode(id);
    let channel = http_channel(&channel_id).expect("well-formed");
    let resp = on_core(&core, move |s| {
        handle_control(
            s,
            RequestEnvelope {
                request_id: 1,
                body: ControlRequest::ClientAuthBegin {
                    subject: body.subject,
                    tenant: body.tenant,
                },
            },
            &RemoteLimits::default(),
            &channel,
        )
    })
    .await;
    match resp.ok().and_then(|r| r.body) {
        Some(ControlResponse::ClientAuthChallenge { challenge }) => Json(AuthBeginReply {
            channel_id,
            challenge_hex: hex::encode(challenge),
        })
        .into_response(),
        _ => refuse(),
    }
}

async fn auth_finish(
    State(core): State<SharedCore>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<AuthFinishBody>,
) -> Response {
    if let Some(r) = refuse_non_loopback(&peer) {
        return r;
    }
    let (Some(channel), Ok(nonce), Ok(signature)) = (
        http_channel(&body.channel_id),
        hex::decode(&body.nonce_hex),
        hex::decode(&body.signature_hex),
    ) else {
        return refuse();
    };
    let resp = on_core(&core, move |s| {
        handle_control(
            s,
            RequestEnvelope {
                request_id: 1,
                body: ControlRequest::ClientAuthFinish { nonce, signature },
            },
            &RemoteLimits::default(),
            &channel,
        )
    })
    .await;
    match resp.ok().and_then(|r| r.body) {
        Some(ControlResponse::ClientAuthOk {
            session_id,
            expires_at_ms,
            ..
        }) => Json(AuthFinishReply {
            session_id,
            expires_at_ms,
        })
        .into_response(),
        _ => refuse(),
    }
}

/// Enrollment needs no session (invite token + proof of possession).
async fn enroll(
    State(core): State<SharedCore>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<ControlRequest>,
) -> Response {
    if let Some(r) = refuse_non_loopback(&peer) {
        return r;
    }
    if !matches!(req, ControlRequest::IdentityEnroll { .. }) {
        return err(StatusCode::BAD_REQUEST, "not an enrollment");
    }
    let mut id = [0u8; 16];
    getrandom_fill(&mut id);
    let channel = format!("{HTTP_CHANNEL_PREFIX}enroll-{}", hex::encode(id));
    let resp = on_core(&core, move |s| {
        handle_control(
            s,
            RequestEnvelope {
                request_id: 1,
                body: req,
            },
            &RemoteLimits::default(),
            &channel,
        )
    })
    .await;
    match resp {
        Ok(r) => Json(r).into_response(),
        Err(_) => err(StatusCode::BAD_REQUEST, "malformed request"),
    }
}

/// Verify the per-request signature; returns the session's HTTP channel.
fn verify_signed(
    s: &mut CoreServerState,
    headers: &HeaderMap,
    path: &str,
    body: &[u8],
) -> Option<String> {
    let session = headers.get(HEADER_SESSION)?.to_str().ok()?.to_string();
    let seq: u64 = headers.get(HEADER_SEQ)?.to_str().ok()?.parse().ok()?;
    let signature = hex::decode(headers.get(HEADER_SIGNATURE)?.to_str().ok()?).ok()?;
    let (auth, dir, _) = s.ownership_parts().ok()?;
    auth.verify_http_request(dir, &session.into(), seq, "POST", path, body, &signature)
        .ok()
}

async fn control(
    State(core): State<SharedCore>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(r) = refuse_non_loopback(&peer) {
        return r;
    }
    let Ok(req) = serde_json::from_slice::<ControlRequest>(&body) else {
        return err(StatusCode::BAD_REQUEST, "malformed request");
    };
    if !control_allowed(&req) {
        return err(StatusCode::FORBIDDEN, "request not available over HTTP");
    }
    let resp = on_core(&core, move |s| {
        let channel = verify_signed(s, &headers, PATH_CONTROL, &body)?;
        Some(handle_control(
            s,
            RequestEnvelope {
                request_id: 1,
                body: req,
            },
            &RemoteLimits::default(),
            &channel,
        ))
    })
    .await;
    match resp {
        None => refuse(),
        Some(Ok(r)) => Json(r).into_response(),
        Some(Err(_)) => err(StatusCode::BAD_REQUEST, "malformed request"),
    }
}

async fn data(
    State(core): State<SharedCore>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(r) = refuse_non_loopback(&peer) {
        return r;
    }
    let Ok(req) = serde_json::from_slice::<DataRequest>(&body) else {
        return err(StatusCode::BAD_REQUEST, "malformed request");
    };
    let resp = on_core(&core, move |s| {
        let channel = verify_signed(s, &headers, PATH_DATA, &body)?;
        Some(handle_data(
            s,
            RequestEnvelope {
                request_id: 1,
                body: req,
            },
            &RemoteLimits::default(),
            &channel,
        ))
    })
    .await;
    match resp {
        None => refuse(),
        Some(Ok(r)) => Json(r).into_response(),
        Some(Err(_)) => err(StatusCode::BAD_REQUEST, "malformed request"),
    }
}

fn getrandom_fill(buf: &mut [u8]) {
    rand::fill(buf);
}

pub fn router(core: SharedCore) -> Router {
    Router::new()
        .route("/v1/auth/begin", post(auth_begin))
        .route("/v1/auth/finish", post(auth_finish))
        .route("/v1/enroll", post(enroll))
        .route(PATH_CONTROL, post(control))
        .route(PATH_DATA, post(data))
        .with_state(core)
}

/// Bind the adapter. Refuses any non-loopback address (there is no TLS here).
pub async fn bind(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    if !addr.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "CLIENT_OWNED HTTP adapter is loopback-only (no TLS)",
        ));
    }
    tokio::net::TcpListener::bind(addr).await
}

pub async fn serve(listener: tokio::net::TcpListener, core: SharedCore) -> std::io::Result<()> {
    axum::serve(
        listener,
        router(core).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}
