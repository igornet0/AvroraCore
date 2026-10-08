//! Ed25519 challenge–response authentication for CLIENT_OWNED subjects (AUTH-BINDING).
//!
//! One implementation for every transport: the transport only delivers the challenge and
//! the signature and sets the request channel ([`AuthService::begin_request`]).
//!
//! * The server holds and uses **public** Ed25519 keys only (`verify_strict`). There is no
//!   signing key type anywhere in the server crates.
//! * A challenge is single-use (removed on the first finish attempt, successful or not),
//!   expires after [`DEFAULT_CHALLENGE_TTL_MS`], and is bound to server instance,
//!   transport and channel. A signature for one channel/transport is useless on another.
//! * Unknown subject, wrong tenant, disabled identity, format-1 bundle, wrong signature,
//!   expired or replayed challenge all fail with the same error (no enumeration oracle).
//! * A successful finish yields only a session bound to the channel — no key material.

use std::collections::HashMap;
use std::fmt;

use dmc_vault::ownership::auth::{CHALLENGE_TTL_MS, Challenge, http_request_statement};
use dmc_vault::ownership::{SubjectId, TenantId};
use ed25519_dalek::{Signature, VerifyingKey};

use crate::auth::credential::INVALID_CREDENTIALS;
use crate::auth::identity::KeyCustody;
use crate::auth::service::AuthService;
use crate::auth::session::{AuthSession, SessionManager};
use crate::identity::SessionId;
use crate::ownership::ClientKeyDirectory;
use crate::{Error, Result};

/// Challenge lifetime issued by this server (must not exceed the client's limit).
pub const DEFAULT_CHALLENGE_TTL_MS: u64 = 30_000;
const MAX_PENDING: usize = 4096;
const _: () = assert!(DEFAULT_CHALLENGE_TTL_MS <= CHALLENGE_TTL_MS);

#[derive(Clone)]
struct Pending {
    challenge: Challenge,
    bytes: Vec<u8>,
    /// `None`: decoy for an unknown/ineligible subject — can never succeed.
    auth_key: Option<[u8; 32]>,
}

#[derive(Clone)]
pub struct ChallengeStore {
    instance: [u8; 16],
    pending: HashMap<[u8; 32], Pending>,
    /// Highest accepted HTTP request sequence number per session (replay protection).
    http_seq: HashMap<String, u64>,
}

impl fmt::Debug for ChallengeStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChallengeStore")
            .field("pending", &self.pending.len())
            .finish()
    }
}

impl Default for ChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ChallengeStore {
    pub fn new() -> Self {
        let mut instance = [0u8; 16];
        rand::fill(&mut instance);
        Self {
            instance,
            pending: HashMap::new(),
            http_seq: HashMap::new(),
        }
    }

    fn prune(&mut self, now: u64) {
        self.pending.retain(|_, p| p.challenge.expires_at_ms > now);
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

/// Strict Ed25519 verification with a public key only.
pub fn verify_signature(public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };
    vk.verify_strict(message, &sig).is_ok()
}

fn failed() -> Error {
    Error::AuthenticationFailed(INVALID_CREDENTIALS.into())
}

impl AuthService {
    fn eligible_auth_key(
        &self,
        dir: &ClientKeyDirectory,
        subject: SubjectId,
        tenant: &TenantId,
    ) -> Option<(u32, [u8; 32])> {
        let identity = self.identities().get_by_subject(subject)?;
        if identity.custody != KeyCustody::Client
            || identity.tenant.as_ref() != Some(tenant)
            || !identity.is_active()
        {
            return None;
        }
        let bundle = dir.active_bundle(subject)?;
        if &bundle.tenant != tenant || !bundle.can_authenticate() {
            return None;
        }
        Some((bundle.key_version, bundle.auth_public_key?))
    }

    /// Step 1: issue a challenge for `subject` on the current request channel.
    pub fn client_auth_begin(
        &mut self,
        dir: &ClientKeyDirectory,
        transport: &str,
        subject: SubjectId,
        tenant: TenantId,
    ) -> Result<Vec<u8>> {
        let channel = self.request_channel().ok_or_else(failed)?.to_string();
        let now = self.sessions().now_ms();
        self.challenges.prune(now);
        if self.challenges.pending.len() >= MAX_PENDING {
            return Err(Error::Conflict(
                "too many pending authentication challenges".into(),
            ));
        }
        let auth = self.eligible_auth_key(dir, subject, &tenant);
        let mut nonce = [0u8; 32];
        rand::fill(&mut nonce);
        let challenge = Challenge {
            server_instance: self.challenges.instance,
            transport: transport.to_string(),
            channel,
            nonce,
            subject,
            tenant,
            key_version: auth.map(|a| a.0).unwrap_or(1),
            issued_at_ms: now,
            expires_at_ms: now + DEFAULT_CHALLENGE_TTL_MS,
        };
        let bytes = challenge.to_bytes();
        self.challenges.pending.insert(
            nonce,
            Pending {
                challenge,
                bytes: bytes.clone(),
                auth_key: auth.map(|a| a.1),
            },
        );
        Ok(bytes)
    }

    /// Step 2: verify the signature over the challenge identified by `nonce` and create a
    /// session bound to the current channel.
    pub fn client_auth_finish(
        &mut self,
        dir: &ClientKeyDirectory,
        transport: &str,
        nonce: [u8; 32],
        signature: &[u8],
    ) -> Result<AuthSession> {
        // single use: gone after the first attempt, whatever its outcome
        let pending = self.challenges.pending.remove(&nonce).ok_or_else(failed)?;
        let c = &pending.challenge;
        let now = self.sessions().now_ms();
        if self.request_channel() != Some(c.channel.as_str())
            || c.transport != transport
            || now >= c.expires_at_ms
        {
            return Err(failed());
        }
        let key = pending.auth_key.ok_or_else(failed)?;
        if !verify_signature(&key, &pending.bytes, signature) {
            return Err(failed());
        }
        // still the ACTIVE key and an active CLIENT identity (rotation/disable in between)
        match self.eligible_auth_key(dir, c.subject, &c.tenant) {
            Some((version, current)) if version == c.key_version && current == key => {}
            _ => return Err(failed()),
        }
        let identity_id = self
            .identities()
            .get_by_subject(c.subject)
            .map(|i| i.id.clone())
            .ok_or_else(failed)?;
        self.create_client_session(identity_id, c.subject, c.key_version)
    }

    /// HTTP has no connection to bind a session to, so every HTTP request is signed by
    /// the session's Ed25519 auth key (`http_request_statement`) with a strictly
    /// increasing `seq`. Returns the session's HTTP channel, which the adapter then uses
    /// as the request channel (D5 check in dispatch). A session obtained on any other
    /// transport, a retired key, a replayed or reordered `seq`, or a bad signature fail.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_http_request(
        &mut self,
        dir: &ClientKeyDirectory,
        session_id: &SessionId,
        seq: u64,
        method: &str,
        path: &str,
        body: &[u8],
        signature: &[u8],
    ) -> Result<String> {
        let session = self
            .sessions()
            .validate_session(session_id)
            .map_err(|_| failed())?;
        self.require_live_identity(&session).map_err(|_| failed())?;
        let channel = session
            .channel
            .clone()
            .filter(|c| c.starts_with(HTTP_CHANNEL_PREFIX))
            .ok_or_else(failed)?;
        let (Some(subject), Some(version)) = (session.subject, session.auth_key_version) else {
            return Err(failed());
        };
        // Signed by the subject's ACTIVE auth key: the session survives the owner's own
        // rotation (as on DMC), but a rotated-out key can no longer drive it.
        let bundle = dir.active_bundle(subject).ok_or_else(failed)?;
        let key = bundle
            .auth_public_key
            .filter(|_| bundle.key_version >= version)
            .ok_or_else(failed)?;
        let statement = http_request_statement(session_id.as_str(), seq, method, path, body);
        if !verify_signature(&key, &statement, signature) {
            return Err(failed());
        }
        let last = self
            .challenges
            .http_seq
            .entry(session_id.as_str().to_string())
            .or_insert(0);
        if seq <= *last {
            return Err(failed());
        }
        *last = seq;
        Ok(channel)
    }
}

/// Channel ids of the HTTP transport start with this prefix (set by the HTTP adapter).
pub const HTTP_CHANNEL_PREFIX: &str = "http:";
