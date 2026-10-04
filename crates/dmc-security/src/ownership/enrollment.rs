//! CLIENT_OWNED enrollment: operator-issued one-time invites + client proof of possession.
//!
//! Two different claims, deliberately kept apart:
//!
//! * **operator-controlled enrollment** — an operator (grant `CREATE` on
//!   `Resource::System`) states "subject S of tenant T, name N, may be claimed by whoever
//!   presents this token before time E". The server picks S; the token (32 random bytes)
//!   is returned once and only its hash is stored.
//! * **cryptographic proof of key ownership** — the enrolling client signs
//!   [`enroll_statement`] with the Ed25519 auth key of the bundle it registers. The server
//!   holds no private key, so it cannot produce this proof for the client's key.
//!
//! Neither proves a human's physical identity. A malicious operator can always issue an
//! invite and enroll a key of its own for a new subject — that is what TOFU/fingerprint
//! verification between partners is for (`cryptographic-ownership.md` §21.3).
//!
//! Invite lifecycle: `Pending` → `Used` (one successful enrollment) or `Burned` (expired,
//! or [`MAX_FAILED_ATTEMPTS`] bad proofs with the right token). A used or burned invite
//! is never accepted again. The `Used` state is persisted **before** the identity and
//! key are created: a crash in between leaves a consumed invite and no identity (fail
//! closed — issue a new invite), never a reusable one.

use std::fs;
use std::path::PathBuf;

use dmc_vault::ownership::auth::{enroll_statement, invite_token_hash};
use dmc_vault::ownership::{ClientPublicKey, SubjectId, TenantId};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::auth::client_auth::verify_signature;
use crate::auth::{Action, AuthService, IdentityId, Resource, SessionManager};
use crate::identity::{SessionId, now_unix_ms};
use crate::ownership::ClientKeyDirectory;
use crate::{Error, Result};

pub const INVITES_FILE: &str = "invites.json";
pub const MAX_FAILED_ATTEMPTS: u32 = 5;
/// Upper bound for an invite's lifetime.
pub const MAX_INVITE_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1000;
const FORMAT: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InviteState {
    Pending,
    Used,
    Burned,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InviteRecord {
    pub invite_id: String,
    #[serde(with = "hex32")]
    pub token_hash: [u8; 32],
    pub name: String,
    pub tenant: TenantId,
    pub subject: SubjectId,
    pub created_by: IdentityId,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub state: InviteState,
    pub failed_attempts: u32,
}

/// Returned once to the operator. The token is the only secret; `Debug` is redacted.
pub struct IssuedInvite {
    pub invite_id: String,
    pub token: Zeroizing<Vec<u8>>,
    pub name: String,
    pub tenant: TenantId,
    pub subject: SubjectId,
    pub expires_at_ms: u64,
}

impl std::fmt::Debug for IssuedInvite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedInvite")
            .field("invite_id", &self.invite_id)
            .field("subject", &self.subject)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Default, Serialize, Deserialize)]
struct InvitesFile {
    format_version: u32,
    invites: Vec<InviteRecord>,
}

#[derive(Debug)]
pub struct InviteStore {
    path: PathBuf,
    invites: Vec<InviteRecord>,
    clock_ms: Option<u64>,
}

impl InviteStore {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let path = dir.into().join(INVITES_FILE);
        let invites = match fs::read(&path) {
            Ok(raw) => {
                let f: InvitesFile = serde_json::from_slice(&raw)
                    .map_err(|e| Error::Conflict(format!("invites decode: {e}")))?;
                if f.format_version != FORMAT {
                    return Err(Error::Conflict("unsupported invites format".into()));
                }
                f.invites
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(Error::Conflict(format!("invites read: {e}"))),
        };
        Ok(Self {
            path,
            invites,
            clock_ms: None,
        })
    }

    pub fn set_clock_ms(&mut self, now: Option<u64>) {
        self.clock_ms = now;
    }

    fn now(&self) -> u64 {
        self.clock_ms.unwrap_or_else(now_unix_ms)
    }

    fn persist(&self) -> Result<()> {
        let raw = serde_json::to_vec_pretty(&InvitesFile {
            format_version: FORMAT,
            invites: self.invites.clone(),
        })
        .map_err(|e| Error::Conflict(format!("invites encode: {e}")))?;
        dmc_vault::secure_fs::write_secret_file(&self.path, &raw)
            .map_err(|e| Error::Conflict(format!("invites write: {e}")))
    }

    pub fn list(&self) -> &[InviteRecord] {
        &self.invites
    }

    /// Operator issues an invite. Requires grant `CREATE` on `Resource::System`.
    pub fn create(
        &mut self,
        auth: &AuthService,
        operator_session: &SessionId,
        name: &str,
        tenant: TenantId,
        ttl_ms: u64,
    ) -> Result<IssuedInvite> {
        let principal = auth.principal_for(operator_session)?;
        if !auth
            .grants()
            .has_grant(&principal.identity_id, &Resource::System, Action::Create)
        {
            return Err(Error::KeyAccessDenied("creating invites needs CREATE on system".into()));
        }
        if ttl_ms == 0 || ttl_ms > MAX_INVITE_TTL_MS {
            return Err(Error::Conflict("invite ttl out of range".into()));
        }
        if name.trim().is_empty()
            || auth.identities().get_by_name(name).is_some()
            || self
                .invites
                .iter()
                .any(|i| i.name == name && i.state == InviteState::Pending && i.expires_at_ms > self.now())
        {
            return Err(Error::Conflict("identity name unavailable".into()));
        }
        let mut token = Zeroizing::new(vec![0u8; 32]);
        rand::fill(token.as_mut_slice());
        let mut id = [0u8; 16];
        rand::fill(&mut id);
        let now = self.now();
        let record = InviteRecord {
            invite_id: hex::encode(id),
            token_hash: invite_token_hash(&token),
            name: name.to_string(),
            tenant: tenant.clone(),
            subject: SubjectId::random(),
            created_by: principal.identity_id,
            created_at_ms: now,
            expires_at_ms: now + ttl_ms,
            state: InviteState::Pending,
            failed_attempts: 0,
        };
        let issued = IssuedInvite {
            invite_id: record.invite_id.clone(),
            token,
            name: record.name.clone(),
            tenant,
            subject: record.subject,
            expires_at_ms: record.expires_at_ms,
        };
        self.invites.push(record);
        self.persist()?;
        Ok(issued)
    }

    /// Client claims an invite with its own key bundle and proof of possession.
    /// Returns the new identity and its subject. All failures are `AuthenticationFailed`.
    pub fn enroll(
        &mut self,
        auth: &mut AuthService,
        dir: &mut ClientKeyDirectory,
        invite_id: &str,
        token: &[u8],
        key: ClientPublicKey,
        signature: &[u8],
    ) -> Result<(IdentityId, SubjectId)> {
        let failed = || Error::AuthenticationFailed("enrollment failed".into());
        let now = self.now();
        let idx = self
            .invites
            .iter()
            .position(|i| i.invite_id == invite_id)
            .ok_or_else(failed)?;
        {
            let inv = &mut self.invites[idx];
            if inv.state == InviteState::Pending && now >= inv.expires_at_ms {
                inv.state = InviteState::Burned;
                self.persist()?;
                return Err(failed());
            }
        }
        let inv = self.invites[idx].clone();
        let token_ok: bool = invite_token_hash(token).ct_eq(&inv.token_hash).into();
        if inv.state != InviteState::Pending || !token_ok {
            return Err(failed());
        }
        // From here the caller knows the token: wrong proofs count towards burning.
        let proof_ok = key.validate().is_ok()
            && key.can_authenticate()
            && key.key_version == 1
            && key.subject == inv.subject
            && key.tenant == inv.tenant
            && dir.active_bundle(inv.subject).is_none()
            && key.auth_public_key.is_some_and(|auth_pk| {
                let statement = enroll_statement(
                    &inv.invite_id,
                    &inv.token_hash,
                    inv.subject,
                    &inv.tenant,
                    &inv.name,
                    &key.fingerprint(),
                );
                verify_signature(&auth_pk, &statement, signature)
            });
        if !proof_ok {
            let inv = &mut self.invites[idx];
            inv.failed_attempts += 1;
            if inv.failed_attempts >= MAX_FAILED_ATTEMPTS {
                inv.state = InviteState::Burned;
            }
            self.persist()?;
            return Err(failed());
        }
        // consume first (crash ⇒ consumed invite, no identity — never a reusable invite)
        self.invites[idx].state = InviteState::Used;
        self.persist()?;
        let identity_id = auth.create_client_identity(&inv.name, inv.tenant.clone(), inv.subject)?;
        dir.register_enrolled(key, now)?;
        Ok((identity_id, inv.subject))
    }
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let raw = hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)?;
        raw.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}
