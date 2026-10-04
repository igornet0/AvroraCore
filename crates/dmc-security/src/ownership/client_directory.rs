//! Server-side store for CLIENT_OWNED key material — public and wrapped data only.
//!
//! Holds:
//! * one [`ClientPublicKey`] per client-custody subject (immutable once registered);
//! * [`ClientKeyEnvelope`]s (DEKs HPKE-sealed to a recipient public key);
//! * delegation grants (policy for who may fetch envelopes and ciphertext).
//!
//! Nothing here can be opened by the server: it has no private keys and no code path
//! that uses one. Checks are identity-level only (session live, identity active,
//! custody = Client, subject/tenant match) plus structural validation of envelopes.
//!
//! The server is untrusted for confidentiality. These checks stop honest mistakes and
//! other users; they do **not** stop a malicious server from serving a wrong public key —
//! clients defend against that with TOFU pins (`dmc-client-crypto::ClientState`).

use std::fs;
use std::path::PathBuf;

use dmc_vault::ownership::auth::{KeyRotationProof, rotation_statement};
use dmc_vault::ownership::{
    ClientEnvelopeKind, ClientKeyEnvelope, ClientPublicKey, PublicKeyStatus, ServerStoredPublicKey,
    SubjectId, TenantId,
};
use serde::{Deserialize, Serialize};

use crate::auth::client_auth::verify_signature;
use crate::auth::{AuthService, IdentityId, KeyCustody, SessionManager};
use crate::identity::{SessionId, now_unix_ms};
use crate::{Error, Result};

pub const CLIENT_DIRECTORY_FILE: &str = "client-directory.json";
const FORMAT: u32 = 2;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientGrant {
    pub owner: SubjectId,
    pub grantee: SubjectId,
    pub tenant: TenantId,
    pub granted_at_ms: u64,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct DirectoryFile {
    format_version: u32,
    /// v1 only (single immutable key per subject); migrated to `keys` on load.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    public_keys: Vec<ClientPublicKey>,
    #[serde(default)]
    keys: Vec<ServerStoredPublicKey>,
    envelopes: Vec<ClientKeyEnvelope>,
    grants: Vec<ClientGrant>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientPrincipal {
    pub identity_id: IdentityId,
    pub subject: SubjectId,
    pub tenant: TenantId,
}

/// Identity-level authority of a CLIENT_OWNED session (no key material involved).
pub fn client_principal(auth: &AuthService, session: &SessionId) -> Result<ClientPrincipal> {
    let s = auth.validate_session(session)?;
    let identity = auth
        .identities()
        .get(&s.identity_id)
        .ok_or_else(|| Error::KeyAccessDenied("unknown identity".into()))?;
    if !identity.is_active() {
        return Err(Error::IdentityDisabled(identity.id.as_str().to_string()));
    }
    if identity.custody != KeyCustody::Client {
        return Err(Error::KeyAccessDenied("not a CLIENT_OWNED identity".into()));
    }
    match (identity.subject_id, identity.tenant.clone()) {
        (Some(subject), Some(tenant)) => Ok(ClientPrincipal {
            identity_id: identity.id.clone(),
            subject,
            tenant,
        }),
        _ => Err(Error::KeyAccessDenied("identity has no subject".into())),
    }
}

/// Who may fetch ciphertext of `owner` (defence in depth; ciphertext is not secret-bearing).
pub trait CiphertextReadPolicy {
    fn may_read(&self, auth: &AuthService, session: &SessionId, owner: SubjectId) -> Result<()>;
}

#[derive(Debug)]
pub struct ClientKeyDirectory {
    path: PathBuf,
    file: DirectoryFile,
    clock_ms: Option<u64>,
}

impl ClientKeyDirectory {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        let path = dir.join(CLIENT_DIRECTORY_FILE);
        let file = match fs::read(&path) {
            Ok(raw) => {
                let mut f: DirectoryFile = serde_json::from_slice(&raw)
                    .map_err(|e| Error::Conflict(format!("client directory decode: {e}")))?;
                match f.format_version {
                    1 => {
                        f.keys = std::mem::take(&mut f.public_keys)
                            .into_iter()
                            .map(|k| ServerStoredPublicKey::new(k, 0))
                            .collect();
                        f.format_version = FORMAT;
                    }
                    FORMAT => {}
                    _ => return Err(Error::Conflict("unsupported client directory format".into())),
                }
                f
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => DirectoryFile {
                format_version: FORMAT,
                ..DirectoryFile::default()
            },
            Err(e) => return Err(Error::Conflict(format!("client directory read: {e}"))),
        };
        Ok(Self {
            path,
            file,
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
        let raw = serde_json::to_vec_pretty(&self.file)
            .map_err(|e| Error::Conflict(format!("client directory encode: {e}")))?;
        dmc_vault::secure_fs::write_secret_file(&self.path, &raw)
            .map_err(|e| Error::Conflict(format!("client directory write: {e}")))
    }

    /// Active key of `subject`.
    fn registered(&self, subject: SubjectId) -> Option<&ClientPublicKey> {
        self.file
            .keys
            .iter()
            .find(|k| k.key.subject == subject && k.status == PublicKeyStatus::Active)
            .map(|k| &k.key)
    }

    /// ACTIVE key bundle of `subject` (public data; used by authentication, which has no
    /// session yet).
    pub fn active_bundle(&self, subject: SubjectId) -> Option<&ClientPublicKey> {
        self.registered(subject)
    }

    fn grant_live(&self, owner: SubjectId, grantee: SubjectId, tenant: &TenantId) -> bool {
        let now = self.now();
        self.file.grants.iter().any(|g| {
            g.owner == owner
                && g.grantee == grantee
                && &g.tenant == tenant
                && g.expires_at_ms.is_none_or(|t| now < t)
        })
    }

    /// Register the caller's own public key. Immutable afterwards (re-registering the same
    /// key is a no-op; a different key is refused).
    pub fn register_public_key(
        &mut self,
        auth: &AuthService,
        session: &SessionId,
        key: ClientPublicKey,
    ) -> Result<()> {
        let p = client_principal(auth, session)?;
        key.validate()?;
        if key.subject != p.subject || key.tenant != p.tenant {
            return Err(Error::KeyAccessDenied("may only register own public key".into()));
        }
        if key.key_version != 1 {
            return Err(Error::Conflict("first registration must be key version 1; use rotate".into()));
        }
        match self.registered(p.subject) {
            Some(existing) if existing == &key => Ok(()),
            Some(_) => Err(Error::Conflict("public key already registered; use rotate".into())),
            None => {
                let now = self.now();
                self.file.keys.push(ServerStoredPublicKey::new(key, now));
                self.persist()
            }
        }
    }

    /// Register the first key bundle of a freshly enrolled subject (called by
    /// enrollment after the invite and the proof of possession were checked).
    pub(crate) fn register_enrolled(&mut self, key: ClientPublicKey, now: u64) -> Result<()> {
        key.validate()?;
        if self.registered(key.subject).is_some() {
            return Err(Error::Conflict("subject already has a key".into()));
        }
        self.file.keys.push(ServerStoredPublicKey::new(key, now));
        self.persist()
    }

    /// Owner rotates its key bundle: new version must be exactly active + 1 and carry an
    /// Ed25519 auth key. `proof.new_signature` (new auth key) proves possession; if the
    /// previous bundle had an auth key, `proof.old_signature` (old auth key) proves
    /// continuity. The previous bundle becomes RETIRED (kept, so envelopes sealed to it
    /// remain meaningful).
    pub fn rotate_public_key(
        &mut self,
        auth: &AuthService,
        session: &SessionId,
        key: ClientPublicKey,
        proof: &KeyRotationProof,
    ) -> Result<()> {
        let p = client_principal(auth, session)?;
        key.validate()?;
        if key.subject != p.subject || key.tenant != p.tenant {
            return Err(Error::KeyAccessDenied("may only rotate own public key".into()));
        }
        let current = self
            .registered(p.subject)
            .ok_or_else(|| Error::KeyAccessDenied("no registered key to rotate".into()))?
            .clone();
        if key.key_version != current.key_version + 1 {
            return Err(Error::Conflict("rotation must register version active+1".into()));
        }
        // no recycling of any earlier key material of this subject (active or retired),
        // compared on raw key bytes — fingerprints include the version
        let reused = self.file.keys.iter().filter(|k| k.key.subject == p.subject).any(|k| {
            k.key.public_key == key.public_key
                || (k.key.auth_public_key.is_some() && k.key.auth_public_key == key.auth_public_key)
        });
        if reused {
            return Err(Error::Conflict("rotation must use new key material".into()));
        }
        let new_auth = key
            .auth_public_key
            .filter(|_| key.can_authenticate())
            .ok_or_else(|| Error::Conflict("rotated bundle must carry an Ed25519 auth key".into()))?;
        let statement = rotation_statement(
            p.subject,
            &p.tenant,
            &current.fingerprint(),
            &key.fingerprint(),
            key.key_version,
        );
        if !verify_signature(&new_auth, &statement, &proof.new_signature) {
            return Err(Error::KeyAccessDenied("no proof of possession of the new auth key".into()));
        }
        if let Some(old_auth) = current.auth_public_key {
            let ok = proof
                .old_signature
                .as_deref()
                .is_some_and(|sig| verify_signature(&old_auth, &statement, sig));
            if !ok {
                return Err(Error::KeyAccessDenied("rotation not signed by the current auth key".into()));
            }
        }
        for k in &mut self.file.keys {
            if k.key.subject == p.subject && k.status == PublicKeyStatus::Active {
                k.status = PublicKeyStatus::Retired;
            }
        }
        let now = self.now();
        self.file.keys.push(ServerStoredPublicKey::new(key, now));
        self.persist()
    }

    /// All key versions of `subject` (active and retired) for a same-tenant client.
    pub fn public_keys(
        &self,
        auth: &AuthService,
        session: &SessionId,
        subject: SubjectId,
    ) -> Result<Vec<ServerStoredPublicKey>> {
        let p = client_principal(auth, session)?;
        let keys: Vec<_> = self
            .file
            .keys
            .iter()
            .filter(|k| k.key.subject == subject && k.key.tenant == p.tenant)
            .cloned()
            .collect();
        if keys.is_empty() {
            return Err(Error::KeyAccessDenied("no public key registered".into()));
        }
        Ok(keys)
    }

    /// Grants where the caller is owner or grantee.
    pub fn list_grants(&self, auth: &AuthService, session: &SessionId) -> Result<Vec<ClientGrant>> {
        let p = client_principal(auth, session)?;
        Ok(self
            .file
            .grants
            .iter()
            .filter(|g| (g.owner == p.subject || g.grantee == p.subject) && g.tenant == p.tenant)
            .cloned()
            .collect())
    }

    /// Public key of `subject` for a same-tenant client (e.g. to delegate to it).
    pub fn public_key(
        &self,
        auth: &AuthService,
        session: &SessionId,
        subject: SubjectId,
    ) -> Result<ClientPublicKey> {
        let p = client_principal(auth, session)?;
        let key = self
            .registered(subject)
            .ok_or_else(|| Error::KeyAccessDenied("no public key registered".into()))?;
        if key.tenant != p.tenant {
            return Err(Error::KeyAccessDenied("tenant mismatch".into()));
        }
        Ok(key.clone())
    }

    /// Owner grants `grantee` read access (policy part of delegation).
    pub fn grant(
        &mut self,
        auth: &AuthService,
        owner_session: &SessionId,
        grantee: SubjectId,
        expires_at_ms: Option<u64>,
    ) -> Result<()> {
        let p = client_principal(auth, owner_session)?;
        let target = self
            .registered(grantee)
            .ok_or_else(|| Error::KeyAccessDenied("grantee has no public key".into()))?;
        if target.tenant != p.tenant || grantee == p.subject {
            return Err(Error::KeyAccessDenied("invalid grantee".into()));
        }
        self.file
            .grants
            .retain(|g| !(g.owner == p.subject && g.grantee == grantee));
        self.file.grants.push(ClientGrant {
            owner: p.subject,
            grantee,
            tenant: p.tenant,
            granted_at_ms: self.now(),
            expires_at_ms,
        });
        self.persist()
    }

    /// Owner revokes: grant and stored envelopes for `grantee` are deleted. Keys the
    /// grantee already downloaded are not cryptographically revoked — rotate the DEK and
    /// re-encrypt client-side for that.
    pub fn revoke(&mut self, auth: &AuthService, owner_session: &SessionId, grantee: SubjectId) -> Result<bool> {
        let p = client_principal(auth, owner_session)?;
        let before = self.file.grants.len() + self.file.envelopes.len();
        self.file
            .grants
            .retain(|g| !(g.owner == p.subject && g.grantee == grantee));
        self.file
            .envelopes
            .retain(|e| !(e.owner == p.subject && e.recipient == grantee));
        let changed = before != self.file.grants.len() + self.file.envelopes.len();
        if changed {
            self.persist()?;
        }
        Ok(changed)
    }

    /// Store an envelope created by its owner. Append-only per (owner, recipient, version).
    pub fn put_envelope(
        &mut self,
        auth: &AuthService,
        session: &SessionId,
        env: ClientKeyEnvelope,
    ) -> Result<()> {
        let p = client_principal(auth, session)?;
        env.validate()?;
        if env.owner != p.subject || env.tenant != p.tenant {
            return Err(Error::KeyAccessDenied("only the owner may store its key envelopes".into()));
        }
        let recipient_key = self
            .registered(env.recipient)
            .ok_or_else(|| Error::KeyAccessDenied("recipient has no public key".into()))?;
        if recipient_key.fingerprint() != env.recipient_key_fingerprint {
            return Err(Error::KeyAccessDenied(
                "envelope must be sealed to the recipient's ACTIVE registered key".into(),
            ));
        }
        if env.kind == ClientEnvelopeKind::DelegatedDataKey
            && !self.grant_live(env.owner, env.recipient, &env.tenant)
        {
            return Err(Error::KeyAccessDenied("no delegation grant".into()));
        }
        if self.file.envelopes.iter().any(|e| {
            e.owner == env.owner
                && e.recipient == env.recipient
                && e.key_version == env.key_version
                && e.recipient_key_fingerprint == env.recipient_key_fingerprint
        }) {
            return Err(Error::Conflict("envelope version already stored".into()));
        }
        self.file.envelopes.push(env);
        self.persist()
    }

    /// Envelopes addressed to the caller: own keys always, delegated keys while granted.
    pub fn envelopes_for(&self, auth: &AuthService, session: &SessionId) -> Result<Vec<ClientKeyEnvelope>> {
        let p = client_principal(auth, session)?;
        Ok(self
            .file
            .envelopes
            .iter()
            .filter(|e| e.recipient == p.subject && e.tenant == p.tenant)
            .filter(|e| e.owner == p.subject || self.grant_live(e.owner, p.subject, &p.tenant))
            .cloned()
            .collect())
    }
}

impl CiphertextReadPolicy for ClientKeyDirectory {
    fn may_read(&self, auth: &AuthService, session: &SessionId, owner: SubjectId) -> Result<()> {
        let p = client_principal(auth, session)?;
        if p.subject == owner || self.grant_live(owner, p.subject, &p.tenant) {
            Ok(())
        } else {
            Err(Error::KeyAccessDenied("not owner and no delegation".into()))
        }
    }
}
