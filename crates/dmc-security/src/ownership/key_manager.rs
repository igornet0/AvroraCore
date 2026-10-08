//! KeyManager: the single place where subject keys are unwrapped and used.
//!
//! ```text
//! AuthService::authenticate_with_key_unlock()  → identity + CredentialUnlock
//! AuthService::create_session()                → SessionId
//! KeyManager::open_session(session, unlock)    → keyring unlocked in RAM (owner only)
//! KeyManager::seal / open_sealed (session, …)  → re-validates session + identity,
//!                                                 policy::decide, then AEAD
//! ```
//!
//! Security invariants:
//! * Authentication alone never unlocks anything; `open_session` needs the credential
//!   unlock *and* a live session of the same identity *and* the current credential id.
//! * Every key use re-checks the session and identity status. A revoked session or a
//!   disabled identity drops its unlocked keys immediately (fail closed).
//! * There is no method that unwraps a keyring without its owner's credential, no
//!   master/admin key, no key export and no plaintext fallback.
//! * Key metadata is persisted before any record can be sealed with it.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use dmc_vault::ownership::{
    CredentialUnlock, KeyState, KeyringStore, RecordContext, RecordHeader, SubjectId,
    SubjectKeyring, TenantId, UnlockedKeyring, open_record, seal_record,
};

use super::policy::{
    AllowReason, CryptoPrincipal, DelegationGrant, DelegationRegistry, KeyOp, decide,
};
use crate::auth::{AuthService, IdentityId, SessionManager};
use crate::identity::{SessionId, now_unix_ms};
use crate::{Error, Result};

pub const DELEGATIONS_FILE: &str = "delegations.json";

struct CryptoSession {
    principal: CryptoPrincipal,
    ring: SubjectKeyring,
    keys: UnlockedKeyring,
}

pub struct KeyManager {
    store: KeyringStore,
    delegations: DelegationRegistry,
    sessions: HashMap<String, CryptoSession>,
    clock_ms: Option<u64>,
}

impl fmt::Debug for KeyManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyManager")
            .field("dir", &self.store.dir())
            .field("open_sessions", &self.sessions.len())
            .finish()
    }
}

impl KeyManager {
    /// Open the keyring directory. Holds no keys until a subject opens a session.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let store = KeyringStore::open(dir.as_ref())?;
        let delegations = DelegationRegistry::open(dir.as_ref().join(DELEGATIONS_FILE))?;
        Ok(Self {
            store,
            delegations,
            sessions: HashMap::new(),
            clock_ms: None,
        })
    }

    pub fn set_clock_ms(&mut self, now: Option<u64>) {
        self.clock_ms = now;
    }

    fn now(&self) -> u64 {
        self.clock_ms.unwrap_or_else(now_unix_ms)
    }

    /// Create the keyring of a freshly enrolled identity (`AuthService::enroll_owner`).
    pub fn enroll(
        &mut self,
        auth: &AuthService,
        identity_id: &IdentityId,
        unlock: CredentialUnlock,
    ) -> Result<SubjectId> {
        let (subject, tenant) = subject_of(auth, identity_id)?;
        if auth.current_credential_id(identity_id).as_deref() != Some(unlock.credential_id()) {
            return Err(Error::KeyAccessDenied("credential is not current".into()));
        }
        if self.store.exists(subject) {
            return Err(Error::Conflict(format!("keyring for subject {subject} already exists")));
        }
        let (ring, _keys) = SubjectKeyring::create(subject, tenant, &unlock, self.now())?;
        self.store.create(&ring)?;
        Ok(subject)
    }

    /// Unlock the caller's own keyring for an authenticated session.
    pub fn open_session(
        &mut self,
        auth: &AuthService,
        session_id: &SessionId,
        unlock: CredentialUnlock,
    ) -> Result<CryptoPrincipal> {
        let session = auth.validate_session(session_id)?;
        let identity_id = session.identity_id.clone();
        let (subject, tenant) = subject_of(auth, &identity_id)?;
        let current = auth.current_credential_id(&identity_id);
        if current.as_deref() != Some(unlock.credential_id()) {
            return Err(Error::KeyAccessDenied("credential is not current".into()));
        }
        let mut ring = self.store.load(subject)?;
        if ring.tenant != tenant {
            return Err(Error::KeyAccessDenied("keyring tenant mismatch".into()));
        }
        let mut keys = ring.unlock(&unlock)?;
        let now = self.now();

        // Crash recovery: finish a rotation whose new key was persisted but not promoted.
        if ring.has_incomplete_rotation() {
            let base = ring.generation;
            ring.complete_rotation(&keys, now)?;
            self.store.save(&ring, base)?;
        }
        // Drop KEK envelopes of superseded credentials (e.g. after a password change).
        let base = ring.generation;
        if ring.retain_credentials(&keys, &[unlock.credential_id()])? {
            self.store.save(&ring, base)?;
        }
        // Drop delegated keys whose grant was revoked or expired.
        let stale: Vec<SubjectId> = ring
            .delegated
            .iter()
            .map(|d| d.owner)
            .filter(|owner| !self.delegations.has_live(*owner, subject, &tenant, now))
            .collect();
        for owner in stale {
            let base = ring.generation;
            ring.remove_delegated_keys(&mut keys, owner)?;
            self.store.save(&ring, base)?;
        }

        let principal = CryptoPrincipal {
            identity_id,
            session_id: session_id.clone(),
            subject,
            tenant,
        };
        self.sessions.insert(
            session_id.as_str().to_string(),
            CryptoSession {
                principal: principal.clone(),
                ring,
                keys,
            },
        );
        Ok(principal)
    }

    /// Drop the session's keys from RAM (zeroized on drop).
    pub fn close_session(&mut self, session_id: &SessionId) -> bool {
        self.sessions.remove(session_id.as_str()).is_some()
    }

    pub fn open_session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Re-validate the auth session and identity; drop keys if either is no longer live.
    fn live_principal(&mut self, auth: &AuthService, session_id: &SessionId) -> Result<CryptoPrincipal> {
        let principal = match self.sessions.get(session_id.as_str()) {
            Some(s) => s.principal.clone(),
            None => return Err(Error::KeyAccessDenied("no crypto session".into())),
        };
        let still_valid = auth
            .validate_session(session_id)
            .ok()
            .filter(|s| s.identity_id == principal.identity_id)
            .and_then(|_| auth.identities().get(&principal.identity_id))
            .is_some_and(|i| i.is_active() && i.subject_id == Some(principal.subject));
        if !still_valid {
            self.sessions.remove(session_id.as_str());
            return Err(Error::KeyAccessDenied("session or identity no longer valid".into()));
        }
        Ok(principal)
    }

    /// Authorization decision for `op` on `owner`'s keys.
    pub fn authorize(
        &mut self,
        auth: &AuthService,
        session_id: &SessionId,
        owner: SubjectId,
        op: KeyOp,
    ) -> Result<AllowReason> {
        let principal = self.live_principal(auth, session_id)?;
        let owner_tenant = auth
            .identities()
            .get_by_subject(owner)
            .and_then(|i| i.tenant.clone());
        decide(
            &principal,
            owner,
            owner_tenant.as_ref(),
            op,
            &self.delegations,
            self.now(),
        )
        .require(op)
    }

    /// Encrypt a record of `owner` (owner only) under the active DEK.
    pub fn seal(
        &mut self,
        auth: &AuthService,
        session_id: &SessionId,
        owner: SubjectId,
        object_id: &str,
        record_version: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        self.authorize(auth, session_id, owner, KeyOp::Write)?;
        let s = self.session(session_id)?;
        let version = s.ring.active_version()?;
        let ctx = RecordContext {
            tenant: s.principal.tenant.clone(),
            owner,
            object_id: object_id.to_string(),
            record_version,
        };
        Ok(seal_record(s.keys.data_key(version)?, version, &ctx, plaintext)?)
    }

    /// Decrypt a record of `owner` (owner, or delegated reader).
    pub fn open_sealed(
        &mut self,
        auth: &AuthService,
        session_id: &SessionId,
        owner: SubjectId,
        object_id: &str,
        sealed: &[u8],
    ) -> Result<Vec<u8>> {
        let reason = self.authorize(auth, session_id, owner, KeyOp::Read)?;
        let header = RecordHeader::parse(sealed)?;
        if header.owner != owner {
            return Err(dmc_vault::ownership::Error::ContextMismatch.into());
        }
        let s = self.session(session_id)?;
        let ctx = RecordContext {
            tenant: s.principal.tenant.clone(),
            owner,
            object_id: object_id.to_string(),
            record_version: header.record_version,
        };
        let dek = match reason {
            AllowReason::Owner => s.keys.data_key(header.key_version)?,
            AllowReason::Delegated => s.keys.delegated_key(owner, header.key_version)?,
        };
        Ok(open_record(dek, &ctx, sealed)?)
    }

    pub fn active_key_version(&self, session_id: &SessionId) -> Result<u32> {
        Ok(self.session(session_id)?.ring.active_version()?)
    }

    pub fn key_state(&self, session_id: &SessionId, version: u32) -> Result<Option<KeyState>> {
        Ok(self.session(session_id)?.ring.state_of(version))
    }

    // ── key lifecycle ─────────────────────────────────────────────────────────

    /// Rotation step 1: persist a new DEK as ROTATING (not yet used for writes).
    pub fn begin_data_key_rotation(&mut self, auth: &AuthService, session_id: &SessionId) -> Result<u32> {
        let owner = self.own_subject(session_id)?;
        self.authorize(auth, session_id, owner, KeyOp::ManageKeys)?;
        let now = self.now();
        let s = self.session_mut(session_id)?;
        let base = s.ring.generation;
        let mut ring = s.ring.clone();
        let version = ring.begin_rotation(&mut s.keys, now)?;
        self.store.save(&ring, base)?;
        self.session_mut(session_id)?.ring = ring;
        Ok(version)
    }

    /// Rotation step 2: promote ROTATING → ACTIVE, previous ACTIVE → RETIRED.
    pub fn complete_data_key_rotation(
        &mut self,
        auth: &AuthService,
        session_id: &SessionId,
    ) -> Result<Option<u32>> {
        let owner = self.own_subject(session_id)?;
        self.authorize(auth, session_id, owner, KeyOp::ManageKeys)?;
        let now = self.now();
        let s = self.session_mut(session_id)?;
        let base = s.ring.generation;
        let mut ring = s.ring.clone();
        let promoted = ring.complete_rotation(&s.keys, now)?;
        if promoted.is_some() {
            self.store.save(&ring, base)?;
            self.session_mut(session_id)?.ring = ring;
        }
        Ok(promoted)
    }

    /// New writes use a fresh DEK; existing records stay readable under their version.
    pub fn rotate_data_key(&mut self, auth: &AuthService, session_id: &SessionId) -> Result<u32> {
        let v = self.begin_data_key_rotation(auth, session_id)?;
        self.complete_data_key_rotation(auth, session_id)?;
        Ok(v)
    }

    /// Crypto-shred a RETIRED key version that no stored record references any more.
    pub fn destroy_retired_key(
        &mut self,
        auth: &AuthService,
        session_id: &SessionId,
        version: u32,
        live_references: u64,
    ) -> Result<()> {
        let owner = self.own_subject(session_id)?;
        self.authorize(auth, session_id, owner, KeyOp::ManageKeys)?;
        let s = self.session_mut(session_id)?;
        let base = s.ring.generation;
        let mut ring = s.ring.clone();
        ring.destroy_retired(&mut s.keys, version, live_references)?;
        self.store.save(&ring, base)?;
        self.session_mut(session_id)?.ring = ring;
        Ok(())
    }

    /// Password change step: add the new credential's KEK envelope (persisted).
    /// Old envelopes are pruned on the next `open_session` with the new credential.
    pub fn add_credential(
        &mut self,
        auth: &AuthService,
        session_id: &SessionId,
        new_unlock: &CredentialUnlock,
    ) -> Result<()> {
        let owner = self.own_subject(session_id)?;
        self.authorize(auth, session_id, owner, KeyOp::ManageKeys)?;
        let now = self.now();
        let s = self.session_mut(session_id)?;
        let base = s.ring.generation;
        let mut ring = s.ring.clone();
        ring.set_credential(&s.keys, new_unlock, now)?;
        self.store.save(&ring, base)?;
        self.session_mut(session_id)?.ring = ring;
        Ok(())
    }

    // ── delegation (online: owner and grantee sessions both open) ─────────────

    /// Owner grants the grantee read access to every current DEK version.
    pub fn delegate_read(
        &mut self,
        auth: &AuthService,
        owner_session: &SessionId,
        grantee_session: &SessionId,
        expires_at_ms: Option<u64>,
    ) -> Result<()> {
        let owner = self.own_subject(owner_session)?;
        self.authorize(auth, owner_session, owner, KeyOp::Delegate)?;
        let grantee = self.live_principal(auth, grantee_session)?;
        let owner_principal = self.session(owner_session)?.principal.clone();
        if grantee.tenant != owner_principal.tenant {
            return Err(Error::KeyAccessDenied("delegation across tenants".into()));
        }
        if grantee.subject == owner {
            return Err(Error::KeyAccessDenied("cannot delegate to self".into()));
        }
        let now = self.now();
        self.delegations.grant(DelegationGrant {
            owner,
            grantee: grantee.subject,
            tenant: owner_principal.tenant.clone(),
            granted_at_ms: now,
            expires_at_ms,
        })?;
        // Take the grantee session out so the owner's keys can be borrowed alongside it.
        let mut g = self
            .sessions
            .remove(grantee_session.as_str())
            .ok_or_else(|| Error::KeyAccessDenied("no crypto session".into()))?;
        let result = (|| {
            let owner_keys = &self.session(owner_session)?.keys;
            let base = g.ring.generation;
            let mut ring = g.ring.clone();
            ring.add_delegated_keys(&mut g.keys, owner_keys, now)?;
            self.store.save(&ring, base)?;
            g.ring = ring;
            Ok(())
        })();
        self.sessions.insert(grantee_session.as_str().to_string(), g);
        result
    }

    /// Owner revokes a delegation. Takes effect immediately for authorization; the
    /// grantee's delegated envelopes are deleted at its next session open.
    pub fn revoke_delegation(
        &mut self,
        auth: &AuthService,
        owner_session: &SessionId,
        grantee: SubjectId,
    ) -> Result<bool> {
        let owner = self.own_subject(owner_session)?;
        self.authorize(auth, owner_session, owner, KeyOp::Delegate)?;
        let revoked = self.delegations.revoke(owner, grantee)?;
        for s in self.sessions.values_mut() {
            if s.principal.subject == grantee && s.keys.has_delegated_from(owner) {
                let base = s.ring.generation;
                let mut ring = s.ring.clone();
                ring.remove_delegated_keys(&mut s.keys, owner)?;
                self.store.save(&ring, base)?;
                s.ring = ring;
            }
        }
        Ok(revoked)
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    fn session(&self, session_id: &SessionId) -> Result<&CryptoSession> {
        self.sessions
            .get(session_id.as_str())
            .ok_or_else(|| Error::KeyAccessDenied("no crypto session".into()))
    }

    fn session_mut(&mut self, session_id: &SessionId) -> Result<&mut CryptoSession> {
        self.sessions
            .get_mut(session_id.as_str())
            .ok_or_else(|| Error::KeyAccessDenied("no crypto session".into()))
    }

    fn own_subject(&self, session_id: &SessionId) -> Result<SubjectId> {
        Ok(self.session(session_id)?.principal.subject)
    }
}

fn subject_of(auth: &AuthService, identity_id: &IdentityId) -> Result<(SubjectId, TenantId)> {
    let identity = auth
        .identities()
        .get(identity_id)
        .ok_or_else(|| Error::UnknownIdentity(identity_id.as_str().to_string()))?;
    if !identity.is_active() {
        return Err(Error::IdentityDisabled(identity_id.as_str().to_string()));
    }
    if identity.custody != crate::auth::KeyCustody::Server {
        return Err(Error::KeyAccessDenied(
            "CLIENT_OWNED subject: keys are held by the client, not by the server".into(),
        ));
    }
    match (identity.subject_id, identity.tenant.clone()) {
        (Some(s), Some(t)) => Ok((s, t)),
        _ => Err(Error::KeyAccessDenied(
            "identity is not enrolled for data ownership".into(),
        )),
    }
}
