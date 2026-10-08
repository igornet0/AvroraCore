//! EncryptedStorage: owned records go through the KeyManager before any backend.
//!
//! The backend receives only sealed bytes, so every layer behind it (WAL, segments,
//! snapshots, compaction, backups, temp files) can only ever persist ciphertext for
//! owned data — independent of whether that layer itself encrypts.
//!
//! Privileged/operational access (`raw_sealed`, `keys`, `key_version_references`) works
//! on ciphertext and cleartext headers only.
//!
//! Two write paths share one storage format:
//! * `put` — sealing inside this process via [`KeyManager`] (current server-side model);
//! * `put_sealed` — ciphertext sealed elsewhere (prepared for client-side encryption);
//!   no key is needed or used here.

use std::collections::{BTreeMap, HashMap};

use dmc_vault::ownership::{KeyDomain, RecordHeader, SubjectId};

use super::key_manager::KeyManager;
use crate::auth::AuthService;
use crate::identity::SessionId;
use crate::{Error, Result};

/// Byte store for sealed records. Implementations never see plaintext.
pub trait RecordBackend {
    fn put(&mut self, key: &str, sealed: &[u8]) -> Result<()>;
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn keys(&self) -> Result<Vec<String>>;
}

/// In-memory backend (tests / caches of ciphertext).
#[derive(Clone, Debug, Default)]
pub struct MemoryRecordBackend {
    records: BTreeMap<String, Vec<u8>>,
}

impl RecordBackend for MemoryRecordBackend {
    fn put(&mut self, key: &str, sealed: &[u8]) -> Result<()> {
        self.records.insert(key.to_string(), sealed.to_vec());
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.records.get(key).cloned())
    }

    fn keys(&self) -> Result<Vec<String>> {
        Ok(self.records.keys().cloned().collect())
    }
}

/// Storage key of an owned object: `{subject}/{object_id}` (subject is opaque).
pub fn storage_key(owner: SubjectId, object_id: &str) -> String {
    format!("{owner}/{object_id}")
}

pub struct EncryptedStorage<B: RecordBackend> {
    backend: B,
}

impl<B: RecordBackend> EncryptedStorage<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn into_backend(self) -> B {
        self.backend
    }

    /// authorize(Write) → resolve active key → seal → backend. Returns the record version.
    pub fn put(
        &mut self,
        keys: &mut KeyManager,
        auth: &AuthService,
        session: &SessionId,
        owner: SubjectId,
        object_id: &str,
        plaintext: &[u8],
    ) -> Result<u64> {
        validate_object_id(object_id)?;
        let key = storage_key(owner, object_id);
        let version = match self.backend.get(&key)? {
            Some(prev) => RecordHeader::parse(&prev)?.record_version + 1,
            None => 1,
        };
        let sealed = keys.seal(auth, session, owner, object_id, version, plaintext)?;
        self.backend.put(&key, &sealed)?;
        Ok(version)
    }

    /// backend → authorize(Read) → resolve key by header version → open. Fails closed.
    pub fn get(
        &self,
        keys: &mut KeyManager,
        auth: &AuthService,
        session: &SessionId,
        owner: SubjectId,
        object_id: &str,
    ) -> Result<Vec<u8>> {
        validate_object_id(object_id)?;
        let sealed = self
            .backend
            .get(&storage_key(owner, object_id))?
            .ok_or_else(|| Error::KeyAccessDenied("record not found".into()))?;
        keys.open_sealed(auth, session, owner, object_id, &sealed)
    }

    /// Store a record that was sealed **outside** this process (client-side encryption).
    ///
    /// The server never sees the plaintext or the key. It checks only what it can check
    /// without a key: the session is live, its identity is active and owns `owner`
    /// (same tenant), the record is well-formed, names `owner` in its header and carries
    /// the next record version. Whether the ciphertext really was produced with the
    /// owner's key is verified by whoever decrypts it (AEAD), not here.
    pub fn put_sealed(
        &mut self,
        auth: &AuthService,
        session: &SessionId,
        owner: SubjectId,
        object_id: &str,
        sealed: &[u8],
    ) -> Result<u64> {
        validate_object_id(object_id)?;
        let custody = authorize_ciphertext_write(auth, session, owner)?;
        let header = RecordHeader::parse(sealed)?;
        if header.owner != owner {
            return Err(Error::KeyAccessDenied("record header names another owner".into()));
        }
        // The two key hierarchies never mix: the record's authenticated key domain must
        // match the owner's custody (CLIENT_OWNED ⇒ format v2, domain CLIENT).
        let expected = match custody {
            crate::auth::KeyCustody::Server => KeyDomain::Server,
            crate::auth::KeyCustody::Client => KeyDomain::Client,
        };
        if header.domain != expected {
            return Err(Error::KeyAccessDenied("record key domain does not match owner custody".into()));
        }
        let key = storage_key(owner, object_id);
        let expected = match self.backend.get(&key)? {
            Some(prev) => RecordHeader::parse(&prev)?.record_version + 1,
            None => 1,
        };
        if header.record_version != expected {
            return Err(Error::KeyAccessDenied(format!(
                "record version {} (expected {expected})",
                header.record_version
            )));
        }
        self.backend.put(&key, sealed)?;
        Ok(expected)
    }

    /// Ciphertext for an authorized reader (owner or delegated grantee per `policy`).
    /// Never decrypts: CLIENT_OWNED records are opened only by the client.
    pub fn get_sealed(
        &self,
        auth: &AuthService,
        session: &SessionId,
        owner: SubjectId,
        object_id: &str,
        policy: &dyn super::client_directory::CiphertextReadPolicy,
    ) -> Result<Vec<u8>> {
        validate_object_id(object_id)?;
        policy.may_read(auth, session, owner)?;
        self.backend
            .get(&storage_key(owner, object_id))?
            .ok_or_else(|| Error::KeyAccessDenied("record not found".into()))
    }

    /// Ciphertext as stored (operational access; never decrypts).
    pub fn raw_sealed(&self, owner: SubjectId, object_id: &str) -> Result<Option<Vec<u8>>> {
        self.backend.get(&storage_key(owner, object_id))
    }

    /// Records per key version for `owner`, from cleartext headers (safe key destruction).
    pub fn key_version_references(&self, owner: SubjectId) -> Result<HashMap<u32, u64>> {
        let prefix = format!("{owner}/");
        let mut refs = HashMap::new();
        for key in self.backend.keys()? {
            if !key.starts_with(&prefix) {
                continue;
            }
            if let Some(bytes) = self.backend.get(&key)? {
                let header = RecordHeader::parse(&bytes)?;
                *refs.entry(header.key_version).or_insert(0) += 1;
            }
        }
        Ok(refs)
    }

    /// Re-encrypt every record of `owner` under the active key (after rotation), so
    /// retired versions lose their last references and can be destroyed.
    pub fn reencrypt_owner(
        &mut self,
        keys: &mut KeyManager,
        auth: &AuthService,
        session: &SessionId,
        owner: SubjectId,
    ) -> Result<usize> {
        let prefix = format!("{owner}/");
        let active = keys.active_key_version(session)?;
        let mut n = 0;
        for key in self.backend.keys()? {
            let Some(object_id) = key.strip_prefix(&prefix) else {
                continue;
            };
            let Some(bytes) = self.backend.get(&key)? else {
                continue;
            };
            if RecordHeader::parse(&bytes)?.key_version == active {
                continue;
            }
            let plain = zeroize::Zeroizing::new(keys.open_sealed(auth, session, owner, object_id, &bytes)?);
            self.put(keys, auth, session, owner, object_id, &plain)?;
            n += 1;
        }
        Ok(n)
    }
}

/// Identity-level check for ciphertext-only writes (no key material involved).
fn authorize_ciphertext_write(
    auth: &AuthService,
    session: &SessionId,
    owner: SubjectId,
) -> Result<crate::auth::KeyCustody> {
    use crate::auth::SessionManager;
    let s = auth.validate_session(session)?;
    let identity = auth
        .identities()
        .get(&s.identity_id)
        .ok_or_else(|| Error::KeyAccessDenied("unknown identity".into()))?;
    if !identity.is_active() || identity.subject_id != Some(owner) {
        return Err(Error::KeyAccessDenied("only the owner may write its records".into()));
    }
    let owner_tenant = auth
        .identities()
        .get_by_subject(owner)
        .and_then(|i| i.tenant.clone());
    if owner_tenant.is_none() || owner_tenant != identity.tenant {
        return Err(Error::KeyAccessDenied("tenant mismatch".into()));
    }
    Ok(identity.custody)
}

fn validate_object_id(object_id: &str) -> Result<()> {
    if object_id.is_empty() || object_id.len() > 512 || object_id.contains('\0') {
        return Err(Error::KeyAccessDenied("invalid object id".into()));
    }
    Ok(())
}
