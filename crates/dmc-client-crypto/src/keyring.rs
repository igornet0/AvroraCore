//! Client-side key hierarchy and record encryption for CLIENT_OWNED data.
//!
//! ```text
//! device root ──► X25519 (sk on device, pk on server)
//!                    │ HPKE open
//!   server stores:  OwnDataKey envelopes (DEK v1, v2, … sealed to pk)
//!                    ▼
//!                  DEK vN ──► SealedRecord v2, domain = CLIENT (same AEAD/format as server)
//! ```
//!
//! Every plaintext ↔ ciphertext transformation happens here, on the client. The server
//! only receives sealed records and envelopes.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use dmc_vault::KeyMaterial;
use dmc_vault::ownership::auth::KeyRotationProof;
use dmc_vault::ownership::{
    ClientKeyEnvelope, ClientPublicKey, KeyDomain, RecordContext, RecordHeader, SubjectId,
    open_record_in, seal_record_in,
};

use crate::error::{Error, Result};
use crate::identity::ClientIdentity;
use crate::state::ClientState;

pub struct ClientKeyring {
    identity: ClientIdentity,
    own: BTreeMap<u32, KeyMaterial>,
    delegated: HashMap<(SubjectId, u32), KeyMaterial>,
}

impl fmt::Debug for ClientKeyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientKeyring")
            .field("subject", &self.identity.subject())
            .field("own_versions", &self.own.keys().collect::<Vec<_>>())
            .field("delegated", &self.delegated.len())
            .field("keys", &"[REDACTED]")
            .finish()
    }
}

impl ClientKeyring {
    /// Fresh keyring: creates DEK v1 and returns the envelope to upload.
    pub fn create(identity: ClientIdentity, state: &mut ClientState) -> Result<(Self, ClientKeyEnvelope)> {
        let mut ring = Self {
            identity,
            own: BTreeMap::new(),
            delegated: HashMap::new(),
        };
        let env = ring.new_data_key(state)?;
        Ok((ring, env))
    }

    /// Rebuild from envelopes fetched from the (untrusted) server.
    ///
    /// Envelopes not addressed to this key are ignored; envelopes that are addressed to
    /// it but fail to open are an error (tampering). If the server withholds own key
    /// versions this client has already seen, loading fails (rollback).
    pub fn load(
        identity: ClientIdentity,
        envelopes: &[ClientKeyEnvelope],
        state: &mut ClientState,
    ) -> Result<Self> {
        let me = identity.subject();
        let mut own = BTreeMap::new();
        let mut delegated = HashMap::new();
        for env in envelopes {
            if env.recipient != me {
                continue;
            }
            let dek = identity.open_envelope(env)?;
            if env.owner == me {
                own.insert(env.key_version, dek);
            } else {
                delegated.insert((env.owner, env.key_version), dek);
            }
        }
        let offered = own.keys().next_back().copied().unwrap_or(0);
        if offered < state.highest_own_version() {
            return Err(Error::Rollback {
                seen: state.highest_own_version(),
                offered,
            });
        }
        state.raise_own_version(offered)?;
        Ok(Self {
            identity,
            own,
            delegated,
        })
    }

    pub fn subject(&self) -> SubjectId {
        self.identity.subject()
    }

    pub fn public_key(&self) -> ClientPublicKey {
        self.identity.public_key()
    }

    pub fn active_version(&self) -> Result<u32> {
        self.own
            .keys()
            .next_back()
            .copied()
            .ok_or_else(|| Error::MissingKey {
                owner: self.subject().to_hex(),
                version: 0,
            })
    }

    /// Rotate the client key bundle (X25519 + Ed25519, version + 1). Returns the new
    /// bundle, the continuity / possession proof to send with it, and envelopes re-sealing
    /// every own DEK to the new encryption key.
    pub fn rotate_identity_key(&mut self) -> Result<(ClientPublicKey, KeyRotationProof, Vec<ClientKeyEnvelope>)> {
        let (pk, proof) = self.identity.rotate_keys()?;
        let envs = self
            .own
            .iter()
            .map(|(v, dek)| self.identity.seal_dek_to(&pk, self.subject(), *v, dek))
            .collect::<Result<Vec<_>>>()?;
        Ok((pk, proof, envs))
    }

    pub fn identity(&self) -> &ClientIdentity {
        &self.identity
    }

    /// Rotation: new DEK version (used for all new writes). Upload the returned envelope
    /// before writing records with it.
    pub fn new_data_key(&mut self, state: &mut ClientState) -> Result<ClientKeyEnvelope> {
        let version = self.own.keys().next_back().copied().unwrap_or(0) + 1;
        let dek = KeyMaterial::random();
        let env = self
            .identity
            .seal_dek_to(&self.identity.public_key(), self.subject(), version, &dek)?;
        self.own.insert(version, dek);
        state.raise_own_version(version)?;
        Ok(env)
    }

    fn ctx(&self, owner: SubjectId, object_id: &str, record_version: u64) -> RecordContext {
        RecordContext {
            tenant: self.identity.tenant().clone(),
            owner,
            object_id: object_id.to_string(),
            record_version,
        }
    }

    /// `seal(owner = self, object, plaintext, context)` — CLIENT domain, format v2.
    pub fn seal(&self, object_id: &str, record_version: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        let v = self.active_version()?;
        Ok(seal_record_in(
            KeyDomain::Client,
            &self.own[&v],
            v,
            &self.ctx(self.subject(), object_id, record_version),
            plaintext,
        )?)
    }

    /// `open(ciphertext, context)` — own records or records delegated to this client.
    pub fn open(&self, owner: SubjectId, object_id: &str, sealed: &[u8]) -> Result<Vec<u8>> {
        let header = RecordHeader::parse(sealed)?;
        if header.domain != KeyDomain::Client || header.owner != owner {
            return Err(dmc_vault::ownership::Error::ContextMismatch.into());
        }
        let missing = || Error::MissingKey {
            owner: owner.to_hex(),
            version: header.key_version,
        };
        let dek = if owner == self.subject() {
            self.own.get(&header.key_version).ok_or_else(missing)?
        } else {
            self.delegated
                .get(&(owner, header.key_version))
                .ok_or_else(missing)?
        };
        Ok(open_record_in(
            KeyDomain::Client,
            dek,
            &self.ctx(owner, object_id, header.record_version),
            sealed,
        )?)
    }

    /// Client-side re-encryption under the active key (server never sees plaintext).
    pub fn reencrypt(&self, object_id: &str, sealed: &[u8]) -> Result<Vec<u8>> {
        let header = RecordHeader::parse(sealed)?;
        let plain = zeroize::Zeroizing::new(self.open(self.subject(), object_id, sealed)?);
        self.seal(object_id, header.record_version + 1, &plain)
    }

    /// Asynchronous delegation: seal every own DEK version to `recipient`'s pinned key.
    /// `recipient` may be offline; the envelopes wait on the server.
    pub fn delegate_to(
        &self,
        recipient: &ClientPublicKey,
        state: &mut ClientState,
    ) -> Result<Vec<ClientKeyEnvelope>> {
        state.check_or_pin(recipient)?;
        if recipient.subject == self.subject() {
            return Err(Error::Format("cannot delegate to self".into()));
        }
        self.own
            .iter()
            .map(|(v, dek)| {
                self.identity
                    .seal_dek_to(recipient, self.subject(), *v, dek)
            })
            .collect()
    }

    pub fn has_delegated_from(&self, owner: SubjectId) -> bool {
        self.delegated.keys().any(|(o, _)| *o == owner)
    }
}

/// SQL helper: standard blob literal `X'…'` carrying a sealed value (ciphertext only).
pub fn sql_blob_literal(sealed: &[u8]) -> String {
    format!("X'{}'", hex::encode_upper(sealed))
}

/// SQL helper: decode a BLOB result cell rendered as `\x…` (or bare hex).
pub fn parse_sql_blob_cell(cell: &str) -> Result<Vec<u8>> {
    let hex_part = cell.strip_prefix("\\x").unwrap_or(cell);
    hex::decode(hex_part).map_err(|e| Error::Format(format!("blob cell: {e}")))
}

/// Object id convention for CLIENT_OWNED SQL values (names are known to the client;
/// catalog ids are not needed).
pub fn sql_client_object_id(table: &str, row_key: &str, column: &str) -> String {
    format!("sqlc/{table}/{row_key}/{column}")
}
