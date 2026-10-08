//! CLIENT_OWNED wire types shared by AvroraClient and AvroraCore.
//!
//! Only *public* or *already wrapped* material lives here. Creating or opening an
//! envelope needs an HPKE private key, which exists only in the client crate
//! (`dmc-client-crypto`). AvroraCore stores these values and checks their structure and
//! bindings; it has no code path that could open them.
//!
//! ```text
//! ClientPublicKey     subject's X25519 KEM public key (+ binding, fingerprint)
//! ClientKeyEnvelope   DEK sealed with HPKE (RFC 9180, base mode) to a recipient public key
//!                     info = canonical binding of every metadata field below
//! ```

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::envelope::push_lp;
use super::error::{Error, Result};
use super::ids::{SubjectId, TenantId};

/// HPKE ciphersuite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM (base mode).
pub const CLIENT_SUITE_V1: &str = "hpke-base/x25519-hkdf-sha256/hkdf-sha256/aes-256-gcm";
pub const CLIENT_WIRE_FORMAT_V1: u16 = 1;
/// Key bundle: X25519 encryption key **and** Ed25519 authentication key (D1).
pub const CLIENT_BUNDLE_FORMAT_V2: u16 = 2;
pub const X25519_PUBLIC_LEN: usize = 32;
pub const ED25519_PUBLIC_LEN: usize = 32;
/// Wrapped 32-byte DEK + 16-byte AES-GCM tag.
pub const WRAPPED_DEK_LEN: usize = 48;

/// A subject's public key bundle. Registered at enrollment; clients pin its fingerprint (TOFU).
///
/// * format 1: X25519 KEM key only (Stage 4). Cannot authenticate.
/// * format 2: X25519 KEM key (encryption only) + Ed25519 auth key (signatures only).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientPublicKey {
    pub format_version: u16,
    pub suite: String,
    pub subject: SubjectId,
    pub tenant: TenantId,
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    pub created_at_ms: u64,
    /// KEM key version of this subject (1, 2, … after rotation).
    #[serde(default = "first_version")]
    pub key_version: u32,
    /// Ed25519 authentication public key (format 2 only). Never used for encryption.
    #[serde(default, with = "opt_hex32")]
    pub auth_public_key: Option<[u8; 32]>,
}

fn first_version() -> u32 {
    1
}

impl ClientPublicKey {
    pub fn validate(&self) -> Result<()> {
        if self.suite != CLIENT_SUITE_V1 {
            return Err(Error::Format("unsupported client key suite".into()));
        }
        match (self.format_version, self.auth_public_key.is_some()) {
            (CLIENT_WIRE_FORMAT_V1, false) | (CLIENT_BUNDLE_FORMAT_V2, true) => {}
            _ => return Err(Error::Format("unsupported client key format".into())),
        }
        if self.public_key.len() != X25519_PUBLIC_LEN {
            return Err(Error::Format("client public key must be 32 bytes".into()));
        }
        if self.key_version == 0 {
            return Err(Error::Format("client key version starts at 1".into()));
        }
        Ok(())
    }

    /// Short key identifier (first 16 hex digits of the fingerprint).
    pub fn key_id(&self) -> String {
        hex::encode(&self.fingerprint()[..8])
    }

    /// Whether this bundle can be used for authentication (has an Ed25519 key).
    pub fn can_authenticate(&self) -> bool {
        self.format_version == CLIENT_BUNDLE_FORMAT_V2 && self.auth_public_key.is_some()
    }

    /// SHA-256 over the suite, subject, tenant and key bytes.
    ///
    /// Format 1 keeps its Stage-4 value (existing TOFU pins stay valid). Format 2 uses a
    /// separate domain and covers both keys and the key version.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        let mut buf = Vec::new();
        match self.auth_public_key {
            None => buf.extend_from_slice(b"avrora/client-public-key/v1\0"),
            Some(_) => buf.extend_from_slice(b"avrora/client-key-bundle/v2\0"),
        }
        push_lp(&mut buf, self.suite.as_bytes());
        buf.extend_from_slice(self.subject.as_bytes());
        push_lp(&mut buf, self.tenant.as_str().as_bytes());
        push_lp(&mut buf, &self.public_key);
        if let Some(auth) = &self.auth_public_key {
            push_lp(&mut buf, auth);
            buf.extend_from_slice(&self.key_version.to_be_bytes());
        }
        h.update(&buf);
        h.finalize().into()
    }

    /// Human-comparable fingerprint (8 groups of 8 hex digits) for out-of-band checks.
    pub fn fingerprint_display(&self) -> String {
        hex::encode(self.fingerprint())
            .as_bytes()
            .chunks(8)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl fmt::Debug for ClientPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientPublicKey")
            .field("subject", &self.subject)
            .field("tenant", &self.tenant)
            .field("fingerprint", &hex::encode(&self.fingerprint()[..8]))
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublicKeyStatus {
    /// Current key: new envelopes must be sealed to it.
    Active,
    /// Superseded by rotation: kept so existing envelopes stay meaningful.
    Retired,
}

/// What the server stores and returns for a public key.
///
/// `fingerprint` is recomputed by the server from the key bytes for display/indexing,
/// but clients must **not** trust it: they recompute it from `key` themselves and compare
/// with their pin or an out-of-band value.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerStoredPublicKey {
    pub key: ClientPublicKey,
    pub key_id: String,
    #[serde(with = "hex32")]
    pub fingerprint: [u8; 32],
    pub status: PublicKeyStatus,
    pub registered_at_ms: u64,
}

impl ServerStoredPublicKey {
    pub fn new(key: ClientPublicKey, registered_at_ms: u64) -> Self {
        Self {
            key_id: key.key_id(),
            fingerprint: key.fingerprint(),
            key,
            status: PublicKeyStatus::Active,
            registered_at_ms,
        }
    }
}

impl fmt::Debug for ServerStoredPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerStoredPublicKey")
            .field("key", &self.key)
            .field("status", &self.status)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientEnvelopeKind {
    /// Owner's DEK sealed to the owner's own public key (multi-device / recovery / restart).
    OwnDataKey,
    /// Owner's DEK sealed to another subject's public key (asynchronous delegation).
    DelegatedDataKey,
}

impl ClientEnvelopeKind {
    fn tag(self) -> u8 {
        match self {
            Self::OwnDataKey => 1,
            Self::DelegatedDataKey => 2,
        }
    }
}

/// A DEK sealed with HPKE to `recipient`'s public key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientKeyEnvelope {
    pub format_version: u16,
    pub suite: String,
    pub kind: ClientEnvelopeKind,
    pub tenant: TenantId,
    /// Subject that owns the DEK.
    pub owner: SubjectId,
    /// Subject whose public key the DEK is sealed to.
    pub recipient: SubjectId,
    /// Fingerprint of the exact recipient public key used (binds the key, not just the id).
    #[serde(with = "hex32")]
    pub recipient_key_fingerprint: [u8; 32],
    pub key_version: u32,
    pub created_at_ms: u64,
    /// HPKE encapsulated key.
    #[serde(with = "hex_bytes")]
    pub enc: Vec<u8>,
    /// HPKE ciphertext of the 32-byte DEK.
    #[serde(with = "hex_bytes")]
    pub ciphertext: Vec<u8>,
}

impl ClientKeyEnvelope {
    /// Canonical binding used as HPKE `info` *and* `aad`: every field except the
    /// encapsulated key and ciphertext. Any edit makes opening fail.
    pub fn binding(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160);
        out.extend_from_slice(b"avrora/client-key-envelope/v1\0");
        out.extend_from_slice(&self.format_version.to_le_bytes());
        push_lp(&mut out, self.suite.as_bytes());
        out.push(self.kind.tag());
        push_lp(&mut out, self.tenant.as_str().as_bytes());
        out.extend_from_slice(self.owner.as_bytes());
        out.extend_from_slice(self.recipient.as_bytes());
        out.extend_from_slice(&self.recipient_key_fingerprint);
        out.extend_from_slice(&self.key_version.to_le_bytes());
        out.extend_from_slice(&self.created_at_ms.to_le_bytes());
        out
    }

    /// Structure checks the server can do without any key.
    pub fn validate(&self) -> Result<()> {
        if self.format_version != CLIENT_WIRE_FORMAT_V1 || self.suite != CLIENT_SUITE_V1 {
            return Err(Error::Format("unsupported client envelope format/suite".into()));
        }
        if self.enc.len() != X25519_PUBLIC_LEN || self.ciphertext.len() != WRAPPED_DEK_LEN {
            return Err(Error::Format("malformed client envelope".into()));
        }
        let own = self.owner == self.recipient;
        match (self.kind, own) {
            (ClientEnvelopeKind::OwnDataKey, true) | (ClientEnvelopeKind::DelegatedDataKey, false) => {
                Ok(())
            }
            _ => Err(Error::Format("envelope kind does not match owner/recipient".into())),
        }
    }
}

impl fmt::Debug for ClientKeyEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientKeyEnvelope")
            .field("kind", &self.kind)
            .field("tenant", &self.tenant)
            .field("owner", &self.owner)
            .field("recipient", &self.recipient)
            .field("key_version", &self.key_version)
            .field("ciphertext", &format_args!("<{} bytes>", self.ciphertext.len()))
            .finish()
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

mod opt_hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_some(&hex::encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        match Option::<String>::deserialize(d)? {
            None => Ok(None),
            Some(h) => {
                let raw = hex::decode(h).map_err(serde::de::Error::custom)?;
                raw.try_into()
                    .map(Some)
                    .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(subject: SubjectId) -> ClientPublicKey {
        ClientPublicKey {
            format_version: CLIENT_WIRE_FORMAT_V1,
            suite: CLIENT_SUITE_V1.into(),
            subject,
            tenant: TenantId::new("acme").unwrap(),
            public_key: vec![9u8; 32],
            created_at_ms: 1,
            key_version: 1,
            auth_public_key: None,
        }
    }

    #[test]
    fn bundle_v2_fingerprint_covers_auth_key_and_v1_is_unchanged() {
        let v1 = pk(SubjectId::random());
        let v1_fp = v1.fingerprint();
        let mut v2 = v1.clone();
        v2.format_version = CLIENT_BUNDLE_FORMAT_V2;
        v2.auth_public_key = Some([7u8; 32]);
        assert!(v2.validate().is_ok() && v2.can_authenticate() && !v1.can_authenticate());
        assert_ne!(v1_fp, v2.fingerprint(), "separate domain");
        let mut other_auth = v2.clone();
        other_auth.auth_public_key = Some([8u8; 32]);
        assert_ne!(v2.fingerprint(), other_auth.fingerprint(), "auth key is bound");
        // format/key mismatch is rejected
        let mut bad = v1.clone();
        bad.auth_public_key = Some([7u8; 32]);
        assert!(bad.validate().is_err());
        let mut bad2 = v2.clone();
        bad2.auth_public_key = None;
        assert!(bad2.validate().is_err());
        // JSON without the field (Stage-4 records) still parses as format 1
        let mut json: serde_json::Value = serde_json::to_value(&v1).unwrap();
        json.as_object_mut().unwrap().remove("auth_public_key");
        let parsed: ClientPublicKey = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.fingerprint(), v1_fp);
        // JSON round trip keeps the auth key (directory file format)
        let back: ClientPublicKey = serde_json::from_slice(&serde_json::to_vec(&v2).unwrap()).unwrap();
        assert_eq!(back, v2);
    }

    #[test]
    fn key_version_defaults_to_one_and_zero_is_invalid() {
        let a = pk(SubjectId::random());
        let mut json: serde_json::Value = serde_json::to_value(&a).unwrap();
        json.as_object_mut().unwrap().remove("key_version");
        let old: ClientPublicKey = serde_json::from_value(json).unwrap();
        assert_eq!(old.key_version, 1, "pre-versioning records are version 1");
        let mut zero = a.clone();
        zero.key_version = 0;
        assert!(zero.validate().is_err());
    }

    #[test]
    fn fingerprint_binds_subject_tenant_and_key() {
        let s = SubjectId::random();
        let a = pk(s);
        assert!(a.validate().is_ok());
        let mut b = a.clone();
        b.public_key[0] ^= 1;
        assert_ne!(a.fingerprint(), b.fingerprint());
        let mut c = a.clone();
        c.subject = SubjectId::random();
        assert_ne!(a.fingerprint(), c.fingerprint());
        assert_eq!(a.fingerprint_display().split(' ').count(), 8);
        let mut bad = a.clone();
        bad.public_key.pop();
        assert!(bad.validate().is_err());
    }
}
