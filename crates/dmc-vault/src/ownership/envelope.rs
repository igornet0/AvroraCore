//! Versioned key envelope: one secret key AEAD-wrapped under another.
//!
//! All metadata (format, kind, tenant, owner, holder, key id/version, algorithm,
//! wrapping-key reference) is bound into the AES-256-GCM associated data, so moving an
//! envelope to another subject/tenant/slot or editing any field makes `open` fail.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::error::{Error, Result};
use super::ids::{SubjectId, TenantId};
use crate::crypto::{AeadBlob, decrypt, encrypt};
use crate::key::KeyMaterial;

pub const ENVELOPE_FORMAT_V1: u16 = 1;
pub const ALG_AES256GCM: &str = "aes-256-gcm";
const AAD_DOMAIN: &[u8] = b"avrora/key-envelope/v1\0";

/// What the wrapped key is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeKind {
    /// Subject KEK wrapped under a credential-derived key.
    SubjectKek,
    /// Subject DEK wrapped under the subject KEK.
    DataKey,
    /// Another subject's DEK wrapped under the holder's KEK (delegated read access).
    DelegatedDataKey,
}

impl EnvelopeKind {
    fn tag(self) -> u8 {
        match self {
            Self::SubjectKek => 1,
            Self::DataKey => 2,
            Self::DelegatedDataKey => 3,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEnvelope {
    pub format_version: u16,
    pub kind: EnvelopeKind,
    pub tenant: TenantId,
    /// Subject that owns the wrapped key.
    pub owner: SubjectId,
    /// Subject whose key (credential or KEK) wraps it. Equals `owner` except for delegation.
    pub holder: SubjectId,
    /// Version of the wrapped key (KEK epoch or DEK version).
    pub key_version: u32,
    pub alg: String,
    /// Reference to the wrapping key, e.g. `credential:<id>` or `kek:<epoch>`.
    pub wrapped_by: String,
    pub created_at_ms: u64,
    #[serde(with = "hex_nonce")]
    pub nonce: [u8; 12],
    #[serde(with = "hex_vec")]
    pub wrapped_key: Vec<u8>,
}

/// Inputs bound into an envelope (everything except the ciphertext).
pub struct EnvelopeSpec<'a> {
    pub kind: EnvelopeKind,
    pub tenant: &'a TenantId,
    pub owner: SubjectId,
    pub holder: SubjectId,
    pub key_version: u32,
    pub wrapped_by: String,
    pub created_at_ms: u64,
}

impl KeyEnvelope {
    pub fn key_id(&self) -> String {
        format!(
            "{}:{}:{}",
            match self.kind {
                EnvelopeKind::SubjectKek => "kek",
                EnvelopeKind::DataKey => "dek",
                EnvelopeKind::DelegatedDataKey => "delegated-dek",
            },
            self.owner,
            self.key_version
        )
    }

    pub fn seal(spec: EnvelopeSpec<'_>, wrapping: &KeyMaterial, secret: &KeyMaterial) -> Result<Self> {
        let mut env = Self {
            format_version: ENVELOPE_FORMAT_V1,
            kind: spec.kind,
            tenant: spec.tenant.clone(),
            owner: spec.owner,
            holder: spec.holder,
            key_version: spec.key_version,
            alg: ALG_AES256GCM.to_string(),
            wrapped_by: spec.wrapped_by,
            created_at_ms: spec.created_at_ms,
            nonce: [0u8; 12],
            wrapped_key: Vec::new(),
        };
        let blob = encrypt(wrapping, secret.as_bytes(), &env.aad())
            .map_err(|_| Error::Format("envelope encrypt failed".into()))?;
        env.nonce = blob.nonce;
        env.wrapped_key = blob.ciphertext;
        Ok(env)
    }

    /// Unwrap. Any field edit, wrong wrapping key or modified ciphertext → error.
    pub fn open(&self, wrapping: &KeyMaterial) -> Result<KeyMaterial> {
        if self.format_version != ENVELOPE_FORMAT_V1 {
            return Err(Error::Format(format!(
                "unsupported envelope format {}",
                self.format_version
            )));
        }
        if self.alg != ALG_AES256GCM {
            return Err(Error::Format(format!("unsupported envelope alg {}", self.alg)));
        }
        let blob = AeadBlob {
            nonce: self.nonce,
            ciphertext: self.wrapped_key.clone(),
        };
        let bytes = zeroize::Zeroizing::new(
            decrypt(wrapping, &blob, &self.aad()).map_err(|_| Error::DecryptFailed)?,
        );
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::Format("wrapped key length".into()))?;
        Ok(KeyMaterial::from_bytes(arr))
    }

    fn aad(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(AAD_DOMAIN);
        out.extend_from_slice(&self.format_version.to_le_bytes());
        out.push(self.kind.tag());
        push_lp(&mut out, self.tenant.as_str().as_bytes());
        out.extend_from_slice(self.owner.as_bytes());
        out.extend_from_slice(self.holder.as_bytes());
        out.extend_from_slice(&self.key_version.to_le_bytes());
        push_lp(&mut out, self.alg.as_bytes());
        push_lp(&mut out, self.wrapped_by.as_bytes());
        out.extend_from_slice(&self.created_at_ms.to_le_bytes());
        out
    }
}

pub(crate) fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

impl fmt::Debug for KeyEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyEnvelope")
            .field("format_version", &self.format_version)
            .field("kind", &self.kind)
            .field("tenant", &self.tenant)
            .field("owner", &self.owner)
            .field("holder", &self.holder)
            .field("key_version", &self.key_version)
            .field("alg", &self.alg)
            .field("wrapped_by", &self.wrapped_by)
            .field("wrapped_key", &format_args!("<{} bytes>", self.wrapped_key.len()))
            .finish()
    }
}

mod hex_nonce {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(n: &[u8; 12], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(n))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 12], D::Error> {
        let raw = hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)?;
        raw.try_into()
            .map_err(|_| serde::de::Error::custom("nonce must be 12 bytes"))
    }
}

mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(tenant: &TenantId, owner: SubjectId) -> EnvelopeSpec<'_> {
        EnvelopeSpec {
            kind: EnvelopeKind::DataKey,
            tenant,
            owner,
            holder: owner,
            key_version: 1,
            wrapped_by: "kek:1".into(),
            created_at_ms: 7,
        }
    }

    #[test]
    fn roundtrip_and_wrong_key() {
        let tenant = TenantId::new("t1").unwrap();
        let owner = SubjectId::random();
        let kek = KeyMaterial::random();
        let dek = KeyMaterial::random();
        let env = KeyEnvelope::seal(spec(&tenant, owner), &kek, &dek).unwrap();
        assert_eq!(env.open(&kek).unwrap().as_bytes(), dek.as_bytes());
        assert!(matches!(env.open(&KeyMaterial::random()), Err(Error::DecryptFailed)));
    }

    #[test]
    fn any_metadata_edit_breaks_open() {
        let tenant = TenantId::new("t1").unwrap();
        let owner = SubjectId::random();
        let kek = KeyMaterial::random();
        let env = KeyEnvelope::seal(spec(&tenant, owner), &kek, &KeyMaterial::random()).unwrap();

        let edits: Vec<Box<dyn Fn(&mut KeyEnvelope)>> = vec![
            Box::new(|e| e.tenant = TenantId::new("t2").unwrap()),
            Box::new(|e| e.owner = SubjectId::random()),
            Box::new(|e| e.holder = SubjectId::random()),
            Box::new(|e| e.key_version = 2),
            Box::new(|e| e.kind = EnvelopeKind::SubjectKek),
            Box::new(|e| e.wrapped_by = "kek:2".into()),
            Box::new(|e| e.created_at_ms = 8),
            Box::new(|e| e.wrapped_key[0] ^= 1),
            Box::new(|e| e.nonce[0] ^= 1),
        ];
        for edit in edits {
            let mut tampered = env.clone();
            edit(&mut tampered);
            assert!(tampered.open(&kek).is_err());
        }
    }

    #[test]
    fn debug_hides_ciphertext() {
        let tenant = TenantId::new("t1").unwrap();
        let env = KeyEnvelope::seal(
            spec(&tenant, SubjectId::random()),
            &KeyMaterial::random(),
            &KeyMaterial::random(),
        )
        .unwrap();
        let shown = format!("{env:?}");
        assert!(!shown.contains(&hex::encode(&env.wrapped_key)));
        assert!(shown.contains("<48 bytes>"));
    }
}
