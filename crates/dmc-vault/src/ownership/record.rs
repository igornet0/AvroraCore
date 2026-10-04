//! Sealed record: the only form in which owned user payload reaches storage.
//!
//! ```text
//! v1 (SERVER_OWNED, unchanged):
//! "AVSR" | fmt=1 | alg u8 | key_version u32 | owner 16B | record_version u64 | nonce 12B | ct+tag
//! v2 (adds an authenticated key domain):
//! "AVSR" | fmt=2 | alg u8 | domain u8 | key_version u32 | owner 16B | record_version u64 | nonce 12B | ct+tag
//! └──────────────────────────────── header (cleartext) ────────────────────────────────┘
//! AAD = domain-tag ‖ header ‖ lp(tenant) ‖ lp(object_id)
//! ```
//!
//! The header is readable without keys (needed to pick the DEK and to count key-version
//! references for safe key destruction). Tenant and object id are *not* stored in the
//! record but bound through AAD: decrypting under another tenant/object context fails.
//!
//! The key domain separates the two key hierarchies:
//! * [`KeyDomain::Server`] — keys unwrapped inside AvroraCore by `KeyManager` (v1 or v2);
//! * [`KeyDomain::Client`] — keys that exist only in AvroraClient (v2 only). AvroraCore can
//!   parse the header and check structure, never decrypt.
//!
//! Because the domain byte is part of the AAD, relabelling a record's domain breaks it.

use std::fmt;

use super::envelope::push_lp;
use super::error::{Error, Result};
use super::ids::{SubjectId, TenantId};
use crate::crypto::{AeadBlob, decrypt, encrypt};
use crate::key::KeyMaterial;

pub const RECORD_MAGIC: &[u8; 4] = b"AVSR";
pub const RECORD_FORMAT_V1: u8 = 1;
pub const RECORD_FORMAT_V2: u8 = 2;
pub const ALG_ID_AES256GCM: u8 = 1;
/// v1 header length (kept for compatibility).
pub const HEADER_LEN: usize = 4 + 1 + 1 + 4 + 16 + 8;
pub const HEADER_LEN_V2: usize = HEADER_LEN + 1;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const AAD_DOMAIN: &[u8] = b"avrora/sealed-record/v1\0";
pub const MAX_OBJECT_ID_LEN: usize = 1024;

/// Which key hierarchy a record belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyDomain {
    /// SERVER_OWNED: subject keys unwrapped in the database process (`KeyManager`).
    Server,
    /// CLIENT_OWNED: subject keys exist only on the client.
    Client,
}

impl KeyDomain {
    fn tag(self) -> u8 {
        match self {
            Self::Server => 1,
            Self::Client => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::Server),
            2 => Ok(Self::Client),
            other => Err(Error::Format(format!("unknown key domain {other}"))),
        }
    }
}

/// Cleartext header of a sealed record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordHeader {
    pub format: u8,
    pub domain: KeyDomain,
    pub key_version: u32,
    pub owner: SubjectId,
    pub record_version: u64,
}

impl RecordHeader {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 5 || &bytes[0..4] != RECORD_MAGIC {
            return Err(Error::Format("not a sealed record".into()));
        }
        let format = bytes[4];
        let (domain, off) = match format {
            RECORD_FORMAT_V1 => (KeyDomain::Server, 6),
            RECORD_FORMAT_V2 => {
                if bytes.len() < 7 {
                    return Err(Error::Format("sealed record too short".into()));
                }
                (KeyDomain::from_tag(bytes[6])?, 7)
            }
            other => return Err(Error::Format(format!("unsupported record format {other}"))),
        };
        if bytes.len() < header_len(format) + NONCE_LEN + TAG_LEN {
            return Err(Error::Format("sealed record too short".into()));
        }
        if bytes[5] != ALG_ID_AES256GCM {
            return Err(Error::Format(format!("unsupported record alg {}", bytes[5])));
        }
        let key_version = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        let owner = SubjectId::from_bytes(bytes[off + 4..off + 20].try_into().unwrap());
        let record_version = u64::from_le_bytes(bytes[off + 20..off + 28].try_into().unwrap());
        Ok(Self {
            format,
            domain,
            key_version,
            owner,
            record_version,
        })
    }

    pub fn len(&self) -> usize {
        header_len(self.format)
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN_V2);
        out.extend_from_slice(RECORD_MAGIC);
        out.push(self.format);
        out.push(ALG_ID_AES256GCM);
        if self.format == RECORD_FORMAT_V2 {
            out.push(self.domain.tag());
        }
        out.extend_from_slice(&self.key_version.to_le_bytes());
        out.extend_from_slice(self.owner.as_bytes());
        out.extend_from_slice(&self.record_version.to_le_bytes());
        out
    }
}

fn header_len(format: u8) -> usize {
    if format == RECORD_FORMAT_V2 { HEADER_LEN_V2 } else { HEADER_LEN }
}

/// Context every record is bound to. All fields must match on decrypt.
#[derive(Clone, PartialEq, Eq)]
pub struct RecordContext {
    pub tenant: TenantId,
    pub owner: SubjectId,
    pub object_id: String,
    pub record_version: u64,
}

impl fmt::Debug for RecordContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordContext")
            .field("tenant", &self.tenant)
            .field("owner", &self.owner)
            .field("object_id", &self.object_id)
            .field("record_version", &self.record_version)
            .finish()
    }
}

impl RecordContext {
    fn validate(&self) -> Result<()> {
        if self.object_id.is_empty() || self.object_id.len() > MAX_OBJECT_ID_LEN {
            return Err(Error::Format("invalid object id".into()));
        }
        Ok(())
    }

    fn aad(&self, header: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + header.len() + 64);
        aad.extend_from_slice(AAD_DOMAIN);
        aad.extend_from_slice(header);
        push_lp(&mut aad, self.tenant.as_str().as_bytes());
        push_lp(&mut aad, self.object_id.as_bytes());
        aad
    }
}

fn seal_with(header: RecordHeader, dek: &KeyMaterial, ctx: &RecordContext, plaintext: &[u8]) -> Result<Vec<u8>> {
    ctx.validate()?;
    let header = header.encode();
    let blob = encrypt(dek, plaintext, &ctx.aad(&header))
        .map_err(|_| Error::Format("record encrypt failed".into()))?;
    let mut out = Vec::with_capacity(header.len() + NONCE_LEN + blob.ciphertext.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&blob.nonce);
    out.extend_from_slice(&blob.ciphertext);
    Ok(out)
}

/// SERVER_OWNED (format v1, unchanged): encrypt under `dek` with a fresh random nonce.
pub fn seal_record(
    dek: &KeyMaterial,
    key_version: u32,
    ctx: &RecordContext,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    seal_with(
        RecordHeader {
            format: RECORD_FORMAT_V1,
            domain: KeyDomain::Server,
            key_version,
            owner: ctx.owner,
            record_version: ctx.record_version,
        },
        dek,
        ctx,
        plaintext,
    )
}

/// Format v2 with an explicit, authenticated key domain.
pub fn seal_record_in(
    domain: KeyDomain,
    dek: &KeyMaterial,
    key_version: u32,
    ctx: &RecordContext,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    seal_with(
        RecordHeader {
            format: RECORD_FORMAT_V2,
            domain,
            key_version,
            owner: ctx.owner,
            record_version: ctx.record_version,
        },
        dek,
        ctx,
        plaintext,
    )
}

/// Decrypt a SERVER_OWNED record (v1 or v2/server). Client-domain records are refused.
pub fn open_record(dek: &KeyMaterial, ctx: &RecordContext, sealed: &[u8]) -> Result<Vec<u8>> {
    open_record_in(KeyDomain::Server, dek, ctx, sealed)
}

/// Decrypt a record that must belong to `domain`. Header must match `ctx`; AEAD must
/// verify. No fallback.
pub fn open_record_in(
    domain: KeyDomain,
    dek: &KeyMaterial,
    ctx: &RecordContext,
    sealed: &[u8],
) -> Result<Vec<u8>> {
    ctx.validate()?;
    let header = RecordHeader::parse(sealed)?;
    if header.domain != domain {
        return Err(Error::ContextMismatch);
    }
    if header.owner != ctx.owner || header.record_version != ctx.record_version {
        return Err(Error::ContextMismatch);
    }
    let hlen = header.len();
    let nonce: [u8; NONCE_LEN] = sealed[hlen..hlen + NONCE_LEN].try_into().unwrap();
    let blob = AeadBlob {
        nonce,
        ciphertext: sealed[hlen + NONCE_LEN..].to_vec(),
    };
    decrypt(dek, &blob, &ctx.aad(&sealed[..hlen])).map_err(|_| Error::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"VERY_SECRET_TEST_PAYLOAD";

    fn ctx(owner: SubjectId) -> RecordContext {
        RecordContext {
            tenant: TenantId::new("acme").unwrap(),
            owner,
            object_id: "notes/1".into(),
            record_version: 1,
        }
    }

    #[test]
    fn roundtrip_and_no_plaintext_in_bytes() {
        let dek = KeyMaterial::random();
        let c = ctx(SubjectId::random());
        let sealed = seal_record(&dek, 3, &c, SECRET).unwrap();
        assert!(!sealed.windows(SECRET.len()).any(|w| w == SECRET));
        let h = RecordHeader::parse(&sealed).unwrap();
        assert_eq!((h.key_version, h.owner, h.record_version), (3, c.owner, 1));
        assert_eq!(open_record(&dek, &c, &sealed).unwrap(), SECRET);
    }

    #[test]
    fn nonces_are_unique() {
        let dek = KeyMaterial::random();
        let c = ctx(SubjectId::random());
        let a = seal_record(&dek, 1, &c, SECRET).unwrap();
        let b = seal_record(&dek, 1, &c, SECRET).unwrap();
        assert_ne!(a[HEADER_LEN..HEADER_LEN + 12], b[HEADER_LEN..HEADER_LEN + 12]);
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_key_tamper_and_context_fail() {
        let dek = KeyMaterial::random();
        let c = ctx(SubjectId::random());
        let sealed = seal_record(&dek, 1, &c, SECRET).unwrap();

        assert_eq!(
            open_record(&KeyMaterial::random(), &c, &sealed),
            Err(Error::DecryptFailed)
        );
        for i in [HEADER_LEN, HEADER_LEN + 12, sealed.len() - 1] {
            let mut t = sealed.clone();
            t[i] ^= 0x01;
            assert_eq!(open_record(&dek, &c, &t), Err(Error::DecryptFailed));
        }
        let mut header_edit = sealed.clone();
        header_edit[6] ^= 0x01; // key_version
        assert_eq!(open_record(&dek, &c, &header_edit), Err(Error::DecryptFailed));

        let mut other_tenant = c.clone();
        other_tenant.tenant = TenantId::new("evil").unwrap();
        assert_eq!(open_record(&dek, &other_tenant, &sealed), Err(Error::DecryptFailed));
        let mut other_object = c.clone();
        other_object.object_id = "notes/2".into();
        assert_eq!(open_record(&dek, &other_object, &sealed), Err(Error::DecryptFailed));
        let mut other_owner = c.clone();
        other_owner.owner = SubjectId::random();
        assert_eq!(open_record(&dek, &other_owner, &sealed), Err(Error::ContextMismatch));
        let mut other_version = c.clone();
        other_version.record_version = 2;
        assert_eq!(open_record(&dek, &other_version, &sealed), Err(Error::ContextMismatch));
        assert!(open_record(&dek, &c, &sealed[..20]).is_err());
    }

    #[test]
    fn v2_client_domain_roundtrip_and_domain_separation() {
        let dek = KeyMaterial::random();
        let c = ctx(SubjectId::random());
        let sealed = seal_record_in(KeyDomain::Client, &dek, 4, &c, SECRET).unwrap();
        let h = RecordHeader::parse(&sealed).unwrap();
        assert_eq!((h.format, h.domain, h.key_version), (RECORD_FORMAT_V2, KeyDomain::Client, 4));
        assert_eq!(open_record_in(KeyDomain::Client, &dek, &c, &sealed).unwrap(), SECRET);
        // a server-domain opener refuses client records even with the right key
        assert_eq!(open_record(&dek, &c, &sealed), Err(Error::ContextMismatch));
        // relabelling the domain byte breaks authentication
        let mut relabelled = sealed.clone();
        relabelled[6] = 1;
        assert_eq!(open_record(&dek, &c, &relabelled), Err(Error::DecryptFailed));
        // v1 records still parse as server domain
        let v1 = seal_record(&dek, 1, &c, SECRET).unwrap();
        assert_eq!(RecordHeader::parse(&v1).unwrap().domain, KeyDomain::Server);
        assert_eq!(open_record_in(KeyDomain::Client, &dek, &c, &v1), Err(Error::ContextMismatch));
    }
}
