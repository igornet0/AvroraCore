use std::fmt;

use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::error::{Error, Result};

/// Opaque data-subject identifier.
///
/// Random 128-bit value generated at enrollment. It is **not** derived from the
/// authentication account (name, `IdentityId`), so the value alone does not
/// reveal which user owns a record. The `IdentityId → SubjectId` mapping lives
/// only in the identity directory (see `dmc-security`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SubjectId([u8; 16]);

impl SubjectId {
    pub fn random() -> Self {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let raw = hex::decode(s.trim()).map_err(|_| Error::Format("subject id is not hex".into()))?;
        let bytes: [u8; 16] = raw
            .try_into()
            .map_err(|_| Error::Format("subject id must be 16 bytes".into()))?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for SubjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SubjectId({})", self.to_hex())
    }
}

impl fmt::Display for SubjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for SubjectId {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for SubjectId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Tenant (isolation domain). Bound into every envelope and record AAD.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TenantId(String);

pub const MAX_TENANT_LEN: usize = 128;

impl TenantId {
    pub fn new(raw: impl Into<String>) -> Result<Self> {
        let raw = raw.into();
        if raw.is_empty()
            || raw.len() > MAX_TENANT_LEN
            || raw.chars().any(|c| c.is_control() || c == '/')
        {
            return Err(Error::Format(format!("invalid tenant id `{raw}`")));
        }
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TenantId {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl From<TenantId> for String {
    fn from(value: TenantId) -> Self {
        value.0
    }
}

impl fmt::Debug for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TenantId({})", self.0)
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_ids_are_random_and_roundtrip() {
        let a = SubjectId::random();
        let b = SubjectId::random();
        assert_ne!(a, b);
        assert_eq!(SubjectId::from_hex(&a.to_hex()).unwrap(), a);
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(serde_json::from_str::<SubjectId>(&json).unwrap(), a);
    }

    #[test]
    fn tenant_validation() {
        assert!(TenantId::new("acme").is_ok());
        assert!(TenantId::new("").is_err());
        assert!(TenantId::new("a/b").is_err());
        assert!(TenantId::new("a\nb").is_err());
        assert!(serde_json::from_str::<TenantId>("\"x/y\"").is_err());
    }
}
