//! Byte strings signed by CLIENT_OWNED Ed25519 authentication keys.
//!
//! Pure and key-free: the client builds these to sign, the server rebuilds them to verify.
//! Every statement starts with its own NUL-terminated domain label, and no label is a
//! prefix of another, so a signature made for one purpose cannot be replayed as another
//! (challenge ≠ enrollment ≠ rotation ≠ HTTP request). The X25519 encryption key never
//! signs anything.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::envelope::push_lp;
use super::error::{Error, Result};
use super::ids::{SubjectId, TenantId};

pub const CHALLENGE_DOMAIN: &[u8] = b"avrora/client-owned/auth-challenge/v1\0";
pub const ENROLL_DOMAIN: &[u8] = b"avrora/client-owned/enroll/v1\0";
pub const ROTATE_DOMAIN: &[u8] = b"avrora/client-owned/rotate/v1\0";
pub const HTTP_REQUEST_DOMAIN: &[u8] = b"avrora/client-owned/http-request/v1\0";
const INVITE_TOKEN_DOMAIN: &[u8] = b"avrora/invite/v1\0";

/// Maximum challenge lifetime accepted by clients and issued by servers.
pub const CHALLENGE_TTL_MS: u64 = 60_000;

/// Fields of an authentication challenge (§4.3 of `client-owned-authentication.md`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub server_instance: [u8; 16],
    pub transport: String,
    pub channel: String,
    pub nonce: [u8; 32],
    pub subject: SubjectId,
    pub tenant: TenantId,
    pub key_version: u32,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

impl Challenge {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = CHALLENGE_DOMAIN.to_vec();
        out.extend_from_slice(&self.server_instance);
        push_lp(&mut out, self.transport.as_bytes());
        push_lp(&mut out, self.channel.as_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(self.subject.as_bytes());
        push_lp(&mut out, self.tenant.as_str().as_bytes());
        out.extend_from_slice(&self.key_version.to_be_bytes());
        out.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        out
    }

    /// Strict parse: the client signs only well-formed challenges (never arbitrary bytes).
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let bad = || Error::Format("malformed authentication challenge".into());
        let mut r = Reader { b: bytes };
        if r.take(CHALLENGE_DOMAIN.len()).ok_or_else(bad)? != CHALLENGE_DOMAIN {
            return Err(bad());
        }
        let server_instance = r.array::<16>().ok_or_else(bad)?;
        let transport = r.lp_str().ok_or_else(bad)?;
        let channel = r.lp_str().ok_or_else(bad)?;
        let nonce = r.array::<32>().ok_or_else(bad)?;
        let subject = SubjectId::from_bytes(r.array::<16>().ok_or_else(bad)?);
        let tenant = TenantId::new(r.lp_str().ok_or_else(bad)?).map_err(|_| bad())?;
        let key_version = u32::from_be_bytes(r.array::<4>().ok_or_else(bad)?);
        let issued_at_ms = u64::from_be_bytes(r.array::<8>().ok_or_else(bad)?);
        let expires_at_ms = u64::from_be_bytes(r.array::<8>().ok_or_else(bad)?);
        if !r.b.is_empty() || expires_at_ms <= issued_at_ms || expires_at_ms - issued_at_ms > CHALLENGE_TTL_MS {
            return Err(bad());
        }
        Ok(Self {
            server_instance,
            transport,
            channel,
            nonce,
            subject,
            tenant,
            key_version,
            issued_at_ms,
            expires_at_ms,
        })
    }
}

struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.b.len() < n {
            return None;
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Some(h)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn lp_str(&mut self) -> Option<String> {
        let n = u32::from_le_bytes(self.array::<4>()?) as usize;
        String::from_utf8(self.take(n)?.to_vec()).ok()
    }
}

/// Hash under which the server stores an invite token (the token itself is not stored).
pub fn invite_token_hash(token: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(INVITE_TOKEN_DOMAIN);
    h.update(token);
    h.finalize().into()
}

/// What the enrolling client signs with its new auth key (proof of possession bound to
/// the invite, the assigned subject and the exact key bundle).
pub fn enroll_statement(
    invite_id: &str,
    token_hash: &[u8; 32],
    subject: SubjectId,
    tenant: &TenantId,
    name: &str,
    bundle_fingerprint: &[u8; 32],
) -> Vec<u8> {
    let mut out = ENROLL_DOMAIN.to_vec();
    push_lp(&mut out, invite_id.as_bytes());
    out.extend_from_slice(token_hash);
    out.extend_from_slice(subject.as_bytes());
    push_lp(&mut out, tenant.as_str().as_bytes());
    push_lp(&mut out, name.as_bytes());
    out.extend_from_slice(bundle_fingerprint);
    out
}

/// Key-bundle rotation `old → new`, signed by the old auth key (continuity, if it has one)
/// and by the new auth key (proof of possession).
pub fn rotation_statement(
    subject: SubjectId,
    tenant: &TenantId,
    old_fingerprint: &[u8; 32],
    new_fingerprint: &[u8; 32],
    new_version: u32,
) -> Vec<u8> {
    let mut out = ROTATE_DOMAIN.to_vec();
    out.extend_from_slice(subject.as_bytes());
    push_lp(&mut out, tenant.as_str().as_bytes());
    out.extend_from_slice(old_fingerprint);
    out.extend_from_slice(new_fingerprint);
    out.extend_from_slice(&new_version.to_be_bytes());
    out
}

/// Signatures accompanying a key-bundle rotation (wire type; no secret material).
///
/// * `new_signature` — by the **new** auth key over [`rotation_statement`]: proves the
///   rotating client holds it (nobody can register someone else's public key as theirs).
/// * `old_signature` — by the **old** auth key, if the old bundle had one: continuity
///   `v → v+1` that partners can check. Absent only when upgrading a format-1 bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotationProof {
    pub old_signature: Option<Vec<u8>>,
    pub new_signature: Vec<u8>,
}

/// One signed HTTP request (HTTP has no connection to bind a session to).
pub fn http_request_statement(session_id: &str, seq: u64, method: &str, path: &str, body: &[u8]) -> Vec<u8> {
    let mut out = HTTP_REQUEST_DOMAIN.to_vec();
    push_lp(&mut out, session_id.as_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    push_lp(&mut out, method.as_bytes());
    push_lp(&mut out, path.as_bytes());
    out.extend_from_slice(&Sha256::digest(body));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn challenge() -> Challenge {
        Challenge {
            server_instance: [1; 16],
            transport: "dmc-ipc".into(),
            channel: "conn-1".into(),
            nonce: [2; 32],
            subject: SubjectId::random(),
            tenant: TenantId::new("acme").unwrap(),
            key_version: 1,
            issued_at_ms: 1_000,
            expires_at_ms: 61_000,
        }
    }

    #[test]
    fn challenge_roundtrip_and_strict_parse() {
        let c = challenge();
        let b = c.to_bytes();
        assert_eq!(Challenge::parse(&b).unwrap(), c);
        assert!(Challenge::parse(&b[..b.len() - 1]).is_err(), "truncated");
        let mut extra = b.clone();
        extra.push(0);
        assert!(Challenge::parse(&extra).is_err(), "trailing bytes");
        let mut long = c.clone();
        long.expires_at_ms = long.issued_at_ms + CHALLENGE_TTL_MS + 1;
        assert!(Challenge::parse(&long.to_bytes()).is_err(), "TTL too long");
        // other statements are not challenges
        let e = enroll_statement("i", &[0; 32], c.subject, &c.tenant, "n", &[0; 32]);
        assert!(Challenge::parse(&e).is_err());
    }

    #[test]
    fn domains_are_distinct_and_prefix_free() {
        let d = [CHALLENGE_DOMAIN, ENROLL_DOMAIN, ROTATE_DOMAIN, HTTP_REQUEST_DOMAIN];
        for (i, a) in d.iter().enumerate() {
            for (j, b) in d.iter().enumerate() {
                if i != j {
                    assert!(!a.starts_with(b), "{a:?} / {b:?}");
                }
            }
        }
    }
}
