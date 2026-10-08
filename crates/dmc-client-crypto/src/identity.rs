//! Device-held root of CLIENT_OWNED cryptographic authority.
//!
//! ```text
//! root (32 random bytes, generated on the device, never sent anywhere)
//!   ├─ HKDF-SHA256("avrora/client-kem/v1[/kv{n}]")            → HPKE DeriveKeyPair → X25519 (encryption only)
//!   └─ HKDF-SHA256("avrora/client-owned/ed25519/v1/kv{n}")    → Ed25519 (authentication only)
//! ```
//!
//! The two keys are domain-separated by their HKDF labels and used for one purpose each:
//! X25519 never signs, Ed25519 never encrypts. The Ed25519 key signs only the statements
//! of `dmc_vault::ownership::auth` (challenge, enrollment, rotation, HTTP request) — there
//! is no "sign arbitrary bytes" API.
//!
//! * The root is independent of the login password: authenticating to AvroraCore never
//!   reveals anything that derives client keys.
//! * The root *is* the recovery secret. It is shown once as a [`RecoveryCode`] and can
//!   re-create the identity on another device. Losing the device file and the recovery
//!   code means permanent loss of CLIENT_OWNED data — there is no server-side recovery.
//! * Only the public key ([`ClientPublicKey`]) and HPKE envelopes go to the server.

use std::fmt;
use std::path::Path;

use dmc_vault::KeyMaterial;
use dmc_vault::ownership::auth::{self as stmt, Challenge, KeyRotationProof};
use dmc_vault::ownership::client::CLIENT_BUNDLE_FORMAT_V2;
use dmc_vault::ownership::{
    CLIENT_SUITE_V1, CLIENT_WIRE_FORMAT_V1, ClientEnvelopeKind, ClientKeyEnvelope, ClientPublicKey,
    SubjectId, TenantId,
};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

type Kem = X25519HkdfSha256;
const KEM_INFO: &[u8] = b"avrora/client-kem/v1";
const IDENTITY_FORMAT: u16 = 1;
const RECOVERY_PREFIX: &str = "AVRC1";

/// X25519 private key of one KEM key version. Exists only inside this crate (client);
/// there is no serialization and no accessor that returns its bytes.
struct ClientPrivateKey(<Kem as KemTrait>::PrivateKey);

pub struct ClientIdentity {
    subject: SubjectId,
    tenant: TenantId,
    root: Zeroizing<[u8; 32]>,
    kem_version: u32,
    sk: ClientPrivateKey,
    pk: <Kem as KemTrait>::PublicKey,
    created_at_ms: u64,
    /// First key version whose bundle carries an Ed25519 auth key (`None`: format-1
    /// identity from before D1; it gains one on its next rotation).
    auth_from: Option<u32>,
}

impl fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("subject", &self.subject)
            .field("tenant", &self.tenant)
            .field("keys", &"[REDACTED]")
            .finish()
    }
}

/// The root secret encoded for a human to store offline. Shown once; redacted `Debug`.
pub struct RecoveryCode(Zeroizing<String>);

impl RecoveryCode {
    fn from_root(root: &[u8; 32]) -> Self {
        let check = &Sha256::digest(root)[..4];
        let body = hex::encode(root);
        let groups: Vec<&str> = body
            .as_bytes()
            .chunks(8)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        Self(Zeroizing::new(format!(
            "{RECOVERY_PREFIX}-{}-{}",
            groups.join("-"),
            hex::encode(check)
        )))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn to_root(code: &str) -> Result<Zeroizing<[u8; 32]>> {
        let compact: String = code.trim().split('-').collect();
        let rest = compact.strip_prefix(RECOVERY_PREFIX).ok_or(Error::RecoveryCode)?;
        if rest.len() != 64 + 8 {
            return Err(Error::RecoveryCode);
        }
        let raw = Zeroizing::new(hex::decode(&rest[..64]).map_err(|_| Error::RecoveryCode)?);
        let check = hex::decode(&rest[64..]).map_err(|_| Error::RecoveryCode)?;
        let mut root = Zeroizing::new([0u8; 32]);
        root.copy_from_slice(&raw);
        if Sha256::digest(root.as_ref())[..4] != check[..] {
            return Err(Error::RecoveryCode);
        }
        Ok(root)
    }
}

impl From<&str> for RecoveryCode {
    fn from(value: &str) -> Self {
        Self(Zeroizing::new(value.to_string()))
    }
}

impl fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryCode([REDACTED])")
    }
}

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    format_version: u16,
    subject: SubjectId,
    tenant: TenantId,
    root_hex: String,
    created_at_ms: u64,
    #[serde(default = "first_version")]
    kem_version: u32,
    /// Absent in pre-D1 files (no auth key yet).
    #[serde(default)]
    auth_from_version: Option<u32>,
}

fn first_version() -> u32 {
    1
}

/// Per-version KEM derivation. Version 1 keeps the original label (compatibility).
fn derive_kem(root: &[u8; 32], version: u32) -> (<Kem as KemTrait>::PrivateKey, <Kem as KemTrait>::PublicKey) {
    let hk = Hkdf::<Sha256>::new(None, root);
    let mut ikm = Zeroizing::new([0u8; 32]);
    let info = if version == 1 {
        KEM_INFO.to_vec()
    } else {
        format!("avrora/client-kem/v1/kv{version}").into_bytes()
    };
    hk.expand(&info, ikm.as_mut())
        .expect("HKDF expand with 32-byte OKM never fails");
    Kem::derive_keypair(ikm.as_ref())
}

/// Per-version Ed25519 authentication key (separate HKDF label from the KEM key).
fn derive_auth(root: &[u8; 32], version: u32) -> SigningKey {
    let hk = Hkdf::<Sha256>::new(None, root);
    let mut seed = Zeroizing::new([0u8; 32]);
    hk.expand(format!("avrora/client-owned/ed25519/v1/kv{version}").as_bytes(), seed.as_mut())
        .expect("HKDF expand with 32-byte OKM never fails");
    SigningKey::from_bytes(&seed)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl ClientIdentity {
    /// New device identity. The recovery code is returned once and never stored.
    pub fn generate(subject: SubjectId, tenant: TenantId) -> (Self, RecoveryCode) {
        let mut root = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(root.as_mut());
        let code = RecoveryCode::from_root(&root);
        (Self::from_root(subject, tenant, root, now_ms()), code)
    }

    /// Re-create the identity on a new device from its recovery code.
    pub fn from_recovery(subject: SubjectId, tenant: TenantId, code: &RecoveryCode) -> Result<Self> {
        let root = RecoveryCode::to_root(code.as_str())?;
        Ok(Self::from_root(subject, tenant, root, now_ms()))
    }

    /// Recovery onto a device after key rotation(s): derive up to `kem_version`.
    pub fn from_recovery_at_version(
        subject: SubjectId,
        tenant: TenantId,
        code: &RecoveryCode,
        kem_version: u32,
    ) -> Result<Self> {
        let mut id = Self::from_recovery(subject, tenant, code)?;
        while id.kem_version < kem_version {
            id.rotate_kem();
        }
        Ok(id)
    }

    fn from_root(subject: SubjectId, tenant: TenantId, root: Zeroizing<[u8; 32]>, created_at_ms: u64) -> Self {
        Self::from_root_at(subject, tenant, root, created_at_ms, 1, Some(1))
    }

    fn from_root_at(
        subject: SubjectId,
        tenant: TenantId,
        root: Zeroizing<[u8; 32]>,
        created_at_ms: u64,
        kem_version: u32,
        auth_from: Option<u32>,
    ) -> Self {
        let (sk, pk) = derive_kem(&root, kem_version);
        Self {
            subject,
            tenant,
            root,
            kem_version,
            sk: ClientPrivateKey(sk),
            pk,
            created_at_ms,
            auth_from,
        }
    }

    /// Recovery of an identity created before D1 (format-1 bundles up to
    /// `auth_from - 1`). `auth_from = None`: never upgraded.
    pub fn from_recovery_legacy(
        subject: SubjectId,
        tenant: TenantId,
        code: &RecoveryCode,
        kem_version: u32,
        auth_from: Option<u32>,
    ) -> Result<Self> {
        let root = RecoveryCode::to_root(code.as_str())?;
        Ok(Self::from_root_at(subject, tenant, root, now_ms(), kem_version.max(1), auth_from))
    }

    fn has_auth_at(&self, version: u32) -> bool {
        self.auth_from.is_some_and(|from| from <= version)
    }

    fn auth_key(&self) -> Result<SigningKey> {
        if !self.has_auth_at(self.kem_version) {
            return Err(Error::Format(
                "this identity has no authentication key yet (format-1 bundle): rotate first".into(),
            ));
        }
        Ok(derive_auth(&self.root, self.kem_version))
    }

    /// Sign a server challenge (`ClientAuthBegin` response). The bytes are parsed first:
    /// only a well-formed challenge for this subject, tenant and current key version,
    /// not yet expired, is signed.
    pub fn sign_challenge(&self, challenge: &[u8]) -> Result<Vec<u8>> {
        let c = Challenge::parse(challenge)?;
        if c.subject != self.subject || c.tenant != self.tenant || c.key_version != self.kem_version {
            return Err(Error::Format("challenge is not for this identity/key version".into()));
        }
        if c.expires_at_ms <= now_ms() {
            return Err(Error::Format("challenge expired".into()));
        }
        Ok(self.auth_key()?.sign(challenge).to_bytes().to_vec())
    }

    /// Proof of possession for enrollment with an operator-issued invite.
    pub fn sign_enrollment(&self, invite_id: &str, token: &[u8], name: &str) -> Result<Vec<u8>> {
        if self.kem_version != 1 {
            return Err(Error::Format("enrollment registers key version 1".into()));
        }
        let statement = stmt::enroll_statement(
            invite_id,
            &stmt::invite_token_hash(token),
            self.subject,
            &self.tenant,
            name,
            &self.public_key().fingerprint(),
        );
        Ok(self.auth_key()?.sign(&statement).to_bytes().to_vec())
    }

    /// Signature over one HTTP request (see `dmc_vault::ownership::auth::http_request_statement`).
    pub fn sign_http_request(&self, session_id: &str, seq: u64, method: &str, path: &str, body: &[u8]) -> Result<Vec<u8>> {
        let statement = stmt::http_request_statement(session_id, seq, method, path, body);
        Ok(self.auth_key()?.sign(&statement).to_bytes().to_vec())
    }

    /// Rotate both keys to version n+1 and produce the continuity / possession proof.
    pub fn rotate_keys(&mut self) -> Result<(ClientPublicKey, KeyRotationProof)> {
        let old = self.public_key();
        let old_auth = self.auth_key().ok();
        let new = self.rotate_kem();
        let statement =
            stmt::rotation_statement(self.subject, &self.tenant, &old.fingerprint(), &new.fingerprint(), new.key_version);
        let proof = KeyRotationProof {
            old_signature: old_auth.map(|k| k.sign(&statement).to_bytes().to_vec()),
            new_signature: self.auth_key()?.sign(&statement).to_bytes().to_vec(),
        };
        Ok((new, proof))
    }

    pub fn kem_version(&self) -> u32 {
        self.kem_version
    }

    /// Rotate the KEM keypair (new version derived from the same root). Envelopes sealed
    /// to older versions stay openable. Rotation does **not** help if the root itself is
    /// compromised — that needs a new identity.
    pub fn rotate_kem(&mut self) -> ClientPublicKey {
        let next = self.kem_version + 1;
        let (sk, pk) = derive_kem(&self.root, next);
        self.kem_version = next;
        self.sk = ClientPrivateKey(sk);
        self.pk = pk;
        // a format-1 identity gains its Ed25519 auth key with this rotation
        self.auth_from.get_or_insert(next);
        self.public_key()
    }

    /// Public key of an earlier (or the current) KEM version.
    pub fn public_key_at(&self, version: u32) -> Option<ClientPublicKey> {
        if version == 0 || version > self.kem_version {
            return None;
        }
        let (_, pk) = derive_kem(&self.root, version);
        Some(self.public_key_from(pk.to_bytes().to_vec(), version))
    }

    fn public_key_from(&self, bytes: Vec<u8>, key_version: u32) -> ClientPublicKey {
        let auth = self
            .has_auth_at(key_version)
            .then(|| derive_auth(&self.root, key_version).verifying_key().to_bytes());
        ClientPublicKey {
            format_version: if auth.is_some() { CLIENT_BUNDLE_FORMAT_V2 } else { CLIENT_WIRE_FORMAT_V1 },
            suite: CLIENT_SUITE_V1.into(),
            subject: self.subject,
            tenant: self.tenant.clone(),
            public_key: bytes,
            created_at_ms: self.created_at_ms,
            key_version,
            auth_public_key: auth,
        }
    }

    pub fn subject(&self) -> SubjectId {
        self.subject
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Public half, safe to register with the (untrusted) server.
    pub fn public_key(&self) -> ClientPublicKey {
        self.public_key_from(self.pk.to_bytes().to_vec(), self.kem_version)
    }

    /// Device file (owner-only, 0600). Holds the root secret: protect it like a private key.
    pub fn save(&self, path: &Path) -> Result<()> {
        let file = IdentityFile {
            format_version: IDENTITY_FORMAT,
            subject: self.subject,
            tenant: self.tenant.clone(),
            root_hex: hex::encode(self.root.as_ref()),
            created_at_ms: self.created_at_ms,
            kem_version: self.kem_version,
            auth_from_version: self.auth_from,
        };
        let raw = Zeroizing::new(serde_json::to_vec_pretty(&file).map_err(|e| Error::Format(e.to_string()))?);
        let _wipe = Zeroizing::new(file.root_hex);
        dmc_vault::secure_fs::write_secret_file(path, &raw).map_err(Error::io)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = Zeroizing::new(std::fs::read(path).map_err(Error::io)?);
        let file: IdentityFile = serde_json::from_slice(&raw).map_err(|e| Error::Format(e.to_string()))?;
        let root_hex = Zeroizing::new(file.root_hex);
        if file.format_version != IDENTITY_FORMAT {
            return Err(Error::Format("unsupported identity file".into()));
        }
        let bytes = Zeroizing::new(hex::decode(root_hex.as_str()).map_err(|e| Error::Format(e.to_string()))?);
        let mut root = Zeroizing::new([0u8; 32]);
        if bytes.len() != 32 {
            return Err(Error::Format("identity root must be 32 bytes".into()));
        }
        root.copy_from_slice(&bytes);
        Ok(Self::from_root_at(
            file.subject,
            file.tenant,
            root,
            file.created_at_ms,
            file.kem_version.max(1),
            file.auth_from_version,
        ))
    }

    /// Seal `dek` (owned by `owner`) to `recipient` with HPKE. The caller is responsible
    /// for having verified `recipient` (see [`crate::ClientState::check_or_pin`]).
    pub fn seal_dek_to(
        &self,
        recipient: &ClientPublicKey,
        owner: SubjectId,
        key_version: u32,
        dek: &KeyMaterial,
    ) -> Result<ClientKeyEnvelope> {
        recipient.validate()?;
        if recipient.tenant != self.tenant {
            return Err(Error::Format("recipient is in another tenant".into()));
        }
        let pk_r = <Kem as KemTrait>::PublicKey::from_bytes(&recipient.public_key).map_err(|_| Error::Hpke)?;
        let kind = if recipient.subject == owner {
            ClientEnvelopeKind::OwnDataKey
        } else {
            ClientEnvelopeKind::DelegatedDataKey
        };
        let mut env = ClientKeyEnvelope {
            format_version: CLIENT_WIRE_FORMAT_V1,
            suite: CLIENT_SUITE_V1.into(),
            kind,
            tenant: self.tenant.clone(),
            owner,
            recipient: recipient.subject,
            recipient_key_fingerprint: recipient.fingerprint(),
            key_version,
            created_at_ms: now_ms(),
            enc: Vec::new(),
            ciphertext: Vec::new(),
        };
        let binding = env.binding();
        let (enc, ct) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, Kem, _>(
            &OpModeS::Base,
            &pk_r,
            &binding,
            dek.as_bytes(),
            &binding,
            &mut rand::thread_rng(),
        )
        .map_err(|_| Error::Hpke)?;
        env.enc = enc.to_bytes().to_vec();
        env.ciphertext = ct;
        env.validate()?;
        Ok(env)
    }

    /// Open an envelope addressed to any KEM version (≤ current) of this identity.
    pub fn open_envelope(&self, env: &ClientKeyEnvelope) -> Result<KeyMaterial> {
        env.validate()?;
        if env.recipient != self.subject || env.tenant != self.tenant {
            return Err(Error::NotForThisKey);
        }
        let current = self.public_key();
        let older;
        let sk: &<Kem as KemTrait>::PrivateKey = if env.recipient_key_fingerprint == current.fingerprint() {
            &self.sk.0
        } else {
            let v = (1..self.kem_version)
                .find(|v| {
                    self.public_key_at(*v)
                        .is_some_and(|k| k.fingerprint() == env.recipient_key_fingerprint)
                })
                .ok_or(Error::NotForThisKey)?;
            older = derive_kem(&self.root, v).0;
            &older
        };
        let enc = <Kem as KemTrait>::EncappedKey::from_bytes(&env.enc).map_err(|_| Error::Hpke)?;
        let binding = env.binding();
        let pt = Zeroizing::new(
            hpke::single_shot_open::<AesGcm256, HkdfSha256, Kem>(
                &OpModeR::Base,
                sk,
                &enc,
                &binding,
                &env.ciphertext,
                &binding,
            )
            .map_err(|_| Error::Hpke)?,
        );
        let arr: [u8; 32] = pt
            .as_slice()
            .try_into()
            .map_err(|_| Error::Format("wrapped DEK length".into()))?;
        Ok(KeyMaterial::from_bytes(arr))
    }
}
