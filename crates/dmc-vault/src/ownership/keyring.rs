//! Per-subject key hierarchy.
//!
//! ```text
//! credential (password / recovery code)
//!     │ Argon2id → HKDF "kek-wrap"
//!     ▼
//! SubjectKek envelope  ──open──▶  KEK (random, per subject, epoch N)
//!                                   │
//!                     DataKey envelopes (one per DEK version, wrapped under KEK)
//!                                   ▼
//!                       DEK v1 (Retired) · DEK v2 (Active) · …
//! ```
//!
//! Invariants:
//! * The KEK is random and independent of the vault Master Key: unlocking the vault
//!   (or holding `cap_root`) gives no access to it.
//! * Changing a credential rewraps only the KEK envelope; DEKs and data are untouched.
//! * Exactly one DEK is `Active` (used for new writes). `Rotating` is a persisted
//!   intermediate state; `Retired` keys still decrypt; `Destroyed` keys are gone
//!   (crypto-shredded) and may only be destroyed when no record references them.
//! * Every persisted keyring carries an HMAC (key derived from the KEK) over all its
//!   metadata, so states, versions and envelope lists cannot be edited undetected by
//!   someone who does not hold the KEK.

use std::collections::HashMap;
use std::fmt;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use super::credential::CredentialUnlock;
use super::envelope::{EnvelopeKind, EnvelopeSpec, KeyEnvelope};
use super::error::{Error, Result};
use super::ids::{SubjectId, TenantId};
use crate::key::KeyMaterial;

pub const KEYRING_FORMAT_V1: u16 = 1;
const MAC_INFO: &[u8] = b"avrora/keyring-mac/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyState {
    /// Used for new writes. Exactly one per keyring.
    Active,
    /// Persisted, not yet used for writes. Promoted to Active when rotation completes.
    Rotating,
    /// Decrypt-only.
    Retired,
    /// Key material deleted. Records under this version are permanently unreadable.
    Destroyed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataKeyEntry {
    pub version: u32,
    pub state: KeyState,
    pub created_at_ms: u64,
    #[serde(default)]
    pub retired_at_ms: Option<u64>,
    /// `None` once destroyed.
    pub envelope: Option<KeyEnvelope>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialEntry {
    pub credential_id: String,
    pub envelope: KeyEnvelope,
}

/// Read access to another subject's DEK version, wrapped under this subject's KEK.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegatedKeyEntry {
    pub owner: SubjectId,
    pub version: u32,
    pub envelope: KeyEnvelope,
}

/// Persisted keyring. Contains only wrapped keys and metadata — no plaintext secrets.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectKeyring {
    pub format_version: u16,
    pub subject: SubjectId,
    pub tenant: TenantId,
    pub kek_epoch: u32,
    /// Incremented on every persisted change (optimistic concurrency + rollback evidence).
    pub generation: u64,
    pub credentials: Vec<CredentialEntry>,
    pub data_keys: Vec<DataKeyEntry>,
    #[serde(default)]
    pub delegated: Vec<DelegatedKeyEntry>,
    #[serde(with = "hex32")]
    pub mac: [u8; 32],
}

impl fmt::Debug for SubjectKeyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubjectKeyring")
            .field("subject", &self.subject)
            .field("tenant", &self.tenant)
            .field("kek_epoch", &self.kek_epoch)
            .field("generation", &self.generation)
            .field("credentials", &self.credentials.len())
            .field(
                "data_keys",
                &self
                    .data_keys
                    .iter()
                    .map(|k| (k.version, k.state))
                    .collect::<Vec<_>>(),
            )
            .field("delegated", &self.delegated.len())
            .finish()
    }
}

/// Keys of one subject held in RAM for the lifetime of a crypto session.
/// All `KeyMaterial` is zeroized on drop. Not `Clone`, redacted `Debug`.
pub struct UnlockedKeyring {
    subject: SubjectId,
    tenant: TenantId,
    kek_epoch: u32,
    kek: KeyMaterial,
    deks: HashMap<u32, KeyMaterial>,
    delegated: HashMap<(SubjectId, u32), KeyMaterial>,
}

impl fmt::Debug for UnlockedKeyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockedKeyring")
            .field("subject", &self.subject)
            .field("tenant", &self.tenant)
            .field("keys", &"[REDACTED]")
            .finish()
    }
}

impl UnlockedKeyring {
    pub fn subject(&self) -> SubjectId {
        self.subject
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Own DEK for `version` (fails closed if destroyed / unknown).
    pub fn data_key(&self, version: u32) -> Result<&KeyMaterial> {
        self.deks
            .get(&version)
            .ok_or(Error::KeyVersionUnavailable(version))
    }

    /// Delegated DEK of `owner` (read-only access granted by that owner).
    pub fn delegated_key(&self, owner: SubjectId, version: u32) -> Result<&KeyMaterial> {
        self.delegated
            .get(&(owner, version))
            .ok_or(Error::KeyVersionUnavailable(version))
    }

    #[cfg(test)]
    pub(crate) fn kek_for_tests(&self) -> &KeyMaterial {
        &self.kek
    }

    pub fn has_delegated_from(&self, owner: SubjectId) -> bool {
        self.delegated.keys().any(|(o, _)| *o == owner)
    }
}

#[derive(Serialize)]
struct MacView<'a> {
    domain: &'static str,
    format_version: u16,
    subject: &'a SubjectId,
    tenant: &'a TenantId,
    kek_epoch: u32,
    generation: u64,
    credentials: &'a [CredentialEntry],
    data_keys: &'a [DataKeyEntry],
    delegated: &'a [DelegatedKeyEntry],
}

type HmacSha256 = Hmac<Sha256>;

fn mac_key(kek: &KeyMaterial) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, kek.as_bytes());
    let mut out = [0u8; 32];
    hk.expand(MAC_INFO, &mut out)
        .expect("HKDF expand with 32-byte OKM never fails");
    out
}

fn credential_ref(id: &str) -> String {
    format!("credential:{id}")
}

fn kek_ref(epoch: u32) -> String {
    format!("kek:{epoch}")
}

impl SubjectKeyring {
    /// Enroll: fresh random KEK + DEK v1 (Active), KEK wrapped under the credential.
    pub fn create(
        subject: SubjectId,
        tenant: TenantId,
        credential: &CredentialUnlock,
        now_ms: u64,
    ) -> Result<(Self, UnlockedKeyring)> {
        validate_credential_id(credential.credential_id())?;
        let kek = KeyMaterial::random();
        let dek = KeyMaterial::random();
        let kek_epoch = 1;
        let cred_env = KeyEnvelope::seal(
            EnvelopeSpec {
                kind: EnvelopeKind::SubjectKek,
                tenant: &tenant,
                owner: subject,
                holder: subject,
                key_version: kek_epoch,
                wrapped_by: credential_ref(credential.credential_id()),
                created_at_ms: now_ms,
            },
            credential.wrap_key(),
            &kek,
        )?;
        let dek_env = seal_dek(&tenant, subject, &kek, kek_epoch, 1, &dek, now_ms)?;
        let mut ring = Self {
            format_version: KEYRING_FORMAT_V1,
            subject,
            tenant: tenant.clone(),
            kek_epoch,
            generation: 1,
            credentials: vec![CredentialEntry {
                credential_id: credential.credential_id().to_string(),
                envelope: cred_env,
            }],
            data_keys: vec![DataKeyEntry {
                version: 1,
                state: KeyState::Active,
                created_at_ms: now_ms,
                retired_at_ms: None,
                envelope: Some(dek_env),
            }],
            delegated: Vec::new(),
            mac: [0u8; 32],
        };
        ring.mac = ring.compute_mac(&kek)?;
        let mut deks = HashMap::new();
        deks.insert(1, dek);
        Ok((
            ring,
            UnlockedKeyring {
                subject,
                tenant,
                kek_epoch,
                kek,
                deks,
                delegated: HashMap::new(),
            },
        ))
    }

    /// Open the KEK with a credential, verify the keyring MAC and unwrap all live DEKs.
    pub fn unlock(&self, credential: &CredentialUnlock) -> Result<UnlockedKeyring> {
        if self.format_version != KEYRING_FORMAT_V1 {
            return Err(Error::Format(format!(
                "unsupported keyring format {}",
                self.format_version
            )));
        }
        let entry = self
            .credentials
            .iter()
            .find(|c| c.credential_id == credential.credential_id())
            .ok_or(Error::WrongCredential)?;
        let env = &entry.envelope;
        if env.kind != EnvelopeKind::SubjectKek
            || env.owner != self.subject
            || env.holder != self.subject
            || env.tenant != self.tenant
            || env.key_version != self.kek_epoch
            || env.wrapped_by != credential_ref(&entry.credential_id)
        {
            return Err(Error::KeyringTampered);
        }
        let kek = env
            .open(credential.wrap_key())
            .map_err(|_| Error::WrongCredential)?;
        self.verify_mac(&kek)?;

        let mut deks = HashMap::new();
        for k in &self.data_keys {
            if let Some(env) = &k.envelope {
                if env.kind != EnvelopeKind::DataKey
                    || env.owner != self.subject
                    || env.key_version != k.version
                    || env.wrapped_by != kek_ref(self.kek_epoch)
                {
                    return Err(Error::KeyringTampered);
                }
                let dek = env.open(&kek).map_err(|_| Error::KeyringTampered)?;
                deks.insert(k.version, dek);
            }
        }
        let mut delegated = HashMap::new();
        for d in &self.delegated {
            let env = &d.envelope;
            if env.kind != EnvelopeKind::DelegatedDataKey
                || env.owner != d.owner
                || env.holder != self.subject
                || env.key_version != d.version
                || env.tenant != self.tenant
            {
                return Err(Error::KeyringTampered);
            }
            let dek = env.open(&kek).map_err(|_| Error::KeyringTampered)?;
            delegated.insert((d.owner, d.version), dek);
        }
        self.active_version()?;
        Ok(UnlockedKeyring {
            subject: self.subject,
            tenant: self.tenant.clone(),
            kek_epoch: self.kek_epoch,
            kek,
            deks,
            delegated,
        })
    }

    /// Version used for new writes.
    pub fn active_version(&self) -> Result<u32> {
        let mut active = self
            .data_keys
            .iter()
            .filter(|k| k.state == KeyState::Active)
            .map(|k| k.version);
        match (active.next(), active.next()) {
            (Some(v), None) => Ok(v),
            _ => Err(Error::KeyringTampered),
        }
    }

    pub fn state_of(&self, version: u32) -> Option<KeyState> {
        self.data_keys
            .iter()
            .find(|k| k.version == version)
            .map(|k| k.state)
    }

    pub fn has_incomplete_rotation(&self) -> bool {
        self.data_keys.iter().any(|k| k.state == KeyState::Rotating)
    }

    pub fn credential_ids(&self) -> Vec<String> {
        self.credentials
            .iter()
            .map(|c| c.credential_id.clone())
            .collect()
    }

    // ── credential management (no data re-encryption) ─────────────────────────

    /// Add or replace the KEK envelope for `credential.credential_id()`.
    pub fn set_credential(
        &mut self,
        unlocked: &UnlockedKeyring,
        credential: &CredentialUnlock,
        now_ms: u64,
    ) -> Result<()> {
        self.check_unlocked(unlocked)?;
        validate_credential_id(credential.credential_id())?;
        let env = KeyEnvelope::seal(
            EnvelopeSpec {
                kind: EnvelopeKind::SubjectKek,
                tenant: &self.tenant,
                owner: self.subject,
                holder: self.subject,
                key_version: self.kek_epoch,
                wrapped_by: credential_ref(credential.credential_id()),
                created_at_ms: now_ms,
            },
            credential.wrap_key(),
            &unlocked.kek,
        )?;
        self.credentials
            .retain(|c| c.credential_id != credential.credential_id());
        self.credentials.push(CredentialEntry {
            credential_id: credential.credential_id().to_string(),
            envelope: env,
        });
        self.bump(unlocked)
    }

    /// Remove every credential envelope whose id is not in `keep` (never the last one).
    pub fn retain_credentials(&mut self, unlocked: &UnlockedKeyring, keep: &[&str]) -> Result<bool> {
        self.check_unlocked(unlocked)?;
        let before = self.credentials.len();
        let survivors = self
            .credentials
            .iter()
            .filter(|c| keep.contains(&c.credential_id.as_str()))
            .count();
        if survivors == 0 {
            return Err(Error::Lifecycle(
                "refusing to remove the last credential of a keyring".into(),
            ));
        }
        self.credentials
            .retain(|c| keep.contains(&c.credential_id.as_str()));
        if self.credentials.len() == before {
            return Ok(false);
        }
        self.bump(unlocked)?;
        Ok(true)
    }

    // ── DEK rotation ──────────────────────────────────────────────────────────

    /// Step 1: persist a new DEK as `Rotating`. Not used for writes yet.
    pub fn begin_rotation(&mut self, unlocked: &mut UnlockedKeyring, now_ms: u64) -> Result<u32> {
        self.check_unlocked(unlocked)?;
        if self.has_incomplete_rotation() {
            return Err(Error::Lifecycle("rotation already in progress".into()));
        }
        let version = self
            .data_keys
            .iter()
            .map(|k| k.version)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| Error::Lifecycle("key version overflow".into()))?;
        let dek = KeyMaterial::random();
        let env = seal_dek(
            &self.tenant,
            self.subject,
            &unlocked.kek,
            self.kek_epoch,
            version,
            &dek,
            now_ms,
        )?;
        self.data_keys.push(DataKeyEntry {
            version,
            state: KeyState::Rotating,
            created_at_ms: now_ms,
            retired_at_ms: None,
            envelope: Some(env),
        });
        unlocked.deks.insert(version, dek);
        self.bump(unlocked)?;
        Ok(version)
    }

    /// Step 2: promote `Rotating` → `Active`, previous `Active` → `Retired`.
    /// Idempotent: returns `None` when nothing was rotating.
    pub fn complete_rotation(
        &mut self,
        unlocked: &UnlockedKeyring,
        now_ms: u64,
    ) -> Result<Option<u32>> {
        self.check_unlocked(unlocked)?;
        let Some(new_version) = self
            .data_keys
            .iter()
            .find(|k| k.state == KeyState::Rotating)
            .map(|k| k.version)
        else {
            return Ok(None);
        };
        if !unlocked.deks.contains_key(&new_version) {
            return Err(Error::KeyVersionUnavailable(new_version));
        }
        for k in &mut self.data_keys {
            if k.state == KeyState::Active {
                k.state = KeyState::Retired;
                k.retired_at_ms = Some(now_ms);
            } else if k.version == new_version {
                k.state = KeyState::Active;
            }
        }
        self.bump(unlocked)?;
        Ok(Some(new_version))
    }

    /// Crypto-shred a retired DEK. Refused while any record still references it.
    pub fn destroy_retired(
        &mut self,
        unlocked: &mut UnlockedKeyring,
        version: u32,
        live_references: u64,
    ) -> Result<()> {
        self.check_unlocked(unlocked)?;
        if live_references != 0 {
            return Err(Error::Lifecycle(format!(
                "key version {version} still referenced by {live_references} record(s)"
            )));
        }
        let entry = self
            .data_keys
            .iter_mut()
            .find(|k| k.version == version)
            .ok_or(Error::KeyVersionUnavailable(version))?;
        if entry.state != KeyState::Retired {
            return Err(Error::Lifecycle(format!(
                "only RETIRED keys can be destroyed (version {version} is {:?})",
                entry.state
            )));
        }
        entry.state = KeyState::Destroyed;
        entry.envelope = None;
        unlocked.deks.remove(&version);
        self.bump(unlocked)
    }

    // ── KEK rotation (rewrap only, no data re-encryption) ────────────────────

    /// New random KEK; every DEK / delegated envelope is rewrapped, the KEK is wrapped
    /// under `credential` only. Other credentials must be re-added afterwards.
    pub fn rotate_kek(
        &mut self,
        unlocked: &mut UnlockedKeyring,
        credential: &CredentialUnlock,
        now_ms: u64,
    ) -> Result<u32> {
        self.check_unlocked(unlocked)?;
        let new_epoch = self
            .kek_epoch
            .checked_add(1)
            .ok_or_else(|| Error::Lifecycle("kek epoch overflow".into()))?;
        let new_kek = KeyMaterial::random();
        for k in &mut self.data_keys {
            if k.envelope.is_some() {
                let dek = unlocked
                    .deks
                    .get(&k.version)
                    .ok_or(Error::KeyVersionUnavailable(k.version))?;
                k.envelope = Some(seal_dek(
                    &self.tenant,
                    self.subject,
                    &new_kek,
                    new_epoch,
                    k.version,
                    dek,
                    now_ms,
                )?);
            }
        }
        for d in &mut self.delegated {
            let dek = unlocked
                .delegated
                .get(&(d.owner, d.version))
                .ok_or(Error::KeyVersionUnavailable(d.version))?;
            d.envelope = seal_delegated(&self.tenant, d.owner, self.subject, &new_kek, new_epoch, d.version, dek, now_ms)?;
        }
        let cred_env = KeyEnvelope::seal(
            EnvelopeSpec {
                kind: EnvelopeKind::SubjectKek,
                tenant: &self.tenant,
                owner: self.subject,
                holder: self.subject,
                key_version: new_epoch,
                wrapped_by: credential_ref(credential.credential_id()),
                created_at_ms: now_ms,
            },
            credential.wrap_key(),
            &new_kek,
        )?;
        self.credentials = vec![CredentialEntry {
            credential_id: credential.credential_id().to_string(),
            envelope: cred_env,
        }];
        self.kek_epoch = new_epoch;
        unlocked.kek = new_kek;
        unlocked.kek_epoch = new_epoch;
        self.bump(unlocked)?;
        Ok(new_epoch)
    }

    // ── delegation ───────────────────────────────────────────────────────────

    /// Store `owner`'s DEKs (read access) wrapped under this keyring's KEK.
    /// `self`/`unlocked` belong to the grantee.
    pub fn add_delegated_keys(
        &mut self,
        unlocked: &mut UnlockedKeyring,
        owner: &UnlockedKeyring,
        now_ms: u64,
    ) -> Result<usize> {
        self.check_unlocked(unlocked)?;
        if owner.tenant != self.tenant {
            return Err(Error::Lifecycle("delegation across tenants is not allowed".into()));
        }
        if owner.subject == self.subject {
            return Err(Error::Lifecycle("cannot delegate to self".into()));
        }
        let mut added = 0;
        let mut versions: Vec<_> = owner.deks.keys().copied().collect();
        versions.sort_unstable();
        for version in versions {
            if unlocked.delegated.contains_key(&(owner.subject, version)) {
                continue;
            }
            let dek = &owner.deks[&version];
            let env = seal_delegated(
                &self.tenant,
                owner.subject,
                self.subject,
                &unlocked.kek,
                self.kek_epoch,
                version,
                dek,
                now_ms,
            )?;
            self.delegated.push(DelegatedKeyEntry {
                owner: owner.subject,
                version,
                envelope: env,
            });
            unlocked
                .delegated
                .insert((owner.subject, version), dek.clone());
            added += 1;
        }
        if added > 0 {
            self.bump(unlocked)?;
        }
        Ok(added)
    }

    /// Drop every delegated key received from `owner`.
    pub fn remove_delegated_keys(
        &mut self,
        unlocked: &mut UnlockedKeyring,
        owner: SubjectId,
    ) -> Result<usize> {
        self.check_unlocked(unlocked)?;
        let before = self.delegated.len();
        self.delegated.retain(|d| d.owner != owner);
        unlocked.delegated.retain(|(o, _), _| *o != owner);
        let removed = before - self.delegated.len();
        if removed > 0 {
            self.bump(unlocked)?;
        }
        Ok(removed)
    }

    // ── integrity ────────────────────────────────────────────────────────────

    fn check_unlocked(&self, unlocked: &UnlockedKeyring) -> Result<()> {
        if unlocked.subject != self.subject
            || unlocked.tenant != self.tenant
            || unlocked.kek_epoch != self.kek_epoch
        {
            return Err(Error::Lifecycle("unlocked keyring does not match".into()));
        }
        Ok(())
    }

    fn bump(&mut self, unlocked: &UnlockedKeyring) -> Result<()> {
        self.generation += 1;
        self.mac = self.compute_mac(&unlocked.kek)?;
        Ok(())
    }

    fn compute_mac(&self, kek: &KeyMaterial) -> Result<[u8; 32]> {
        let view = MacView {
            domain: "avrora/keyring/v1",
            format_version: self.format_version,
            subject: &self.subject,
            tenant: &self.tenant,
            kek_epoch: self.kek_epoch,
            generation: self.generation,
            credentials: &self.credentials,
            data_keys: &self.data_keys,
            delegated: &self.delegated,
        };
        let bytes = serde_json::to_vec(&view).map_err(|e| Error::Format(e.to_string()))?;
        let mut key = mac_key(kek);
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).map_err(|_| Error::Kdf)?;
        zeroize::Zeroize::zeroize(&mut key);
        mac.update(&bytes);
        Ok(mac.finalize().into_bytes().into())
    }

    fn verify_mac(&self, kek: &KeyMaterial) -> Result<()> {
        let view = MacView {
            domain: "avrora/keyring/v1",
            format_version: self.format_version,
            subject: &self.subject,
            tenant: &self.tenant,
            kek_epoch: self.kek_epoch,
            generation: self.generation,
            credentials: &self.credentials,
            data_keys: &self.data_keys,
            delegated: &self.delegated,
        };
        let bytes = serde_json::to_vec(&view).map_err(|e| Error::Format(e.to_string()))?;
        let mut key = mac_key(kek);
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).map_err(|_| Error::Kdf)?;
        zeroize::Zeroize::zeroize(&mut key);
        mac.update(&bytes);
        mac.verify_slice(&self.mac)
            .map_err(|_| Error::KeyringTampered)
    }
}

fn validate_credential_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 64 || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(Error::Format(format!("invalid credential id `{id}`")));
    }
    Ok(())
}

fn seal_dek(
    tenant: &TenantId,
    subject: SubjectId,
    kek: &KeyMaterial,
    kek_epoch: u32,
    version: u32,
    dek: &KeyMaterial,
    now_ms: u64,
) -> Result<KeyEnvelope> {
    KeyEnvelope::seal(
        EnvelopeSpec {
            kind: EnvelopeKind::DataKey,
            tenant,
            owner: subject,
            holder: subject,
            key_version: version,
            wrapped_by: kek_ref(kek_epoch),
            created_at_ms: now_ms,
        },
        kek,
        dek,
    )
}

#[allow(clippy::too_many_arguments)]
fn seal_delegated(
    tenant: &TenantId,
    owner: SubjectId,
    holder: SubjectId,
    holder_kek: &KeyMaterial,
    holder_epoch: u32,
    version: u32,
    dek: &KeyMaterial,
    now_ms: u64,
) -> Result<KeyEnvelope> {
    KeyEnvelope::seal(
        EnvelopeSpec {
            kind: EnvelopeKind::DelegatedDataKey,
            tenant,
            owner,
            holder,
            key_version: version,
            wrapped_by: kek_ref(holder_epoch),
            created_at_ms: now_ms,
        },
        holder_kek,
        dek,
    )
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
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
    use crate::ownership::credential::{derive_credential_secrets, random_salt, test_params};

    fn unlock_for(pw: &str, salt: &[u8]) -> CredentialUnlock {
        let s = derive_credential_secrets(pw, salt, &test_params()).unwrap();
        CredentialUnlock::new("password", s.wrap_key)
    }

    fn fresh() -> (SubjectKeyring, UnlockedKeyring, [u8; 16]) {
        let salt = random_salt();
        let (ring, un) = SubjectKeyring::create(
            SubjectId::random(),
            TenantId::new("acme").unwrap(),
            &unlock_for("alice-password", &salt),
            1,
        )
        .unwrap();
        (ring, un, salt)
    }

    #[test]
    fn create_unlock_and_wrong_credential() {
        let (ring, un, salt) = fresh();
        let again = ring.unlock(&unlock_for("alice-password", &salt)).unwrap();
        assert_eq!(
            again.data_key(1).unwrap().as_bytes(),
            un.data_key(1).unwrap().as_bytes()
        );
        assert!(matches!(
            ring.unlock(&unlock_for("not-the-password", &salt)),
            Err(Error::WrongCredential)
        ));
    }

    #[test]
    fn password_change_rewraps_kek_only() {
        let (mut ring, un, salt) = fresh();
        let dek_before = un.data_key(1).unwrap().as_bytes().to_owned();
        let dek_env_before = ring.data_keys[0].envelope.clone();
        let new_salt = random_salt();
        let new_unlock = CredentialUnlock::new(
            "password-2",
            derive_credential_secrets("new-password", &new_salt, &test_params())
                .unwrap()
                .wrap_key,
        );
        ring.set_credential(&un, &new_unlock, 2).unwrap();
        ring.retain_credentials(&un, &["password-2"]).unwrap();
        assert_eq!(ring.data_keys[0].envelope, dek_env_before, "DEK untouched");
        let un2 = ring.unlock(&new_unlock).unwrap();
        assert_eq!(un2.data_key(1).unwrap().as_bytes(), &dek_before);
        assert!(ring.unlock(&unlock_for("alice-password", &salt)).is_err());
    }

    #[test]
    fn rotation_lifecycle() {
        let (mut ring, mut un, _) = fresh();
        let v2 = ring.begin_rotation(&mut un, 2).unwrap();
        assert_eq!(v2, 2);
        assert_eq!(ring.active_version().unwrap(), 1, "rotating key not yet active");
        assert_eq!(ring.state_of(2), Some(KeyState::Rotating));
        assert!(ring.begin_rotation(&mut un, 2).is_err());
        assert_eq!(ring.complete_rotation(&un, 3).unwrap(), Some(2));
        assert_eq!(ring.active_version().unwrap(), 2);
        assert_eq!(ring.state_of(1), Some(KeyState::Retired));
        assert!(un.data_key(1).is_ok(), "retired key still decrypts");
        assert_eq!(ring.complete_rotation(&un, 3).unwrap(), None);
    }

    #[test]
    fn destroy_requires_retired_and_unreferenced() {
        let (mut ring, mut un, salt) = fresh();
        assert!(ring.destroy_retired(&mut un, 1, 0).is_err(), "active key");
        ring.begin_rotation(&mut un, 2).unwrap();
        ring.complete_rotation(&un, 2).unwrap();
        assert!(matches!(
            ring.destroy_retired(&mut un, 1, 3),
            Err(Error::Lifecycle(_))
        ));
        ring.destroy_retired(&mut un, 1, 0).unwrap();
        assert!(matches!(un.data_key(1), Err(Error::KeyVersionUnavailable(1))));
        let reopened = ring.unlock(&unlock_for("alice-password", &salt)).unwrap();
        assert!(reopened.data_key(1).is_err());
        assert!(reopened.data_key(2).is_ok());
    }

    #[test]
    fn mac_detects_state_tampering() {
        let (mut ring, mut un, salt) = fresh();
        ring.begin_rotation(&mut un, 2).unwrap();
        ring.complete_rotation(&un, 2).unwrap();
        let mut tampered = ring.clone();
        tampered.data_keys[0].state = KeyState::Active;
        tampered.data_keys[1].state = KeyState::Retired;
        assert!(matches!(
            tampered.unlock(&unlock_for("alice-password", &salt)),
            Err(Error::KeyringTampered)
        ));
        let mut rolled = ring.clone();
        rolled.generation -= 1;
        assert!(matches!(
            rolled.unlock(&unlock_for("alice-password", &salt)),
            Err(Error::KeyringTampered)
        ));
    }

    #[test]
    fn envelope_swapped_between_subjects_is_rejected() {
        let (alice, _, alice_salt) = fresh();
        let (bob, _, _) = fresh();
        let mut franken = alice.clone();
        franken.data_keys[0].envelope = bob.data_keys[0].envelope.clone();
        assert!(franken.unlock(&unlock_for("alice-password", &alice_salt)).is_err());
    }

    #[test]
    fn kek_rotation_keeps_deks() {
        let (mut ring, mut un, salt) = fresh();
        let dek = un.data_key(1).unwrap().as_bytes().to_owned();
        let cred = unlock_for("alice-password", &salt);
        assert_eq!(ring.rotate_kek(&mut un, &cred, 5).unwrap(), 2);
        let re = ring.unlock(&cred).unwrap();
        assert_eq!(re.data_key(1).unwrap().as_bytes(), &dek);
    }

    #[test]
    fn delegation_roundtrip_and_tenant_guard() {
        let (_alice, alice_un, _) = fresh();
        let (mut bob, mut bob_un, bob_salt) = fresh();
        assert_eq!(bob.add_delegated_keys(&mut bob_un, &alice_un, 3).unwrap(), 1);
        let re = bob.unlock(&unlock_for("alice-password", &bob_salt)).unwrap();
        assert_eq!(
            re.delegated_key(alice_un.subject(), 1).unwrap().as_bytes(),
            alice_un.data_key(1).unwrap().as_bytes()
        );
        bob.remove_delegated_keys(&mut bob_un, alice_un.subject()).unwrap();
        assert!(bob_un.delegated_key(alice_un.subject(), 1).is_err());

        let salt = random_salt();
        let (mut other, mut other_un) = SubjectKeyring::create(
            SubjectId::random(),
            TenantId::new("other-tenant").unwrap(),
            &unlock_for("other-password", &salt),
            1,
        )
        .unwrap();
        assert!(other.add_delegated_keys(&mut other_un, &alice_un, 1).is_err());
    }

    #[test]
    fn debug_never_prints_keys() {
        let (ring, un, _) = fresh();
        let shown = format!("{ring:?} {un:?}");
        assert!(!shown.contains(&un.data_key(1).unwrap().to_hex()));
        assert!(shown.contains("REDACTED"));
    }
}
