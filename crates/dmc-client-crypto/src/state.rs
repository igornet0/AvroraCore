//! Client-local trust state: TOFU public-key pins and the key-version rollback floor.
//!
//! The server is untrusted, so the client must not accept whatever public key the server
//! returns for a delegation target. On first use the fingerprint is pinned; later a
//! different key for the same subject is refused ([`Error::PinMismatch`]). A pin can also
//! be set from a fingerprint verified out of band ([`ClientState::pin_verified`]).
//!
//! Limitation (documented): if the server substitutes a key at the very first contact and
//! the user does not compare fingerprints out of band, TOFU pins the attacker's key.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use dmc_vault::ownership::{ClientPublicKey, SubjectId};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Pin {
    fingerprint: String,
    key_version: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum PinRecord {
    V2(Pin),
    /// format 1: bare fingerprint (key version 1)
    V1(String),
}

impl PinRecord {
    fn pin(&self) -> Pin {
        match self {
            Self::V2(p) => p.clone(),
            Self::V1(fp) => Pin {
                fingerprint: fp.clone(),
                key_version: 1,
            },
        }
    }
}

/// Result of a trust check on a server-provided public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustDecision {
    /// First contact: pinned now (TOFU). Not authenticated against a malicious server
    /// unless the fingerprint was also compared out of band.
    PinnedOnFirstUse,
    /// Matches the pinned key.
    Matches,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StateFile {
    format_version: u16,
    /// subject → pinned key
    pins: BTreeMap<String, PinRecord>,
    /// Highest own DEK version ever seen (rollback floor).
    highest_own_version: u32,
}

#[derive(Debug)]
pub struct ClientState {
    path: Option<PathBuf>,
    file: StateFile,
}

impl ClientState {
    /// Volatile state (tests / ephemeral clients).
    pub fn in_memory() -> Self {
        Self {
            path: None,
            file: StateFile {
                format_version: 1,
                ..StateFile::default()
            },
        }
    }

    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let file = match std::fs::read(&path) {
            Ok(raw) => serde_json::from_slice(&raw).map_err(|e| Error::Format(e.to_string()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => StateFile {
                format_version: 1,
                ..StateFile::default()
            },
            Err(e) => return Err(Error::io(e)),
        };
        Ok(Self {
            path: Some(path),
            file,
        })
    }

    fn persist(&self) -> Result<()> {
        if let Some(path) = &self.path {
            let raw = serde_json::to_vec_pretty(&self.file).map_err(|e| Error::Format(e.to_string()))?;
            dmc_vault::secure_fs::write_secret_file(Path::new(path), &raw).map_err(Error::io)?;
        }
        Ok(())
    }

    /// TOFU: pin on first sight; afterwards the received key must equal the pin.
    /// A different key is `KeyChanged` (refused by default), an older version `KeyRollback`.
    /// The fingerprint is always recomputed locally from the key bytes — a fingerprint sent
    /// by the server is never trusted.
    pub fn check_or_pin(&mut self, key: &ClientPublicKey) -> Result<TrustDecision> {
        key.validate()?;
        let fp = hex::encode(key.fingerprint());
        let subject = key.subject.to_hex();
        match self.file.pins.get(&subject).map(PinRecord::pin) {
            Some(pin) if pin.fingerprint == fp => Ok(TrustDecision::Matches),
            Some(pin) if key.key_version < pin.key_version => Err(Error::KeyRollback {
                subject,
                pinned: pin.key_version,
                offered: key.key_version,
            }),
            Some(_) => Err(Error::KeyChanged { subject }),
            None => {
                self.file.pins.insert(
                    subject,
                    PinRecord::V2(Pin {
                        fingerprint: fp,
                        key_version: key.key_version,
                    }),
                );
                self.persist()?;
                Ok(TrustDecision::PinnedOnFirstUse)
            }
        }
    }

    /// Explicit trust after out-of-band comparison (`fingerprint_display` form). This is
    /// the only way to accept a changed key; it never accepts an older key version.
    pub fn pin_verified(&mut self, key: &ClientPublicKey, expected_display: &str) -> Result<()> {
        key.validate()?;
        if key.fingerprint_display() != expected_display.trim() {
            return Err(Error::KeyChanged {
                subject: key.subject.to_hex(),
            });
        }
        if let Some(pin) = self.file.pins.get(&key.subject.to_hex()).map(PinRecord::pin) {
            if key.key_version < pin.key_version {
                return Err(Error::KeyRollback {
                    subject: key.subject.to_hex(),
                    pinned: pin.key_version,
                    offered: key.key_version,
                });
            }
        }
        self.file.pins.insert(
            key.subject.to_hex(),
            PinRecord::V2(Pin {
                fingerprint: hex::encode(key.fingerprint()),
                key_version: key.key_version,
            }),
        );
        self.persist()
    }

    pub fn is_pinned(&self, subject: SubjectId) -> bool {
        self.file.pins.contains_key(&subject.to_hex())
    }

    pub(crate) fn highest_own_version(&self) -> u32 {
        self.file.highest_own_version
    }

    pub(crate) fn raise_own_version(&mut self, v: u32) -> Result<()> {
        if v > self.file.highest_own_version {
            self.file.highest_own_version = v;
            self.persist()?;
        }
        Ok(())
    }
}
