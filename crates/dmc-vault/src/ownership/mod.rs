//! Cryptographic data ownership (per-subject key hierarchy).
//!
//! Independent of the vault Master Key: the database process stores and moves only
//! wrapped keys and sealed records. Opening a subject's keys requires that subject's
//! credential (via [`CredentialUnlock`]). There is deliberately no admin/master path
//! into a keyring, no key-export API and no plaintext fallback.
//!
//! Authentication and authorization live in `dmc-security`; this module only provides
//! the primitives (envelopes, keyrings, sealed records, durable keyring store).
//!
//! # Invariant: KEKs are not exportable
//!
//! Neither the vault [`crate::KeyTree`] nor an [`UnlockedKeyring`] offers a way to read a
//! KEK. These must not compile:
//!
//! ```compile_fail
//! let (tree, _master) = dmc_vault::KeyTree::create_new().unwrap();
//! let _kek = tree.export_kek(&dmc_vault::KeyPath::root());
//! ```
//!
//! ```compile_fail
//! let (mut tree, _master) = dmc_vault::KeyTree::create_new().unwrap();
//! tree.install_kek(&dmc_vault::KeyPath::root(), dmc_vault::KeyMaterial::random());
//! ```
//!
//! ```compile_fail
//! fn leak(k: &dmc_vault::ownership::UnlockedKeyring) -> &dmc_vault::KeyMaterial { k.kek() }
//! ```
//!
//! ```compile_fail
//! fn leak(k: &dmc_vault::ownership::UnlockedKeyring) -> &dmc_vault::KeyMaterial { &k.kek }
//! ```
//!
//! Control (same paths, legitimate calls) — compiles, so the cases above fail only
//! because the KEK accessors do not exist:
//!
//! ```
//! let (tree, _master) = dmc_vault::KeyTree::create_new().unwrap();
//! assert!(tree.peek_dek(&dmc_vault::KeyPath::root()).is_ok());
//! fn version(k: &dmc_vault::ownership::UnlockedKeyring) -> bool { k.data_key(1).is_ok() }
//! let _ = version;
//! ```

pub mod auth;
pub mod client;
pub mod credential;
pub mod envelope;
pub mod error;
pub mod ids;
pub mod keyring;
pub mod record;
pub mod store;

pub use client::{
    CLIENT_SUITE_V1, CLIENT_WIRE_FORMAT_V1, ClientEnvelopeKind, ClientKeyEnvelope, ClientPublicKey,
    PublicKeyStatus, ServerStoredPublicKey,
};
pub use credential::{
    CredentialSecrets, CredentialUnlock, KdfAlg, PasswordKdfParams, Verifier,
    check_key_credential_policy, derive_credential_secrets, random_salt,
};
pub use envelope::{ALG_AES256GCM, ENVELOPE_FORMAT_V1, EnvelopeKind, KeyEnvelope};
pub use error::{Error, Result};
pub use ids::{SubjectId, TenantId};
pub use keyring::{
    CredentialEntry, DataKeyEntry, DelegatedKeyEntry, KEYRING_FORMAT_V1, KeyState,
    SubjectKeyring, UnlockedKeyring,
};
pub use record::{
    KeyDomain, RecordContext, RecordHeader, open_record, open_record_in, seal_record,
    seal_record_in,
};
pub use store::KeyringStore;
