//! Cryptographic data ownership on top of the identity directory.
//!
//! Separation of concerns:
//!
//! | Concern | Type |
//! |---------|------|
//! | Authentication (who?) | [`crate::auth::AuthService`] (`authenticate_with_key_unlock`) |
//! | Authorization for keys (may they?) | [`policy::decide`] / [`KeyManager::authorize`] |
//! | Key access + crypto context | [`KeyManager`] |
//! | Envelopes, keyrings, sealed records | `dmc_vault::ownership` |
//! | Storage of ciphertext | [`EncryptedStorage`] + [`RecordBackend`] |
//!
//! Successful authentication never implies access to keys: `KeyManager` checks the
//! session, the identity status and the ownership/delegation policy on every use.
//! Administrators (vault Master Key, `cap_root`, catalog grants) are not inputs to
//! the policy and have no API into subject keyrings.

pub mod client_directory;
pub mod enrollment;
pub mod key_manager;
pub mod policy;
pub mod storage;

pub use client_directory::{
    CLIENT_DIRECTORY_FILE, CiphertextReadPolicy, ClientGrant, ClientKeyDirectory, ClientPrincipal,
    client_principal,
};
pub use enrollment::{InviteRecord, InviteState, InviteStore, IssuedInvite, INVITES_FILE};
pub use key_manager::{DELEGATIONS_FILE, KeyManager};
pub use policy::{
    AllowReason, CryptoPrincipal, DelegationGrant, DelegationRegistry, DenyReason,
    KeyAccessDecision, KeyOp, decide,
};
pub use storage::{EncryptedStorage, MemoryRecordBackend, RecordBackend, storage_key};
