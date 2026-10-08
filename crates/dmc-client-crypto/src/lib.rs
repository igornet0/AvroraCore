//! CLIENT_OWNED cryptography — runs in AvroraClient, never in AvroraCore.
//!
//! Trust boundary: the user/device running this crate and its key material are trusted;
//! the database process, its administrators, hosts, disks, WAL, snapshots and backups
//! are not. The server receives only:
//! * [`dmc_vault::ownership::ClientPublicKey`] (public),
//! * [`dmc_vault::ownership::ClientKeyEnvelope`] (DEKs HPKE-sealed to a public key),
//! * sealed records (format v2, key domain CLIENT).
//!
//! Data encryption reuses the canonical `dmc_vault::ownership::record` format and AEAD.
//! HPKE (RFC 9180, `hpke` crate) is used **only** for key encapsulation (own DEK storage
//! and asynchronous delegation), not per record.
//!
//! Authentication to AvroraCore is independent: logging in never yields client keys, and
//! nothing the server receives at login derives them.

pub mod error;
pub mod identity;
pub mod keyring;
pub mod state;

pub use error::{Error, Result};
pub use identity::{ClientIdentity, RecoveryCode};
pub use keyring::{ClientKeyring, parse_sql_blob_cell, sql_blob_literal, sql_client_object_id};
pub use state::{ClientState, TrustDecision};
