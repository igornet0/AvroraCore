//! Whole-file encryption at rest for SQL-plane files (D4-A stage 4).
//!
//! One set of rules for every whole-file writer (event log, snapshot, statistics):
//!
//! | file on disk | keys given | result |
//! |---|---|---|
//! | empty | any | empty content |
//! | sealed | yes | decrypted (wrong key / tampering → error) |
//! | sealed | no | error — "storage keys required" (never read as empty) |
//! | plaintext | yes | error — "explicit migration required" (never converted implicitly) |
//! | plaintext | no | read as plaintext (dev/test, pre-D4 data roots) |
//!
//! Plaintext only exists in memory, in buffers that are zeroized on drop.

use dmc_vault::storage_cipher::{file_context, looks_sealed};
use dmc_vault::{StorageCipher, StoragePurpose};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Decode file bytes per the table above. `what` names the file in errors.
pub fn decode_file(
    raw: &[u8],
    cipher: Option<&StorageCipher>,
    purpose: StoragePurpose,
    context: &str,
    what: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    if raw.is_empty() {
        return Ok(Zeroizing::new(Vec::new()));
    }
    match (looks_sealed(raw), cipher) {
        (true, Some(c)) => c
            .open(purpose, &file_context(context), raw)
            .map(Zeroizing::new)
            .map_err(|_| {
                Error::Corrupt(format!(
                    "{what} cannot be decrypted (wrong key or tampered)"
                ))
            }),
        (true, None) => Err(Error::Corrupt(format!(
            "{what} is encrypted: storage keys required"
        ))),
        (false, Some(_)) => Err(Error::Corrupt(format!(
            "plaintext {what} on encrypted storage: explicit migration required"
        ))),
        (false, None) => Ok(Zeroizing::new(raw.to_vec())),
    }
}

/// A writer without keys never replaces a sealed file with plaintext (D4-A stage 4.6):
/// a keyless path that read nothing (e.g. defaults after "storage keys required") must
/// not silently downgrade encrypted storage. `what` names the file in the error.
pub fn refuse_plaintext_over_sealed(
    dest: &std::path::Path,
    cipher: Option<&StorageCipher>,
    what: &str,
) -> Result<()> {
    if cipher.is_some() {
        return Ok(());
    }
    use dmc_vault::storage_cipher::{STORAGE_HEADER_LEN, STORAGE_TAG_LEN};
    // every sealed file holds at least a header and a tag
    let mut head = [0u8; STORAGE_HEADER_LEN + STORAGE_TAG_LEN];
    let sealed = std::fs::File::open(dest)
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut head))
        .map(|_| looks_sealed(&head))
        .unwrap_or(false);
    if sealed {
        return Err(Error::Corrupt(format!(
            "{what} is encrypted: refusing to overwrite it without storage keys"
        )));
    }
    Ok(())
}

/// Bytes to write: sealed when keys are given.
pub fn encode_file(
    plain: &[u8],
    cipher: Option<&StorageCipher>,
    purpose: StoragePurpose,
    context: &str,
) -> Result<Vec<u8>> {
    match cipher {
        Some(c) => c
            .seal(purpose, &file_context(context), plain)
            .map_err(|e| Error::Corrupt(format!("seal {context}: {e}"))),
        None => Ok(plain.to_vec()),
    }
}
