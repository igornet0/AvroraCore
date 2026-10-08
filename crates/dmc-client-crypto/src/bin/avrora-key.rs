//! `avrora-key` — client-side key utility (never part of the server binary).
//!
//! ```text
//! avrora-key fingerprint --identity <device identity.json>   # your own key, from the device
//! avrora-key fingerprint --public-key <key.json>             # a key received from the server
//! ```
//!
//! The fingerprint is always computed locally from the key bytes. Compare it with the
//! other party over an independent channel (in person, phone, signed message). TOFU only
//! protects contacts *after* the first trusted one; a malicious server can substitute a key
//! at first contact unless fingerprints are compared out of band.

use std::path::PathBuf;
use std::process::ExitCode;

use dmc_client_crypto::ClientIdentity;
use dmc_vault::ownership::{ClientPublicKey, ServerStoredPublicKey};

fn usage() -> ExitCode {
    eprintln!("usage: avrora-key fingerprint (--identity <identity.json> | --public-key <key.json>)");
    ExitCode::from(2)
}

fn print(key: &ClientPublicKey) {
    println!("subject      {}", key.subject);
    println!("tenant       {}", key.tenant);
    println!("key_version  {}", key.key_version);
    println!("key_id       {}", key.key_id());
    println!("fingerprint  {}", key.fingerprint_display());
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [cmd, flag, path] if cmd == "fingerprint" && flag == "--identity" => {
            match ClientIdentity::load(&PathBuf::from(path)) {
                Ok(id) => {
                    print(&id.public_key());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        [cmd, flag, path] if cmd == "fingerprint" && flag == "--public-key" => {
            let raw = match std::fs::read(path) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            };
            // Accept either a bare ClientPublicKey or a server record; the server-supplied
            // fingerprint field is ignored and recomputed.
            let key = serde_json::from_slice::<ClientPublicKey>(&raw)
                .or_else(|_| serde_json::from_slice::<ServerStoredPublicKey>(&raw).map(|s| s.key));
            match key.map_err(|e| e.to_string()).and_then(|k| k.validate().map(|_| k).map_err(|e| e.to_string())) {
                Ok(k) => {
                    print(&k);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => usage(),
    }
}
