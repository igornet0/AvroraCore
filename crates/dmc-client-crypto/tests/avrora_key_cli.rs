//! `avrora-key fingerprint` prints the locally computed fingerprint; a server-supplied
//! fingerprint field is ignored.

use std::process::Command;

use dmc_client_crypto::ClientIdentity;
use dmc_vault::ownership::{ServerStoredPublicKey, SubjectId, TenantId};

#[test]
fn fingerprint_from_identity_and_from_server_record() {
    let dir = tempfile::tempdir().unwrap();
    let (id, _) = ClientIdentity::generate(SubjectId::random(), TenantId::new("acme").unwrap());
    let id_path = dir.path().join("identity.json");
    id.save(&id_path).unwrap();
    let expected = id.public_key().fingerprint_display();

    let out = Command::new(env!("CARGO_BIN_EXE_avrora-key"))
        .args(["fingerprint", "--identity"])
        .arg(&id_path)
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains(&expected), "{text}");

    // server record with a forged fingerprint field: the CLI recomputes from key bytes
    let mut record = ServerStoredPublicKey::new(id.public_key(), 1);
    record.fingerprint = [0xAA; 32];
    let rec_path = dir.path().join("server-key.json");
    std::fs::write(&rec_path, serde_json::to_vec(&record).unwrap()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_avrora-key"))
        .args(["fingerprint", "--public-key"])
        .arg(&rec_path)
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains(&expected) && !text.contains("aaaaaaaa"), "{text}");
}
