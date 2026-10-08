//! D4-E (variant B) client side: the backup anchor next to the KeyPass names exactly one
//! backup (id, checkpoint, SHA-256 of its authenticated `manifest.sealed`) that this client
//! authorizes for an emergency restore. An older backup never replaces a newer one, an
//! unencrypted backup cannot be authorized, and a corrupt file is an error.

use dmc_client::keypass::{BACKUP_ANCHOR_FILE, BackupAnchor};
use dmc_client::{BackupCreateResult, KeyPassHandle, UnlockMaterial};

fn created(id: &str, n: u64, byte: u8) -> BackupCreateResult {
    BackupCreateResult {
        backup_id: id.into(),
        checkpoint_sequence: n,
        manifest_sealed_sha256: hex(&[byte; 32]),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn one_backup_anchor_only_newer_replaces_it_and_corruption_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let handle =
        KeyPassHandle::mock_for_tests(UnlockMaterial::random()).with_anchor_dir(dir.path());
    assert_eq!(handle.backup_anchor().unwrap(), None);

    assert!(handle.record_backup(&created("b1", 5, 0x11)).unwrap());
    let expected = BackupAnchor {
        backup_id: "b1".into(),
        checkpoint_sequence: 5,
        manifest_sealed_sha256: [0x11; 32],
    };
    assert_eq!(handle.backup_anchor().unwrap(), Some(expected.clone()));

    // a newer backup replaces it (one anchor = one artifact) ...
    assert!(handle.record_backup(&created("b2", 9, 0x22)).unwrap());
    assert_eq!(
        handle
            .backup_anchor()
            .unwrap()
            .unwrap()
            .manifest_sealed_sha256,
        [0x22; 32]
    );
    // ... an older one never does
    assert!(!handle.record_backup(&expected_result(&expected)).unwrap());
    assert_eq!(handle.backup_anchor().unwrap().unwrap().backup_id, "b2");

    // an unencrypted backup (no authenticated manifest) cannot be authorized
    let mut plain = created("b3", 12, 0);
    plain.manifest_sealed_sha256.clear();
    assert!(handle.record_backup(&plain).is_err());
    assert_eq!(handle.backup_anchor().unwrap().unwrap().backup_id, "b2");

    // corrupt / truncated / extra fields → error, never "no anchor"
    for bad in [
        &b"garbage"[..],
        b"b2 9",
        b"b2 9 abcd",
        b"b2 nine 2222222222222222222222222222222222222222222222222222222222222222",
        b"b2 9 2222222222222222222222222222222222222222222222222222222222222222 extra",
    ] {
        std::fs::write(dir.path().join(BACKUP_ANCHOR_FILE), bad).unwrap();
        assert!(
            handle.backup_anchor().is_err(),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }

    // a handle without a KeyPass directory keeps no backup anchor
    let no_dir = KeyPassHandle::mock_for_tests(UnlockMaterial::random());
    assert_eq!(no_dir.backup_anchor().unwrap(), None);
    assert!(!no_dir.record_backup(&created("b9", 1, 0x33)).unwrap());
}

fn expected_result(a: &BackupAnchor) -> BackupCreateResult {
    BackupCreateResult {
        backup_id: a.backup_id.clone(),
        checkpoint_sequence: a.checkpoint_sequence,
        manifest_sealed_sha256: hex(&a.manifest_sealed_sha256),
    }
}
