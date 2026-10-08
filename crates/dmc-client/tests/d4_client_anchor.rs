//! D4-D client side: the anti-rollback anchor next to the KeyPass only ever rises, and a
//! corrupt anchor file is an error — never silently 0 (which would disable the check).

use dmc_client::keypass::ANCHOR_FILE;
use dmc_client::{KeyPassHandle, UnlockMaterial};

#[test]
fn anchor_only_rises_and_corruption_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let handle =
        KeyPassHandle::mock_for_tests(UnlockMaterial::random()).with_anchor_dir(dir.path());
    assert_eq!(handle.anchor().unwrap(), 0, "no state yet: no anchor");
    handle.record_generation(7).unwrap();
    assert_eq!(handle.anchor().unwrap(), 7);
    handle.record_generation(3).unwrap();
    assert_eq!(handle.anchor().unwrap(), 7, "never lowered implicitly");

    std::fs::write(dir.path().join(ANCHOR_FILE), b"not-a-number").unwrap();
    assert!(
        handle.anchor().is_err(),
        "corrupt anchor refused, not treated as 0"
    );

    let no_dir = KeyPassHandle::mock_for_tests(UnlockMaterial::random());
    assert_eq!(
        no_dir.anchor().unwrap(),
        0,
        "handle without a directory keeps no anchor"
    );
}
