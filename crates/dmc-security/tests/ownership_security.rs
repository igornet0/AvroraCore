//! Adversarial tests: authentication ≠ key access, owner isolation, admin isolation,
//! key lifecycle across restarts and crashes, fail-closed behaviour.

use std::path::Path;

use dmc_security::auth::{AuthService, Credential, IdentityId, SessionManager};
use dmc_security::ownership::{
    EncryptedStorage, KeyManager, KeyOp, MemoryRecordBackend, RecordBackend, storage_key,
};
use dmc_security::{Error, SessionId};
use dmc_vault::ownership::{KeyState, SubjectId, TenantId};

const SECRET: &[u8] = b"VERY_SECRET_TEST_PAYLOAD";

struct World {
    auth: AuthService,
    keys: KeyManager,
    dir: tempfile::TempDir,
}

struct User {
    name: &'static str,
    password: &'static str,
    id: IdentityId,
    subject: SubjectId,
}

fn tenant(t: &str) -> TenantId {
    TenantId::new(t).unwrap()
}

fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    let keys = KeyManager::open(dir.path().join("keyring")).unwrap();
    World {
        auth: AuthService::new(),
        keys,
        dir,
    }
}

fn enroll(w: &mut World, name: &'static str, password: &'static str, t: &str) -> User {
    let (id, subject, unlock) = w.auth.enroll_owner(name, password, tenant(t)).unwrap();
    assert_eq!(w.keys.enroll(&w.auth, &id, unlock).unwrap(), subject);
    User {
        name,
        password,
        id,
        subject,
    }
}

fn login(w: &mut World, u: &User) -> SessionId {
    let (identity, unlock) = w
        .auth
        .authenticate_with_key_unlock(&Credential::Password {
            identity_name: u.name.into(),
            password: u.password.into(),
        })
        .unwrap();
    let session = w.auth.create_session(identity.identity_id).unwrap();
    w.keys.open_session(&w.auth, &session.id, unlock).unwrap();
    session.id.clone()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn assert_no_plaintext_in_dir(dir: &Path) {
    for entry in walk(dir) {
        let bytes = std::fs::read(&entry).unwrap();
        assert!(
            !contains(&bytes, SECRET),
            "plaintext found in {}",
            entry.display()
        );
    }
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

// ── Authentication ────────────────────────────────────────────────────────────

#[test]
fn auth_valid_invalid_disabled_revoked() {
    let mut w = world();
    let alice = enroll(&mut w, "alice", "alice-password", "acme");

    // valid
    let s = login(&mut w, &alice);
    assert!(w.auth.validate_session(&s).is_ok());

    // invalid password / unknown identity: same error kind, no unlock material
    for (name, pw) in [("alice", "wrong-password"), ("mallory", "alice-password")] {
        let err = w
            .auth
            .authenticate_with_key_unlock(&Credential::Password {
                identity_name: name.into(),
                password: pw.into(),
            })
            .unwrap_err();
        assert!(matches!(err, Error::AuthenticationFailed(_)), "{err}");
    }

    // revoked session: crypto session is torn down on next use
    w.auth.revoke_session(&s).unwrap();
    let err = w
        .keys
        .authorize(&w.auth, &s, alice.subject, KeyOp::Read)
        .unwrap_err();
    assert!(matches!(err, Error::KeyAccessDenied(_)));
    assert_eq!(w.keys.open_session_count(), 0, "keys dropped after revoke");

    // disabled identity: cannot authenticate, and live crypto sessions die
    let s2 = login(&mut w, &alice);
    w.auth.disable_identity(&alice.id).unwrap();
    assert!(w.keys.authorize(&w.auth, &s2, alice.subject, KeyOp::Read).is_err());
    let err = w
        .auth
        .authenticate_with_key_unlock(&Credential::Password {
            identity_name: "alice".into(),
            password: "alice-password".into(),
        })
        .unwrap_err();
    assert!(matches!(err, Error::IdentityDisabled(_)));
}

#[test]
fn authentication_alone_does_not_unlock_keys() {
    let mut w = world();
    let alice = enroll(&mut w, "alice", "alice-password", "acme");
    // A live session without the credential-derived unlock has no crypto session.
    let session = w.auth.create_session(alice.id.clone()).unwrap();
    let err = w
        .keys
        .authorize(&w.auth, &session.id, alice.subject, KeyOp::Read)
        .unwrap_err();
    assert!(matches!(err, Error::KeyAccessDenied(_)));
}

#[test]
fn key_credential_policy_and_password_never_stored() {
    let mut w = world();
    assert!(w.auth.enroll_owner("weak", "short", tenant("acme")).is_err());
    let _alice = enroll(&mut w, "alice", "alice-password", "acme");
    let path = w.dir.path().join("identities.json");
    w.auth.save_identities(&path).unwrap();
    let raw = std::fs::read(&path).unwrap();
    assert!(!contains(&raw, b"alice-password"));
    assert!(!format!("{:?}", w.auth).contains("alice-password"));
}

// ── Authorization ─────────────────────────────────────────────────────────────

#[test]
fn owner_isolation_matrix() {
    let mut w = world();
    let alice = enroll(&mut w, "alice", "alice-password", "acme");
    let bob = enroll(&mut w, "bob", "bob-password", "acme");
    let sa = login(&mut w, &alice);
    let sb = login(&mut w, &bob);
    let mut store = EncryptedStorage::new(MemoryRecordBackend::default());

    store
        .put(&mut w.keys, &w.auth, &sa, alice.subject, "diary", SECRET)
        .unwrap();
    store
        .put(&mut w.keys, &w.auth, &sb, bob.subject, "diary", b"bob data")
        .unwrap();

    // Alice → Alice: allowed
    assert_eq!(
        store.get(&mut w.keys, &w.auth, &sa, alice.subject, "diary").unwrap(),
        SECRET
    );
    // Alice → Bob / Bob → Alice: denied (read and write)
    for (s, owner) in [(&sa, bob.subject), (&sb, alice.subject)] {
        let err = store
            .get(&mut w.keys, &w.auth, s, owner, "diary")
            .unwrap_err();
        assert!(matches!(err, Error::KeyAccessDenied(_)), "{err}");
        assert!(store
            .put(&mut w.keys, &w.auth, s, owner, "diary", b"overwrite")
            .is_err());
    }
    // Bob cannot use a raw copy of Alice's ciphertext either
    let raw = store.raw_sealed(alice.subject, "diary").unwrap().unwrap();
    assert!(w.keys.open_sealed(&w.auth, &sb, alice.subject, "diary", &raw).is_err());
    assert!(w.keys.open_sealed(&w.auth, &sb, bob.subject, "diary", &raw).is_err());
}

#[test]
fn tenant_isolation() {
    let mut w = world();
    let alice = enroll(&mut w, "alice", "alice-password", "acme");
    let eve = enroll(&mut w, "eve", "eve-password", "globex");
    let sa = login(&mut w, &alice);
    let se = login(&mut w, &eve);
    let mut store = EncryptedStorage::new(MemoryRecordBackend::default());
    store
        .put(&mut w.keys, &w.auth, &sa, alice.subject, "x", SECRET)
        .unwrap();
    assert!(store.get(&mut w.keys, &w.auth, &se, alice.subject, "x").is_err());
    let err = w.keys.delegate_read(&w.auth, &sa, &se, None).unwrap_err();
    assert!(matches!(err, Error::KeyAccessDenied(_)));
}

#[test]
fn delegated_read_and_revocation() {
    let mut w = world();
    let alice = enroll(&mut w, "alice", "alice-password", "acme");
    let bob = enroll(&mut w, "bob", "bob-password", "acme");
    let sa = login(&mut w, &alice);
    let sb = login(&mut w, &bob);
    let mut store = EncryptedStorage::new(MemoryRecordBackend::default());
    store
        .put(&mut w.keys, &w.auth, &sa, alice.subject, "shared", SECRET)
        .unwrap();

    // Bob can only ever delegate his own keys (here: to Alice), never Alice's.
    assert!(w.keys.delegate_read(&w.auth, &sb, &sa, None).is_ok());
    w.keys.revoke_delegation(&w.auth, &sb, alice.subject).unwrap();

    w.keys.delegate_read(&w.auth, &sa, &sb, None).unwrap();
    assert_eq!(
        store.get(&mut w.keys, &w.auth, &sb, alice.subject, "shared").unwrap(),
        SECRET
    );
    // delegated access is read-only
    assert!(store
        .put(&mut w.keys, &w.auth, &sb, alice.subject, "shared", b"tamper")
        .is_err());

    // survives re-login of the grantee
    w.keys.close_session(&sb);
    let sb = login(&mut w, &bob);
    assert!(store.get(&mut w.keys, &w.auth, &sb, alice.subject, "shared").is_ok());

    // revocation: immediate, and envelopes are purged
    w.keys.revoke_delegation(&w.auth, &sa, bob.subject).unwrap();
    assert!(store.get(&mut w.keys, &w.auth, &sb, alice.subject, "shared").is_err());
    let ring = std::fs::read_to_string(
        w.dir
            .path()
            .join("keyring")
            .join(format!("{}.keyring.json", bob.subject)),
    )
    .unwrap();
    assert!(!ring.contains("delegated_data_key"));
}

// ── Cryptography ──────────────────────────────────────────────────────────────

#[test]
fn ciphertext_tamper_wrong_key_wrong_context() {
    let mut w = world();
    let alice = enroll(&mut w, "alice", "alice-password", "acme");
    let sa = login(&mut w, &alice);
    let sealed = w
        .keys
        .seal(&w.auth, &sa, alice.subject, "doc", 1, SECRET)
        .unwrap();
    assert!(!contains(&sealed, SECRET));

    let mut tampered = sealed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x80;
    assert!(w.keys.open_sealed(&w.auth, &sa, alice.subject, "doc", &tampered).is_err());
    // moved to another object id → AAD mismatch
    assert!(w.keys.open_sealed(&w.auth, &sa, alice.subject, "other", &sealed).is_err());

    // same plaintext under another subject's key (wrong key)
    let bob = enroll(&mut w, "bob", "bob-password", "acme");
    let sb = login(&mut w, &bob);
    let bob_sealed = w.keys.seal(&w.auth, &sb, bob.subject, "doc", 1, SECRET).unwrap();
    let mut forged = bob_sealed.clone();
    forged[10..26].copy_from_slice(alice.subject.as_bytes()); // claim Alice owns it
    assert!(w.keys.open_sealed(&w.auth, &sa, alice.subject, "doc", &forged).is_err());
}

// ── Administrator isolation ───────────────────────────────────────────────────

#[test]
fn administrator_has_no_cryptographic_authority() {
    let mut w = world();
    let alice = enroll(&mut w, "alice", "alice-password", "acme");
    let sa = login(&mut w, &alice);
    let mut store = EncryptedStorage::new(MemoryRecordBackend::default());
    store
        .put(&mut w.keys, &w.auth, &sa, alice.subject, "diary", SECRET)
        .unwrap();

    // The DBA has a fully privileged, authenticated identity of its own …
    let admin = enroll(&mut w, "dba", "dba-password-1", "acme");
    let sadmin = login(&mut w, &admin);
    // … full access to stored bytes and metadata (operational API) …
    let raw = store.raw_sealed(alice.subject, "diary").unwrap().unwrap();
    assert!(!contains(&raw, SECRET));
    let refs = store.key_version_references(alice.subject).unwrap();
    assert_eq!(refs.get(&1), Some(&1));
    // … and can even reset Alice's password in the identity directory:
    w.auth.configure_credential("alice", "admin-chosen-pw");
    // but there is still no way to the plaintext:
    assert!(store.get(&mut w.keys, &w.auth, &sadmin, alice.subject, "diary").is_err());
    let (identity, unlock) = w
        .auth
        .authenticate_with_key_unlock(&Credential::Password {
            identity_name: "alice".into(),
            password: "admin-chosen-pw".into(),
        })
        .unwrap();
    let hijack = w.auth.create_session(identity.identity_id).unwrap();
    let err = w.keys.open_session(&w.auth, &hijack.id, unlock).unwrap_err();
    assert!(
        matches!(err, Error::Ownership(dmc_vault::ownership::Error::WrongCredential)),
        "{err}"
    );
    // keyring files hold no usable secrets
    assert_no_plaintext_in_dir(&w.dir.path().join("keyring"));
}

// ── Key rotation ──────────────────────────────────────────────────────────────

#[test]
fn rotation_old_readable_new_version_and_survives_restart() {
    let mut w = world();
    let alice = enroll(&mut w, "alice", "alice-password", "acme");
    let sa = login(&mut w, &alice);
    let mut store = EncryptedStorage::new(MemoryRecordBackend::default());
    store
        .put(&mut w.keys, &w.auth, &sa, alice.subject, "old", SECRET)
        .unwrap();
    assert_eq!(w.keys.rotate_data_key(&w.auth, &sa).unwrap(), 2);
    store
        .put(&mut w.keys, &w.auth, &sa, alice.subject, "new", b"after rotation")
        .unwrap();
    let refs = store.key_version_references(alice.subject).unwrap();
    assert_eq!((refs[&1], refs[&2]), (1, 1), "new records use the new version");

    // restart: new KeyManager over the same directory
    let backend = store.into_backend();
    w.keys = KeyManager::open(w.dir.path().join("keyring")).unwrap();
    let sa = login(&mut w, &alice);
    let store = EncryptedStorage::new(backend);
    assert_eq!(w.keys.active_key_version(&sa).unwrap(), 2);
    assert_eq!(w.keys.key_state(&sa, 1).unwrap(), Some(KeyState::Retired));
    assert_eq!(store.get(&mut w.keys, &w.auth, &sa, alice.subject, "old").unwrap(), SECRET);

    // another subject's keys never decrypt it
    let bob = enroll(&mut w, "bob", "bob-password", "acme");
    let sb = login(&mut w, &bob);
    assert!(store.get(&mut w.keys, &w.auth, &sb, alice.subject, "old").is_err());
}

#[test]
fn retired_key_destroyed_only_when_unreferenced() {
    let mut w = world();
    let alice = enroll(&mut w, "alice", "alice-password", "acme");
    let sa = login(&mut w, &alice);
    let mut store = EncryptedStorage::new(MemoryRecordBackend::default());
    store
        .put(&mut w.keys, &w.auth, &sa, alice.subject, "a", SECRET)
        .unwrap();
    w.keys.rotate_data_key(&w.auth, &sa).unwrap();
    let refs = store.key_version_references(alice.subject).unwrap();
    assert!(w.keys.destroy_retired_key(&w.auth, &sa, 1, refs[&1]).is_err());

    assert_eq!(store.reencrypt_owner(&mut w.keys, &w.auth, &sa, alice.subject).unwrap(), 1);
    let refs = store.key_version_references(alice.subject).unwrap();
    assert_eq!(refs.get(&1).copied().unwrap_or(0), 0);
    w.keys.destroy_retired_key(&w.auth, &sa, 1, 0).unwrap();
    assert_eq!(store.get(&mut w.keys, &w.auth, &sa, alice.subject, "a").unwrap(), SECRET);
    assert_eq!(w.keys.key_state(&sa, 1).unwrap(), Some(KeyState::Destroyed));
}

#[test]
fn crash_between_rotation_steps_is_recovered() {
    let mut w = world();
    let alice = enroll(&mut w, "alice", "alice-password", "acme");
    let sa = login(&mut w, &alice);
    let mut store = EncryptedStorage::new(MemoryRecordBackend::default());
    store
        .put(&mut w.keys, &w.auth, &sa, alice.subject, "before", SECRET)
        .unwrap();
    // crash point: ROTATING persisted, promotion never happened
    w.keys.begin_data_key_rotation(&w.auth, &sa).unwrap();
    assert_eq!(w.keys.active_key_version(&sa).unwrap(), 1, "writes still on v1");
    store
        .put(&mut w.keys, &w.auth, &sa, alice.subject, "during", b"during")
        .unwrap();
    drop(std::mem::replace(
        &mut w.keys,
        KeyManager::open(w.dir.path().join("keyring")).unwrap(),
    ));

    let sa = login(&mut w, &alice); // completes the rotation
    assert_eq!(w.keys.active_key_version(&sa).unwrap(), 2);
    assert_eq!(store.get(&mut w.keys, &w.auth, &sa, alice.subject, "before").unwrap(), SECRET);
    assert_eq!(store.get(&mut w.keys, &w.auth, &sa, alice.subject, "during").unwrap(), b"during");
}

#[test]
fn password_change_rewraps_without_reencryption_and_crash_windows() {
    let mut w = world();
    let alice = enroll(&mut w, "alice", "alice-password", "acme");
    let sa = login(&mut w, &alice);
    let mut store = EncryptedStorage::new(MemoryRecordBackend::default());
    store
        .put(&mut w.keys, &w.auth, &sa, alice.subject, "doc", SECRET)
        .unwrap();
    let before = store.raw_sealed(alice.subject, "doc").unwrap();

    let ids_path = w.dir.path().join("identities.json");
    w.auth.save_identities(&ids_path).unwrap();
    let (_old, new) = w
        .auth
        .change_password("alice", "alice-password", "alice-new-password")
        .unwrap();
    w.keys.add_credential(&w.auth, &sa, &new).unwrap();
    // crash window 1 (simulated on a copy of the disk state): identities not yet saved →
    // restart sees the old directory; the old password still opens the keyring.
    let crash_dir = w.dir.path().join("crash-keyring");
    std::fs::create_dir_all(&crash_dir).unwrap();
    for f in walk(&w.dir.path().join("keyring")) {
        std::fs::copy(&f, crash_dir.join(f.file_name().unwrap())).unwrap();
    }
    let mut crashed = AuthService::new();
    crashed.load_identities(&ids_path).unwrap();
    {
        let mut km = KeyManager::open(&crash_dir).unwrap();
        let (id, unlock) = crashed
            .authenticate_with_key_unlock(&Credential::Password {
                identity_name: "alice".into(),
                password: "alice-password".into(),
            })
            .unwrap();
        let s = crashed.create_session(id.identity_id).unwrap();
        km.open_session(&crashed, &s.id, unlock).unwrap();
    }
    // normal path: persist identities, re-login with the new password
    w.auth.save_identities(&ids_path).unwrap();
    w.keys.close_session(&sa);
    let alice2 = User {
        password: "alice-new-password",
        ..alice
    };
    let sa = login(&mut w, &alice2);
    assert_eq!(store.get(&mut w.keys, &w.auth, &sa, alice2.subject, "doc").unwrap(), SECRET);
    assert_eq!(store.raw_sealed(alice2.subject, "doc").unwrap(), before, "no re-encryption");
    // old password no longer authenticates
    assert!(w
        .auth
        .authenticate_with_key_unlock(&Credential::Password {
            identity_name: "alice".into(),
            password: "alice-password".into(),
        })
        .is_err());
}

// ── Fail closed ───────────────────────────────────────────────────────────────

#[test]
fn missing_or_corrupt_key_material_fails_closed() {
    let mut w = world();
    let alice = enroll(&mut w, "alice", "alice-password", "acme");
    let sa = login(&mut w, &alice);
    let mut store = EncryptedStorage::new(MemoryRecordBackend::default());
    store
        .put(&mut w.keys, &w.auth, &sa, alice.subject, "doc", SECRET)
        .unwrap();
    w.keys.close_session(&sa);
    let ring = w
        .dir
        .path()
        .join("keyring")
        .join(format!("{}.keyring.json", alice.subject));

    // corrupted keyring → integrity error, never a new key
    let good = std::fs::read(&ring).unwrap();
    let text = String::from_utf8(good.clone()).unwrap();
    std::fs::write(&ring, text.replacen("\"ACTIVE\"", "\"RETIRED\"", 1)).unwrap();
    let (id, unlock) = w
        .auth
        .authenticate_with_key_unlock(&Credential::Password {
            identity_name: "alice".into(),
            password: "alice-password".into(),
        })
        .unwrap();
    let s = w.auth.create_session(id.identity_id.clone()).unwrap();
    let err = w.keys.open_session(&w.auth, &s.id, unlock).unwrap_err();
    assert!(matches!(err, Error::Ownership(_)), "{err}");

    // deleted keyring → KeyringNotFound, and no keyring is silently recreated
    std::fs::remove_file(&ring).unwrap();
    let (_, unlock) = w
        .auth
        .authenticate_with_key_unlock(&Credential::Password {
            identity_name: "alice".into(),
            password: "alice-password".into(),
        })
        .unwrap();
    let err = w.keys.open_session(&w.auth, &s.id, unlock).unwrap_err();
    assert!(
        matches!(
            err,
            Error::Ownership(dmc_vault::ownership::Error::KeyringNotFound(_))
        ),
        "{err}"
    );
    assert!(!ring.exists());
    let raw = store
        .backend()
        .get(&storage_key(alice.subject, "doc"))
        .unwrap()
        .unwrap();
    assert!(!contains(&raw, SECRET));
}

// ── Prepared operator-blind path: ciphertext sealed outside the server ────────

#[test]
fn externally_sealed_records_are_stored_without_server_keys() {
    let mut w = world();
    let alice = enroll(&mut w, "alice", "alice-password", "acme");
    let bob = enroll(&mut w, "bob", "bob-password", "acme");
    // "Client" side: Alice's keys live in a KeyManager the server never opens.
    let mut client_keys = KeyManager::open(w.dir.path().join("keyring")).unwrap();
    let (identity, unlock) = w
        .auth
        .authenticate_with_key_unlock(&Credential::Password {
            identity_name: "alice".into(),
            password: "alice-password".into(),
        })
        .unwrap();
    let client_session = w.auth.create_session(identity.identity_id).unwrap().id.clone();
    client_keys.open_session(&w.auth, &client_session, unlock).unwrap();
    let sealed = client_keys
        .seal(&w.auth, &client_session, alice.subject, "diary", 1, SECRET)
        .unwrap();

    // "Server" side: authenticated session for Alice, but NO crypto session / keys.
    let server_session = w.auth.create_session(alice.id.clone()).unwrap().id.clone();
    let mut store = EncryptedStorage::new(MemoryRecordBackend::default());
    assert_eq!(
        store
            .put_sealed(&w.auth, &server_session, alice.subject, "diary", &sealed)
            .unwrap(),
        1
    );
    assert_eq!(w.keys.open_session_count(), 0, "server holds no keys");
    // server cannot decrypt what it stores
    assert!(store
        .get(&mut w.keys, &w.auth, &server_session, alice.subject, "diary")
        .is_err());
    // client can
    let raw = store.raw_sealed(alice.subject, "diary").unwrap().unwrap();
    assert_eq!(
        client_keys
            .open_sealed(&w.auth, &client_session, alice.subject, "diary", &raw)
            .unwrap(),
        SECRET
    );

    // replay of the same version, foreign owner, non-owner writer: all refused
    assert!(store
        .put_sealed(&w.auth, &server_session, alice.subject, "diary", &sealed)
        .is_err());
    let bob_session = w.auth.create_session(bob.id.clone()).unwrap().id.clone();
    assert!(store
        .put_sealed(&w.auth, &bob_session, alice.subject, "other", &sealed)
        .is_err());
    assert!(store
        .put_sealed(&w.auth, &server_session, bob.subject, "x", &sealed)
        .is_err());
    assert!(store
        .put_sealed(&w.auth, &server_session, alice.subject, "junk", b"not a record")
        .is_err());
}

/// Regression (F7): a session issued before the identity was disabled must not keep
/// working on the generic session path (SQL authorization uses `validate_session` /
/// `principal_for`, not the key manager).
#[test]
fn disabled_identity_sessions_stop_working_on_every_session_path() {
    let mut w = world();
    let alice = enroll(&mut w, "alice", "alice-password", "acme");
    let bob = enroll(&mut w, "bob", "bob-password", "acme");
    let (sa, _) = w.auth.login("alice", "alice-password").unwrap();
    let (sb, _) = w.auth.login("bob", "bob-password").unwrap();
    let (sa, sb) = (sa.id.clone(), sb.id.clone());
    assert!(w.auth.principal_for(&sa).is_ok());

    w.auth.disable_identity(&alice.id).unwrap();
    assert!(w.auth.validate_session(&sa).is_err());
    assert!(w.auth.principal_for(&sa).is_err());
    assert!(w.auth.unlock_binding_key(&sa).is_err());
    // other identities are unaffected
    assert!(w.auth.principal_for(&sb).is_ok());
    let _ = bob;
}
