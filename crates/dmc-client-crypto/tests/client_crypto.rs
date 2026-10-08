//! Client-side crypto: basic properties, tampering, recovery, restart, rotation,
//! rollback, TOFU pinning and asynchronous delegation (no server involved).

use dmc_client_crypto::{
    ClientIdentity, ClientKeyring, ClientState, Error, RecoveryCode, parse_sql_blob_cell,
    sql_blob_literal,
};
use dmc_vault::ownership::{ClientKeyEnvelope, SubjectId, TenantId};

const SECRET: &[u8] = b"VERY_SECRET_CLIENT_PAYLOAD";

fn acme() -> TenantId {
    TenantId::new("acme").unwrap()
}

fn user(tenant: &TenantId) -> (ClientKeyring, ClientState, Vec<ClientKeyEnvelope>, RecoveryCode) {
    let (id, code) = ClientIdentity::generate(SubjectId::random(), tenant.clone());
    let mut state = ClientState::in_memory();
    let (ring, env) = ClientKeyring::create(id, &mut state).unwrap();
    (ring, state, vec![env], code)
}

/// Same identity on "another process" (restart / second device) via its recovery code.
fn again(ring: &ClientKeyring, code: &RecoveryCode) -> ClientIdentity {
    ClientIdentity::from_recovery(ring.subject(), acme(), code).unwrap()
}

fn contains(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}

#[test]
fn seal_open_wrong_key_owner_tenant_object_and_tamper() {
    let (alice, ..) = user(&acme());
    let (bob, ..) = user(&acme());
    let sealed = alice.seal("notes/1", 1, SECRET).unwrap();
    assert!(!contains(&sealed, SECRET));
    assert_eq!(alice.open(alice.subject(), "notes/1", &sealed).unwrap(), SECRET);

    // wrong key: Bob has no key for Alice
    assert!(matches!(bob.open(alice.subject(), "notes/1", &sealed), Err(Error::MissingKey { .. })));
    // wrong owner claimed
    assert!(alice.open(bob.subject(), "notes/1", &sealed).is_err());
    // wrong object
    assert!(alice.open(alice.subject(), "notes/2", &sealed).is_err());
    // modified ciphertext / header
    for i in [6usize, 10, sealed.len() - 1] {
        let mut t = sealed.clone();
        t[i] ^= 0x01;
        assert!(alice.open(alice.subject(), "notes/1", &t).is_err(), "byte {i}");
    }
    // wrong tenant: identical subject/key root in another tenant cannot open
    let (other_tenant, ..) = user(&TenantId::new("globex").unwrap());
    assert!(other_tenant.open(alice.subject(), "notes/1", &sealed).is_err());
}

#[test]
fn envelopes_are_bound_and_not_openable_by_others() {
    let (alice, _s, envs, code) = user(&acme());
    let env = envs[0].clone();
    // the envelope opens for its recipient …
    assert!(ClientKeyring::load(again(&alice, &code), &[env.clone()], &mut ClientState::in_memory()).is_ok());
    // … but any metadata/ciphertext edit breaks HPKE (binding is info + aad)
    let mut edits = Vec::new();
    for f in 0..5 {
        let mut e = env.clone();
        match f {
            0 => e.key_version = 9,
            1 => e.created_at_ms += 1,
            2 => e.ciphertext[0] ^= 1,
            3 => e.enc[0] ^= 1,
            _ => e.recipient_key_fingerprint[0] ^= 1,
        }
        edits.push(e);
    }
    for bad in edits {
        assert!(
            ClientKeyring::load(again(&alice, &code), &[bad], &mut ClientState::in_memory()).is_err()
        );
    }
    // another subject's identity cannot open it (not addressed to it → ignored, no key)
    let (bob, _, _, bob_code) = user(&acme());
    let bob_view = ClientKeyring::load(again(&bob, &bob_code), &[env], &mut ClientState::in_memory()).unwrap();
    let sealed = alice.seal("x", 1, SECRET).unwrap();
    assert!(bob_view.open(alice.subject(), "x", &sealed).is_err());
}

#[test]
fn recovery_code_restores_identity_on_new_device() {
    let tenant = acme();
    let subject = SubjectId::random();
    let (id, code) = ClientIdentity::generate(subject, tenant.clone());
    let pk = id.public_key();
    let mut state = ClientState::in_memory();
    let (ring, env) = ClientKeyring::create(id, &mut state).unwrap();
    let sealed = ring.seal("doc", 1, SECRET).unwrap();
    assert!(!format!("{code:?} {ring:?}").contains(&code.as_str()[6..20]));

    // new device: only the recovery code + server-held envelopes
    let restored = ClientIdentity::from_recovery(subject, tenant.clone(), &code).unwrap();
    assert_eq!(restored.public_key().public_key, pk.public_key);
    let ring2 = ClientKeyring::load(restored, &[env.clone()], &mut ClientState::in_memory()).unwrap();
    assert_eq!(ring2.open(subject, "doc", &sealed).unwrap(), SECRET);

    // corrupted code → refused, no fallback identity
    let mut bad = code.as_str().to_string();
    let last = bad.pop().unwrap();
    bad.push(if last == '0' { '1' } else { '0' });
    assert!(matches!(
        ClientIdentity::from_recovery(subject, tenant, &RecoveryCode::from(bad.as_str())),
        Err(Error::RecoveryCode)
    ));
}

#[test]
fn identity_file_persists_owner_only_and_restart_works() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client/identity.json");
    let (id, _) = ClientIdentity::generate(SubjectId::random(), acme());
    let subject = id.subject();
    id.save(&path).unwrap();
    #[cfg(unix)]
    assert_eq!(dmc_vault::secure_fs::mode_of(&path), Some(0o600));
    let mut state = ClientState::open(dir.path().join("client/state.json")).unwrap();
    let (ring, env) = ClientKeyring::create(ClientIdentity::load(&path).unwrap(), &mut state).unwrap();
    let sealed = ring.seal("doc", 1, SECRET).unwrap();
    drop(ring);

    // client restart
    let mut state = ClientState::open(dir.path().join("client/state.json")).unwrap();
    let ring = ClientKeyring::load(ClientIdentity::load(&path).unwrap(), &[env], &mut state).unwrap();
    assert_eq!(ring.open(subject, "doc", &sealed).unwrap(), SECRET);
}

#[test]
fn rotation_mixed_versions_survive_restart() {
    let (mut ring, mut state, mut envs, code) = user(&acme());
    let me = ring.subject();
    let old = ring.seal("a", 1, b"old").unwrap();
    envs.push(ring.new_data_key(&mut state).unwrap());
    let new = ring.seal("b", 1, b"new").unwrap();
    assert_eq!(dmc_vault::ownership::RecordHeader::parse(&old).unwrap().key_version, 1);
    assert_eq!(dmc_vault::ownership::RecordHeader::parse(&new).unwrap().key_version, 2);

    // client-side re-encryption: old record moves to v2, server never sees plaintext
    let re = ring.reencrypt("a", &old).unwrap();
    let h = dmc_vault::ownership::RecordHeader::parse(&re).unwrap();
    assert_eq!((h.key_version, h.record_version), (2, 2));

    // restart: mixed versions readable from server-held envelopes
    let ring2 = ClientKeyring::load(again(&ring, &code), &envs, &mut ClientState::in_memory()).unwrap();
    assert_eq!(ring2.active_version().unwrap(), 2);
    assert_eq!(ring2.open(me, "a", &old).unwrap(), b"old");
    assert_eq!(ring2.open(me, "b", &new).unwrap(), b"new");
    assert_eq!(ring2.open(me, "a", &re).unwrap(), b"old");
}

#[test]
fn rollback_floor_is_enforced_on_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("id.json");
    let (id, _) = ClientIdentity::generate(SubjectId::random(), acme());
    id.save(&path).unwrap();
    let mut state = ClientState::open(dir.path().join("state.json")).unwrap();
    let (mut ring, e1) = ClientKeyring::create(ClientIdentity::load(&path).unwrap(), &mut state).unwrap();
    let e2 = ring.new_data_key(&mut state).unwrap();
    drop(ring);

    let mut state = ClientState::open(dir.path().join("state.json")).unwrap();
    let err = ClientKeyring::load(ClientIdentity::load(&path).unwrap(), &[e1.clone()], &mut state).unwrap_err();
    assert!(matches!(err, Error::Rollback { seen: 2, offered: 1 }), "{err}");
    assert!(ClientKeyring::load(ClientIdentity::load(&path).unwrap(), &[e1, e2], &mut state).is_ok());
}

#[test]
fn async_delegation_alice_to_bob_and_charlie() {
    let tenant = acme();
    let (alice, mut alice_state, _, _) = user(&tenant);
    let (bob, _, bob_own, bob_code) = user(&tenant);
    let (charlie, _, charlie_own, charlie_code) = user(&tenant);
    let a_doc = alice.seal("shared", 1, SECRET).unwrap();
    let c_doc = charlie.seal("private", 1, b"charlie only").unwrap();

    // Alice delegates with only the recipients' public keys (they can be offline).
    let to_bob = alice.delegate_to(&bob.public_key(), &mut alice_state).unwrap();
    let to_charlie = alice.delegate_to(&charlie.public_key(), &mut alice_state).unwrap();
    drop(alice); // Alice goes offline

    // Later, Bob and Charlie load what the server stored for them.
    let mut for_bob = bob_own.clone();
    for_bob.extend(to_bob.iter().cloned());
    for_bob.extend(to_charlie.iter().cloned()); // server may hand over others' envelopes
    let bob2 = ClientKeyring::load(again(&bob, &bob_code), &for_bob, &mut ClientState::in_memory()).unwrap();
    let alice_subject = to_bob[0].owner;
    assert_eq!(bob2.open(alice_subject, "shared", &a_doc).unwrap(), SECRET);
    // Bob cannot access Charlie's data
    assert!(bob2.open(charlie.subject(), "private", &c_doc).is_err());
    assert!(!bob2.has_delegated_from(charlie.subject()));

    let mut for_charlie = charlie_own.clone();
    for_charlie.extend(to_charlie.iter().cloned());
    let charlie2 =
        ClientKeyring::load(again(&charlie, &charlie_code), &for_charlie, &mut ClientState::in_memory()).unwrap();
    assert_eq!(charlie2.open(alice_subject, "shared", &a_doc).unwrap(), SECRET);
    // delegated access is read-only: Charlie can only seal under Charlie's own key
    let forged = charlie2.seal("shared", 2, b"forged").unwrap();
    assert_eq!(
        dmc_vault::ownership::RecordHeader::parse(&forged).unwrap().owner,
        charlie2.subject()
    );
}

#[test]
fn tofu_pin_rejects_substituted_public_key() {
    let tenant = acme();
    let (alice, mut state, _, _) = user(&tenant);
    let (bob, ..) = user(&tenant);
    let real = bob.public_key();
    alice.delegate_to(&real, &mut state).unwrap();
    // malicious server later returns an attacker key under Bob's subject id
    let (mallory, _) = ClientIdentity::generate(real.subject, tenant.clone());
    let fake = mallory.public_key();
    assert!(matches!(alice.delegate_to(&fake, &mut state), Err(Error::KeyChanged { .. })));
    // out-of-band verified pin
    let mut fresh = ClientState::in_memory();
    assert!(fresh.pin_verified(&fake, &real.fingerprint_display()).is_err());
    fresh.pin_verified(&real, &real.fingerprint_display()).unwrap();
}

#[test]
fn sql_blob_helpers_roundtrip_and_debug_redaction() {
    let (alice, _, _, code) = user(&acme());
    let sealed = alice.seal("sqlc/notes/1/body", 1, SECRET).unwrap();
    let lit = sql_blob_literal(&sealed);
    assert!(lit.starts_with("X'") && !lit.contains("VERY_SECRET"));
    let cell = format!("\\x{}", &lit[2..lit.len() - 1].to_lowercase());
    assert_eq!(parse_sql_blob_cell(&cell).unwrap(), sealed);
    let shown = format!("{alice:?} {code:?}");
    assert!(shown.contains("REDACTED") && !shown.contains(&code.as_str()[6..14]));
}
