//! D4-A stage 1: the SQL plane's key store is persistent.
//!
//! * the first start creates `vault/keytree.json` (0600, public state only) and issues the
//!   Master Key once; every later start issues none and is unlocked with that same key;
//! * a different key is refused (`UnlockFailed`);
//! * the storage key nodes exist and their DEKs are stable across restarts;
//! * an unreadable key store stops startup — it is never silently replaced.

use dmc_ops::{CoreConfig, StartupError, StartupOptions, parse_config_json, start_core};
use dmc_protocol::{
    ControlRequest, ControlResponse, ProtocolErrorCode, RemoteLimits, RequestEnvelope,
};
use dmc_server::{
    CoreServerState, KEY_TREE_FILE, MockKeyPassProvider, STORAGE_KEY_PATHS, UnlockMaterial,
    create_unlock_blob, expect_ok_control, handle_control,
};
use tempfile::tempdir;

fn cfg_for(root: &std::path::Path) -> CoreConfig {
    parse_config_json(&format!(
        r#"{{ "data_root": "{}", "profile": "development" }}"#,
        root.display()
    ))
    .unwrap()
}

fn ctl(
    state: &mut CoreServerState,
    body: ControlRequest,
) -> dmc_protocol::ResponseEnvelope<ControlResponse> {
    handle_control(
        state,
        RequestEnvelope {
            request_id: 1,
            body,
        },
        &RemoteLimits::default(),
        "conn-d4",
    )
    .unwrap()
}

fn try_unlock(state: &mut CoreServerState, master: &UnlockMaterial) -> Option<ProtocolErrorCode> {
    state.auth_mut().create_identity("unlocker", "pw").ok();
    let ControlResponse::Authenticate {
        session_id,
        unlock_binding_key,
        ..
    } = expect_ok_control(ctl(
        state,
        ControlRequest::Authenticate {
            identity_name: "unlocker".into(),
            password: "pw".into(),
        },
    ))
    .unwrap()
    else {
        panic!()
    };
    let key: [u8; 32] = unlock_binding_key.as_slice().try_into().unwrap();
    let blob = create_unlock_blob(
        &session_id,
        &key,
        &MockKeyPassProvider::with_material(master.clone()),
    )
    .unwrap();
    ctl(state, ControlRequest::VaultUnlock { session_id, blob }).error_code
}

fn storage_deks(state: &mut CoreServerState) -> Vec<Vec<u8>> {
    STORAGE_KEY_PATHS
        .iter()
        .map(|p| {
            state
                .unlock_gate
                .storage_dek(p)
                .unwrap()
                .as_bytes()
                .to_vec()
        })
        .collect()
}

#[test]
fn key_store_is_created_once_and_survives_restarts() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("data");

    let mut first = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    let master = first
        .unlock_material
        .clone()
        .expect("first start issues the Master Key");
    let key_store = first.layout.vault_root().join(KEY_TREE_FILE);
    assert!(key_store.is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&key_store).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    // locked: no storage key before unlock
    assert!(
        first
            .server
            .unlock_gate
            .storage_dek(STORAGE_KEY_PATHS[0])
            .is_err()
    );
    assert_eq!(try_unlock(&mut first.server, &master), None);
    let deks = storage_deks(&mut first.server);
    // the key store holds no secret: not the Master Key, not a storage DEK (raw or hex)
    let raw = std::fs::read(&key_store).unwrap();
    let text = String::from_utf8_lossy(&raw).to_string();
    for secret in std::iter::once(master.0.to_vec()).chain(deks.iter().cloned()) {
        assert!(!raw.windows(secret.len()).any(|w| w == secret.as_slice()));
        assert!(!text.contains(&hex::encode(&secret)));
    }
    let snapshot = raw.clone();
    drop(first);

    // restart: no new Master Key, same storage keys with the original Master Key
    let mut second = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    assert!(
        second.unlock_material.is_none(),
        "a restart never issues a new Master Key"
    );
    assert_eq!(
        std::fs::read(&key_store).unwrap(),
        snapshot,
        "key store unchanged by restart"
    );
    let wrong = UnlockMaterial([0x5a; 32]);
    assert_eq!(
        try_unlock(&mut second.server, &wrong),
        Some(ProtocolErrorCode::UnlockFailed)
    );
    assert_eq!(try_unlock(&mut second.server, &master), None);
    assert_eq!(
        storage_deks(&mut second.server),
        deks,
        "storage DEKs stable across restarts"
    );
    drop(second);

    // an unreadable key store stops startup and is left as is (never replaced)
    std::fs::write(&key_store, b"{\"format_version\": 1, \"truncated\": tru").unwrap();
    let corrupt = std::fs::read(&key_store).unwrap();
    match start_core(cfg_for(&root), StartupOptions::production()) {
        Err(StartupError::Vault(_)) => {}
        Err(other) => panic!("unexpected {other}"),
        Ok(_) => panic!("started with an unreadable key store"),
    }
    assert_eq!(std::fs::read(&key_store).unwrap(), corrupt);
}

/// Stage 2: the storage cipher comes from the persistent key store — a value sealed before
/// a restart opens after it (same Master Key), and no cipher exists while locked.
#[test]
fn storage_cipher_is_stable_across_restarts_and_absent_while_locked() {
    use dmc_vault::StoragePurpose;
    use dmc_vault::storage_cipher::{file_context, row_record_context};

    let dir = tempdir().unwrap();
    let root = dir.path().join("data");
    let mut first = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    let master = first.unlock_material.clone().unwrap();
    assert!(
        first.server.unlock_gate.storage_cipher().is_err(),
        "locked: no cipher"
    );
    assert_eq!(try_unlock(&mut first.server, &master), None);
    let cipher = first.server.unlock_gate.storage_cipher().unwrap();
    let marker = b"D4_STAGE2_RESTART_MARKER_c71d";
    let events = cipher
        .seal(
            StoragePurpose::Events,
            &file_context("state_events.json"),
            marker,
        )
        .unwrap();
    let row = cipher
        .seal(
            StoragePurpose::Rows,
            &row_record_context("table_0", 1, 16),
            marker,
        )
        .unwrap();
    drop(cipher);
    drop(first);

    let mut second = start_core(cfg_for(&root), StartupOptions::production()).unwrap();
    assert!(
        second.server.unlock_gate.storage_cipher().is_err(),
        "locked after restart"
    );
    assert_eq!(try_unlock(&mut second.server, &master), None);
    let cipher = second.server.unlock_gate.storage_cipher().unwrap();
    assert_eq!(
        cipher
            .open(
                StoragePurpose::Events,
                &file_context("state_events.json"),
                &events
            )
            .unwrap(),
        marker
    );
    assert_eq!(
        cipher
            .open(
                StoragePurpose::Rows,
                &row_record_context("table_0", 1, 16),
                &row
            )
            .unwrap(),
        marker
    );

    // a different installation's keys cannot open it
    let other = dir.path().join("other");
    let mut third = start_core(cfg_for(&other), StartupOptions::production()).unwrap();
    let other_master = third.unlock_material.clone().unwrap();
    assert_eq!(try_unlock(&mut third.server, &other_master), None);
    let foreign = third.server.unlock_gate.storage_cipher().unwrap();
    assert!(
        foreign
            .open(
                StoragePurpose::Events,
                &file_context("state_events.json"),
                &events
            )
            .is_err()
    );
}
