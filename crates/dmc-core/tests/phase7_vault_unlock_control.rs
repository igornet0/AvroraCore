//! Phase 7 VaultUnlock over Avrora control plane.

use std::net::SocketAddr;

use avrora_client::identity::DeviceIdentity;
use avrora_client::keypass::{unwrap_master, wrap_and_save};
use avrora_client::transport::{ConnectOpts, ControlClient};
use avrora_client::unlock_blob::{create_unlock_blob, parse_binding_key_hex};
use avrora_proto::{ControlMsg, DeviceAuthenticator, LEGACY_UNLOCK_DISABLED};
use dmc_core::control;
use dmc_core::control::sessions::ControlSessions;
use dmc_core::runtime::{DbStatus, Runtime};
use dmc_protocol::ProtocolErrorCode;
use dmc_security::{AuthManager, ISSUER, UI_OPERATOR, ui_auth_path};
use totp_rs::{Builder, Secret};

async fn setup_locked_vault(
    dir: &tempfile::TempDir,
) -> (
    Runtime,
    ControlClient,
    String,
    String,
    String,
    std::path::PathBuf,
) {
    let db_path = dir.path().join("store.dbs.json");
    let control_dir = dir.path().join("control");
    let client_home = dir.path().join("client");
    let usb = dir.path().join("usb");
    std::fs::create_dir(&usb).unwrap();

    let rt = Runtime::at_path(&db_path);
    let (master_hex, db_id) = rt.create_dev(false).await.unwrap();
    let master = dmc_vault::KeyMaterial::from_hex(&master_hex).unwrap();
    wrap_and_save(&usb, None, &master, "test-password", &db_id).unwrap();
    rt.lock().await.unwrap();
    assert_eq!(rt.status().await, DbStatus::Locked);

    let init = control::init_control(&control_dir).unwrap();
    let auth = AuthManager::open(ui_auth_path(&db_path));
    let (addr, serve) = control::bind(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        control_dir,
        rt.clone(),
        auth,
        ControlSessions::new(),
    )
    .await
    .unwrap();
    tokio::spawn(async move {
        let _ = serve.await;
    });

    let id = DeviceIdentity::init(&client_home).unwrap();
    let c = ControlClient::connect_config(&ConnectOpts {
        host: "127.0.0.1".into(),
        port: addr.port(),
        home: client_home.clone(),
        tofu: true,
        expected_fingerprint: None,
    })
    .unwrap();
    let mut live = c.open().await.unwrap();
    let begin = live
        .request(ControlMsg::BootstrapBegin {
            token: init.token,
            device_id: id.device_id().to_string(),
            public_key_hex: id.public_key_hex(),
        })
        .await
        .unwrap();
    let ControlMsg::BootstrapChallenge { nonce_hex } = begin else {
        panic!("{begin:?}");
    };
    let done = live
        .request(ControlMsg::BootstrapFinish {
            signature_hex: hex::encode(id.sign(&hex::decode(nonce_hex).unwrap())),
        })
        .await
        .unwrap();
    let ControlMsg::BootstrapOk {
        client_cert_pem,
        client_key_pem,
        ca_cert_pem,
        server_fingerprint,
        ..
    } = done
    else {
        panic!("{done:?}");
    };
    DeviceIdentity::save_bootstrap(
        &client_home,
        &format!("127.0.0.1:{}", addr.port()),
        &server_fingerprint,
        &client_cert_pem,
        &client_key_pem,
        &ca_cert_pem,
    )
    .unwrap();

    let mut mtls = ControlClient::connect_config(&ConnectOpts {
        host: "127.0.0.1".into(),
        port: addr.port(),
        home: client_home,
        tofu: false,
        expected_fingerprint: None,
    })
    .unwrap();

    let setup = mtls
        .roundtrip(ControlMsg::AuthSetupBegin {
            access_key: "secret-access-key".into(),
        })
        .await
        .unwrap();
    let ControlMsg::AuthSetupBeginOk { totp_secret, .. } = setup else {
        panic!("{setup:?}");
    };
    let totp = Builder::new()
        .with_secret(Secret::try_from_base32(&totp_secret).unwrap())
        .with_account_name(UI_OPERATOR)
        .with_issuer(Some(ISSUER))
        .build()
        .unwrap();
    let auth_ok = mtls
        .roundtrip(ControlMsg::AuthSetupConfirm {
            access_key: "secret-access-key".into(),
            totp_code: totp.generate_current().to_string(),
        })
        .await
        .unwrap();
    let ControlMsg::AuthOk {
        token: session,
        unlock_binding_key_hex,
        ..
    } = auth_ok
    else {
        panic!("{auth_ok:?}");
    };

    (rt, mtls, session, unlock_binding_key_hex, db_id, usb)
}

#[tokio::test]
async fn vault_unlock_via_unlock_blob() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, mut mtls, session, binding_hex, db_id, usb) = setup_locked_vault(&dir).await;

    let master = unwrap_master(&usb, "test-password", Some(&db_id)).unwrap();
    let binding = parse_binding_key_hex(&binding_hex).unwrap();
    let blob = create_unlock_blob(&session, &binding, master.as_bytes()).unwrap();

    let reply = mtls
        .roundtrip(ControlMsg::VaultUnlock {
            session: session.clone(),
            blob: blob.clone(),
        })
        .await
        .unwrap();
    assert!(matches!(reply, ControlMsg::VaultUnlockOk { .. }));
    assert_eq!(rt.status().await, DbStatus::Unlocked);

    let replay = mtls
        .roundtrip(ControlMsg::VaultUnlock {
            session,
            blob,
        })
        .await
        .unwrap();
    let ControlMsg::Error { message } = replay else {
        panic!("expected replay error, got {replay:?}");
    };
    assert_eq!(message, ProtocolErrorCode::UnlockBlobReplay.as_str());
}

#[tokio::test]
async fn legacy_master_key_hex_unlock_still_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, mut mtls, session, _, db_id, usb) = setup_locked_vault(&dir).await;
    let unwrapped = unwrap_master(&usb, "test-password", Some(&db_id)).unwrap();

    #[allow(deprecated)]
    let reply = mtls
        .roundtrip(ControlMsg::Unlock {
            session,
            master_key_hex: unwrapped.to_hex(),
        })
        .await
        .unwrap();
    let ControlMsg::Error { message } = reply else {
        panic!("expected LegacyUnlockDisabled, got {reply:?}");
    };
    assert_eq!(message, LEGACY_UNLOCK_DISABLED);
    assert_eq!(rt.status().await, DbStatus::Locked);
}

#[tokio::test]
async fn vault_unlock_wrong_material_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, mut mtls, session, binding_hex, _, _) = setup_locked_vault(&dir).await;

    let binding = parse_binding_key_hex(&binding_hex).unwrap();
    let blob = create_unlock_blob(&session, &binding, &[0u8; 32]).unwrap();

    let reply = mtls
        .roundtrip(ControlMsg::VaultUnlock { session, blob })
        .await
        .unwrap();
    let ControlMsg::Error { .. } = reply else {
        panic!("expected unlock failure, got {reply:?}");
    };
    assert_eq!(rt.status().await, DbStatus::Locked);
}
