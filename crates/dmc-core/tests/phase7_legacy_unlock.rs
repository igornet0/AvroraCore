//! Phase 7.6.4 — legacy ControlMsg::Unlock.master_key_hex is rejected.

use std::net::SocketAddr;

use avrora_client::identity::DeviceIdentity;
use avrora_client::keypass::{unwrap_master, wrap_and_save};
use avrora_client::transport::{ConnectOpts, ControlClient};
use avrora_proto::{ControlMsg, DeviceAuthenticator, LEGACY_UNLOCK_DISABLED};
use dmc_core::control;
use dmc_core::control::sessions::ControlSessions;
use dmc_core::runtime::{DbStatus, Runtime};
use dmc_security::{AuthManager, ui_auth_path};

async fn bootstrap_mtls(
    control_dir: &std::path::Path,
    client_home: &std::path::Path,
    db_path: &std::path::Path,
    rt: Runtime,
) -> ControlClient {
    let init = control::init_control(control_dir).unwrap();
    let auth = AuthManager::open(ui_auth_path(db_path));
    let (addr, serve) = control::bind(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        control_dir.to_path_buf(),
        rt,
        auth,
        ControlSessions::new(),
    )
    .await
    .unwrap();
    tokio::spawn(async move {
        let _ = serve.await;
    });

    let id = DeviceIdentity::init(client_home).unwrap();
    let c = ControlClient::connect_config(&ConnectOpts {
        host: "127.0.0.1".into(),
        port: addr.port(),
        home: client_home.to_path_buf(),
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
        client_home,
        &format!("127.0.0.1:{}", addr.port()),
        &server_fingerprint,
        &client_cert_pem,
        &client_key_pem,
        &ca_cert_pem,
    )
    .unwrap();

    ControlClient::connect_config(&ConnectOpts {
        host: "127.0.0.1".into(),
        port: addr.port(),
        home: client_home.to_path_buf(),
        tofu: false,
        expected_fingerprint: None,
    })
    .unwrap()
}

#[tokio::test]
async fn legacy_master_key_hex_unlock_rejected_vault_stays_locked() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("store.dbs.json");
    let control_dir = dir.path().join("control");
    let client_home = dir.path().join("client");
    let usb = dir.path().join("usb");
    std::fs::create_dir(&usb).unwrap();

    let rt = Runtime::at_path(&db_path);
    let (master_hex, db_id) = rt.create_dev(false).await.unwrap();
    rt.lock().await.unwrap();
    assert_eq!(rt.status().await, DbStatus::Locked);

    let master = dmc_vault::KeyMaterial::from_hex(&master_hex).unwrap();
    wrap_and_save(&usb, None, &master, "test-password", &db_id).unwrap();
    let unwrapped = unwrap_master(&usb, "test-password", Some(&db_id)).unwrap();

    let mut mtls = bootstrap_mtls(&control_dir, &client_home, &db_path, rt.clone()).await;

    #[allow(deprecated)]
    let reply = mtls
        .roundtrip(ControlMsg::Unlock {
            session: "any".into(),
            master_key_hex: unwrapped.to_hex(),
        })
        .await
        .unwrap();
    let ControlMsg::Error { message } = reply else {
        panic!("expected LegacyUnlockDisabled, got {reply:?}");
    };
    assert_eq!(message, LEGACY_UNLOCK_DISABLED);
    assert_eq!(rt.status().await, DbStatus::Locked);

    #[allow(deprecated)]
    let again = mtls
        .roundtrip(ControlMsg::Unlock {
            session: "any".into(),
            master_key_hex: unwrapped.to_hex(),
        })
        .await
        .unwrap();
    assert!(matches!(
        again,
        ControlMsg::Error {
            message
        } if message == LEGACY_UNLOCK_DISABLED
    ));
    assert_eq!(rt.status().await, DbStatus::Locked);
}
