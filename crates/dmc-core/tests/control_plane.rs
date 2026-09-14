use std::net::SocketAddr;

use avrora_client::identity::DeviceIdentity;
use avrora_client::keypass::{unwrap_master, wrap_and_save};
use avrora_client::transport::{ConnectOpts, ControlClient};
use avrora_proto::{ControlMsg, DeviceAuthenticator};
use dmc_core::control;
use dmc_core::control::sessions::ControlSessions;
use dmc_core::runtime::{DbStatus, Runtime};
use dmc_security::{AuthManager, ISSUER, UI_OPERATOR, ui_auth_path};
use totp_rs::{Builder, Secret};

#[tokio::test]
async fn control_bootstrap_auth_create_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("store.dbs.json");
    let control_dir = dir.path().join("control");
    let client_home = dir.path().join("client");
    let usb = dir.path().join("usb");
    std::fs::create_dir(&usb).unwrap();

    let init = control::init_control(&control_dir).unwrap();
    let token = init.token.clone();

    let rt = Runtime::at_path(&db_path);
    let auth = AuthManager::open(ui_auth_path(&db_path));
    let (addr, serve) = control::bind(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        control_dir.clone(),
        rt.clone(),
        auth,
        ControlSessions::new(),
    )
    .await
    .unwrap();
    tokio::spawn(async move {
        let _ = serve.await;
    });

    let server = format!("127.0.0.1:{}", addr.port());
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
            token: token.clone(),
            device_id: id.device_id().to_string(),
            public_key_hex: id.public_key_hex(),
        })
        .await
        .unwrap();
    let ControlMsg::BootstrapChallenge { nonce_hex } = begin else {
        panic!("{begin:?}");
    };
    let nonce = hex::decode(&nonce_hex).unwrap();
    let done = live
        .request(ControlMsg::BootstrapFinish {
            signature_hex: hex::encode(id.sign(&nonce)),
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
        &server,
        &server_fingerprint,
        &client_cert_pem,
        &client_key_pem,
        &ca_cert_pem,
    )
    .unwrap();

    let reused = ControlClient::connect_config(&ConnectOpts {
        host: "127.0.0.1".into(),
        port: addr.port(),
        home: client_home.clone(),
        tofu: true,
        expected_fingerprint: None,
    })
    .unwrap()
    .open()
    .await
    .unwrap()
    .request(ControlMsg::BootstrapBegin {
        token,
        device_id: "other".into(),
        public_key_hex: id.public_key_hex(),
    })
    .await
    .unwrap();
    let ControlMsg::Error { message } = reused else {
        panic!("expected token reuse error, got {reused:?}");
    };
    assert!(
        message.contains("consumed") || message.contains("already"),
        "{message}"
    );

    let mut mtls = ControlClient::connect_config(&ConnectOpts {
        host: "127.0.0.1".into(),
        port: addr.port(),
        home: client_home.clone(),
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
    let code = totp.generate_current().to_string();
    let auth_ok = mtls
        .roundtrip(ControlMsg::AuthSetupConfirm {
            access_key: "secret-access-key".into(),
            totp_code: code,
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

    let created = mtls
        .roundtrip(ControlMsg::DbCreate {
            session: session.clone(),
            with_demo: false,
        })
        .await
        .unwrap();
    let ControlMsg::DbCreateOk {
        master_key_hex,
        db_id,
    } = created
    else {
        panic!("{created:?}");
    };
    assert_eq!(rt.status().await, DbStatus::Unlocked);
    let master = dmc_vault::KeyMaterial::from_hex(&master_key_hex).unwrap();
    wrap_and_save(&usb, None, &master, "test-password", &db_id).unwrap();

    mtls.roundtrip(ControlMsg::Lock {
        session: session.clone(),
    })
    .await
    .unwrap();
    assert_eq!(rt.status().await, DbStatus::Locked);

    let bad = unwrap_master(&usb, "wrong-password", Some(&db_id));
    assert!(bad.is_err());

    let unwrapped = unwrap_master(&usb, "test-password", Some(&db_id)).unwrap();
    let binding = avrora_client::unlock_blob::parse_binding_key_hex(&unlock_binding_key_hex).unwrap();
    let blob = avrora_client::unlock_blob::create_unlock_blob(
        &session,
        &binding,
        unwrapped.as_bytes(),
    )
    .unwrap();
    let unlocked = mtls
        .roundtrip(ControlMsg::VaultUnlock {
            session: session.clone(),
            blob,
        })
        .await
        .unwrap();
    let ControlMsg::VaultUnlockOk { status } = unlocked else {
        panic!("expected VaultUnlockOk, got {unlocked:?}");
    };
    assert_eq!(status, "unlocked");
    assert_eq!(rt.status().await, DbStatus::Unlocked);
}

#[tokio::test]
async fn control_rejects_unlock_without_session() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("store.dbs.json");
    let control_dir = dir.path().join("control");
    let client_home = dir.path().join("client");
    let usb = dir.path().join("usb");
    std::fs::create_dir(&usb).unwrap();

    let init = control::init_control(&control_dir).unwrap();
    let rt = Runtime::at_path(&db_path);
    let (master_hex, db_id) = rt.create_dev(false).await.unwrap();
    rt.lock().await.unwrap();
    let master = dmc_vault::KeyMaterial::from_hex(&master_hex).unwrap();
    wrap_and_save(&usb, None, &master, "test-password", &db_id).unwrap();

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
    let unwrapped = unwrap_master(&usb, "test-password", Some(&db_id)).unwrap();
    #[allow(deprecated)]
    let denied = mtls
        .roundtrip(ControlMsg::Unlock {
            session: "ctl_bogus".into(),
            master_key_hex: unwrapped.to_hex(),
        })
        .await
        .unwrap();
    let ControlMsg::Error { message } = denied else {
        panic!("expected LegacyUnlockDisabled, got {denied:?}");
    };
    assert_eq!(message, avrora_proto::LEGACY_UNLOCK_DISABLED);
    assert_eq!(rt.status().await, DbStatus::Locked);
}

#[tokio::test]
async fn control_status_requires_auth_session() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("store.dbs.json");
    let control_dir = dir.path().join("control");
    let client_home = dir.path().join("client");

    let init = control::init_control(&control_dir).unwrap();
    let rt = Runtime::at_path(&db_path);
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
    let denied = mtls
        .roundtrip(ControlMsg::DbStatus {
            session: "nope".into(),
        })
        .await
        .unwrap();
    assert!(matches!(denied, ControlMsg::Error { .. }));
}
