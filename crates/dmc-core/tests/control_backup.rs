//! Control plane backup over avrora-proto.

use std::net::SocketAddr;

use avrora_client::identity::DeviceIdentity;
use avrora_client::transport::{ConnectOpts, ControlClient};
use avrora_proto::{ControlMsg, DeviceAuthenticator};
use dmc_core::control;
use dmc_core::control::sessions::ControlSessions;
use dmc_core::runtime::{DbStatus, Runtime};
use dmc_security::{AuthManager, ISSUER, UI_OPERATOR, ui_auth_path};
use totp_rs::{Builder, Secret};

async fn setup_server_client(
    dir: &tempfile::TempDir,
) -> (Runtime, ControlClient, String) {
    let db_path = dir.path().join("store.dbs.json");
    let control_dir = dir.path().join("control");
    let client_home = dir.path().join("client");

    let rt = Runtime::at_path(&db_path);
    rt.create_dev(false).await.unwrap();

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
    let ControlMsg::AuthOk { token: session, .. } = auth_ok else {
        panic!("{auth_ok:?}");
    };

    (rt, mtls, session)
}

#[tokio::test]
async fn control_plane_backup_create_list_verify() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, mut mtls, session) = setup_server_client(&dir).await;
    assert_eq!(rt.status().await, DbStatus::Unlocked);

    let created = mtls
        .roundtrip(ControlMsg::BackupCreate {
            session: session.clone(),
            backup_id: "daily-01".into(),
            include_rowstore: false,
        })
        .await
        .unwrap();
    let ControlMsg::BackupCreateOk {
        backup_id,
        checkpoint_sequence,
    } = created
    else {
        panic!("{created:?}");
    };
    assert_eq!(backup_id, "daily-01");

    let listed = mtls
        .roundtrip(ControlMsg::BackupList {
            session: session.clone(),
        })
        .await
        .unwrap();
    let ControlMsg::BackupListOk { items } = listed else {
        panic!("{listed:?}");
    };
    assert_eq!(items.len(), 1);
    assert!(items[0].valid);

    let verified = mtls
        .roundtrip(ControlMsg::BackupVerify {
            session,
            backup_id: "daily-01".into(),
        })
        .await
        .unwrap();
    let ControlMsg::BackupVerifyOk { valid, .. } = verified else {
        panic!("{verified:?}");
    };
    assert!(valid);
    let _ = checkpoint_sequence;
}
