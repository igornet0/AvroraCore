use dmc_core::runtime::{DbStatus, Runtime};
use dmc_vault::key::KeyMaterial;
use dmc_vault::keypass as kp;

#[tokio::test]
async fn create_returns_master_without_server_usb() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let usb = dir.path().join("usb");
    std::fs::create_dir(&usb).unwrap();

    let rt = Runtime::at_path(&path);
    let (master_hex, db_id) = rt.create_dev(false).await.unwrap();
    assert_eq!(rt.status().await, DbStatus::Unlocked);

    let master = KeyMaterial::from_hex(&master_hex).unwrap();
    let bundle = kp::wrap(&master, "test-password", &db_id).unwrap();
    kp::save(&kp::usb_dir(&usb), &bundle).unwrap();
    assert!(kp::exists(&kp::usb_dir(&usb)));
    assert!(!kp::exists(&kp::local_dir(&path)));

    rt.lock().await.unwrap();
    let loaded = kp::load(&kp::usb_dir(&usb)).unwrap();
    let unwrapped = kp::unwrap_for_db(&loaded, "test-password", Some(&db_id)).unwrap();
    rt.unlock(&unwrapped.to_hex()).await.unwrap();
    assert_eq!(rt.status().await, DbStatus::Unlocked);
}
