//! Dev provisioning split: create (keys only) vs devo_init (roles/users).

use dmc_core::control::run_devo_init;
use dmc_core::runtime::{DbStatus, Runtime};

#[tokio::test]
async fn empty_vault_reports_not_provisioned() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    assert_eq!(rt.status().await, DbStatus::Empty);
    assert!(!rt.is_dev_provisioned().await.unwrap());
}

#[tokio::test]
async fn create_alone_has_no_root_identity() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_hex, _id) = rt.create().await.unwrap();
    assert_eq!(rt.status().await, DbStatus::Unlocked);
    assert!(!rt.is_dev_provisioned().await.unwrap());
    assert!(rt.admin_session().await.is_err());
}

#[tokio::test]
async fn devo_init_provisions_root_after_create() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    rt.create().await.unwrap();
    rt.devo_init(false).await.unwrap();
    assert!(rt.is_dev_provisioned().await.unwrap());
    assert!(rt.admin_session().await.is_ok());
}

#[tokio::test]
async fn run_devo_init_from_empty_creates_and_provisions() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let r = run_devo_init(&rt, false, None, false, None).await.unwrap();
    assert!(r.created_vault);
    assert!(r.provisioned_identity);
    assert!(rt.admin_session().await.is_ok());
}

#[tokio::test]
async fn run_devo_init_custom_ui_access_key() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let r = run_devo_init(&rt, false, None, true, Some("my-ui-secret-key")).await.unwrap();
    assert_eq!(r.ui_access_key.as_deref(), Some("my-ui-secret-key"));
}

#[test]
fn reset_ui_auth_replaces_enrollment() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("store.dbs.json");
    let first = dmc_core::control::reset_ui_auth(&db_path, Some("first-ui-key-01")).unwrap();
    assert_eq!(first.access_key, "first-ui-key-01");
    let second = dmc_core::control::reset_ui_auth(&db_path, Some("second-ui-key-02")).unwrap();
    assert_eq!(second.access_key, "second-ui-key-02");
    assert_ne!(first.totp_secret, second.totp_secret);
}
