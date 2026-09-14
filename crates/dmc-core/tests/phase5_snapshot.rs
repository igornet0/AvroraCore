use std::fs;

use dmc_core::runtime::Runtime;
use dmc_journal::{encode_snapshot_blob, SnapshotStore, StorageLayout};

async fn create_unlocked() -> (tempfile::TempDir, Runtime, String) {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (master, _) = rt.create_dev(false).await.unwrap();
    (dir, rt, master)
}

async fn restart(dir: &std::path::Path, master: &str, rt: &Runtime) -> Runtime {
    rt.lock().await.unwrap();
    let rt2 = Runtime::at_path(dir.join("store.dbs.json"));
    rt2.unlock(master).await.unwrap();
    rt2
}

async fn put_n(rt: &Runtime, n: u64) {
    let admin = rt.admin_session().await.unwrap();
    for i in 0..n {
        rt.put_data(
            &admin,
            &format!("company/data/{i}"),
            format!("v{i}").as_bytes(),
        )
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn force_snapshot_publishes_manifest_and_pin() {
    let (_dir, rt, _master) = create_unlocked().await;
    put_n(&rt, 3).await;
    let seq = rt.force_snapshot().await.unwrap();
    assert_eq!(seq, 3);
    assert_eq!(rt.published_snapshot_sequence().await.unwrap(), Some(3));
    let layout = StorageLayout::from_db_path(_dir.path().join("store.dbs.json"));
    let manifest = SnapshotStore::new(&layout)
        .read_manifest()
        .unwrap()
        .unwrap();
    assert_eq!(manifest.sequence, 3);
    let wm = rt.retention_watermark().await.unwrap();
    assert_eq!(wm.trim_through, Some(3));
}

#[tokio::test]
async fn restart_restores_snapshot_pin_from_manifest() {
    let (dir, rt, master) = create_unlocked().await;
    put_n(&rt, 4).await;
    rt.force_snapshot().await.unwrap();
    let rt2 = restart(dir.path(), &master, &rt).await;
    assert_eq!(rt2.published_snapshot_sequence().await.unwrap(), Some(4));
    assert_eq!(
        rt2.retention_watermark().await.unwrap().trim_through,
        Some(4)
    );
}

#[tokio::test]
async fn unpublished_snapshot_file_is_ignored_after_crash() {
    let (dir, rt, master) = create_unlocked().await;
    put_n(&rt, 2).await;
    rt.force_snapshot().await.unwrap();
    let layout = StorageLayout::from_db_path(dir.path().join("store.dbs.json"));
    let store = SnapshotStore::new(&layout);
    put_n(&rt, 3).await;
    let snap = dmc_vault::persist::DbSnapshot::load(&layout.base_snapshot()).unwrap();
    let payload = serde_json::to_vec(&snap).unwrap();
    let orphan = encode_snapshot_blob(5, &payload);
    fs::write(
        store.snapshots_dir().join("snapshot-000000000005.bin"),
        orphan,
    )
    .unwrap();
    let rt2 = restart(dir.path(), &master, &rt).await;
    assert_eq!(rt2.published_snapshot_sequence().await.unwrap(), Some(2));
}

#[tokio::test]
async fn crash_after_manifest_publication_restores_new_pin() {
    let (dir, rt, master) = create_unlocked().await;
    put_n(&rt, 1).await;
    rt.force_snapshot().await.unwrap();
    put_n(&rt, 4).await;
    rt.force_snapshot().await.unwrap();
    let rt2 = restart(dir.path(), &master, &rt).await;
    assert_eq!(rt2.published_snapshot_sequence().await.unwrap(), Some(5));
}

#[tokio::test]
async fn corrupted_snapshot_rejects_unlock() {
    let (dir, rt, master) = create_unlocked().await;
    put_n(&rt, 2).await;
    rt.force_snapshot().await.unwrap();
    rt.lock().await.unwrap();
    let layout = StorageLayout::from_db_path(dir.path().join("store.dbs.json"));
    let manifest = SnapshotStore::new(&layout)
        .read_manifest()
        .unwrap()
        .unwrap();
    let path = SnapshotStore::new(&layout)
        .snapshots_dir()
        .join(&manifest.snapshot_file);
    let mut bytes = fs::read(&path).unwrap();
    if let Some(b) = bytes.last_mut() {
        *b ^= 0xff;
    }
    fs::write(&path, &bytes).unwrap();
    let rt2 = Runtime::at_path(dir.path().join("store.dbs.json"));
    let err = rt2.unlock(&master).await.unwrap_err();
    assert!(err.to_string().to_lowercase().contains("corrupt"));
}

#[tokio::test]
async fn corrupted_manifest_rejects_unlock() {
    let (dir, rt, master) = create_unlocked().await;
    put_n(&rt, 1).await;
    rt.force_snapshot().await.unwrap();
    rt.lock().await.unwrap();
    let layout = StorageLayout::from_db_path(dir.path().join("store.dbs.json"));
    fs::write(
        layout.snapshot_manifest(),
        r#"{"snapshot_id":"not-a-uuid","sequence":1,"format_version":1,"snapshot_file":"x.bin","checksum":"00","created_at_ms":0}"#,
    )
    .unwrap();
    let rt2 = Runtime::at_path(dir.path().join("store.dbs.json"));
    let err = rt2.unlock(&master).await.unwrap_err();
    assert!(err.to_string().to_lowercase().contains("corrupt"));
}

#[tokio::test]
async fn replacing_snapshot_keeps_single_pin() {
    let (_dir, rt, _master) = create_unlocked().await;
    put_n(&rt, 2).await;
    rt.force_snapshot().await.unwrap();
    put_n(&rt, 3).await;
    rt.force_snapshot().await.unwrap();
    assert_eq!(rt.published_snapshot_sequence().await.unwrap(), Some(5));
    let wm = rt.retention_watermark().await.unwrap();
    assert_eq!(wm.trim_through, Some(5));
}

#[tokio::test]
async fn manifest_ahead_of_journal_head_rejects_unlock() {
    let (dir, rt, master) = create_unlocked().await;
    put_n(&rt, 2).await;
    rt.lock().await.unwrap();
    let layout = StorageLayout::from_db_path(dir.path().join("store.dbs.json"));
    SnapshotStore::new(&layout)
        .publish(999, b"{}", 0)
        .unwrap();
    let rt2 = Runtime::at_path(dir.path().join("store.dbs.json"));
    let err = rt2.unlock(&master).await.unwrap_err();
    assert!(err.to_string().to_lowercase().contains("inconsistent"));
}

#[tokio::test]
async fn tmp_manifest_is_ignored_on_recovery() {
    let (dir, rt, master) = create_unlocked().await;
    put_n(&rt, 1).await;
    rt.force_snapshot().await.unwrap();
    let layout = StorageLayout::from_db_path(dir.path().join("store.dbs.json"));
    fs::write(
        layout.snapshots_dir().join("manifest.tmp"),
        r#"{"snapshot_id":"00000000-0000-7000-8000-000000000099","sequence":99,"format_version":1,"snapshot_file":"snapshot-000000000099.bin","checksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","created_at_ms":0}"#,
    )
    .unwrap();
    let rt2 = restart(dir.path(), &master, &rt).await;
    assert_eq!(rt2.published_snapshot_sequence().await.unwrap(), Some(1));
}
