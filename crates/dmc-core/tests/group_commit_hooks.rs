//! Group-commit tests driven by process-wide journal hooks (own test binary; the tests in
//! this file are serialized through `HOOKS`).

use std::sync::Arc;

use dmc_core::runtime::Runtime;

static HOOKS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A failed group-commit fsync must never produce an ACK.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn fsync_failure_yields_no_ack_and_fails_closed() {
    let _hooks = HOOKS.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let rt = Runtime::at_path(&path);
    let (master, _) = rt.create_dev(false).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    rt.put_data(&admin, "gc/fail/before", b"ok").await.unwrap();
    let rt = Arc::new(rt);

    dmc_journal::set_test_fail_fsync(true);
    let mut tasks = Vec::new();
    for i in 0..32 {
        let (rt, admin) = (rt.clone(), admin.clone());
        tasks.push(tokio::spawn(async move {
            rt.put_data(&admin, &format!("gc/fail/{i}"), b"x").await
        }));
    }
    for t in tasks {
        assert!(t.await.unwrap().is_err(), "no ACK without a successful fsync");
    }
    dmc_journal::set_test_fail_fsync(false);

    // Not acknowledged ⇒ not applied / not visible.
    for i in 0..32 {
        assert!(rt.get_data(&admin, &format!("gc/fail/{i}")).await.is_err());
    }
    // Fail-closed: journal refuses further writes until reopen, even with fsync healthy again.
    assert!(rt.put_data(&admin, "gc/fail/after", b"x").await.is_err());
    assert_eq!(rt.get_data(&admin, "gc/fail/before").await.unwrap(), b"ok");
    drop(admin);
    drop(rt);

    // Reopen: acknowledged data intact; journal writable again.
    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    assert_eq!(rt.get_data(&admin, "gc/fail/before").await.unwrap(), b"ok");
    rt.put_data(&admin, "gc/fail/after", b"y").await.unwrap();
    assert_eq!(rt.get_data(&admin, "gc/fail/after").await.unwrap(), b"y");
}

/// A put whose group fsync is still in flight (outside the lock) must be applied before any
/// later mutation of the same path: the commit barrier preserves journal order in memory.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn in_flight_put_is_ordered_before_later_delete() {
    let _hooks = HOOKS.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let rt = Runtime::at_path(&path);
    let (master, _) = rt.create_dev(false).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    // Warm-up: the first commit after create persists topology (new segment) synchronously.
    rt.put_data(&admin, "gc/race/warmup", b"w").await.unwrap();
    let rt = Arc::new(rt);
    dmc_journal::set_test_group_sync_delay_ms(300);
    let (rt2, admin2) = (rt.clone(), admin.clone());
    let put = tokio::spawn(async move { rt2.put_data(&admin2, "gc/race/x", b"v").await });
    // Let the put be appended and its group fsync start (stalled 300 ms outside the lock).
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    rt.delete_data(&admin, "gc/race/x").await.unwrap();
    dmc_journal::set_test_group_sync_delay_ms(0);
    put.await.unwrap().unwrap();
    let live = rt.get_data(&admin, "gc/race/x").await.ok();
    assert_eq!(live, None, "delete (later sequence) must win in memory");
    drop(admin);
    drop(rt);
    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    assert_eq!(rt.get_data(&admin, "gc/race/x").await.ok(), live, "live == replayed");
}
