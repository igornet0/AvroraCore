//! Group commit for `put_data`: concurrent writers share fsyncs without weakening the
//! durability contract (ACK ⇒ durable + applied), ordering, idempotency or recovery.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use dmc_core::runtime::{PutOptions, Runtime};

async fn fresh() -> (tempfile::TempDir, std::path::PathBuf, Runtime, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let rt = Runtime::at_path(&path);
    let (master, _) = rt.create_dev(false).await.unwrap();
    (dir, path, rt, master)
}

async fn reopen(path: &std::path::Path, master: &str) -> Runtime {
    let rt = Runtime::at_path(path);
    rt.unlock(master).await.unwrap();
    rt
}

/// 64 concurrent writers: every ACK has a unique sequence, sequences are contiguous, the value
/// visible for each path is the one with the highest acknowledged sequence, and everything
/// acknowledged survives reopen.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_writers_unique_ordered_durable() {
    let (_dir, path, rt, master) = fresh().await;
    let admin = rt.admin_session().await.unwrap();
    let rt = Arc::new(rt);
    let writers = 64;
    let per_writer = 20;
    let mut tasks = Vec::new();
    for w in 0..writers {
        let (rt, admin) = (rt.clone(), admin.clone());
        tasks.push(tokio::spawn(async move {
            let mut acks = Vec::new();
            for i in 0..per_writer {
                // Half the writes contend on 8 shared paths, half go to private paths.
                let p = if i % 2 == 0 {
                    format!("gc/shared/{}", (w + i) % 8)
                } else {
                    format!("gc/private/{w}/{i}")
                };
                let v = format!("w{w}-i{i}").into_bytes();
                let r = rt.put_data_with(&admin, &p, &v, None).await.unwrap();
                assert!(!r.replay);
                // Read-your-write: ACK implies applied.
                let got = rt.get_data(&admin, &p).await.unwrap();
                assert!(got == v || p.starts_with("gc/shared/"));
                acks.push((r.sequence, p, v));
            }
            acks
        }));
    }
    let mut all = Vec::new();
    for t in tasks {
        all.extend(t.await.unwrap());
    }
    let seqs: HashSet<u64> = all.iter().map(|(s, _, _)| *s).collect();
    assert_eq!(seqs.len(), all.len(), "duplicate sequence acknowledged");
    let (min, max) = (*seqs.iter().min().unwrap(), *seqs.iter().max().unwrap());
    assert_eq!(max - min + 1, all.len() as u64, "gap among acknowledged sequences");

    let mut latest: HashMap<String, (u64, Vec<u8>)> = HashMap::new();
    for (s, p, v) in &all {
        let e = latest.entry(p.clone()).or_insert((0, Vec::new()));
        if *s > e.0 {
            *e = (*s, v.clone());
        }
    }
    for (p, (_, v)) in &latest {
        assert_eq!(&rt.get_data(&admin, p).await.unwrap(), v, "{p}: last-sequence wins");
    }
    drop(admin);
    drop(rt);

    let rt = reopen(&path, &master).await;
    let admin = rt.admin_session().await.unwrap();
    for (p, (_, v)) in &latest {
        assert_eq!(&rt.get_data(&admin, p).await.unwrap(), v, "{p} after reopen");
    }
}

/// Concurrent puts with one idempotency key produce exactly one journal entry; every caller
/// gets that entry's sequence, all but one flagged `replay`.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_idempotent_puts_single_entry() {
    let (_dir, path, rt, master) = fresh().await;
    let admin = rt.admin_session().await.unwrap();
    let rt = Arc::new(rt);
    let before = rt.last_sequence().await;
    let mut tasks = Vec::new();
    for _ in 0..32 {
        let (rt, admin) = (rt.clone(), admin.clone());
        tasks.push(tokio::spawn(async move {
            rt.put_data_with(
                &admin,
                "gc/idem/x",
                b"payload",
                Some(PutOptions {
                    producer_id: "p1".into(),
                    idempotency_key: "k-1".into(),
                }),
            )
            .await
            .unwrap()
        }));
    }
    let mut results = Vec::new();
    for t in tasks {
        results.push(t.await.unwrap());
    }
    let seqs: HashSet<u64> = results.iter().map(|r| r.sequence).collect();
    assert_eq!(seqs.len(), 1, "one entry for one idempotency key");
    assert_eq!(results.iter().filter(|r| !r.replay).count(), 1);
    assert_eq!(rt.last_sequence().await, before + 1);
    drop(admin);
    drop(rt);
    let rt = reopen(&path, &master).await;
    let admin = rt.admin_session().await.unwrap();
    let again = rt
        .put_data_with(
            &admin,
            "gc/idem/x",
            b"payload",
            Some(PutOptions {
                producer_id: "p1".into(),
                idempotency_key: "k-1".into(),
            }),
        )
        .await
        .unwrap();
    assert!(again.replay);
    assert!(seqs.contains(&again.sequence));
}

/// Other operations observe only committed state: the barrier commits in-flight puts before
/// e.g. a delete, so the per-path order (put → delete) is preserved.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn barrier_orders_puts_before_other_mutations() {
    let (_dir, _path, rt, _master) = fresh().await;
    let admin = rt.admin_session().await.unwrap();
    let rt = Arc::new(rt);
    for round in 0..50 {
        let p = format!("gc/order/{round}");
        let (rt2, admin2, p2) = (rt.clone(), admin.clone(), p.clone());
        let put = tokio::spawn(async move { rt2.put_data(&admin2, &p2, b"v").await });
        put.await.unwrap().unwrap();
        rt.delete_data(&admin, &p).await.unwrap();
        assert!(rt.get_data(&admin, &p).await.is_err(), "delete after ACKed put wins");
    }
}

/// Concurrent puts and deletes (different commit paths: group commit vs barrier + sync) on the
/// same paths: the live state must equal the state rebuilt from the journal after reopen, i.e.
/// in-memory apply order == journal sequence order.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn mixed_puts_and_deletes_live_state_matches_replay() {
    let (_dir, path, rt, master) = fresh().await;
    let admin = rt.admin_session().await.unwrap();
    let rt = Arc::new(rt);
    let mut tasks = Vec::new();
    for w in 0..32u64 {
        let (rt, admin) = (rt.clone(), admin.clone());
        tasks.push(tokio::spawn(async move {
            let mut x = w.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
            for i in 0..40u64 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let p = format!("gc/mixed/{}", x % 6);
                if x % 4 == 0 {
                    let _ = rt.delete_data(&admin, &p).await;
                } else {
                    rt.put_data(&admin, &p, format!("w{w}-{i}").as_bytes())
                        .await
                        .unwrap();
                }
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let mut live = Vec::new();
    for k in 0..6 {
        live.push(rt.get_data(&admin, &format!("gc/mixed/{k}")).await.ok());
    }
    drop(admin);
    drop(rt);
    let rt = reopen(&path, &master).await;
    let admin = rt.admin_session().await.unwrap();
    for k in 0..6 {
        let replayed = rt.get_data(&admin, &format!("gc/mixed/{k}")).await.ok();
        assert_eq!(replayed, live[k], "gc/mixed/{k}: live state != replayed state");
    }
}
