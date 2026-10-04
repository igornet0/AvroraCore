//! Benchmark V2 suites: write scalability matrix (writers × record size × partitions, with
//! journal fsync accounting) and consumer cost vs backlog (+ recovery time).
//!
//! Partition count and commit mode come from the runtime environment
//! (`DMC_JOURNAL_PARTITION_COUNT`, `DMC_GROUP_COMMIT`) and are recorded with every result.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use dmc_core::runtime::Runtime;
use dmc_core::RetryPolicy;
use serde_json::{json, Value};

use crate::channel::chan_env;
use crate::common::{make_payload, round2, self_pid, size_label, Lat, ResMonitor, Sink, Timing};
use crate::driver::closed_loop;
use crate::storage::av_env;

fn env_params() -> Value {
    json!({
        "partitions": std::env::var("DMC_JOURNAL_PARTITION_COUNT").unwrap_or_else(|_| "1".into()),
        "group_commit": std::env::var("DMC_GROUP_COMMIT").map_or(true, |v| v != "0"),
    })
}

pub async fn write_matrix(sink: &Sink, timing: Timing, writers: &[usize], sizes: &[usize]) {
    for &size in sizes {
        for &w in writers {
            // Fresh database per point: no carry-over of key count / segments between points.
            let env = av_env().await;
            let (rt, admin) = (env.rt.clone(), env.admin.clone());
            let completed = Arc::new(AtomicU64::new(0));
            let done = completed.clone();
            let fsync0 = dmc_journal::journal_fsync_count();
            let t0 = Instant::now();
            let mon = ResMonitor::start(vec![self_pid()]);
            let out = closed_loop(w, timing, u64::MAX, move |wk, i| {
                let (rt, admin, done) = (rt.clone(), admin.clone(), done.clone());
                async move {
                    let p = make_payload(size, i, wk as u32, i, 0);
                    match rt.put_data(&admin, &format!("wm/{wk}/{i}"), &p).await {
                        Ok(()) => {
                            done.fetch_add(1, Ordering::Relaxed);
                            Ok((1, size as u64))
                        }
                        Err(e) => Err(e.to_string()),
                    }
                }
            })
            .await;
            let res = mon.finish();
            let wall = t0.elapsed().as_secs_f64();
            let fsyncs = dmc_journal::journal_fsync_count() - fsync0;
            let writes = completed.load(Ordering::Relaxed);
            let mut rec = out.json();
            let o = rec.as_object_mut().unwrap();
            o.insert("suite".into(), json!("v2_write_matrix"));
            o.insert("system".into(), json!("avrora_kv_inproc"));
            o.insert("scenario".into(), json!("put_unique_keys"));
            o.insert(
                "params".into(),
                json!({"size": size_label(size), "writers": w, "env": env_params(), "timing": timing.json()}),
            );
            o.insert(
                "durability".into(),
                json!({
                    "journal_fsyncs": fsyncs,
                    "fsync_per_s": round2(fsyncs as f64 / wall),
                    "writes_total": writes,
                    "writes_per_fsync": round2(writes as f64 / fsyncs.max(1) as f64),
                }),
            );
            o.insert("resources".into(), res);
            sink.emit(rec);
        }
    }
}

/// Produce `backlog` messages, then measure consume+ack of the first `probe` deliveries
/// (cost per delivery as a function of backlog) and reopen (recovery) time.
pub async fn consume_backlog(sink: &Sink, backlogs: &[u64], size: usize, probe: u64) {
    for &n in backlogs {
        let ce = chan_env(1, RetryPolicy::default()).await;
        let rt = ce.env.rt.clone();
        let admin = ce.env.admin.clone();
        let produced = Arc::new(AtomicU64::new(0));
        let t0 = Instant::now();
        let producers = 32u64;
        let mut tasks = Vec::new();
        for p in 0..producers {
            let (rt, admin, produced) = (rt.clone(), admin.clone(), produced.clone());
            tasks.push(tokio::spawn(async move {
                let mut i = p;
                while i < n {
                    let payload = make_payload(size, i, p as u32, i, 0);
                    rt.put_data(&admin, &format!("chan/m/{i}"), &payload)
                        .await
                        .expect("produce");
                    produced.fetch_add(1, Ordering::Relaxed);
                    i += producers;
                }
            }));
        }
        for t in tasks {
            t.await.expect("producer");
        }
        let produce_s = t0.elapsed().as_secs_f64();

        let sub = ce.subs[0].clone();
        let mut consume_lat = Lat::with_capacity(probe as usize);
        let mut ack_lat = Lat::with_capacity(probe as usize);
        let mon = ResMonitor::start(vec![self_pid()]);
        let tc = Instant::now();
        let mut delivered = 0u64;
        while delivered < probe.min(n) {
            let t = Instant::now();
            let evs = rt.consume(&sub, 1).await.expect("consume");
            consume_lat.record(t.elapsed());
            for ev in evs {
                let ta = Instant::now();
                rt.ack(&ce.reader, &sub, &ev.delivery.delivery_id)
                    .await
                    .expect("ack");
                ack_lat.record(ta.elapsed());
                delivered += 1;
            }
        }
        let consume_s = tc.elapsed().as_secs_f64();
        let res = mon.finish();

        // Recovery: reopen + unlock the same database.
        let (db, master) = (ce.env.db.clone(), ce.env.master_hex.clone());
        let _keep_dir = ce.env.dir; // dropping the TempDir would delete the database
        drop(rt);
        drop(ce.env.rt);
        let tr = Instant::now();
        let reopened = Runtime::at_path(&db);
        reopened.unlock(&master).await.expect("reopen");
        let recovery_s = tr.elapsed().as_secs_f64();

        sink.emit(json!({
            "suite": "v2_consume_backlog",
            "system": "avrora_runtime_inproc",
            "scenario": "consume_ack_from_backlog",
            "params": {"backlog": n, "size": size_label(size), "probe": probe, "env": env_params()},
            "produce": {"msgs": n, "seconds": round2(produce_s), "msgs_per_s": round2(n as f64 / produce_s)},
            "consume": {
                "delivered": delivered,
                "deliveries_per_s": round2(delivered as f64 / consume_s),
                "consume_latency": consume_lat.stats(),
                "ack_latency": ack_lat.stats(),
            },
            "recovery_s": round2(recovery_s),
            "resources": res,
        }));
    }
}
