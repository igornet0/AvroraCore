//! Correctness under load: idempotent producer, retry/DLQ exactness, graceful restart and
//! real SIGKILL crash/recovery cycles (child process). Every check reports
//! produced / received / acked / retried / dlq / lost / duplicated.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{PutOptions, RetryPolicy, StreamId, SubscriptionId};
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};
use rand::Rng;
use serde_json::json;

use crate::channel::chan_env;
use crate::common::{make_payload, parse_header, Sink};

pub async fn run(sink: &Sink, crash_cycles: u32) {
    idempotent_producer(sink).await;
    retry_exact(sink).await;
    dlq_exact(sink).await;
    graceful_restart(sink).await;
    crash_recovery(sink, crash_cycles).await;
}

fn verdict(ok: bool) -> &'static str {
    if ok {
        "PASS"
    } else {
        "FAIL"
    }
}

async fn drain(rt: &Runtime, reader: &dmc_core::SessionId, sub: &SubscriptionId, ack: bool, max: Duration) -> Vec<(u64, u64, u32)> {
    let mut out = Vec::new();
    let t = Instant::now();
    let mut idle = 0;
    while t.elapsed() < max {
        match rt.consume(sub, 1).await {
            Ok(evs) if evs.is_empty() => {
                idle += 1;
                if idle > 20 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok(evs) => {
                idle = 0;
                for ev in evs {
                    let id = parse_header(&ev.payload).map(|h| h.0).unwrap_or(u64::MAX);
                    out.push((id, ev.sequence, ev.delivery.attempt));
                    if ack {
                        rt.ack(reader, sub, &ev.delivery.delivery_id).await.expect("ack");
                    }
                }
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(2)).await,
        }
    }
    out
}

async fn idempotent_producer(sink: &Sink) {
    let ce = chan_env(1, RetryPolicy::immediate()).await;
    let rt = ce.env.rt.clone();
    let n = 500u64;
    let mut replays = 0u64;
    let mut seq_mismatch = 0u64;
    let head0 = rt.last_sequence().await;
    // Two concurrent producers send the SAME (producer_id, key) set.
    let mut handles = Vec::new();
    for _ in 0..2 {
        let (rt, admin) = (rt.clone(), ce.env.admin.clone());
        handles.push(tokio::spawn(async move {
            let mut res = Vec::new();
            for i in 0..n {
                let p = make_payload(256, i, 0, i, 0);
                let r = rt
                    .put_data_with(&admin, &format!("chan/idem/m{i}"), &p, Some(PutOptions { producer_id: "p1".into(), idempotency_key: format!("k{i}") }))
                    .await
                    .expect("put");
                res.push((i, r.sequence, r.replay));
            }
            res
        }));
    }
    let a = handles.remove(0).await.unwrap();
    let b = handles.remove(0).await.unwrap();
    for ((i, s1, r1), (_, s2, r2)) in a.iter().zip(b.iter()) {
        if *r1 || *r2 {
            replays += 1;
        }
        if s1 != s2 {
            seq_mismatch += 1;
            let _ = i;
        }
    }
    let head1 = rt.last_sequence().await;
    // Restart, then resend the same keys again
    let db = ce.env.db.clone();
    // Graceful: lock (syncs journal, wipes keys) before a new instance opens the same files.
    let lock_res = rt.lock().await.map_err(|e| e.to_string());
    drop(rt);
    let rt2 = Runtime::at_path(&db);
    let reopened = rt2.unlock(&ce.env.master_hex).await;
    let mut replays_after_restart = 0u64;
    let mut new_after_restart = 0u64;
    if reopened.is_ok() {
        let admin = rt2.admin_session().await.expect("admin");
        for i in 0..100u64 {
            let p = make_payload(256, i, 0, i, 0);
            let r = rt2
                .put_data_with(&admin, &format!("chan/idem/m{i}"), &p, Some(PutOptions { producer_id: "p1".into(), idempotency_key: format!("k{i}") }))
                .await
                .expect("put after restart");
            if r.replay {
                replays_after_restart += 1;
            } else {
                new_after_restart += 1;
            }
        }
    }
    let reader = rt2.open_user_session("consumer", Some("bench")).await.expect("reader");
    let got = drain(&rt2, &reader, &ce.subs[0], true, Duration::from_secs(120)).await;
    let ids: HashSet<u64> = got.iter().map(|x| x.0).collect();
    let dups = got.len() as u64 - ids.len() as u64;
    let ok = replays == n && seq_mismatch == 0 && head1 - head0 == n && replays_after_restart == 100 && ids.len() as u64 == n && dups == 0;
    sink.emit(json!({"suite": "correctness", "system": "avrora_runtime_inproc", "scenario": "idempotent_producer",
        "produced_attempts": 2 * n, "unique_keys": n, "journal_entries_added": head1 - head0,
        "replay_flags": replays, "sequence_mismatch_between_duplicates": seq_mismatch,
        "restart_unlock_ok": reopened.is_ok(), "lock_before_restart": format!("{lock_res:?}"), "replays_after_restart": replays_after_restart, "new_entries_after_restart": new_after_restart,
        "received": got.len(), "received_unique": ids.len(), "acked": got.len(), "duplicated": dups,
        "lost": n.saturating_sub(ids.len() as u64), "result": verdict(ok)}));
}

async fn retry_exact(sink: &Sink) {
    let ce = chan_env(1, RetryPolicy::immediate()).await;
    let rt = &ce.env.rt;
    let n = 200u64;
    for i in 0..n {
        rt.put_data(&ce.env.admin, &format!("chan/r/m{i}"), &make_payload(128, i, 0, i, 0)).await.unwrap();
    }
    let sub = &ce.subs[0];
    let mut per_id: HashMap<u64, Vec<u32>> = HashMap::new();
    let mut acked = 0u64;
    let t = Instant::now();
    while acked < n && t.elapsed() < Duration::from_secs(300) {
        let evs = rt.consume(sub, 1).await.unwrap_or_default();
        for ev in evs {
            let id = parse_header(&ev.payload).unwrap().0;
            per_id.entry(id).or_default().push(ev.delivery.attempt);
            if ev.delivery.attempt >= 3 {
                rt.ack(&ce.reader, sub, &ev.delivery.delivery_id).await.unwrap();
                acked += 1;
            }
        }
    }
    let exact = per_id.values().filter(|v| v.as_slice() == [1, 2, 3]).count() as u64;
    let deliveries: u64 = per_id.values().map(|v| v.len() as u64).sum();
    let ok = exact == n && acked == n;
    sink.emit(json!({"suite": "correctness", "system": "avrora_runtime_inproc", "scenario": "retry_ack_on_3rd_attempt",
        "produced": n, "received_unique": per_id.len(), "deliveries": deliveries, "retried": deliveries - per_id.len() as u64,
        "acked": acked, "ids_with_attempts_exactly_1_2_3": exact, "dlq": 0, "lost": n - per_id.len() as u64,
        "duplicated": 0, "result": verdict(ok)}));
}

async fn dlq_exact(sink: &Sink) {
    let policy = RetryPolicy { max_attempts: 3, initial_backoff_ms: 0, max_backoff_ms: 0, multiplier: 1 };
    let ce = chan_env(1, policy).await;
    let rt = &ce.env.rt;
    let n = 100u64;
    for i in 0..n {
        rt.put_data(&ce.env.admin, &format!("chan/d/m{i}"), &make_payload(128, i, 0, i, 0)).await.unwrap();
    }
    let sub = &ce.subs[0];
    let got = drain(rt, &ce.reader, sub, false, Duration::from_secs(300)).await;
    let dlq_res = rt.list_dlq(&ce.reader, sub).await;
    let dlq_err = dlq_res.as_ref().err().map(|e| e.to_string());
    let admin_dlq = rt.list_dlq(&ce.env.admin, sub).await.map(|v| v.len()).map_err(|e| e.to_string());
    // Consumer role is scoped to its stream and cannot read its own DLQ; verify via admin.
    let dlq = match dlq_res {
        Ok(v) => v,
        Err(_) => rt.list_dlq(&ce.env.admin, sub).await.unwrap_or_default(),
    };
    let dlq_seqs: HashSet<u64> = dlq.iter().map(|e| e.original_sequence).collect();
    let delivered_seqs: HashSet<u64> = got.iter().map(|x| x.1).collect();
    let attempts_ok = dlq.iter().all(|e| e.attempts == 3);
    let lag = rt.consumer_lag(sub).await.ok();
    let ok = dlq.len() as u64 == n && dlq_seqs == delivered_seqs && attempts_ok && got.len() as u64 == 3 * n;
    sink.emit(json!({"suite": "correctness", "system": "avrora_runtime_inproc", "scenario": "dlq_max_attempts_3",
        "produced": n, "deliveries": got.len(), "received_unique": delivered_seqs.len(), "acked": 0,
        "retried": got.len() as u64 - delivered_seqs.len() as u64, "dlq": dlq.len(), "dlq_entries_attempts_all_3": attempts_ok,
        "dlq_sequences_match_delivered": dlq_seqs == delivered_seqs,
        "final_lag_events": lag.as_ref().map(|l| l.lag_events), "lag_dlq_count": lag.as_ref().map(|l| l.dlq_count),
        "list_dlq_error_consumer_session": dlq_err, "list_dlq_admin_session": format!("{admin_dlq:?}"), "final_pending": lag.as_ref().map(|l| l.pending.is_some()),
        "lost": n.saturating_sub(dlq.len() as u64), "duplicated": 0, "result": verdict(ok)}));
}

async fn graceful_restart(sink: &Sink) {
    let ce = chan_env(1, RetryPolicy::immediate()).await;
    let n = 1000u64;
    for i in 0..n {
        ce.env.rt.put_data(&ce.env.admin, &format!("chan/g/m{i}"), &make_payload(256, i, 0, i, 0)).await.unwrap();
    }
    let sub = ce.subs[0].clone();
    // consume + ack 400, then consume 1 more WITHOUT ack (pending at restart)
    let mut before = Vec::new();
    while before.len() < 400 {
        for ev in ce.env.rt.consume(&sub, 1).await.unwrap() {
            before.push(parse_header(&ev.payload).unwrap().0);
            ce.env.rt.ack(&ce.reader, &sub, &ev.delivery.delivery_id).await.unwrap();
        }
    }
    let pending = ce.env.rt.consume(&sub, 1).await.unwrap();
    let pending_id = pending.first().map(|e| parse_header(&e.payload).unwrap().0);
    let db = ce.env.db.clone();
    let master = ce.env.master_hex.clone();
    ce.env.rt.lock().await.expect("lock before restart");
    let rt2 = Runtime::at_path(&db);
    let unlock = rt2.unlock(&master).await;
    let reader = rt2.open_user_session("consumer", Some("bench")).await;
    let (after, err) = match (&unlock, &reader) {
        (Ok(_), Ok(r)) => (drain(&rt2, r, &sub, true, Duration::from_secs(300)).await, None),
        _ => (Vec::new(), Some(format!("unlock={:?} reader={:?}", unlock.as_ref().err().map(|e| e.to_string()), reader.as_ref().err().map(|e| e.to_string())))),
    };
    let before_set: HashSet<u64> = before.iter().copied().collect();
    let after_ids: Vec<u64> = after.iter().map(|x| x.0).collect();
    let after_set: HashSet<u64> = after_ids.iter().copied().collect();
    let redelivered_acked = after_set.intersection(&before_set).count();
    let union: HashSet<u64> = before_set.union(&after_set).copied().collect();
    let pending_redelivered = pending_id.map(|p| after_set.contains(&p)).unwrap_or(false);
    let ok = err.is_none() && union.len() as u64 == n && redelivered_acked == 0 && after_ids.len() == after_set.len();
    sink.emit(json!({"suite": "correctness", "system": "avrora_runtime_inproc", "scenario": "graceful_restart",
        "produced": n, "acked_before_restart": before.len(), "pending_at_restart": pending_id,
        "pending_redelivered_after_restart": pending_redelivered,
        "received_after_restart": after_ids.len(), "received_unique_total": union.len(),
        "acked_redelivered": redelivered_acked, "lost": n - union.len() as u64,
        "duplicated": after_ids.len() - after_set.len(), "error": err, "result": verdict(ok)}));
}

// ───────────────────────── SIGKILL crash cycles ─────────────────────────

async fn setup_persistent(dir: &Path) -> (String, SubscriptionId) {
    let db = dir.join("store.dbs.json");
    let rt = Runtime::at_path(&db);
    let (master, _) = rt.create_dev(false).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    rt.create_role(&admin, "reader".into(), "Reader".into(), KeyPath::parse("chan").unwrap(), PermissionSet::empty().with(Permission::Read)).await.unwrap();
    rt.create_user(&admin, "consumer".into(), vec!["reader".into()]).await.unwrap();
    rt.configure_channel(ChannelSpec::internal("bus")).await.unwrap();
    let stream = rt
        .create_stream(StreamSpec {
            id: StreamId::from("chan-out"),
            direction: StreamDirection::Outbound,
            channel_id: "bus".into(),
            path_scope: KeyPath::parse("chan").unwrap(),
            required_perms: PermissionSet::empty().with(Permission::Read),
        })
        .await
        .unwrap();
    let reader = rt.open_user_session("consumer", Some("bench")).await.unwrap();
    let sub = rt.create_subscription(&reader, &stream, Some("crash-consumer")).await.unwrap();
    rt.set_retry_policy(&reader, &sub.id, RetryPolicy::immediate()).await.unwrap();
    (master, sub.id)
}

/// Child: reopen, then loop { put → print "W id"; every 5 puts consume+ack → print "A id" }.
pub async fn crash_child(dir: PathBuf, master: String, start_id: u64, size: usize) {
    let rt = Runtime::at_path(dir.join("store.dbs.json"));
    if let Err(e) = rt.unlock(&master).await {
        println!("E unlock {e}");
        return;
    }
    let admin = rt.admin_session().await.expect("admin");
    let reader = rt.open_user_session("consumer", Some("bench")).await.expect("reader");
    let sub = rt.list_subscriptions().await.into_iter().next().expect("subscription").id;
    println!("READY");
    let mut out = std::io::stdout();
    let mut id = start_id;
    loop {
        let p = make_payload(size, id, 1, id, 0);
        rt.put_data(&admin, &format!("chan/k/m{id}"), &p).await.expect("put");
        writeln!(out, "W {id}").unwrap();
        out.flush().unwrap();
        id += 1;
        if id % 5 == 0 {
            for _ in 0..3 {
                if let Ok(evs) = rt.consume(&sub, 1).await {
                    for ev in evs {
                        let mid = parse_header(&ev.payload).map(|h| h.0).unwrap_or(u64::MAX);
                        writeln!(out, "D {mid} {}", ev.delivery.attempt).unwrap();
                        out.flush().unwrap();
                        if rt.ack(&reader, &sub, &ev.delivery.delivery_id).await.is_ok() {
                            writeln!(out, "A {mid}").unwrap();
                            out.flush().unwrap();
                        }
                    }
                }
            }
        }
    }
}

async fn crash_recovery(sink: &Sink, cycles: u32) {
    let dir = tempfile::tempdir().unwrap();
    let (master, sub) = setup_persistent(dir.path()).await;
    let exe = std::env::current_exe().unwrap();
    let mut written: Vec<u64> = Vec::new();
    let mut delivered: Vec<u64> = Vec::new();
    let mut acked: Vec<u64> = Vec::new();
    let mut start_id = 0u64;
    let mut cycle_reports = Vec::new();
    for c in 0..cycles {
        let mut child = Command::new(&exe)
            .args(["crash-child", "--dir"])
            .arg(dir.path())
            .args(["--master", &master, "--start-id", &start_id.to_string(), "--size", "1024"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel::<String>();
        let reader_thread = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        // wait READY, then let it run for a random 1.5–4 s and SIGKILL it
        let ready_deadline = Instant::now() + Duration::from_secs(60);
        let mut ready = false;
        while Instant::now() < ready_deadline {
            if let Ok(l) = rx.recv_timeout(Duration::from_millis(100)) {
                if l == "READY" {
                    ready = true;
                    break;
                }
                if l.starts_with("E ") {
                    break;
                }
            }
        }
        let run_ms = rand::thread_rng().gen_range(1500..4000);
        tokio::time::sleep(Duration::from_millis(run_ms)).await;
        unsafe {
            libc::kill(child.id() as i32, libc::SIGKILL);
        }
        let _ = child.wait();
        let _ = reader_thread.join();
        let (mut w, mut d, mut a) = (0, 0, 0);
        while let Ok(l) = rx.try_recv() {
            let mut it = l.split_whitespace();
            match (it.next(), it.next().and_then(|x| x.parse::<u64>().ok())) {
                (Some("W"), Some(id)) => {
                    written.push(id);
                    w += 1;
                    start_id = start_id.max(id + 1);
                }
                (Some("D"), Some(id)) => {
                    delivered.push(id);
                    d += 1;
                }
                (Some("A"), Some(id)) => {
                    acked.push(id);
                    a += 1;
                }
                _ => {}
            }
        }
        start_id += 100; // skip ids that may have been in flight
        cycle_reports.push(json!({"cycle": c, "ready": ready, "ran_ms": run_ms, "acknowledged_writes": w, "deliveries": d, "acks": a}));
    }
    // Recovery verification in-process
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let unlock = rt.unlock(&master).await;
    let mut lost_acked_writes = Vec::new();
    let mut corrupt = 0u64;
    let mut after = Vec::new();
    let mut acked_redelivered = 0u64;
    if unlock.is_ok() {
        let admin = rt.admin_session().await.unwrap();
        for id in &written {
            match rt.get_data(&admin, &format!("chan/k/m{id}")).await {
                Ok(p) => {
                    if parse_header(&p).map(|h| h.0) != Some(*id) {
                        corrupt += 1;
                    }
                }
                Err(_) => lost_acked_writes.push(*id),
            }
        }
        let reader = rt.open_user_session("consumer", Some("bench")).await.unwrap();
        after = drain(&rt, &reader, &sub, true, Duration::from_secs(600)).await;
        let acked_set: HashSet<u64> = acked.iter().copied().collect();
        acked_redelivered = after.iter().filter(|x| acked_set.contains(&x.0)).count() as u64;
    }
    let delivered_all: HashSet<u64> = delivered.iter().copied().chain(after.iter().map(|x| x.0)).collect();
    let written_set: HashSet<u64> = written.iter().copied().collect();
    let never_delivered = written_set.difference(&delivered_all).count() as u64;
    let acked_set: HashSet<u64> = acked.iter().copied().collect();
    let dup_acks = acked.len() as u64 - acked_set.len() as u64;
    let ok = unlock.is_ok() && lost_acked_writes.is_empty() && corrupt == 0 && never_delivered == 0 && acked_redelivered == 0 && dup_acks == 0;
    sink.emit(json!({"suite": "correctness", "system": "avrora_runtime_child_process", "scenario": "sigkill_crash_recovery",
        "cycles": cycles, "cycle_reports": cycle_reports,
        "produced_acknowledged": written.len(), "received_unique": delivered_all.len(),
        "deliveries_before_crashes": delivered.len(), "deliveries_after_recovery": after.len(),
        "acked": acked.len(), "duplicated_acks": dup_acks,
        "acked_then_redelivered_after_recovery": acked_redelivered,
        "lost_acknowledged_writes": lost_acked_writes.len(), "lost_sample": lost_acked_writes.iter().take(10).collect::<Vec<_>>(),
        "corrupt_payloads": corrupt, "never_delivered": never_delivered,
        "recovery_unlock": unlock.as_ref().map(|_| "ok".to_string()).unwrap_or_else(|e| e.to_string()),
        "result": verdict(ok)}));
}
