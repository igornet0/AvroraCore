//! Channel / stream benchmark: producer(s) → `put_data` on a stream scope → durable
//! subscriptions → consumer(s) `consume` → `ack`. Every message carries a unique id
//! (producer, seq) and a produce timestamp for end-to-end latency and loss/dup/order checks.
//!
//! Semantics under test (from code): each consumer is an independent subscription
//! (fan-out); delivery is at-least-once with exactly ONE in-flight delivery per subscription
//! (a second `consume` before `ack` re-delivers the pending event as a retry).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{BatchLimits, ConsumerPolicy, RetryPolicy, SessionId, StreamId, SubscriptionId};
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};
use serde_json::{json, Value};

use crate::common::{make_payload, parse_header, round2, self_pid, Lat, ResMonitor, Sink, Timing};
use crate::storage::{av_env, AvEnv};

pub struct ChanEnv {
    pub env: AvEnv,
    pub reader: SessionId,
    pub stream: StreamId,
    pub subs: Vec<SubscriptionId>,
}

pub async fn chan_env(consumers: usize, retry: RetryPolicy) -> ChanEnv {
    let env = av_env().await;
    let rt = &env.rt;
    let admin = env.admin.clone();
    rt.create_role(
        &admin,
        "reader".into(),
        "Reader".into(),
        KeyPath::parse("chan").unwrap(),
        PermissionSet::empty().with(Permission::Read),
    )
    .await
    .expect("role");
    rt.create_user(&admin, "consumer".into(), vec!["reader".into()]).await.expect("user");
    rt.configure_channel(ChannelSpec::internal("bus")).await.expect("channel");
    let stream = rt
        .create_stream(StreamSpec {
            id: StreamId::from("chan-out"),
            direction: StreamDirection::Outbound,
            channel_id: "bus".into(),
            path_scope: KeyPath::parse("chan").unwrap(),
            required_perms: PermissionSet::empty().with(Permission::Read),
        })
        .await
        .expect("stream");
    let reader = rt.open_user_session("consumer", Some("bench")).await.expect("session");
    let mut subs = Vec::new();
    for k in 0..consumers {
        let s = rt
            .create_subscription(&reader, &stream, Some(&format!("c{k}")))
            .await
            .expect("subscription");
        rt.set_retry_policy(&reader, &s.id, retry).await.expect("retry policy");
        subs.push(s.id);
    }
    ChanEnv {
        env,
        reader,
        stream,
        subs,
    }
}

fn now_ns(base: Instant) -> u64 {
    base.elapsed().as_nanos() as u64
}

#[derive(Default)]
struct ConsumerStats {
    deliveries: u64,
    unique: HashSet<u64>,
    dups: u64,
    seq_violations: u64,
    producer_order_violations: u64,
    acked: u64,
    ack_errors: u64,
    consume_errors: u64,
    e2e: Lat,
    consume_lat: Lat,
    ack_lat: Lat,
    last_seq: u64,
    last_per_producer: HashMap<u32, u64>,
    bytes: u64,
    attempts_hist: HashMap<u32, u64>,
}

pub struct ScenarioCfg {
    pub name: String,
    pub producers: usize,
    pub consumers: usize,
    pub size: usize,
    /// Open-loop target total produce rate (msgs/s); None = closed loop (as fast as possible)
    pub rate: Option<f64>,
    /// Consumer behaviour: ack every Nth delivery attempt (1 = ack first delivery)
    pub ack_on_attempt: u32,
    /// Never ack (DLQ test)
    pub never_ack: bool,
    pub use_ack_batch: bool,
    pub drain_timeout: Duration,
    pub retry: RetryPolicy,
    /// Producers overwrite one path each (no key-tree growth) instead of a new path per message
    pub same_path: bool,
}

pub async fn run_scenario(sink: &Sink, timing: Timing, cfg: &ScenarioCfg) -> Value {
    let ce = chan_env(cfg.consumers, cfg.retry).await;
    let rt = ce.env.rt.clone();
    let admin = ce.env.admin.clone();
    let base = Instant::now();
    let measure_start = base + timing.warmup;
    let end = measure_start + timing.measure;
    let produced = Arc::new(AtomicU64::new(0));
    let produced_measure = Arc::new(AtomicU64::new(0));
    let produce_errors = Arc::new(AtomicU64::new(0));
    let producers_done = Arc::new(AtomicBool::new(false));
    let prod_lat = Arc::new(Mutex::new(Lat::default()));
    let mon = ResMonitor::start(vec![self_pid()]);

    // Producers
    let mut ph = Vec::new();
    for p in 0..cfg.producers {
        let (rt, admin, produced, pm, pe, pl) = (rt.clone(), admin.clone(), produced.clone(), produced_measure.clone(), produce_errors.clone(), prod_lat.clone());
        let size = cfg.size;
        let same_path = cfg.same_path;
        let per_producer_interval = cfg.rate.map(|r| Duration::from_secs_f64(cfg.producers as f64 / r));
        ph.push(tokio::spawn(async move {
            let mut local = Lat::default();
            let mut seq = 0u64;
            let mut next_at = Instant::now();
            while Instant::now() < end {
                if let Some(iv) = per_producer_interval {
                    let now = Instant::now();
                    if now < next_at {
                        tokio::time::sleep(next_at - now).await;
                    }
                    next_at += iv;
                }
                let id = ((p as u64) << 40) | seq;
                let t = Instant::now();
                let payload = make_payload(size, id, p as u32, seq, now_ns(base));
                match rt.put_data(&admin, &if same_path { format!("chan/p{p}") } else { format!("chan/p{p}/m{seq}") }, &payload).await {
                    Ok(()) => {
                        produced.fetch_add(1, Ordering::Relaxed);
                        if t >= measure_start {
                            pm.fetch_add(1, Ordering::Relaxed);
                            local.record(t.elapsed());
                        }
                        seq += 1;
                    }
                    Err(_) => {
                        pe.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            pl.lock().unwrap().merge(local);
        }));
    }

    // Backlog / lag sampler
    let timeline = Arc::new(Mutex::new(Vec::<Value>::new()));
    let delivered_total = Arc::new(AtomicU64::new(0));
    let sampler = {
        let (rt, sub0, tl, produced, dt, done) = (rt.clone(), ce.subs[0].clone(), timeline.clone(), produced.clone(), delivered_total.clone(), producers_done.clone());
        let consumers = cfg.consumers as u64;
        tokio::spawn(async move {
            let mut last = Instant::now();
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let lag = rt.consumer_lag(&sub0).await.ok();
                let p = produced.load(Ordering::Relaxed);
                let d = dt.load(Ordering::Relaxed);
                tl.lock().unwrap().push(json!({
                    "t_s": round2(base.elapsed().as_secs_f64()),
                    "produced": p,
                    "delivered_all_consumers": d,
                    "backlog_msgs": (p * consumers).saturating_sub(d),
                    "sub0_lag_events": lag.as_ref().map(|l| l.lag_events),
                    "sub0_pending": lag.as_ref().map(|l| l.pending.is_some()),
                }));
                if done.load(Ordering::Relaxed) && last.elapsed() > Duration::from_secs(1) {
                    let all = p * consumers;
                    if d >= all {
                        break;
                    }
                }
                last = Instant::now();
                if base.elapsed() > timing.warmup + timing.measure + Duration::from_secs(600) {
                    break;
                }
            }
        })
    };

    // Consumers
    let mut ch = Vec::new();
    for sub in ce.subs.clone() {
        let (rt, reader, done, produced, dt) = (rt.clone(), ce.reader.clone(), producers_done.clone(), produced.clone(), delivered_total.clone());
        let (ack_on, never, batch_ack, drain) = (cfg.ack_on_attempt, cfg.never_ack, cfg.use_ack_batch, cfg.drain_timeout);
        let max_attempts = cfg.retry.max_attempts;
        let warmup_ns = timing.warmup.as_nanos() as u64;
        ch.push(tokio::spawn(async move {
            let mut st = ConsumerStats::default();
            let mut drain_deadline: Option<Instant> = None;
            loop {
                if done.load(Ordering::Relaxed) {
                    let target = produced.load(Ordering::Relaxed);
                    let dl = *drain_deadline.get_or_insert(Instant::now() + drain);
                    let finished = if never {
                        // DLQ mode: each message delivered max_attempts times then dead-lettered.
                        st.unique.len() as u64 >= target && st.deliveries >= target * max_attempts as u64
                    } else {
                        st.acked >= target
                    };
                    if finished || Instant::now() > dl {
                        if never {
                            // one more consume pass to move the last pending entry to DLQ
                            let _ = rt.consume(&sub, 1).await;
                        }
                        break;
                    }
                }
                let t = Instant::now();
                let r = rt.consume(&sub, 1).await;
                let cl = t.elapsed();
                match r {
                    Ok(evs) if evs.is_empty() => {
                        tokio::time::sleep(Duration::from_micros(200)).await;
                    }
                    Ok(evs) => {
                        for ev in evs {
                            st.consume_lat.record(cl);
                            st.deliveries += 1;
                            dt.fetch_add(1, Ordering::Relaxed);
                            st.bytes += ev.payload.len() as u64;
                            *st.attempts_hist.entry(ev.delivery.attempt).or_default() += 1;
                            let Some((id, prod, pseq, t_ns)) = parse_header(&ev.payload) else { continue };
                            let first = st.unique.insert(id);
                            if first {
                                if t_ns >= warmup_ns {
                                    st.e2e.record_ns(now_ns(base).saturating_sub(t_ns));
                                }
                                if ev.sequence <= st.last_seq {
                                    st.seq_violations += 1;
                                }
                                st.last_seq = st.last_seq.max(ev.sequence);
                                if let Some(prev) = st.last_per_producer.get(&prod) {
                                    if pseq <= *prev {
                                        st.producer_order_violations += 1;
                                    }
                                }
                                st.last_per_producer.insert(prod, pseq);
                            } else if ev.delivery.attempt <= 1 {
                                st.dups += 1; // re-delivery that was NOT a retry
                            }
                            if never || ev.delivery.attempt < ack_on {
                                continue; // NACK: leave pending → retry / DLQ
                            }
                            let ta = Instant::now();
                            let ar = if batch_ack {
                                rt.ack_batch(&reader, &sub, &[ev.delivery.delivery_id.clone()]).await.map(|_| ())
                            } else {
                                rt.ack(&reader, &sub, &ev.delivery.delivery_id).await
                            };
                            match ar {
                                Ok(()) => {
                                    st.acked += 1;
                                    st.ack_lat.record(ta.elapsed());
                                }
                                Err(_) => st.ack_errors += 1,
                            }
                        }
                    }
                    Err(e) => {
                        st.consume_errors += 1;
                        if matches!(e, dmc_core::Error::RetryBackoff { .. }) {
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        } else {
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                    }
                }
            }
            st
        }));
    }

    for h in ph {
        let _ = h.await;
    }
    let producer_stop = Instant::now();
    let backlog_at_stop = (produced.load(Ordering::Relaxed) * cfg.consumers as u64)
        .saturating_sub(delivered_total.load(Ordering::Relaxed));
    producers_done.store(true, Ordering::Relaxed);
    let mut stats = Vec::new();
    for h in ch {
        stats.push(h.await.unwrap());
    }
    let drain_s = producer_stop.elapsed().as_secs_f64();
    sampler.abort();
    let res = mon.finish();

    let total_produced = produced.load(Ordering::Relaxed);
    let pm = produced_measure.load(Ordering::Relaxed);
    let measure_s = timing.measure.as_secs_f64();
    let mut e2e = Lat::default();
    let mut cons_lat = Lat::default();
    let mut ack_lat = Lat::default();
    let (mut deliveries, mut unique, mut dups, mut acked, mut seqv, mut pov, mut ack_err, mut cons_err, mut bytes) = (0, 0, 0, 0, 0, 0, 0, 0, 0u64);
    let mut attempts: HashMap<u32, u64> = HashMap::new();
    for s in stats {
        deliveries += s.deliveries;
        unique += s.unique.len() as u64;
        dups += s.dups;
        acked += s.acked;
        seqv += s.seq_violations;
        pov += s.producer_order_violations;
        ack_err += s.ack_errors;
        cons_err += s.consume_errors;
        bytes += s.bytes;
        e2e.merge(s.e2e);
        cons_lat.merge(s.consume_lat);
        ack_lat.merge(s.ack_lat);
        for (k, v) in s.attempts_hist {
            *attempts.entry(k).or_default() += v;
        }
    }
    let expected_unique = total_produced * cfg.consumers as u64;
    let retried = deliveries.saturating_sub(unique);
    // DLQ verification
    let mut dlq_total = 0u64;
    let mut dlq_list_errors = Vec::new();
    for sub in &ce.subs {
        match rt.list_dlq(&admin, sub).await {
            Ok(l) => dlq_total += l.len() as u64,
            Err(e) => dlq_list_errors.push(e.to_string()),
        }
    }
    let mut final_lag = Vec::new();
    for sub in &ce.subs {
        if let Ok(l) = rt.consumer_lag(sub).await {
            final_lag.push(json!({"lag_events": l.lag_events, "pending": l.pending.is_some(), "dlq": l.dlq_count}));
        }
    }
    let total_wall = base.elapsed().as_secs_f64() - timing.warmup.as_secs_f64();
    let rec = json!({
        "suite": "channel", "system": "avrora_runtime_inproc", "scenario": cfg.name,
        "params": {"producers": cfg.producers, "consumers": cfg.consumers, "size": cfg.size,
                   "target_rate": cfg.rate, "ack_on_attempt": cfg.ack_on_attempt, "never_ack": cfg.never_ack,
                   "ack_batch": cfg.use_ack_batch, "same_path": cfg.same_path, "retry_max_attempts": cfg.retry.max_attempts, "timing": timing.json()},
        "produced_total": total_produced,
        "produce_errors": produce_errors.load(Ordering::Relaxed),
        "produce_msgs_per_s": round2(pm as f64 / measure_s),
        "produce_mb_per_s": round2(pm as f64 * cfg.size as f64 / 1_048_576.0 / measure_s),
        "delivered_msgs_per_s_all_consumers": round2(deliveries as f64 / total_wall.max(1e-9)),
        "delivered_mb_per_s_all_consumers": round2(bytes as f64 / 1_048_576.0 / total_wall.max(1e-9)),
        "ack_per_s": round2(acked as f64 / total_wall.max(1e-9)),
        "backlog_at_producer_stop": backlog_at_stop,
        "drain_s": round2(drain_s),
        "producer_latency": prod_lat.lock().unwrap().stats(),
        "consume_call_latency": cons_lat.stats(),
        "ack_latency": ack_lat.stats(),
        "e2e_latency": e2e.stats(),
        "correctness": {
            "produced": total_produced, "expected_deliveries_unique": expected_unique,
            "received_unique": unique, "deliveries": deliveries, "acked": acked,
            "retried": retried, "dlq": dlq_total, "dlq_list_errors": dlq_list_errors,
            "lost_or_undelivered": expected_unique.saturating_sub(unique),
            "duplicated_non_retry": dups,
            "sequence_order_violations": seqv, "producer_order_violations": pov,
            "ack_errors": ack_err, "consume_errors": cons_err,
            "attempts_histogram": attempts, "final_lag": final_lag,
        },
        "timeline": *timeline.lock().unwrap(),
        "resources": res,
        "ops_per_s": round2(pm as f64 / measure_s),
        "mb_per_s": round2(pm as f64 * cfg.size as f64 / 1_048_576.0 / measure_s),
        "latency": e2e.stats(),
        "errors": produce_errors.load(Ordering::Relaxed) + ack_err,
    });
    sink.emit(rec.clone());
    rec
}

fn base_cfg(name: &str, p: usize, c: usize, size: usize) -> ScenarioCfg {
    ScenarioCfg {
        name: name.into(),
        producers: p,
        consumers: c,
        size,
        rate: None,
        ack_on_attempt: 1,
        never_ack: false,
        use_ack_batch: false,
        drain_timeout: Duration::from_secs(120),
        retry: RetryPolicy::immediate(),
        same_path: false,
    }
}

pub async fn run(sink: &Sink, timing: Timing, size: usize, ramp: bool, only: Option<&str>, drain_timeout: u64) {
    let mut list = vec![
        base_cfg("1P_1C", 1, 1, size),
        base_cfg("10P_1C", 10, 1, size),
        base_cfg("1P_10C", 1, 10, size),
        base_cfg("10P_10C", 10, 10, size),
    ];
    let mut sp = base_cfg("1P_1C_same_path", 1, 1, size);
    sp.same_path = true;
    list.push(sp);
    let mut b = base_cfg("1P_1C_ack_batch", 1, 1, size);
    b.use_ack_batch = true;
    list.push(b);
    let mut r = base_cfg("1P_1C_retry_ack_on_2nd", 1, 1, size);
    r.ack_on_attempt = 2;
    list.push(r);
    let mut d = base_cfg("1P_1C_dlq_max3", 1, 1, size);
    d.never_ack = true;
    d.retry = RetryPolicy {
        max_attempts: 3,
        initial_backoff_ms: 0,
        max_backoff_ms: 0,
        multiplier: 1,
    };
    list.push(d);
    for cfg in list.iter_mut() {
        cfg.drain_timeout = Duration::from_secs(drain_timeout);
    }
    for cfg in &list {
        if only.is_some_and(|o| o != cfg.name) {
            continue;
        }
        run_scenario(sink, timing, cfg).await;
    }
    if only.is_none() || only == Some("backpressure") {
        backpressure_probe(sink).await;
    }
    if ramp {
        rate_ramp(sink, timing, size, 1).await;
        rate_ramp(sink, timing, size, 10).await;
    }
}

/// Open-loop ramp: increase target produce rate until the pipeline can no longer keep up.
pub async fn rate_ramp(sink: &Sink, timing: Timing, size: usize, consumers: usize) {
    let mut best: Option<f64> = None;
    let mut fails = 0;
    for rate in [5.0, 10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 80.0, 100.0, 150.0, 200.0, 300.0, 500.0] {
        let mut cfg = base_cfg(&format!("ramp_1P_{consumers}C_{rate}"), 1, consumers, size);
        cfg.rate = Some(rate);
        cfg.drain_timeout = Duration::from_secs(30);
        let rec = run_scenario(sink, timing, &cfg).await;
        let achieved = rec["produce_msgs_per_s"].as_f64().unwrap_or(0.0);
        let backlog = rec["backlog_at_producer_stop"].as_u64().unwrap_or(u64::MAX) as f64;
        let p99 = rec["e2e_latency"]["p99_us"].as_f64().unwrap_or(f64::MAX);
        let lost = rec["correctness"]["lost_or_undelivered"].as_u64().unwrap_or(1);
        let stable = achieved >= 0.95 * rate
            && backlog <= (rate * consumers as f64).max(consumers as f64 * 2.0)
            && p99 < 1_000_000.0
            && lost == 0;
        sink.emit(json!({"suite": "channel", "system": "avrora_runtime_inproc", "scenario": "ramp_verdict",
            "params": {"consumers": consumers, "size": size, "target_rate": rate},
            "achieved_rate": achieved, "backlog_at_stop": backlog, "e2e_p99_us": p99, "lost_or_undelivered": lost,
            "stable": stable,
            "stability_rule": "achieved >= 95% target AND backlog at producer stop <= 1 s of fan-out traffic AND e2e p99 < 1 s AND 0 undelivered after drain"}));
        if stable {
            best = Some(rate);
            fails = 0;
        } else {
            fails += 1;
            if fails >= 2 {
                break;
            }
        }
    }
    sink.emit(json!({"suite": "channel", "system": "avrora_runtime_inproc", "scenario": "MAX_STABLE",
        "params": {"producers": 1, "consumers": consumers, "size": size},
        "max_stable_msgs_per_s": best, "max_stable_mb_per_s": best.map(|r| round2(r * size as f64 / 1_048_576.0)),
        "max_stable_delivered_msgs_per_s": best.map(|r| r * consumers as f64)}));
}

/// Backpressure / in-flight semantics probe.
async fn backpressure_probe(sink: &Sink) {
    let ce = chan_env(1, RetryPolicy::immediate()).await;
    let rt = &ce.env.rt;
    let sub = &ce.subs[0];
    for i in 0..5u64 {
        rt.put_data(&ce.env.admin, &format!("chan/bp/m{i}"), &make_payload(128, i, 0, i, 0)).await.unwrap();
    }
    rt.set_consumer_policy(&ce.reader, sub, ConsumerPolicy { max_in_flight: 1, max_batch_events: 10, max_batch_bytes: 1 << 20 })
        .await
        .unwrap();
    let first = rt.consume_batch(sub, BatchLimits { max_events: 10, max_bytes: 0 }).await;
    let first_n = first.as_ref().map(|v| v.len()).unwrap_or(0);
    let second = rt.consume_batch(sub, BatchLimits { max_events: 10, max_bytes: 0 }).await;
    let second_desc = match &second {
        Ok(v) => format!("Ok({} events, seq={:?}, attempt={:?})", v.len(), v.first().map(|e| e.sequence), v.first().map(|e| e.delivery.attempt)),
        Err(e) => format!("Err({e})"),
    };
    // consume() twice without ack → redelivery of the same sequence?
    let ce2 = chan_env(1, RetryPolicy::immediate()).await;
    for i in 0..3u64 {
        ce2.env.rt.put_data(&ce2.env.admin, &format!("chan/x/m{i}"), &make_payload(128, i, 0, i, 0)).await.unwrap();
    }
    let a = ce2.env.rt.consume(&ce2.subs[0], 10).await.unwrap();
    let b = ce2.env.rt.consume(&ce2.subs[0], 10).await.unwrap();
    sink.emit(json!({"suite": "channel", "system": "avrora_runtime_inproc", "scenario": "backpressure_inflight_probe",
        "consume_batch_max_events_10_returned": first_n,
        "second_consume_batch_while_pending": second_desc,
        "consume_limit_10_returned": a.len(),
        "consume_again_without_ack": {"same_sequence": a.first().map(|e| e.sequence) == b.first().map(|e| e.sequence),
                                       "attempt": b.first().map(|e| e.delivery.attempt)},
        "producer_side_backpressure": "none in API: put_data never rejects due to consumer lag (see backlog timelines)"}));
}

pub fn rt_of(ce: &ChanEnv) -> &Runtime {
    &ce.env.rt
}
