//! Closed-loop load drivers: N workers issue the next operation as soon as the previous
//! one completes. Latency is recorded only inside the measurement window (after warmup).

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::common::{round2, Lat, Timing};

pub struct RunOut {
    pub lat: Lat,
    pub ops: u64,
    pub records: u64,
    pub bytes: u64,
    pub errors: u64,
    pub err_samples: Vec<String>,
    pub elapsed_s: f64,
    pub stopped_by_budget: bool,
}

impl RunOut {
    pub fn json(&self) -> Value {
        json!({
            "ops": self.ops,
            "records": self.records,
            "duration_s": round2(self.elapsed_s),
            "ops_per_s": round2(self.records as f64 / self.elapsed_s.max(1e-9)),
            "batches_per_s": round2(self.ops as f64 / self.elapsed_s.max(1e-9)),
            "mb_per_s": round2(self.bytes as f64 / 1_048_576.0 / self.elapsed_s.max(1e-9)),
            "errors": self.errors,
            "error_rate": round2(self.errors as f64 / (self.ops + self.errors).max(1) as f64 * 100.0),
            "error_samples": self.err_samples,
            "stopped_by_byte_budget": self.stopped_by_budget,
            "latency": self.lat.stats(),
        })
    }
}

/// Outcome of one operation: (records, payload bytes).
pub type OpResult = Result<(u64, u64), String>;

struct Shared {
    lat: Mutex<Lat>,
    ops: AtomicU64,
    records: AtomicU64,
    bytes: AtomicU64,
    errors: AtomicU64,
    samples: Mutex<Vec<String>>,
    stop: AtomicBool,
    budget_hit: AtomicBool,
    stop_at: Mutex<Option<Instant>>,
}

impl Shared {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            lat: Mutex::new(Lat::default()),
            ops: AtomicU64::new(0),
            records: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            samples: Mutex::new(Vec::new()),
            stop: AtomicBool::new(false),
            budget_hit: AtomicBool::new(false),
            stop_at: Mutex::new(None),
        })
    }

    fn account(&self, r: OpResult, budget: u64) {
        match r {
            Ok((records, bytes)) => {
                self.ops.fetch_add(1, Ordering::Relaxed);
                self.records.fetch_add(records, Ordering::Relaxed);
                let total = self.bytes.fetch_add(bytes, Ordering::Relaxed) + bytes;
                if budget > 0 && total >= budget && !self.stop.swap(true, Ordering::SeqCst) {
                    self.budget_hit.store(true, Ordering::SeqCst);
                    *self.stop_at.lock().unwrap() = Some(Instant::now());
                }
            }
            Err(e) => {
                self.errors.fetch_add(1, Ordering::Relaxed);
                let mut s = self.samples.lock().unwrap();
                if s.len() < 5 {
                    s.push(e);
                }
            }
        }
    }

    fn finish(&self, measure_start: Instant, end: Instant) -> RunOut {
        let stop_at = self.stop_at.lock().unwrap().unwrap_or(end).min(end);
        RunOut {
            lat: std::mem::take(&mut *self.lat.lock().unwrap()),
            ops: self.ops.load(Ordering::Relaxed),
            records: self.records.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            err_samples: self.samples.lock().unwrap().clone(),
            elapsed_s: stop_at.saturating_duration_since(measure_start).as_secs_f64(),
            stopped_by_budget: self.budget_hit.load(Ordering::Relaxed),
        }
    }
}

/// Async closed loop. `f(worker, iteration)` performs one operation.
pub async fn closed_loop<F, Fut>(workers: usize, timing: Timing, byte_budget: u64, f: F) -> RunOut
where
    F: Fn(usize, u64) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = OpResult> + Send + 'static,
{
    let f = Arc::new(f);
    let shared = Shared::new();
    let start = Instant::now();
    let measure_start = start + timing.warmup;
    let end = measure_start + timing.measure;
    let mut handles = Vec::new();
    for w in 0..workers {
        let f = f.clone();
        let sh = shared.clone();
        handles.push(tokio::spawn(async move {
            let mut local = Lat::with_capacity(4096);
            let mut i = 0u64;
            loop {
                let now = Instant::now();
                if now >= end || sh.stop.load(Ordering::Relaxed) {
                    break;
                }
                let t = Instant::now();
                let r = f(w, i).await;
                let d = t.elapsed();
                if t >= measure_start {
                    if r.is_ok() {
                        local.record(d);
                    }
                    sh.account(r, byte_budget);
                }
                i += 1;
            }
            sh.lat.lock().unwrap().merge(local);
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    shared.finish(measure_start, end)
}

/// Thread-based closed loop for blocking clients. `factory(worker)` builds a per-worker op.
pub fn closed_loop_threads<M>(workers: usize, timing: Timing, byte_budget: u64, factory: M) -> RunOut
where
    M: Fn(usize) -> Box<dyn FnMut(u64) -> OpResult + Send> + Send + Sync + 'static,
{
    let factory = Arc::new(factory);
    let shared = Shared::new();
    let start = Instant::now();
    let measure_start = start + timing.warmup;
    let end = measure_start + timing.measure;
    let mut handles = Vec::new();
    for w in 0..workers {
        let factory = factory.clone();
        let sh = shared.clone();
        handles.push(std::thread::spawn(move || {
            let mut op = factory(w);
            let mut local = Lat::with_capacity(4096);
            let mut i = 0u64;
            loop {
                if Instant::now() >= end || sh.stop.load(Ordering::Relaxed) {
                    break;
                }
                let t = Instant::now();
                let r = op(i);
                let d = t.elapsed();
                if t >= measure_start {
                    if r.is_ok() {
                        local.record(d);
                    }
                    sh.account(r, byte_budget);
                }
                i += 1;
            }
            sh.lat.lock().unwrap().merge(local);
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    shared.finish(measure_start, end)
}

pub fn secs(s: f64) -> Duration {
    Duration::from_secs_f64(s)
}
