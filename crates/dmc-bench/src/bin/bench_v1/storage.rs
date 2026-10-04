//! Storage benchmark — Avrora encrypted KV through the production runtime API
//! (`Runtime::put_data` / `get_data`): AuthZ + AES-256-GCM + AVJL journal append + fsync.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use dmc_core::runtime::Runtime;
use dmc_core::SessionId;
use rand::Rng;
use serde_json::json;

use crate::common::{dataset_rows, dir_size, make_payload, round2, self_pid, size_label, ResMonitor, Sink, Timing};
use crate::driver::closed_loop;

pub const BATCH: u64 = 100;
pub const CONC: usize = 16;
/// Per-scenario write budget (bytes written during the measurement window).
pub const WRITE_BUDGET: u64 = 512 << 20;

pub struct AvEnv {
    pub dir: tempfile::TempDir,
    pub db: PathBuf,
    pub rt: Runtime,
    pub admin: SessionId,
    pub master_hex: String,
}

pub async fn av_env() -> AvEnv {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("store.dbs.json");
    let rt = Runtime::at_path(&db);
    // create() alone provisions no root identity; devo_init (via create_dev) is the only
    // root-provisioning path. Encryption / journal / AuthZ are identical.
    let (master_hex, _) = rt.create_dev(false).await.expect("create vault");
    let admin = rt.admin_session().await.expect("admin session");
    AvEnv {
        dir,
        db,
        rt,
        admin,
        master_hex,
    }
}

pub fn kv_key(i: u64) -> String {
    format!("bench/kv/k{i}")
}

pub const SCENARIOS: [&str; 9] = [
    "write",
    "read",
    "random_read",
    "random_rw",
    "batch_write",
    "batch_read",
    "concurrent_read",
    "concurrent_write",
    "mixed_80r_20w",
];

pub async fn run(sink: &Sink, timing: Timing, sizes: &[usize], only: Option<&str>) {
    if only.is_none() || only == Some("write_scaling") {
        write_scaling(sink).await;
    }
    if only.is_none() || only == Some("concurrency_ramp") {
        concurrency_ramp(sink, timing).await;
    }
    if only.is_some_and(|o| o == "write_scaling" || o == "concurrency_ramp") {
        return;
    }
    for &size in sizes {
        let env = av_env().await;
        let rows = dataset_rows(size);
        // Preload dataset (also reported as a sequential-load measurement).
        let t = Instant::now();
        let mon = ResMonitor::start(vec![self_pid()]);
        for i in 0..rows {
            let p = make_payload(size, i, 0, i, 0);
            env.rt.put_data(&env.admin, &kv_key(i), &p).await.expect("preload");
        }
        let res = mon.finish();
        let el = t.elapsed().as_secs_f64();
        sink.emit(json!({
            "suite": "storage", "system": "avrora_kv_inproc", "scenario": "preload_sequential",
            "params": {"size": size_label(size), "rows": rows},
            "ops": rows, "duration_s": round2(el),
            "ops_per_s": round2(rows as f64 / el), "mb_per_s": round2((rows as usize * size) as f64 / 1_048_576.0 / el),
            "errors": 0, "resources": res,
        }));
        let rt = env.rt.clone();
        let admin = env.admin.clone();
        for sc in SCENARIOS {
            if only.is_some_and(|o| o != sc) {
                continue;
            }
            let workers = if sc.starts_with("concurrent") || sc.starts_with("mixed") { CONC } else { 1 };
            let disk_before = dir_size(env.dir.path());
            let mon = ResMonitor::start(vec![self_pid()]);
            let (rt2, ad2) = (rt.clone(), admin.clone());
            let sc_name = sc.to_string();
            let out = closed_loop(workers, timing, WRITE_BUDGET, move |w, i| {
                let rt = rt2.clone();
                let admin = ad2.clone();
                let sc = sc_name.clone();
                async move { av_op(&rt, &admin, &sc, size, rows, w, i).await }
            })
            .await;
            let res = mon.finish();
            let mut rec = out.json();
            let o = rec.as_object_mut().unwrap();
            o.insert("suite".into(), json!("storage"));
            o.insert("system".into(), json!("avrora_kv_inproc"));
            o.insert("scenario".into(), json!(sc));
            o.insert(
                "params".into(),
                json!({"size": size_label(size), "dataset_rows": rows, "workers": workers,
                       "batch": if sc.starts_with("batch") { BATCH } else { 1 }, "timing": timing.json()}),
            );
            o.insert("resources".into(), res);
            o.insert(
                "data_dir_growth_mb".into(),
                json!(round2(dir_size(env.dir.path()).saturating_sub(disk_before) as f64 / 1_048_576.0)),
            );
            sink.emit(rec);
        }
        let total = dir_size(env.dir.path());
        sink.emit(json!({"suite": "storage", "system": "avrora_kv_inproc", "scenario": "data_dir_total",
            "params": {"size": size_label(size)}, "data_dir_mb": round2(total as f64 / 1_048_576.0)}));
        drop(env);
    }
}

async fn av_op(
    rt: &Runtime,
    admin: &SessionId,
    sc: &str,
    size: usize,
    rows: u64,
    w: usize,
    i: u64,
) -> crate::driver::OpResult {
    // Draw randomness before any await (ThreadRng is !Send).
    let (rk, coin) = {
        let mut rng = rand::thread_rng();
        (rng.gen_range(0..rows), rng.gen_range(0..100u32))
    };
    let e = |e: dmc_core::Error| e.to_string();
    match sc {
        "write" | "concurrent_write" => {
            let p = make_payload(size, i, w as u32, i, 0);
            rt.put_data(admin, &format!("bench/w/{sc}/w{w}/k{i}"), &p).await.map_err(e)?;
            Ok((1, size as u64))
        }
        "read" => {
            let v = rt.get_data(admin, &kv_key(i % rows)).await.map_err(e)?;
            Ok((1, v.len() as u64))
        }
        "random_read" | "concurrent_read" => {
            let v = rt.get_data(admin, &kv_key(rk)).await.map_err(e)?;
            Ok((1, v.len() as u64))
        }
        "random_rw" | "mixed_80r_20w" => {
            let write_pct = if sc == "random_rw" { 50 } else { 20 };
            let k = rk;
            if coin < write_pct {
                let p = make_payload(size, k, w as u32, i, 0);
                rt.put_data(admin, &kv_key(k), &p).await.map_err(e)?;
                Ok((1, size as u64))
            } else {
                let v = rt.get_data(admin, &kv_key(k)).await.map_err(e)?;
                Ok((1, v.len() as u64))
            }
        }
        "batch_write" => {
            // No native batch-put API exists: a "batch" is BATCH sequential put_data calls.
            for j in 0..BATCH {
                let p = make_payload(size, i * BATCH + j, w as u32, j, 0);
                rt.put_data(admin, &format!("bench/b/k{i}-{j}"), &p).await.map_err(e)?;
            }
            Ok((BATCH, BATCH * size as u64))
        }
        "batch_read" => {
            let mut bytes = 0u64;
            for j in 0..BATCH {
                let v = rt.get_data(admin, &kv_key((i * BATCH + j) % rows)).await.map_err(e)?;
                bytes += v.len() as u64;
            }
            Ok((BATCH, bytes))
        }
        other => Err(format!("unknown scenario {other}")),
    }
}

pub fn shared<T>(v: T) -> Arc<T> {
    Arc::new(v)
}

/// Write throughput as a function of distinct keys already present (1 KiB values).
async fn write_scaling(sink: &Sink) {
    let env = av_env().await;
    let window = 1000u64;
    let started = Instant::now();
    let mut k = 0u64;
    let mut points = Vec::new();
    while started.elapsed().as_secs() < 420 && k < 40_000 {
        let mon = ResMonitor::start(vec![self_pid()]);
        let t = Instant::now();
        for _ in 0..window {
            let p = make_payload(1024, k, 0, k, 0);
            env.rt.put_data(&env.admin, &kv_key(k), &p).await.expect("put");
            k += 1;
        }
        let el = t.elapsed().as_secs_f64();
        let res = mon.finish();
        points.push(json!({"keys_before": k - window, "writes_per_s": round2(window as f64 / el),
            "avg_latency_ms": round2(el * 1000.0 / window as f64), "cpu_pct": res["cpu_pct"],
            "disk_write_mb_s": res["disk_write_mb_s"], "rss_mb": res["peak_rss_mb"]}));
    }
    sink.emit(json!({"suite": "storage", "system": "avrora_kv_inproc", "scenario": "write_scaling_vs_keys",
        "params": {"size": "1KB", "window": window}, "points": points,
        "data_dir_mb": round2(dir_size(env.dir.path()) as f64 / 1_048_576.0)}));
}

/// Concurrency ramp (1 KiB): writers and readers 1..64 against one runtime.
async fn concurrency_ramp(sink: &Sink, timing: Timing) {
    let short = Timing { warmup: timing.warmup.min(std::time::Duration::from_secs(3)), measure: timing.measure.min(std::time::Duration::from_secs(15)) };
    for kind in ["write", "read"] {
        let env = av_env().await;
        let rows = 2000u64;
        for i in 0..rows {
            env.rt.put_data(&env.admin, &kv_key(i), &make_payload(1024, i, 0, i, 0)).await.unwrap();
        }
        for workers in [1usize, 2, 4, 8, 16, 32, 64] {
            let (rt, admin) = (env.rt.clone(), env.admin.clone());
            let mon = ResMonitor::start(vec![self_pid()]);
            let sc = if kind == "write" { "concurrent_write" } else { "concurrent_read" };
            let out = closed_loop(workers, short, WRITE_BUDGET, move |w, i| {
                let (rt, admin) = (rt.clone(), admin.clone());
                async move { av_op(&rt, &admin, sc, 1024, rows, w, i).await }
            })
            .await;
            let mut rec = out.json();
            let o = rec.as_object_mut().unwrap();
            o.insert("suite".into(), json!("stress"));
            o.insert("system".into(), json!("avrora_kv_inproc"));
            o.insert("scenario".into(), json!(format!("concurrency_ramp_{kind}")));
            o.insert("params".into(), json!({"size": "1KB", "workers": workers, "timing": short.json()}));
            o.insert("resources".into(), mon.finish());
            sink.emit(rec);
        }
    }
}
