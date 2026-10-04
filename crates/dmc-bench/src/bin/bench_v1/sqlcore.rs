//! SQL Core benchmark over local IPC (unix socket) against a separate `dmc serve --dev`
//! process (release build). Client: `dmc-client` SDK. Auth: dev identity `analyst/pw`
//! (the only identity that exists — see REPORT_V1 S-9). Table: `items` (grants: INSERT/SELECT).

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use dmc_client::{Client, ConnectionTarget, MockKeyPassProvider, UnlockMaterial};
use rand::Rng;
use serde_json::json;

use crate::common::{dir_size, round2, size_label, ResMonitor, Sink, Timing};
use crate::driver::{closed_loop_threads, OpResult};

/// Reconnect before the server-side 10 000 requests/connection limit (exceeding it stops
/// the whole IPC listener — REPORT_V1 S-7; verified separately by `request_limit_probe`).
const RECONNECT_EVERY: u64 = 5_000;

pub struct DmcServer {
    pub child: Child,
    pub dir: tempfile::TempDir,
    pub socket: PathBuf,
    pub master: UnlockMaterial,
}

impl Drop for DmcServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn dmc_bin() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    exe.parent().unwrap().join("dmc")
}

pub fn spawn_dmc() -> DmcServer {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    let socket = dir.path().join("s.sock");
    let child = Command::new(dmc_bin())
        .args(["serve", "--dev", "--data-dir"])
        .arg(&data)
        .arg("--socket")
        .arg(&socket)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dmc serve (build: cargo build --release -p dmc-cli --bin dmc)");
    for _ in 0..100 {
        if socket.exists() && data.join(".dmc-dev-master.hex").exists() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let master = load_master(&data.join(".dmc-dev-master.hex"));
    let srv = DmcServer {
        child,
        dir,
        socket,
        master,
    };
    let mut c = connect(&srv);
    c.control()
        .vault_unlock(&MockKeyPassProvider::with_material(srv.master.clone()))
        .expect("unlock");
    c.sql()
        .execute("CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT, score BIGINT)")
        .expect("create items");
    drop(c);
    srv
}

fn load_master(p: &Path) -> UnlockMaterial {
    let raw = std::fs::read_to_string(p).expect("master file");
    let b = hex::decode(raw.trim()).unwrap();
    let mut m = [0u8; 32];
    m.copy_from_slice(&b);
    UnlockMaterial(m)
}

pub fn connect(srv: &DmcServer) -> Client {
    let mut c = Client::with_client_id(
        ConnectionTarget::Local {
            socket: srv.socket.clone(),
        },
        "bench-v1",
    );
    c.connect().expect("connect");
    c.control().authenticate("analyst", "pw").expect("auth");
    c
}

fn text(size: usize, seed: u64) -> String {
    let mut s = String::with_capacity(size);
    let mut x = seed | 1;
    while s.len() < size {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s.push((b'a' + (x % 26) as u8) as char);
    }
    s
}

fn batch_for(size: usize) -> u64 {
    // Whole statement must fit the 1 MiB SQL/frame limit.
    ((512 * 1024) / (size + 64)).clamp(1, 100) as u64
}

pub fn run(sink: &Sink, timing: Timing, sizes: &[usize], only: Option<&str>) {
    request_limit_probe(sink);
    persistent_concurrency_probe(sink);
    for &size in sizes {
        let srv = Arc::new(spawn_dmc());
        let pid = srv.child.id() as i32;
        // state_events.json is rewritten in full per commit: cap row data at 16 MiB to bound
        // total disk writes (otherwise O(rows^2) bytes, tens of GB for 100 KiB rows).
        let rows: u64 = ((16usize << 20) / size).clamp(50, 2_000) as u64;
        // Preload
        let t = Instant::now();
        let mut c = connect(&srv);
        let mut errors = 0;
        let mut first_err = None;
        for i in 0..rows {
            if i > 0 && i % RECONNECT_EVERY == 0 {
                c = connect(&srv);
            }
            let sql = format!("INSERT INTO items (id, name, score) VALUES ({i}, '{}', {i})", text(size, i));
            if let Err(e) = c.sql().execute(&sql) {
                errors += 1;
                first_err.get_or_insert(e.to_string());
                if errors > 20 {
                    break;
                }
            }
        }
        drop(c);
        let el = t.elapsed().as_secs_f64();
        sink.emit(json!({"suite": "sql", "system": "avrora_sqlcore_ipc", "scenario": "preload_insert",
            "params": {"size": size_label(size), "rows": rows}, "ops": rows - errors as u64, "duration_s": round2(el),
            "ops_per_s": round2((rows - errors as u64) as f64 / el), "errors": errors, "error_samples": first_err,
            "data_dir_mb": round2(dir_size(srv.dir.path()) as f64 / 1_048_576.0)}));
        if errors > 20 {
            sink.emit(json!({"suite": "sql", "system": "avrora_sqlcore_ipc", "scenario": "size_unsupported",
                "params": {"size": size_label(size)}, "note": "preload failed; remaining SQL scenarios skipped for this size"}));
            continue;
        }
        let next_id = Arc::new(AtomicU64::new(1_000_000));
        let scenarios: [(&str, usize); 6] = [
            ("insert", 1),
            ("select_pk", 1),
            ("batch_insert", 1),
            ("select_scan_limit100", 1),
            ("concurrent_insert_conn_per_op", 4),
            ("concurrent_select_conn_per_op", 4),
        ];
        for (sc, workers) in scenarios {
            if only.is_some_and(|o| o != sc) {
                continue;
            }
            let mon = ResMonitor::start(vec![pid]);
            let (srv2, ids) = (srv.clone(), next_id.clone());
            let sc_s = sc.to_string();
            let out = closed_loop_threads(workers, timing, 0, move |_w| {
                let srv = srv2.clone();
                let ids = ids.clone();
                let sc = sc_s.clone();
                let mut client: Option<Client> = None;
                let mut n = 0u64;
                Box::new(move |_i| -> OpResult {
                    let per_op = sc.contains("conn_per_op");
                    if per_op || client.is_none() || n % RECONNECT_EVERY == 0 {
                        client = Some(connect(&srv));
                    }
                    n += 1;
                    let c = client.as_mut().unwrap();
                    let r = sql_op(c, &sc, size, rows, &ids);
                    if per_op {
                        client = None;
                    }
                    r
                })
            });
            let res = mon.finish();
            let mut rec = out.json();
            let o = rec.as_object_mut().unwrap();
            o.insert("suite".into(), json!("sql"));
            o.insert("system".into(), json!("avrora_sqlcore_ipc"));
            o.insert("scenario".into(), json!(sc));
            o.insert("params".into(), json!({"size": size_label(size), "dataset_rows": rows, "workers": workers,
                "batch": if sc == "batch_insert" { batch_for(size) } else { 1 }, "timing": timing.json()}));
            o.insert("resources".into(), res);
            o.insert("server_data_dir_mb".into(), json!(round2(dir_size(srv.dir.path()) as f64 / 1_048_576.0)));
            sink.emit(rec);
        }
    }
    insert_degradation(sink);
}

fn sql_op(c: &mut Client, sc: &str, size: usize, rows: u64, ids: &AtomicU64) -> OpResult {
    let e = |e: dmc_client::ClientError| e.to_string();
    match sc {
        "insert" | "concurrent_insert_conn_per_op" => {
            let id = ids.fetch_add(1, Ordering::Relaxed);
            let sql = format!("INSERT INTO items (id, name, score) VALUES ({id}, '{}', {id})", text(size, id));
            c.sql().execute(&sql).map_err(e)?;
            Ok((1, size as u64))
        }
        "select_pk" | "concurrent_select_conn_per_op" => {
            let k = rand::thread_rng().gen_range(0..rows);
            let r = c.sql().query(&format!("SELECT id, name FROM items WHERE id = {k}")).map_err(e)?;
            if r.rows.len() != 1 {
                return Err(format!("expected 1 row for id {k}, got {}", r.rows.len()));
            }
            Ok((1, size as u64))
        }
        "select_scan_limit100" => {
            let r = c.sql().query("SELECT id, name FROM items LIMIT 100").map_err(e)?;
            Ok((r.rows.len() as u64, r.rows.len() as u64 * size as u64))
        }
        "batch_insert" => {
            let b = batch_for(size);
            let base = ids.fetch_add(b, Ordering::Relaxed);
            let values: Vec<String> = (0..b)
                .map(|j| format!("({}, '{}', {})", base + j, text(size, base + j), j))
                .collect();
            let sql = format!("INSERT INTO items (id, name, score) VALUES {}", values.join(", "));
            c.sql().execute(&sql).map_err(e)?;
            Ok((b, b * size as u64))
        }
        other => Err(format!("unknown {other}")),
    }
}

/// Insert throughput as a function of rows already in the table (state_events.json is
/// rewritten in full on every commit — REPORT_V1 §3.1).
fn insert_degradation(sink: &Sink) {
    let srv = spawn_dmc();
    let pid = srv.child.id() as i32;
    let mut c = connect(&srv);
    let window = 500u64;
    let started = Instant::now();
    let mut id = 0u64;
    let mut points = Vec::new();
    while started.elapsed() < Duration::from_secs(240) && id < 20_000 {
        let mon = ResMonitor::start(vec![pid]);
        let t = Instant::now();
        for _ in 0..window {
            if id % RECONNECT_EVERY == 0 && id > 0 {
                c = connect(&srv);
            }
            let sql = format!("INSERT INTO items (id, name, score) VALUES ({id}, '{}', {id})", text(1024, id));
            c.sql().execute(&sql).expect("insert");
            id += 1;
        }
        let el = t.elapsed().as_secs_f64();
        let res = mon.finish();
        points.push(json!({"rows_before": id - window, "inserts_per_s": round2(window as f64 / el),
            "avg_latency_ms": round2(el / window as f64 * 1000.0), "server_cpu_pct": res["cpu_pct"],
            "disk_write_mb_s": res["disk_write_mb_s"],
            "state_events_mb": round2(std::fs::metadata(srv.dir.path().join("data/state_events.json")).map(|m| m.len()).unwrap_or(0) as f64 / 1_048_576.0)}));
    }
    sink.emit(json!({"suite": "sql", "system": "avrora_sqlcore_ipc", "scenario": "insert_degradation_1KB",
        "params": {"size": "1KB", "window": window}, "points": points}));
}

/// Verifies whether exceeding max_requests_per_connection stops the IPC listener.
fn request_limit_probe(sink: &Sink) {
    let srv = spawn_dmc();
    let mut c = connect(&srv);
    let mut served = 0u64;
    let mut first_err = None;
    for i in 0..10_050u64 {
        match c.sql().query("SELECT id FROM items LIMIT 1") {
            Ok(_) => served += 1,
            Err(e) => {
                first_err = Some(format!("at request {i}: {e}"));
                break;
            }
        }
    }
    drop(c);
    // After the limit: can a NEW client still connect and query?
    let (tx, rx) = std::sync::mpsc::channel();
    let sock = srv.socket.clone();
    thread::spawn(move || {
        let mut c = Client::with_client_id(ConnectionTarget::Local { socket: sock }, "probe");
        let r = c
            .connect()
            .and_then(|_| c.control().authenticate("analyst", "pw").map(|_| ()))
            .and_then(|_| c.sql().query("SELECT id FROM items LIMIT 1").map(|_| ()));
        let _ = tx.send(r.map_err(|e| e.to_string()));
    });
    let after = match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(())) => "new client served".to_string(),
        Ok(Err(e)) => format!("new client failed: {e}"),
        Err(_) => "new client timed out (10s)".to_string(),
    };
    let alive = matches!(srv_child_alive(&srv), true);
    sink.emit(json!({"suite": "sql", "system": "avrora_sqlcore_ipc", "scenario": "request_limit_probe",
        "requests_served_on_one_connection": served, "first_error": first_err,
        "after_limit": after, "server_process_alive": alive}));
}

fn srv_child_alive(srv: &DmcServer) -> bool {
    unsafe { libc::kill(srv.child.id() as i32, 0) == 0 }
}

/// 4 clients with persistent connections for 15 s: how many make progress concurrently?
fn persistent_concurrency_probe(sink: &Sink) {
    let srv = spawn_dmc();
    let counters: Vec<Arc<AtomicU64>> = (0..4).map(|_| Arc::new(AtomicU64::new(0))).collect();
    let deadline = Instant::now() + Duration::from_secs(15);
    for ctr in &counters {
        let ctr = ctr.clone();
        let sock = srv.socket.clone();
        thread::spawn(move || {
            let mut c = Client::with_client_id(ConnectionTarget::Local { socket: sock }, "probe");
            if c.connect().is_err() || c.control().authenticate("analyst", "pw").is_err() {
                return;
            }
            while Instant::now() < deadline {
                // Stay below the 10k request limit; keep the connection open (idle) afterwards.
                if ctr.load(Ordering::Relaxed) >= 4_000 {
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
                if c.sql().query("SELECT id FROM items LIMIT 1").is_err() {
                    return;
                }
                ctr.fetch_add(1, Ordering::Relaxed);
            }
        });
    }
    thread::sleep(Duration::from_secs(17));
    let per_client: Vec<u64> = counters.iter().map(|c| c.load(Ordering::Relaxed)).collect();
    let progressing = per_client.iter().filter(|x| **x > 0).count();
    sink.emit(json!({"suite": "sql", "system": "avrora_sqlcore_ipc", "scenario": "persistent_concurrency_probe",
        "clients": 4, "duration_s": 15, "requests_per_client": per_client, "clients_making_progress": progressing}));
    drop(srv); // kills server → unblocks waiting clients
}
