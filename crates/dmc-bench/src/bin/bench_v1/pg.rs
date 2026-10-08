//! PostgreSQL comparison on the same machine. A dedicated cluster is created with `initdb`
//! in a temp directory (never touches the user's running PostgreSQL) and started on its own
//! port. Client: tokio-postgres over the unix socket (local, no TLS), one connection/worker.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::Rng;
use serde_json::{json, Value};
use tokio_postgres::{Client, NoTls, Statement};

use crate::common::{dataset_rows, dir_size, make_payload, round2, size_label, ResMonitor, Sink, Timing};
use crate::driver::{closed_loop, OpResult};
use crate::storage::{BATCH, CONC, SCENARIOS, WRITE_BUDGET};

pub struct PgInstance {
    pub child: Child,
    pub dir: tempfile::TempDir,
    pub sock: PathBuf,
    pub port: u16,
    pub settings: Value,
}

impl Drop for PgInstance {
    fn drop(&mut self) {
        let _ = Command::new("pg_ctl")
            .args(["stop", "-m", "fast", "-D"])
            .arg(self.dir.path().join("pgdata"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = self.child.wait();
    }
}

pub async fn start_pg(port: u16, wal_sync_method: Option<&str>, max_connections: usize) -> PgInstance {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("pgdata");
    let sock = dir.path().join("sock");
    std::fs::create_dir_all(&sock).unwrap();
    let st = Command::new("initdb")
        .args(["-U", "bench", "--auth=trust", "--encoding=UTF8", "--no-instructions", "-D"])
        .arg(&data)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("initdb");
    assert!(st.success(), "initdb failed");
    let mut cmd = Command::new("postgres");
    cmd.arg("-D")
        .arg(&data)
        .args(["-p", &port.to_string(), "-k"])
        .arg(&sock)
        .args(["-c", "listen_addresses=127.0.0.1"])
        .args(["-c", &format!("max_connections={max_connections}")])
        .args(["-c", "shared_buffers=128MB", "-c", "fsync=on", "-c", "synchronous_commit=on"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(m) = wal_sync_method {
        cmd.args(["-c", &format!("wal_sync_method={m}")]);
    }
    let child = cmd.spawn().expect("postgres");
    for _ in 0..200 {
        if sock.join(format!(".s.PGSQL.{port}")).exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut inst = PgInstance {
        child,
        dir,
        sock,
        port,
        settings: Value::Null,
    };
    let c = pg_connect(&inst).await;
    let mut settings = serde_json::Map::new();
    for k in [
        "server_version",
        "shared_buffers",
        "fsync",
        "synchronous_commit",
        "wal_sync_method",
        "full_page_writes",
        "max_connections",
        "wal_level",
    ] {
        let row = c.query_one(&format!("SHOW {k}"), &[]).await.unwrap();
        settings.insert(k.into(), json!(row.get::<_, String>(0)));
    }
    inst.settings = Value::Object(settings);
    c.batch_execute(
        "CREATE TABLE kv (id BIGINT PRIMARY KEY, payload BYTEA NOT NULL);
         CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT, score BIGINT);",
    )
    .await
    .unwrap();
    inst
}

pub async fn pg_connect(inst: &PgInstance) -> Client {
    let conn_str = format!(
        "host={} port={} user=bench dbname=postgres",
        inst.sock.display(),
        inst.port
    );
    let (client, conn) = tokio_postgres::connect(&conn_str, NoTls).await.expect("pg connect");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    client
}

pub async fn pg_connect_tcp(port: u16) -> Result<Client, String> {
    let conn_str = format!("host=127.0.0.1 port={port} user=bench dbname=postgres connect_timeout=10");
    let (client, conn) = tokio_postgres::connect(&conn_str, NoTls).await.map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(client)
}

struct Worker {
    c: Client,
    ins: Statement,
    upsert: Statement,
    get: Statement,
    get_many: Statement,
}

async fn worker(inst: &PgInstance) -> Worker {
    let c = pg_connect(inst).await;
    let ins = c.prepare("INSERT INTO kv (id, payload) VALUES ($1, $2)").await.unwrap();
    let upsert = c
        .prepare("INSERT INTO kv (id, payload) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload")
        .await
        .unwrap();
    let get = c.prepare("SELECT payload FROM kv WHERE id = $1").await.unwrap();
    let get_many = c.prepare("SELECT payload FROM kv WHERE id = ANY($1)").await.unwrap();
    Worker {
        c,
        ins,
        upsert,
        get,
        get_many,
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    sink: &Sink,
    timing: Timing,
    sizes: &[usize],
    only: Option<&str>,
    port: u16,
    wal_sync_method: Option<String>,
    connections: bool,
    max_conns: usize,
) {
    let system = match wal_sync_method.as_deref() {
        Some(m) => format!("postgres_{m}"),
        None => "postgres_default".to_string(),
    };
    if connections {
        conn_ramp(sink, timing, port, max_conns).await;
        return;
    }
    for &size in sizes {
        let inst = start_pg(port, wal_sync_method.as_deref(), 100).await;
        let pid = inst.child.id() as i32;
        sink.emit(json!({"suite": "pg", "system": system, "scenario": "settings", "params": {"size": size_label(size)}, "settings": inst.settings}));
        let rows = dataset_rows(size);
        // Preload with one autocommit INSERT per row (same as Avrora preload).
        let w0 = worker(&inst).await;
        let mon = ResMonitor::start_tree(pid);
        let t = Instant::now();
        for i in 0..rows {
            let p = make_payload(size, i, 0, i, 0);
            w0.c.execute(&w0.ins, &[&(i as i64), &p]).await.unwrap();
        }
        let el = t.elapsed().as_secs_f64();
        let res = mon.finish();
        sink.emit(json!({"suite": "storage", "system": system, "scenario": "preload_sequential",
            "params": {"size": size_label(size), "rows": rows}, "ops": rows, "duration_s": round2(el),
            "ops_per_s": round2(rows as f64 / el), "mb_per_s": round2((rows as usize * size) as f64 / 1_048_576.0 / el),
            "errors": 0, "resources": res}));
        let mut workers = Vec::new();
        for _ in 0..CONC {
            workers.push(Arc::new(worker(&inst).await));
        }
        let workers = Arc::new(workers);
        let next = Arc::new(AtomicU64::new(10_000_000));
        for sc in SCENARIOS {
            if only.is_some_and(|o| o != sc) {
                continue;
            }
            let n = if sc.starts_with("concurrent") || sc.starts_with("mixed") { CONC } else { 1 };
            let disk_before = dir_size(inst.dir.path());
            let mon = ResMonitor::start_tree(pid);
            let (ws, nx) = (workers.clone(), next.clone());
            let sc_s = sc.to_string();
            let out = closed_loop(n, timing, WRITE_BUDGET, move |w, i| {
                let ws = ws.clone();
                let nx = nx.clone();
                let sc = sc_s.clone();
                async move { pg_op(&ws[w], &sc, size, rows, &nx, i).await }
            })
            .await;
            let res = mon.finish();
            let mut rec = out.json();
            let o = rec.as_object_mut().unwrap();
            o.insert("suite".into(), json!("storage"));
            o.insert("system".into(), json!(system));
            o.insert("scenario".into(), json!(sc));
            o.insert("params".into(), json!({"size": size_label(size), "dataset_rows": rows, "workers": n,
                "batch": if sc.starts_with("batch") { BATCH } else { 1 }, "timing": timing.json()}));
            o.insert("resources".into(), res);
            o.insert("data_dir_growth_mb".into(), json!(round2(dir_size(inst.dir.path()).saturating_sub(disk_before) as f64 / 1_048_576.0)));
            sink.emit(rec);
        }
        // SQL-text comparison (mirrors the SQL Core suite: simple query protocol, literals).
        if size <= 100 * 1024 {
            sql_text(sink, timing, &inst, &system, size).await;
        }
    }
}

async fn pg_op(w: &Worker, sc: &str, size: usize, rows: u64, next: &AtomicU64, i: u64) -> OpResult {
    let (rk, coin) = {
        let mut rng = rand::thread_rng();
        (rng.gen_range(0..rows), rng.gen_range(0..100u32))
    };
    let e = |e: tokio_postgres::Error| e.to_string();
    match sc {
        "write" | "concurrent_write" => {
            let id = next.fetch_add(1, Ordering::Relaxed) as i64;
            let p = make_payload(size, id as u64, 0, i, 0);
            w.c.execute(&w.ins, &[&id, &p]).await.map_err(e)?;
            Ok((1, size as u64))
        }
        "read" => {
            let r = w.c.query_one(&w.get, &[&((i % rows) as i64)]).await.map_err(e)?;
            Ok((1, r.get::<_, &[u8]>(0).len() as u64))
        }
        "random_read" | "concurrent_read" => {
            let r = w.c.query_one(&w.get, &[&(rk as i64)]).await.map_err(e)?;
            Ok((1, r.get::<_, &[u8]>(0).len() as u64))
        }
        "random_rw" | "mixed_80r_20w" => {
            let write_pct = if sc == "random_rw" { 50 } else { 20 };
            if coin < write_pct {
                let p = make_payload(size, rk, 0, i, 0);
                w.c.execute(&w.upsert, &[&(rk as i64), &p]).await.map_err(e)?;
                Ok((1, size as u64))
            } else {
                let r = w.c.query_one(&w.get, &[&(rk as i64)]).await.map_err(e)?;
                Ok((1, r.get::<_, &[u8]>(0).len() as u64))
            }
        }
        "batch_write" => {
            // One multi-row INSERT (single transaction / single commit) of BATCH rows.
            let base = next.fetch_add(BATCH, Ordering::Relaxed) as i64;
            let payloads: Vec<Vec<u8>> = (0..BATCH).map(|j| make_payload(size, base as u64 + j, 0, j, 0)).collect();
            let mut sql = String::from("INSERT INTO kv (id, payload) VALUES ");
            let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
            for j in 0..BATCH as usize {
                if j > 0 {
                    sql.push(',');
                }
                sql.push_str(&format!("(${}, ${})", 2 * j + 1, 2 * j + 2));
                params.push(Box::new(base + j as i64));
                params.push(Box::new(payloads[j].clone()));
            }
            let refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
                params.iter().map(|b| b.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync)).collect();
            w.c.execute(sql.as_str(), &refs).await.map_err(e)?;
            Ok((BATCH, BATCH * size as u64))
        }
        "batch_read" => {
            let ids: Vec<i64> = (0..BATCH).map(|j| ((i * BATCH + j) % rows) as i64).collect();
            let rs = w.c.query(&w.get_many, &[&ids]).await.map_err(e)?;
            let bytes: u64 = rs.iter().map(|r| r.get::<_, &[u8]>(0).len() as u64).sum();
            Ok((rs.len() as u64, bytes))
        }
        other => Err(format!("unknown {other}")),
    }
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

async fn sql_text(sink: &Sink, timing: Timing, inst: &PgInstance, system: &str, size: usize) {
    let pid = inst.child.id() as i32;
    let c = Arc::new(pg_connect(inst).await);
    let rows = 2_000u64;
    for i in 0..rows {
        c.simple_query(&format!("INSERT INTO items (id, name, score) VALUES ({i}, '{}', {i})", text(size, i)))
            .await
            .unwrap();
    }
    let next = Arc::new(AtomicU64::new(1_000_000));
    let batch = ((512 * 1024) / (size + 64)).clamp(1, 100) as u64;
    for sc in ["insert", "select_pk", "batch_insert", "select_scan_limit100"] {
        let mon = ResMonitor::start_tree(pid);
        let (c2, nx) = (c.clone(), next.clone());
        let out = closed_loop(1, timing, 0, move |_w, _i| {
            let c = c2.clone();
            let nx = nx.clone();
            async move {
                let e = |e: tokio_postgres::Error| e.to_string();
                match sc {
                    "insert" => {
                        let id = nx.fetch_add(1, Ordering::Relaxed);
                        c.simple_query(&format!("INSERT INTO items (id, name, score) VALUES ({id}, '{}', {id})", text(size, id)))
                            .await
                            .map_err(e)?;
                        Ok((1, size as u64))
                    }
                    "select_pk" => {
                        let k = rand::thread_rng().gen_range(0..rows);
                        c.simple_query(&format!("SELECT id, name FROM items WHERE id = {k}")).await.map_err(e)?;
                        Ok((1, size as u64))
                    }
                    "batch_insert" => {
                        let base = nx.fetch_add(batch, Ordering::Relaxed);
                        let v: Vec<String> = (0..batch).map(|j| format!("({}, '{}', {})", base + j, text(size, base + j), j)).collect();
                        c.simple_query(&format!("INSERT INTO items (id, name, score) VALUES {}", v.join(", "))).await.map_err(e)?;
                        Ok((batch, batch * size as u64))
                    }
                    _ => {
                        c.simple_query("SELECT id, name FROM items LIMIT 100").await.map_err(e)?;
                        Ok((100, 100 * size as u64))
                    }
                }
            }
        })
        .await;
        let res = mon.finish();
        let mut rec = out.json();
        let o = rec.as_object_mut().unwrap();
        o.insert("suite".into(), json!("sql"));
        o.insert("system".into(), json!(format!("{system}_simple_query")));
        o.insert("scenario".into(), json!(sc));
        o.insert("params".into(), json!({"size": size_label(size), "dataset_rows": rows, "workers": 1,
            "batch": if sc == "batch_insert" { batch } else { 1 }, "timing": timing.json()}));
        o.insert("resources".into(), res);
        sink.emit(rec);
    }
}

/// PostgreSQL connection ramp over TCP (127.0.0.1). Each connection is a backend process.
async fn conn_ramp(sink: &Sink, timing: Timing, port: u16, max_conns: usize) {
    let inst = start_pg(port, None, max_conns + 20).await;
    let pid = inst.child.id() as i32;
    {
        let c = pg_connect(&inst).await;
        let p = make_payload(1024, 1, 0, 0, 0);
        for i in 0..1000i64 {
            c.execute("INSERT INTO kv (id, payload) VALUES ($1, $2)", &[&i, &p]).await.unwrap();
        }
    }
    for n in [10usize, 50, 100, 250, 500, 1000, 2500].into_iter().filter(|n| *n <= max_conns) {
        let r = crate::conn::ramp_step(sink, timing, n, "postgres_default_tcp", pid, true, {
            move || async move {
                let c = pg_connect_tcp(port).await?;
                let st = c.prepare("SELECT payload FROM kv WHERE id = $1").await.map_err(|e| e.to_string())?;
                Ok(Box::new(PgConn { c, st }) as Box<dyn crate::conn::LoadConn>)
            }
        })
        .await;
        if !r {
            break;
        }
    }
}

struct PgConn {
    c: Client,
    st: Statement,
}

impl crate::conn::LoadConn for PgConn {
    fn request<'a>(&'a mut self, i: u64) -> crate::conn::BoxFut<'a, Result<(), String>> {
        Box::pin(async move {
            self.c
                .query_one(&self.st, &[&((i % 1000) as i64)])
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        })
    }
}
