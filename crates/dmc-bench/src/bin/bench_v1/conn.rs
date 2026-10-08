//! Connection scalability: the Avrora control plane (TLS 1.3 + mTLS, length-prefixed JSON,
//! `ControlMsg::Data` data plane) running in a SEPARATE process; the load generator opens N
//! persistent mTLS connections and drives closed-loop `GetPath` requests on all of them.

use std::future::Future;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use avrora_client::identity::DeviceIdentity;
use avrora_client::transport::{ConnectOpts, ControlClient, LiveConn};
use avrora_proto::{ControlMsg, DataRequest, DataResponse, DeviceAuthenticator};
use dmc_core::control;
use dmc_core::control::sessions::ControlSessions;
use dmc_core::runtime::Runtime;
use dmc_security::{ui_auth_path, AuthManager, ISSUER, UI_OPERATOR};
use serde_json::json;
use tokio::sync::Semaphore;
use totp_rs::{Builder, Secret};

use crate::common::{make_payload, round2, Lat, ResMonitor, Sink, Timing};

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait LoadConn: Send {
    fn request<'a>(&'a mut self, i: u64) -> BoxFut<'a, Result<(), String>>;
}

// ───────────────────────── server process ─────────────────────────

pub async fn control_server(dir: PathBuf) {
    let db = dir.join("store.dbs.json");
    let control_dir = dir.join("control");
    let init = control::init_control(&control_dir).expect("init control");
    let rt = Runtime::at_path(&db);
    // Root identity is only provisioned by devo_init (see REPORT/BENCHMARK notes).
    let (master, _) = rt.create_dev(false).await.expect("create");
    let auth = AuthManager::open(ui_auth_path(&db));
    let (addr, serve) = control::bind(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        control_dir,
        rt.clone(),
        auth,
        ControlSessions::new(),
    )
    .await
    .expect("bind");
    println!(
        "{}",
        json!({"port": addr.port(), "token": init.token, "master": master, "pid": std::process::id()})
    );
    let _ = serve.await;
}

pub struct ControlProc {
    pub child: Child,
    pub dir: tempfile::TempDir,
    pub port: u16,
    pub home: PathBuf,
    pub session: String,
    pub runtime_session: String,
}

impl Drop for ControlProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn server process, bootstrap a device, enroll UI auth (access key + TOTP), open admin
/// runtime session, and seed 1000 × 1 KiB keys.
pub async fn spawn_control() -> ControlProc {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["control-server", "--dir"])
        .arg(dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn control-server");
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .expect("server ready line");
    let v: serde_json::Value = serde_json::from_str(line.trim()).expect("ready json");
    let port = v["port"].as_u64().unwrap() as u16;
    let token = v["token"].as_str().unwrap().to_string();
    let home = dir.path().join("client");

    let id = DeviceIdentity::init(&home).unwrap();
    let c = ControlClient::connect_config(&opts(port, &home, true)).unwrap();
    let mut live = c.open().await.unwrap();
    let ControlMsg::BootstrapChallenge { nonce_hex } = live
        .request(ControlMsg::BootstrapBegin {
            token,
            device_id: id.device_id().to_string(),
            public_key_hex: id.public_key_hex(),
        })
        .await
        .unwrap()
    else {
        panic!("bootstrap begin")
    };
    let ControlMsg::BootstrapOk {
        client_cert_pem,
        client_key_pem,
        ca_cert_pem,
        server_fingerprint,
        ..
    } = live
        .request(ControlMsg::BootstrapFinish {
            signature_hex: hex::encode(id.sign(&hex::decode(nonce_hex).unwrap())),
        })
        .await
        .unwrap()
    else {
        panic!("bootstrap finish")
    };
    DeviceIdentity::save_bootstrap(
        &home,
        &format!("127.0.0.1:{port}"),
        &server_fingerprint,
        &client_cert_pem,
        &client_key_pem,
        &ca_cert_pem,
    )
    .unwrap();
    let mtls = ControlClient::connect_config(&opts(port, &home, false)).unwrap();
    let mut live = mtls.open().await.unwrap();
    let ControlMsg::AuthSetupBeginOk { totp_secret, .. } = live
        .request(ControlMsg::AuthSetupBegin {
            access_key: "bench-access-key".into(),
        })
        .await
        .unwrap()
    else {
        panic!("auth setup")
    };
    let totp = Builder::new()
        .with_secret(Secret::try_from_base32(&totp_secret).unwrap())
        .with_account_name(UI_OPERATOR)
        .with_issuer(Some(ISSUER))
        .build()
        .unwrap();
    let ControlMsg::AuthOk { token: session, .. } = live
        .request(ControlMsg::AuthSetupConfirm {
            access_key: "bench-access-key".into(),
            totp_code: totp.generate_current().to_string(),
        })
        .await
        .unwrap()
    else {
        panic!("auth confirm")
    };
    let reply = live
        .request(ControlMsg::Data {
            session: session.clone(),
            runtime_session: String::new(),
            request: DataRequest::OpenAdminSession,
        })
        .await
        .unwrap();
    let ControlMsg::DataOk {
        response: DataResponse::Session { runtime_session },
    } = reply
    else {
        panic!("admin session: {reply:?}")
    };
    let p = make_payload(1024, 1, 0, 0, 0);
    for i in 0..1000 {
        let r = live
            .request(ControlMsg::Data {
                session: session.clone(),
                runtime_session: runtime_session.clone(),
                request: DataRequest::PutPath {
                    path: format!("bench/conn/k{i}"),
                    payload: p.clone(),
                    producer_id: None,
                    idempotency_key: None,
                },
            })
            .await
            .unwrap();
        assert!(matches!(r, ControlMsg::DataOk { .. }), "seed put: {r:?}");
    }
    ControlProc {
        child,
        dir,
        port,
        home,
        session,
        runtime_session,
    }
}

pub fn opts(port: u16, home: &Path, tofu: bool) -> ConnectOpts {
    ConnectOpts {
        host: "127.0.0.1".into(),
        port,
        home: home.to_path_buf(),
        tofu,
        expected_fingerprint: None,
    }
}

pub struct AvConn {
    pub live: LiveConn,
    pub session: String,
    pub runtime_session: String,
}

impl LoadConn for AvConn {
    fn request<'a>(&'a mut self, i: u64) -> BoxFut<'a, Result<(), String>> {
        Box::pin(async move {
            let r = self
                .live
                .request(ControlMsg::Data {
                    session: self.session.clone(),
                    runtime_session: self.runtime_session.clone(),
                    request: DataRequest::GetPath {
                        path: format!("bench/conn/k{}", i % 1000),
                    },
                })
                .await
                .map_err(|e| e.to_string())?;
            match r {
                ControlMsg::DataOk { .. } => Ok(()),
                other => Err(format!("{other:?}").chars().take(160).collect()),
            }
        })
    }
}

// ───────────────────────── ramp ─────────────────────────

pub async fn run(sink: &Sink, timing: Timing, steps: &[usize]) {
    let srv = spawn_control().await;
    let pid = srv.child.id() as i32;
    let client = Arc::new(ControlClient::connect_config(&opts(srv.port, &srv.home, false)).unwrap());
    let (session, rs) = (srv.session.clone(), srv.runtime_session.clone());
    let mut unstable_seen = 0;
    for &n in steps {
        let (c, s, r) = (client.clone(), session.clone(), rs.clone());
        let stable = ramp_step(sink, timing, n, "avrora_control_tls13_mtls", pid, false, move || {
            let (c, s, r) = (c.clone(), s.clone(), r.clone());
            async move {
                let live = c.open().await.map_err(|e| e.to_string())?;
                Ok(Box::new(AvConn {
                    live,
                    session: s,
                    runtime_session: r,
                }) as Box<dyn LoadConn>)
            }
        })
        .await;
        if !stable {
            unstable_seen += 1;
            if unstable_seen >= 2 {
                break;
            }
        }
        if !srv_alive(pid) {
            sink.emit(json!({"suite": "connections", "system": "avrora_control_tls13_mtls", "scenario": "server_died", "params": {"after_step": n}}));
            break;
        }
    }
}

fn srv_alive(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

/// One ramp step: open `n` connections (≤256 concurrent handshakes), run closed-loop requests
/// on all of them for warmup+measure, then close. Returns whether the step met the stability
/// criteria: all connections established, error rate < 0.1 %, p99 < 1000 ms.
pub async fn ramp_step<F, Fut>(
    sink: &Sink,
    timing: Timing,
    n: usize,
    system: &str,
    server_pid: i32,
    tree: bool,
    factory: F,
) -> bool
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Box<dyn LoadConn>, String>> + Send + 'static,
{
    let mon = if tree { ResMonitor::start_tree(server_pid) } else { ResMonitor::start(vec![server_pid]) };
    let client_mon = ResMonitor::start(vec![crate::common::self_pid()]);
    let factory = Arc::new(factory);
    let sem = Arc::new(Semaphore::new(256));
    let setup = Arc::new(Mutex::new(Lat::default()));
    let failed = Arc::new(AtomicU64::new(0));
    let fail_samples = Arc::new(Mutex::new(Vec::<String>::new()));
    let t_connect = Instant::now();
    let mut handles = Vec::new();
    for _ in 0..n {
        let (f, sem, setup, failed, fs) = (factory.clone(), sem.clone(), setup.clone(), failed.clone(), fail_samples.clone());
        handles.push(tokio::spawn(async move {
            let _p = sem.acquire().await.unwrap();
            let t = Instant::now();
            match tokio::time::timeout(Duration::from_secs(20), f()).await {
                Ok(Ok(c)) => {
                    setup.lock().unwrap().record(t.elapsed());
                    Some(c)
                }
                Ok(Err(e)) => {
                    failed.fetch_add(1, Ordering::Relaxed);
                    let mut g = fs.lock().unwrap();
                    if g.len() < 3 {
                        g.push(e);
                    }
                    None
                }
                Err(_) => {
                    failed.fetch_add(1, Ordering::Relaxed);
                    let mut g = fs.lock().unwrap();
                    if g.len() < 3 {
                        g.push("connect timeout 20s".into());
                    }
                    None
                }
            }
        }));
    }
    let mut conns = Vec::new();
    for h in handles {
        if let Ok(Some(c)) = h.await {
            conns.push(c);
        }
    }
    let connect_wall = t_connect.elapsed().as_secs_f64();
    let connected = conns.len();

    // Load phase
    let start = Instant::now();
    let measure_start = start + timing.warmup;
    let end = measure_start + timing.measure;
    let ok = Arc::new(AtomicU64::new(0));
    let errs = Arc::new(AtomicU64::new(0));
    let lat = Arc::new(Mutex::new(Lat::default()));
    let err_samples = Arc::new(Mutex::new(Vec::<String>::new()));
    let dead = Arc::new(AtomicBool::new(false));
    let mut tasks = Vec::new();
    for (k, mut c) in conns.into_iter().enumerate() {
        let (ok, errs, lat, es, _dead) = (ok.clone(), errs.clone(), lat.clone(), err_samples.clone(), dead.clone());
        tasks.push(tokio::spawn(async move {
            let mut local = Lat::default();
            let mut i = k as u64;
            while Instant::now() < end {
                let t = Instant::now();
                let r = tokio::time::timeout(Duration::from_secs(10), c.request(i)).await;
                let d = t.elapsed();
                let r = match r {
                    Ok(r) => r,
                    Err(_) => Err("request timeout 10s".into()),
                };
                if t >= measure_start {
                    match r {
                        Ok(()) => {
                            ok.fetch_add(1, Ordering::Relaxed);
                            local.record(d);
                        }
                        Err(e) => {
                            errs.fetch_add(1, Ordering::Relaxed);
                            {
                                let mut g = es.lock().unwrap();
                                if g.len() < 3 {
                                    g.push(e);
                                }
                            }
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                } else if r.is_err() {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                i += 1009;
            }
            lat.lock().unwrap().merge(local);
            drop(c);
        }));
    }
    for t in tasks {
        let _ = t.await;
    }
    let res = mon.finish();
    let cres = client_mon.finish();
    let measured = timing.measure.as_secs_f64();
    let okn = ok.load(Ordering::Relaxed);
    let errn = errs.load(Ordering::Relaxed);
    let stats = lat.lock().unwrap().stats();
    let p99 = stats.get("p99_us").and_then(|v| v.as_f64()).unwrap_or(f64::MAX);
    let err_rate = errn as f64 / (okn + errn).max(1) as f64;
    let stable = connected == n && err_rate < 0.001 && p99 < 1_000_000.0 && okn > 0;
    sink.emit(json!({
        "suite": "connections", "system": system, "scenario": "ramp_step",
        "params": {"connections": n, "timing": timing.json(), "max_concurrent_handshakes": 256},
        "connected": connected, "failed_connections": failed.load(Ordering::Relaxed),
        "connect_failure_samples": *fail_samples.lock().unwrap(),
        "connect_phase_s": round2(connect_wall),
        "connection_setup_latency": setup.lock().unwrap().stats(),
        "ops": okn, "errors": errn, "errors_per_s": round2(errn as f64 / measured),
        "error_samples": *err_samples.lock().unwrap(),
        "ops_per_s": round2(okn as f64 / measured), "duration_s": measured,
        "latency": stats, "resources": res, "client_resources": cres,
        "stable": stable,
        "stability_rule": "all connections established AND error rate < 0.1% AND p99 < 1000 ms",
    }));
    // Let client-side TIME_WAIT sockets expire (macOS MSL 15 s) before the next large step.
    if n >= 1000 {
        tokio::time::sleep(Duration::from_secs(32)).await;
    } else {
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    stable
}
