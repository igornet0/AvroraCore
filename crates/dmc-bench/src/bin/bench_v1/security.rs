//! Security overhead decomposition. Avrora has no "security off" switch, so control
//! baselines are built from the same primitives without the security layer:
//!  * AES-256-GCM (dmc_vault::crypto) cost per payload
//!  * durability: write + F_FULLFSYNC (Rust `sync_all` on macOS) vs libc fsync vs no sync
//!  * transport: identical length-prefixed echo over plain TCP vs TLS 1.3 (rustls/ring)
//!  * end-to-end: Avrora put/get in-process vs over the control plane (TLS 1.3 + mTLS +
//!    control-session check + JSON frames)

use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::Instant;

use avrora_client::transport::ControlClient;
use avrora_proto::{ControlMsg, DataRequest};
use dmc_vault::crypto::{decrypt, encrypt};
use dmc_vault::KeyMaterial;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::common::{make_payload, round2, self_pid, size_label, Lat, ResMonitor, Sink, Timing};
use crate::conn::{opts, spawn_control};
use crate::driver::closed_loop;
use crate::storage::av_env;

const SIZES: [usize; 4] = [100, 1024, 10 * 1024, 100 * 1024];

pub async fn run(sink: &Sink, timing: Timing) {
    aes(sink);
    fsync_variants(sink);
    for &size in &SIZES {
        transport(sink, timing, size, false).await;
        transport(sink, timing, size, true).await;
    }
    handshake(sink).await;
    avrora_local_vs_remote(sink, timing).await;
}

fn emit_micro(sink: &Sink, scenario: &str, size: usize, lat: &Lat, wall: f64, n: u64) {
    sink.emit(json!({"suite": "security", "system": "primitive", "scenario": scenario,
        "params": {"size": size_label(size)}, "ops": n, "duration_s": round2(wall),
        "ops_per_s": round2(n as f64 / wall), "mb_per_s": round2(n as f64 * size as f64 / 1_048_576.0 / wall),
        "latency": lat.stats(), "errors": 0}));
}

fn aes(sink: &Sink) {
    let key = KeyMaterial::random();
    for &size in &[100usize, 1024, 10 * 1024, 100 * 1024, 1 << 20] {
        let p = make_payload(size, 1, 0, 0, 0);
        let n = (200_000_000 / size.max(1000)).clamp(200, 200_000) as u64;
        let (mut le, mut ld) = (Lat::default(), Lat::default());
        let t = Instant::now();
        for _ in 0..n {
            let s = Instant::now();
            let blob = encrypt(&key, &p, b"aad/path").unwrap();
            le.record(s.elapsed());
            let s = Instant::now();
            let out = decrypt(&key, &blob, b"aad/path").unwrap();
            ld.record(s.elapsed());
            assert_eq!(out.len(), size);
        }
        let w = t.elapsed().as_secs_f64();
        emit_micro(sink, "aes256gcm_encrypt", size, &le, w, n);
        emit_micro(sink, "aes256gcm_decrypt", size, &ld, w, n);
    }
}

fn fsync_variants(sink: &Sink) {
    let dir = tempfile::tempdir().unwrap();
    for &size in &[100usize, 1024, 10 * 1024, 100 * 1024, 1 << 20] {
        let p = make_payload(size, 1, 0, 0, 0);
        for mode in ["append_no_sync", "append_fsync_libc", "append_sync_all_F_FULLFSYNC", "append_aes_sync_all"] {
            let path = dir.path().join(format!("{mode}-{size}.log"));
            let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&path).unwrap();
            let key = KeyMaterial::random();
            let n: u64 = if mode == "append_no_sync" { 5_000 } else { 300 };
            let mut lat = Lat::default();
            let t = Instant::now();
            for _ in 0..n {
                let s = Instant::now();
                if mode == "append_aes_sync_all" {
                    let blob = encrypt(&key, &p, b"aad").unwrap();
                    f.write_all(&blob.ciphertext).unwrap();
                } else {
                    f.write_all(&p).unwrap();
                }
                match mode {
                    "append_fsync_libc" => unsafe {
                        libc::fsync(f.as_raw_fd());
                    },
                    "append_sync_all_F_FULLFSYNC" | "append_aes_sync_all" => f.sync_all().unwrap(),
                    _ => {}
                }
                lat.record(s.elapsed());
            }
            emit_micro(sink, mode, size, &lat, t.elapsed().as_secs_f64(), n);
        }
    }
}

// ── transport ──

fn self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>, Vec<u8>) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = ck.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    (vec![cert_der.clone()], key, cert_der.to_vec())
}

async fn read_frame<S: AsyncRead + Unpin>(s: &mut S, buf: &mut Vec<u8>) -> std::io::Result<()> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await?;
    buf.resize(u32::from_be_bytes(len) as usize, 0);
    s.read_exact(buf).await.map(|_| ())
}

async fn write_frame<S: AsyncWrite + Unpin>(s: &mut S, buf: &[u8]) -> std::io::Result<()> {
    s.write_all(&(buf.len() as u32).to_be_bytes()).await?;
    s.write_all(buf).await?;
    s.flush().await
}

async fn echo_loop<S: AsyncRead + AsyncWrite + Unpin>(mut s: S) {
    let mut buf = Vec::new();
    while read_frame(&mut s, &mut buf).await.is_ok() {
        if write_frame(&mut s, &buf).await.is_err() {
            break;
        }
    }
}

fn tls_configs() -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (certs, key, der) = self_signed();
    let srv = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(der)).unwrap();
    let cli = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    (Arc::new(srv), Arc::new(cli))
}

async fn transport(sink: &Sink, timing: Timing, size: usize, tls: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (srv_cfg, cli_cfg) = tls_configs();
    let acceptor = tokio_rustls::TlsAcceptor::from(srv_cfg);
    let server = tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            sock.set_nodelay(true).ok();
            let acc = acceptor.clone();
            tokio::spawn(async move {
                if tls {
                    if let Ok(s) = acc.accept(sock).await {
                        echo_loop(s).await;
                    }
                } else {
                    echo_loop(sock).await;
                }
            });
        }
    });
    let tcp = TcpStream::connect(addr).await.unwrap();
    tcp.set_nodelay(true).ok();
    let mut stream: Box<dyn AsyncRW> = if tls {
        let conn = tokio_rustls::TlsConnector::from(cli_cfg);
        Box::new(conn.connect(ServerName::try_from("localhost").unwrap(), tcp).await.unwrap())
    } else {
        Box::new(tcp)
    };
    let p = make_payload(size, 1, 0, 0, 0);
    let mon = ResMonitor::start(vec![self_pid()]);
    let start = Instant::now();
    let ms = start + timing.warmup;
    let end = ms + timing.measure;
    let mut lat = Lat::default();
    let mut n = 0u64;
    let mut buf = Vec::new();
    while Instant::now() < end {
        let t = Instant::now();
        write_frame(&mut stream, &p).await.unwrap();
        read_frame(&mut stream, &mut buf).await.unwrap();
        if t >= ms {
            lat.record(t.elapsed());
            n += 1;
        }
    }
    let res = mon.finish();
    server.abort();
    let secs = timing.measure.as_secs_f64();
    sink.emit(json!({"suite": "security", "system": if tls { "echo_tls13" } else { "echo_plain_tcp" },
        "scenario": "echo_roundtrip", "params": {"size": size_label(size), "timing": timing.json()},
        "ops": n, "ops_per_s": round2(n as f64 / secs), "mb_per_s": round2(n as f64 * size as f64 * 2.0 / 1_048_576.0 / secs),
        "latency": lat.stats(), "errors": 0,
        "resources": res, "note": "client+server in one process; cpu_pct covers both ends"}));
}

trait AsyncRW: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncRW for T {}

async fn handshake(sink: &Sink) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (srv_cfg, cli_cfg) = tls_configs();
    let acceptor = tokio_rustls::TlsAcceptor::from(srv_cfg);
    let server = tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let acc = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut s) = acc.accept(sock).await {
                    let _ = s.shutdown().await;
                }
            });
        }
    });
    let (mut lt, mut lh) = (Lat::default(), Lat::default());
    let conn = tokio_rustls::TlsConnector::from(cli_cfg);
    for _ in 0..500 {
        let t = Instant::now();
        let tcp = TcpStream::connect(addr).await.unwrap();
        lt.record(t.elapsed());
        let t2 = Instant::now();
        let _s = conn.connect(ServerName::try_from("localhost").unwrap(), tcp).await.unwrap();
        lh.record(t2.elapsed());
    }
    server.abort();
    sink.emit(json!({"suite": "security", "system": "primitive", "scenario": "connect_tcp_only", "latency": lt.stats(), "ops": 500}));
    sink.emit(json!({"suite": "security", "system": "primitive", "scenario": "tls13_handshake_after_tcp", "latency": lh.stats(), "ops": 500}));
}

async fn avrora_local_vs_remote(sink: &Sink, timing: Timing) {
    let srv = spawn_control().await;
    let pid = srv.child.id() as i32;
    let client = ControlClient::connect_config(&opts(srv.port, &srv.home, false)).unwrap();
    for &size in &[100usize, 1024, 10 * 1024, 100 * 1024, 300 * 1024] {
        let p = make_payload(size, 7, 0, 0, 0);
        // Local in-process (fresh vault, same API)
        let env = av_env().await;
        for i in 0..200u64 {
            env.rt.put_data(&env.admin, &format!("sec/k{i}"), &p).await.unwrap();
        }
        for op in ["put", "get"] {
            let (rt, admin, p2) = (env.rt.clone(), env.admin.clone(), p.clone());
            let mon = ResMonitor::start(vec![self_pid()]);
            let out = closed_loop(1, timing, 256 << 20, move |_w, i| {
                let (rt, admin, p) = (rt.clone(), admin.clone(), p2.clone());
                async move {
                    if op == "put" {
                        rt.put_data(&admin, &format!("sec/k{}", i % 200), &p).await.map_err(|e| e.to_string())?;
                    } else {
                        rt.get_data(&admin, &format!("sec/k{}", i % 200)).await.map_err(|e| e.to_string())?;
                    }
                    Ok((1, p.len() as u64))
                }
            })
            .await;
            let mut rec = out.json();
            let o = rec.as_object_mut().unwrap();
            o.insert("suite".into(), json!("security"));
            o.insert("system".into(), json!("avrora_inproc"));
            o.insert("scenario".into(), json!(format!("kv_{op}")));
            o.insert("params".into(), json!({"size": size_label(size), "keys": 200, "timing": timing.json()}));
            o.insert("resources".into(), mon.finish());
            sink.emit(rec);
        }
        drop(env);
        // Remote over control plane (separate server process)
        let mut live = client.open().await.unwrap();
        let mut seed_err = None;
        for i in 0..200u64 {
            let r = live
                .request(ControlMsg::Data {
                    session: srv.session.clone(),
                    runtime_session: srv.runtime_session.clone(),
                    request: DataRequest::PutPath { path: format!("sec/k{i}"), payload: p.clone(), producer_id: None, idempotency_key: None },
                })
                .await;
            match r {
                Ok(ControlMsg::DataOk { .. }) => {}
                Ok(other) => {
                    seed_err = Some(format!("{other:?}").chars().take(200).collect::<String>());
                    break;
                }
                Err(e) => {
                    seed_err = Some(e.to_string());
                    break;
                }
            }
        }
        if let Some(e) = seed_err {
            sink.emit(json!({"suite": "security", "system": "avrora_remote_tls13_mtls", "scenario": "kv_put",
                "params": {"size": size_label(size)}, "errors": 1, "error_samples": [e],
                "note": "payload rejected/failed over control plane (JSON Vec<u8> encoding vs 1 MiB MAX_FRAME)"}));
            continue;
        }
        drop(live);
        for op in ["put", "get"] {
            let live = Arc::new(tokio::sync::Mutex::new(client.open().await.unwrap()));
            let (s, r, p2) = (srv.session.clone(), srv.runtime_session.clone(), p.clone());
            let mon = ResMonitor::start(vec![pid]);
            let cmon = ResMonitor::start(vec![self_pid()]);
            let out = closed_loop(1, timing, 256 << 20, move |_w, i| {
                let (live, s, r, p) = (live.clone(), s.clone(), r.clone(), p2.clone());
                async move {
                    let req = if op == "put" {
                        DataRequest::PutPath { path: format!("sec/k{}", i % 200), payload: p.clone(), producer_id: None, idempotency_key: None }
                    } else {
                        DataRequest::GetPath { path: format!("sec/k{}", i % 200) }
                    };
                    let reply = live
                        .lock()
                        .await
                        .request(ControlMsg::Data { session: s, runtime_session: r, request: req })
                        .await
                        .map_err(|e| e.to_string())?;
                    match reply {
                        ControlMsg::DataOk { .. } => Ok((1, p.len() as u64)),
                        other => Err(format!("{other:?}").chars().take(160).collect()),
                    }
                }
            })
            .await;
            let mut rec = out.json();
            let o = rec.as_object_mut().unwrap();
            o.insert("suite".into(), json!("security"));
            o.insert("system".into(), json!("avrora_remote_tls13_mtls"));
            o.insert("scenario".into(), json!(format!("kv_{op}")));
            o.insert("params".into(), json!({"size": size_label(size), "keys": 200, "timing": timing.json()}));
            o.insert("resources".into(), mon.finish());
            o.insert("client_resources".into(), cmon.finish());
            sink.emit(rec);
        }
    }
}
