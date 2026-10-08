//! Shared measurement primitives for Benchmark V1.
//!
//! * latency recorder (exact percentiles over all recorded samples)
//! * per-process resource sampling via macOS `proc_pid_rusage` (CPU, RSS, disk bytes)
//! * JSONL / CSV result sink and environment capture

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

// ───────────────────────── latency ─────────────────────────

#[derive(Default, Clone)]
pub struct Lat {
    ns: Vec<u64>,
}

impl Lat {
    pub fn with_capacity(n: usize) -> Self {
        Self {
            ns: Vec::with_capacity(n),
        }
    }
    pub fn record(&mut self, d: Duration) {
        self.ns.push(d.as_nanos() as u64);
    }
    pub fn record_ns(&mut self, ns: u64) {
        self.ns.push(ns);
    }
    pub fn merge(&mut self, other: Lat) {
        self.ns.extend(other.ns);
    }
    pub fn len(&self) -> usize {
        self.ns.len()
    }
    pub fn stats(&self) -> Value {
        if self.ns.is_empty() {
            return json!({"count": 0});
        }
        let mut v = self.ns.clone();
        v.sort_unstable();
        let pct = |p: f64| -> f64 {
            let idx = ((p / 100.0) * (v.len() as f64 - 1.0)).round() as usize;
            v[idx.min(v.len() - 1)] as f64 / 1000.0
        };
        let mean = v.iter().map(|x| *x as f64).sum::<f64>() / v.len() as f64 / 1000.0;
        json!({
            "count": v.len(),
            "mean_us": round2(mean),
            "p50_us": round2(pct(50.0)),
            "p95_us": round2(pct(95.0)),
            "p99_us": round2(pct(99.0)),
            "p999_us": round2(pct(99.9)),
            "max_us": round2(*v.last().unwrap() as f64 / 1000.0),
        })
    }
}

pub fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

// ───────────────────────── process resources ─────────────────────────

#[derive(Clone, Copy, Debug, Default)]
pub struct ProcUsage {
    pub cpu_ns: u64,
    pub rss: u64,
    pub footprint: u64,
    pub disk_read: u64,
    pub disk_write: u64,
}

fn timebase() -> (u32, u32) {
    let mut tb = libc::mach_timebase_info { numer: 0, denom: 0 };
    unsafe {
        libc::mach_timebase_info(&mut tb);
    }
    (tb.numer, tb.denom)
}

pub fn proc_usage(pid: i32) -> Option<ProcUsage> {
    let mut info: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::proc_pid_rusage(
            pid,
            libc::RUSAGE_INFO_V2,
            &mut info as *mut libc::rusage_info_v2 as *mut libc::rusage_info_t,
        )
    };
    if rc != 0 {
        return None;
    }
    let (n, d) = timebase();
    let ticks = info.ri_user_time + info.ri_system_time;
    Some(ProcUsage {
        cpu_ns: (ticks as u128 * n as u128 / d.max(1) as u128) as u64,
        rss: info.ri_resident_size,
        footprint: info.ri_phys_footprint,
        disk_read: info.ri_diskio_bytesread,
        disk_write: info.ri_diskio_byteswritten,
    })
}

/// All descendants of `root` (inclusive) — used for PostgreSQL backends.
pub fn process_tree(root: i32) -> Vec<i32> {
    let out = Command::new("ps").args(["-A", "-o", "pid=,ppid="]).output();
    let Ok(out) = out else { return vec![root] };
    let text = String::from_utf8_lossy(&out.stdout);
    let pairs: Vec<(i32, i32)> = text
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
        })
        .collect();
    let mut res = vec![root];
    let mut i = 0;
    while i < res.len() {
        let p = res[i];
        for (pid, ppid) in &pairs {
            if *ppid == p && !res.contains(pid) {
                res.push(*pid);
            }
        }
        i += 1;
    }
    res
}

/// Samples a fixed set of pids (or a dynamic process tree) every 200 ms.
pub struct ResMonitor {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    start: Instant,
    start_usage: Vec<(i32, ProcUsage)>,
    peak_rss: Arc<Mutex<u64>>,
    peak_footprint: Arc<Mutex<u64>>,
    /// Tree mode: pid -> (cpu at first sight, cpu at last sight); pids born after start count from 0.
    tree_cpu: Arc<Mutex<HashMap<i32, (u64, u64, u64, u64)>>>,
    tree_root: Option<i32>,
    pids: Vec<i32>,
}

impl ResMonitor {
    pub fn start(pids: Vec<i32>) -> Self {
        Self::start_inner(pids, None)
    }

    pub fn start_tree(root: i32) -> Self {
        Self::start_inner(process_tree(root), Some(root))
    }

    fn start_inner(pids: Vec<i32>, tree_root: Option<i32>) -> Self {
        let start_usage: Vec<(i32, ProcUsage)> = pids
            .iter()
            .filter_map(|p| proc_usage(*p).map(|u| (*p, u)))
            .collect();
        let stop = Arc::new(AtomicBool::new(false));
        let peak_rss = Arc::new(Mutex::new(0u64));
        let peak_fp = Arc::new(Mutex::new(0u64));
        let tree_cpu: Arc<Mutex<HashMap<i32, (u64, u64, u64, u64)>>> = Arc::new(Mutex::new(
            start_usage.iter().map(|(p, u)| (*p, (u.cpu_ns, u.cpu_ns, u.disk_write, u.disk_write))).collect(),
        ));
        let (s2, r2, f2, p2) = (stop.clone(), peak_rss.clone(), peak_fp.clone(), pids.clone());
        let tc2 = tree_cpu.clone();
        let handle = thread::spawn(move || {
            while !s2.load(Ordering::Relaxed) {
                let pids = match tree_root {
                    Some(root) => process_tree(root),
                    None => p2.clone(),
                };
                let (mut rss, mut fp) = (0u64, 0u64);
                for p in &pids {
                    if let Some(u) = proc_usage(*p) {
                        rss += u.rss;
                        fp += u.footprint;
                        if tree_root.is_some() {
                            let mut g = tc2.lock().unwrap();
                            let e = g.entry(*p).or_insert((0, 0, 0, 0));
                            e.1 = u.cpu_ns;
                            e.3 = u.disk_write;
                        }
                    }
                }
                {
                    let mut g = r2.lock().unwrap();
                    *g = (*g).max(rss);
                }
                {
                    let mut g = f2.lock().unwrap();
                    *g = (*g).max(fp);
                }
                thread::sleep(Duration::from_millis(200));
            }
        });
        Self {
            stop,
            handle: Some(handle),
            start: Instant::now(),
            start_usage,
            peak_rss,
            peak_footprint: peak_fp,
            tree_cpu,
            tree_root,
            pids,
        }
    }

    pub fn finish(mut self) -> Value {
        let wall = self.start.elapsed().as_secs_f64();
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        let pids = match self.tree_root {
            Some(root) => process_tree(root),
            None => self.pids.clone(),
        };
        let (mut cpu, mut dr, mut dw) = (0u64, 0u64, 0u64);
        if self.tree_root.is_some() {
            // Include processes that exited before finish (e.g. closed PG backends).
            for p in &pids {
                if let Some(u) = proc_usage(*p) {
                    let mut g = self.tree_cpu.lock().unwrap();
                    let e = g.entry(*p).or_insert((0, 0, 0, 0));
                    e.1 = u.cpu_ns;
                    e.3 = u.disk_write;
                }
            }
            for (first, last, wfirst, wlast) in self.tree_cpu.lock().unwrap().values() {
                cpu += last.saturating_sub(*first);
                dw += wlast.saturating_sub(*wfirst);
            }
        }
        for p in pids.iter().filter(|_| self.tree_root.is_none()) {
            let Some(end) = proc_usage(*p) else { continue };
            let base = self
                .start_usage
                .iter()
                .find(|(pid, _)| pid == p)
                .map(|(_, u)| *u)
                .unwrap_or_default();
            cpu += end.cpu_ns.saturating_sub(base.cpu_ns);
            dr += end.disk_read.saturating_sub(base.disk_read);
            dw += end.disk_write.saturating_sub(base.disk_write);
        }
        let mb = |b: u64| round2(b as f64 / 1_048_576.0);
        json!({
            "wall_s": round2(wall),
            "processes": pids.len(),
            "cpu_pct": round2(cpu as f64 / 1e9 / wall.max(1e-9) * 100.0),
            "cpu_s": round2(cpu as f64 / 1e9),
            "peak_rss_mb": mb(*self.peak_rss.lock().unwrap()),
            "peak_footprint_mb": mb(*self.peak_footprint.lock().unwrap()),
            "disk_read_mb": mb(dr),
            "disk_write_mb": mb(dw),
            "disk_write_mb_s": round2(dw as f64 / 1_048_576.0 / wall.max(1e-9)),
        })
    }
}

pub fn self_pid() -> i32 {
    std::process::id() as i32
}

pub fn raise_nofile() -> u64 {
    unsafe {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl);
        let target = 61_440u64.min(rl.rlim_max as u64);
        rl.rlim_cur = target as libc::rlim_t;
        libc::setrlimit(libc::RLIMIT_NOFILE, &rl);
        libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl);
        rl.rlim_cur as u64
    }
}

pub fn dir_size(path: &Path) -> u64 {
    let mut total = 0;
    if let Ok(rd) = fs::read_dir(path) {
        for e in rd.flatten() {
            let p = e.path();
            if let Ok(md) = fs::symlink_metadata(&p) {
                if md.is_dir() {
                    total += dir_size(&p);
                } else {
                    total += md.len();
                }
            }
        }
    }
    total
}

// ───────────────────────── output sink ─────────────────────────

#[derive(Clone)]
pub struct Sink {
    pub dir: PathBuf,
    file: Arc<Mutex<File>>,
}

impl Sink {
    pub fn open(dir: &Path) -> Self {
        fs::create_dir_all(dir).expect("results dir");
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("results.jsonl"))
            .expect("results.jsonl");
        Self {
            dir: dir.to_path_buf(),
            file: Arc::new(Mutex::new(file)),
        }
    }

    pub fn emit(&self, record: Value) {
        let line = serde_json::to_string(&record).unwrap();
        println!("{}", summarize(&record));
        let mut f = self.file.lock().unwrap();
        writeln!(f, "{line}").unwrap();
        f.flush().unwrap();
    }
}

fn summarize(r: &Value) -> String {
    let g = |k: &str| r.get(k).cloned().unwrap_or(Value::Null);
    let lat = r.get("latency").cloned().unwrap_or(Value::Null);
    format!(
        "[{}] {} {} {} ops/s={} MB/s={} p50={}us p99={}us err={}",
        g("suite"),
        g("system"),
        g("scenario"),
        r.get("params").map(|p| p.to_string()).unwrap_or_default(),
        g("ops_per_s"),
        g("mb_per_s"),
        lat.get("p50_us").cloned().unwrap_or(Value::Null),
        lat.get("p99_us").cloned().unwrap_or(Value::Null),
        g("errors"),
    )
}

/// Flatten results.jsonl into results.csv (one row per record).
pub fn write_csv(dir: &Path) {
    let Ok(raw) = fs::read_to_string(dir.join("results.jsonl")) else {
        return;
    };
    let mut out = String::from(
        "suite,system,scenario,params,ops,duration_s,ops_per_s,mb_per_s,p50_us,p95_us,p99_us,max_us,errors,cpu_pct,peak_rss_mb,disk_write_mb,disk_read_mb\n",
    );
    for line in raw.lines() {
        let Ok(r) = serde_json::from_str::<Value>(line) else { continue };
        let s = |v: Option<&Value>| match v {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Null) | None => String::new(),
            Some(v) => v.to_string(),
        };
        let lat = r.get("latency");
        let res = r.get("resources");
        let l = |k: &str| s(lat.and_then(|x| x.get(k)));
        let rr = |k: &str| s(res.and_then(|x| x.get(k)));
        out.push_str(&format!(
            "{},{},{},\"{}\",{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            s(r.get("suite")),
            s(r.get("system")),
            s(r.get("scenario")),
            s(r.get("params")).replace('"', "'"),
            s(r.get("ops")),
            s(r.get("duration_s")),
            s(r.get("ops_per_s")),
            s(r.get("mb_per_s")),
            l("p50_us"),
            l("p95_us"),
            l("p99_us"),
            l("max_us"),
            s(r.get("errors")),
            rr("cpu_pct"),
            rr("peak_rss_mb"),
            rr("disk_write_mb"),
            rr("disk_read_mb"),
        ));
    }
    fs::write(dir.join("results.csv"), out).unwrap();
}

// ───────────────────────── environment ─────────────────────────

fn cmd(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

pub fn capture_env(extra: Value) -> Value {
    let disk = cmd("diskutil", &["info", "/"]);
    let disk_lines: Vec<&str> = disk
        .lines()
        .filter(|l| {
            l.contains("Device / Media Name")
                || l.contains("Solid State")
                || l.contains("File System Personality")
                || l.contains("Container Free Space")
        })
        .map(str::trim)
        .collect();
    json!({
        "git_commit": cmd("git", &["rev-parse", "HEAD"]),
        "git_dirty": !cmd("git", &["status", "--porcelain"]).is_empty(),
        "os": format!("{} {} ({})", cmd("sw_vers", &["-productName"]), cmd("sw_vers", &["-productVersion"]), cmd("sw_vers", &["-buildVersion"])),
        "kernel": cmd("uname", &["-a"]),
        "cpu": cmd("sysctl", &["-n", "machdep.cpu.brand_string"]),
        "cpu_cores_logical": cmd("sysctl", &["-n", "hw.ncpu"]),
        "cpu_cores_perf": cmd("sysctl", &["-n", "hw.perflevel0.physicalcpu"]),
        "cpu_cores_eff": cmd("sysctl", &["-n", "hw.perflevel1.physicalcpu"]),
        "ram_bytes": cmd("sysctl", &["-n", "hw.memsize"]),
        "disk": disk_lines,
        "rustc": cmd("rustc", &["--version"]),
        "cargo": cmd("cargo", &["--version"]),
        "postgres": cmd("postgres", &["--version"]),
        "build_profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "kern_maxfilesperproc": cmd("sysctl", &["-n", "kern.maxfilesperproc"]),
        "somaxconn": cmd("sysctl", &["-n", "kern.ipc.somaxconn"]),
        "ephemeral_ports": format!("{}-{}", cmd("sysctl", &["-n", "net.inet.ip.portrange.first"]), cmd("sysctl", &["-n", "net.inet.ip.portrange.last"])),
        "maxprocperuid": cmd("sysctl", &["-n", "kern.maxprocperuid"]),
        "timestamp_utc": chrono::Utc::now().to_rfc3339(),
        "extra": extra,
    })
}

// ───────────────────────── payloads ─────────────────────────

/// Payload: [msg_id u64][producer u32][seq u64][t_ns u64] + filler, total `size` bytes (min 28).
pub const HDR: usize = 28;

pub fn make_payload(size: usize, msg_id: u64, producer: u32, seq: u64, t_ns: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(size.max(HDR));
    v.extend_from_slice(&msg_id.to_le_bytes());
    v.extend_from_slice(&producer.to_le_bytes());
    v.extend_from_slice(&seq.to_le_bytes());
    v.extend_from_slice(&t_ns.to_le_bytes());
    let mut x = msg_id.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    while v.len() < size.max(HDR) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.push((x & 0xff) as u8);
    }
    v
}

pub fn parse_header(p: &[u8]) -> Option<(u64, u32, u64, u64)> {
    if p.len() < HDR {
        return None;
    }
    Some((
        u64::from_le_bytes(p[0..8].try_into().ok()?),
        u32::from_le_bytes(p[8..12].try_into().ok()?),
        u64::from_le_bytes(p[12..20].try_into().ok()?),
        u64::from_le_bytes(p[20..28].try_into().ok()?),
    ))
}

pub fn size_label(n: usize) -> String {
    match n {
        n if n >= 1 << 20 => format!("{}MB", n >> 20),
        n if n >= 1024 => format!("{}KB", n / 1024),
        n => format!("{n}B"),
    }
}

pub const SIZES: [usize; 5] = [100, 1024, 10 * 1024, 100 * 1024, 1024 * 1024];

/// Dataset rows for a record size: bounded by 256 MiB and 10k rows.
pub fn dataset_rows(size: usize) -> u64 {
    ((256usize << 20) / size).clamp(64, 10_000) as u64
}

/// Phase timing for closed-loop runs.
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    pub warmup: Duration,
    pub measure: Duration,
}

impl Timing {
    pub fn json(&self) -> Value {
        json!({"warmup_s": self.warmup.as_secs_f64(), "measure_s": self.measure.as_secs_f64()})
    }
}
