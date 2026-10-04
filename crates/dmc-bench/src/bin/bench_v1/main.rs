//! Avrora Benchmark V1 — reproducible performance / load / correctness suite.
//!
//! ```bash
//! cargo build --release -p dmc-bench --bin avrora-bench-v1 -p dmc-cli --bin dmc
//! target/release/avrora-bench-v1 --out bench-results/v1/<run> env
//! target/release/avrora-bench-v1 --out bench-results/v1/<run> storage
//! ```
//! Every suite appends records to `<out>/results.jsonl`; `csv` flattens them to `results.csv`.

mod channel;
mod common;
mod conn;
mod correctness;
mod driver;
mod pg;
mod security;
mod sqlcore;
mod storage;
mod trigger;
mod v2;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde_json::json;

use crate::common::{capture_env, raise_nofile, Sink, Timing, SIZES};
use crate::driver::secs;

#[derive(Parser)]
#[command(name = "avrora-bench-v1")]
struct Cli {
    /// Results directory (results.jsonl / results.csv / env.json)
    #[arg(long, global = true, default_value = "bench-results/v1/latest")]
    out: PathBuf,
    /// Warmup seconds per closed-loop scenario
    #[arg(long, global = true, default_value_t = 5.0)]
    warmup: f64,
    /// Measurement seconds per closed-loop scenario
    #[arg(long, global = true, default_value_t = 20.0)]
    measure: f64,
    /// Comma-separated record sizes in bytes (default: 100,1024,10240,102400,1048576)
    #[arg(long, global = true)]
    sizes: Option<String>,
    /// Restrict to one scenario name (where applicable)
    #[arg(long, global = true)]
    only: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Capture environment into env.json
    Env,
    /// Avrora KV storage benchmark (in-process production runtime API)
    Storage,
    /// SQL Core over local IPC (spawns `target/release/dmc serve --dev`)
    Sql,
    /// PostgreSQL storage + SQL benchmark (dedicated initdb instance)
    Pg {
        #[arg(long, default_value_t = 55432)]
        port: u16,
        /// wal_sync_method override (e.g. fsync_writethrough)
        #[arg(long)]
        wal_sync_method: Option<String>,
        /// Run the connection ramp against PostgreSQL
        #[arg(long)]
        connections: bool,
        /// Max PostgreSQL connections in the ramp
        #[arg(long, default_value_t = 1000)]
        max_conns: usize,
    },
    /// Channel / stream: producer → subscription → consumer → ACK
    Channel {
        /// Payload bytes
        #[arg(long, default_value_t = 1024)]
        size: usize,
        /// Also run the open-loop rate ramp to find MAX_STABLE
        #[arg(long)]
        ramp: bool,
        /// Consumer drain timeout after producers stop (seconds)
        #[arg(long, default_value_t = 120)]
        drain_timeout: u64,
    },
    /// Triggers: write → trigger → stream receiver
    Trigger {
        #[arg(long, default_value_t = 1024)]
        size: usize,
    },
    /// Connection scalability against the Avrora control plane (TLS 1.3 + mTLS)
    Connections {
        /// Comma-separated connection counts
        #[arg(long, default_value = "10,50,100,250,500,1000,2500,5000,10000")]
        steps: String,
    },
    /// Security overhead decomposition
    Security,
    /// Correctness under load (retry, DLQ, idempotency, restart, kill -9)
    Correctness {
        #[arg(long, default_value_t = 5)]
        crash_cycles: u32,
    },
    /// Internal: control-plane server process for the connection benchmark
    ControlServer {
        #[arg(long)]
        dir: PathBuf,
    },
    /// Internal: writer process killed with SIGKILL by the correctness suite
    CrashChild {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        master: String,
        #[arg(long)]
        start_id: u64,
        #[arg(long)]
        size: usize,
    },
    /// V2: write scalability matrix (writers × sizes; partitions / commit mode from env)
    WriteMatrix {
        #[arg(long, default_value = "1,4,16,64")]
        writers: String,
    },
    /// V2: consume+ack cost vs backlog size, plus reopen (recovery) time
    ConsumeBacklog {
        #[arg(long, default_value = "1000,10000,100000")]
        backlogs: String,
        #[arg(long, default_value_t = 1024)]
        size: usize,
        #[arg(long, default_value_t = 200)]
        probe: u64,
    },
    /// Flatten results.jsonl → results.csv
    Csv,
}

fn main() {
    let cli = Cli::parse();
    let nofile = raise_nofile();
    let timing = Timing {
        warmup: secs(cli.warmup),
        measure: secs(cli.measure),
    };
    let sizes: Vec<usize> = cli
        .sizes
        .as_deref()
        .map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect())
        .unwrap_or_else(|| SIZES.to_vec());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio");
    match cli.cmd {
        Cmd::ControlServer { dir } => {
            rt.block_on(conn::control_server(dir));
            return;
        }
        Cmd::CrashChild {
            dir,
            master,
            start_id,
            size,
        } => {
            rt.block_on(correctness::crash_child(dir, master, start_id, size));
            return;
        }
        _ => {}
    }
    let sink = Sink::open(&cli.out);
    let only = cli.only.as_deref();
    match cli.cmd {
        Cmd::Env => {
            let env = capture_env(json!({"nofile_limit": nofile}));
            std::fs::write(cli.out.join("env.json"), serde_json::to_string_pretty(&env).unwrap()).unwrap();
            println!("{}", serde_json::to_string_pretty(&env).unwrap());
        }
        Cmd::Storage => rt.block_on(storage::run(&sink, timing, &sizes, only)),
        Cmd::Sql => sqlcore::run(&sink, timing, &sizes, only),
        Cmd::Pg {
            port,
            wal_sync_method,
            connections,
            max_conns,
        } => rt.block_on(pg::run(&sink, timing, &sizes, only, port, wal_sync_method, connections, max_conns)),
        Cmd::Channel { size, ramp, drain_timeout } => rt.block_on(channel::run(&sink, timing, size, ramp, only, drain_timeout)),
        Cmd::Trigger { size } => rt.block_on(trigger::run(&sink, timing, size)),
        Cmd::Connections { steps } => {
            let steps: Vec<usize> = steps.split(',').filter_map(|x| x.trim().parse().ok()).collect();
            rt.block_on(conn::run(&sink, timing, &steps))
        }
        Cmd::Security => rt.block_on(security::run(&sink, timing)),
        Cmd::Correctness { crash_cycles } => rt.block_on(correctness::run(&sink, crash_cycles)),
        Cmd::WriteMatrix { writers } => {
            let w: Vec<usize> = writers.split(',').filter_map(|x| x.trim().parse().ok()).collect();
            rt.block_on(v2::write_matrix(&sink, timing, &w, &sizes))
        }
        Cmd::ConsumeBacklog { backlogs, size, probe } => {
            let b: Vec<u64> = backlogs.split(',').filter_map(|x| x.trim().parse().ok()).collect();
            rt.block_on(v2::consume_backlog(&sink, &b, size, probe))
        }
        Cmd::Csv => {}
        Cmd::ControlServer { .. } | Cmd::CrashChild { .. } => unreachable!(),
    }
    common::write_csv(&cli.out);
}
