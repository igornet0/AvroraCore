//! **Legacy engine — D4 gate reference only. Never deployed.**
//!
//! The retired pre-D4 pgwire server (separate `dmc_sql::SqlEngine` storage, no
//! authentication, no SQL authorization, shared transaction). Kept solely so the D4 gate
//! (`tests/d4_at_rest_gate.rs`) can measure the legacy baseline with the real process.
//! Production pgwire is the SQL-plane adapter (`dmc serve --pgwire`); the production
//! `dmc-pgwire` binary refuses to start this engine.

use std::env;
use std::net::SocketAddr;

use dmc_core::{ChannelSpec, Runtime};
use dmc_pgwire::legacy::keyfile::{self, KeySource};
use dmc_pgwire::legacy::{listen, register_sql_channel};
use dmc_sql::SqlEngine;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let parsed = match keyfile::parse_args(&args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let data = parsed.data;
    let listen_addr: SocketAddr = parsed
        .listen
        .as_deref()
        .unwrap_or(dmc_pgwire::legacy::DEFAULT_ADDR)
        .parse()
        .expect("listen addr");
    let fail = |e: String| -> ! {
        eprintln!("{e}");
        std::process::exit(2);
    };

    let engine = match parsed.key {
        KeySource::CreateNew { out } => {
            if out.exists() {
                fail(format!("{} already exists; refusing to overwrite a master key", out.display()));
            }
            let (engine, master) = SqlEngine::create_with_master(&data, None).expect("create db");
            keyfile::write_key_file(&out, &master).unwrap_or_else(|e| fail(e));
            println!("master key written to {} (mode 0600); store it offline", out.display());
            engine
        }
        KeySource::CreateWith { file } => {
            let key = keyfile::read_key_file(&file).unwrap_or_else(|e| fail(e));
            SqlEngine::create_with_master(&data, Some(&key)).expect("create db").0
        }
        KeySource::Unlock { file } => {
            let key = keyfile::read_key_file(&file).unwrap_or_else(|e| fail(e));
            SqlEngine::open(&data, &key).expect("unlock db")
        }
    };

    let rt = Runtime::at_path(&data);
    let _ = rt.configure_channel(ChannelSpec::internal("bus")).await;
    if let Err(err) = register_sql_channel(&rt, listen_addr).await {
        eprintln!("core channel: {err}");
    }

    if let Err(err) = listen(listen_addr, engine).await {
        eprintln!("pgwire error: {err}");
        std::process::exit(1);
    }
}
