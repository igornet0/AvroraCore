use std::env;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;

use dmc_core::{ChannelSpec, Runtime};
use dmc_pgwire::{listen, register_sql_channel};
use dmc_sql::SqlEngine;

#[tokio::main]
async fn main() {
    let mut data = PathBuf::from("data/sql.dbs.json");
    let mut listen_addr: SocketAddr = dmc_pgwire::DEFAULT_ADDR.parse().expect("addr");
    let mut create = false;
    let mut unlock: Option<String> = None;
    let mut master_hex: Option<String> = None;

    let args: Vec<String> = env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data" => {
                i += 1;
                data = PathBuf::from(&args[i]);
            }
            "--listen" => {
                i += 1;
                listen_addr = args[i].parse().expect("listen addr");
            }
            "--create" => create = true,
            "--unlock" => {
                i += 1;
                unlock = Some(args[i].clone());
            }
            "--master-hex" => {
                i += 1;
                master_hex = Some(args[i].clone());
            }
            other => {
                eprintln!("unknown arg: {other}");
                eprintln!(
                    "usage: dmc-pgwire --data PATH [--listen 127.0.0.1:15432] \
                     (--create [--master-hex HEX] | --unlock HEX)"
                );
                std::process::exit(2);
            }
        }
        i += 1;
    }

    let engine = if create {
        let (engine, master) =
            SqlEngine::create_with_master(&data, master_hex.as_deref()).expect("create db");
        println!("master key (store offline, shown once):\n{master}");
        let _ = std::io::stdout().flush();
        engine
    } else {
        let key = unlock
            .or(master_hex)
            .unwrap_or_else(|| {
                eprintln!("pass --create or --unlock <master-hex>");
                std::process::exit(2);
            });
        SqlEngine::open(&data, &key).expect("unlock db")
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
