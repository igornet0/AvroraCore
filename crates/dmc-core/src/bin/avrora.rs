use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use dmc_core::control::{
    self, AvroraPaths, CapabilityRotationConfig, control_port_from_env, format_devo_init,
    format_status, load_backup_config, load_capability_rotation, reset_server_data, resolve_ui_dist,
    run_devo_init_ex, run_init, save_backup_config, save_capability_rotation, BackupConfig,
    ServerConfig,
};
use dmc_core::runtime::{DbStatus, Runtime};
use dmc_core::server;

#[derive(Parser)]
#[command(name = "avrora", about = "Avrora server")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate TLS material and a one-shot bootstrap token
    Init {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Public hostname written into invite.json (default: 127.0.0.1)
        #[arg(long, default_value = "127.0.0.1")]
        invite_host: String,
        #[arg(long)]
        invite_port: Option<u16>,
    },
    /// Export invite JSON (no private keys) for an already-initialized control dir
    Invite {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long)]
        port: Option<u16>,
        /// Kept for compatibility; invite.json is written unless --no-write
        #[arg(long, hide = true)]
        write: bool,
        /// Print invite JSON only (do not write invite.json)
        #[arg(long)]
        no_write: bool,
    },
    /// Run HTTP admin UI + control plane
    Serve,
    /// Print control / vault / listen addresses (no secrets)
    Status,
    /// Delete control plane, vault file, and UI auth under AVRORA_HOME / AVRORA_DATA
    Reset {
        /// Required. Without this flag reset is a no-op error.
        #[arg(long)]
        yes: bool,
    },
    /// User authorization (capability rotation schedule)
    Auth {
        #[command(subcommand)]
        cmd: AuthCmd,
    },
    /// Vault backup / restore / recover (local runtime; use avrora-client when server is running)
    Backup {
        #[command(subcommand)]
        cmd: BackupCmd,
    },
    /// Dev provisioning: root role/user (+ optional demo data) after empty vault create
    DevoInit {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Seed demo org tree and scoped roles (finance/hr)
        #[arg(long)]
        demo: bool,
        /// Master key hex when vault is empty (fixed create) or locked (unlock)
        #[arg(long)]
        master_hex: Option<String>,
        /// UI access key for browser login (default: see `dmc_security::dev::UI_ACCESS_KEY`)
        #[arg(long)]
        ui_access_key: Option<String>,
        /// Fixed TOTP base32 secret for UI 2FA (default fixture: `dmc_security::dev::UI_TOTP_SECRET`)
        #[arg(long)]
        ui_totp_secret: Option<String>,
        /// Do not write .avrora-dev-master.hex when a new vault is created
        #[arg(long)]
        no_write_master: bool,
    },
    /// Interactive operator menu (serve, UI, domain, vault, roles, users)
    Menu,
}

#[derive(Subcommand)]
enum AuthCmd {
    Rotation {
        #[command(subcommand)]
        cmd: RotationCmd,
    },
}

#[derive(Subcommand)]
enum RotationCmd {
    /// Print capability rotation schedule
    Show,
    /// Change schedule (persisted; picked up by a running server)
    Set {
        #[arg(long)]
        time: Option<String>,
        #[arg(long)]
        enabled: Option<bool>,
    },
    /// Rotate capabilities now (vault must be unlocked in this process)
    RunNow,
}

#[derive(Subcommand)]
enum BackupCmd {
    Create {
        id: String,
        #[arg(long)]
        include_rowstore: bool,
    },
    Verify { id: String },
    List,
    Restore {
        id: String,
        #[arg(long)]
        target: String,
    },
    Recover {
        #[arg(long)]
        target: String,
    },
    Status {
        #[arg(long)]
        target: String,
    },
    Schedule {
        #[command(subcommand)]
        cmd: BackupScheduleCmd,
    },
}

#[derive(Subcommand)]
enum BackupScheduleCmd {
    Show,
    Set {
        #[arg(long)]
        time: Option<String>,
        #[arg(long)]
        enabled: Option<bool>,
        #[arg(long)]
        id_prefix: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.cmd.unwrap_or(Cmd::Serve) {
        Cmd::Init {
            data_dir,
            invite_host,
            invite_port,
        } => cmd_init(data_dir, invite_host, invite_port),
        Cmd::Invite {
            data_dir,
            host,
            port,
            write: _,
            no_write,
        } => cmd_invite(data_dir, host, port, !no_write),
        Cmd::Serve => serve().await,
        Cmd::Status => cmd_status().await,
        Cmd::Reset { yes } => cmd_reset(yes),
        Cmd::Auth {
            cmd: AuthCmd::Rotation { cmd },
        } => match cmd {
            RotationCmd::Show => cmd_rotation_show(),
            RotationCmd::Set { time, enabled } => cmd_rotation_set(time, enabled),
            RotationCmd::RunNow => cmd_rotation_run_now().await,
        },
        Cmd::Backup { cmd } => cmd_backup(cmd).await,
        Cmd::DevoInit {
            data_dir,
            demo,
            master_hex,
            ui_access_key,
            ui_totp_secret,
            no_write_master,
        } => {
            cmd_devo_init(
                data_dir,
                demo,
                master_hex,
                ui_access_key,
                ui_totp_secret,
                no_write_master,
            )
            .await
        }
        Cmd::Menu => {
            let handle = tokio::runtime::Handle::current();
            let err = tokio::task::block_in_place(|| dmc_core::menu::run(&handle));
            if let Err(e) = err {
                eprintln!("avrora menu: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn cmd_init(data_dir: Option<PathBuf>, invite_host: String, invite_port: Option<u16>) {
    let paths = AvroraPaths::resolve();
    let dir = data_dir.unwrap_or(paths.control_dir);
    let port = invite_port.unwrap_or_else(control_port_from_env);
    match run_init(&dir, &invite_host, port) {
        Ok(out) => print!("{out}"),
        Err(e) => {
            eprintln!("avrora init: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_invite(data_dir: Option<PathBuf>, host: String, port: Option<u16>, write: bool) {
    let paths = AvroraPaths::resolve();
    let dir = data_dir.unwrap_or(paths.control_dir);
    let port = port.unwrap_or_else(control_port_from_env);
    match control::export_invite(&dir, &host, port) {
        Ok(invite) => {
            let json = serde_json::to_string_pretty(&invite).unwrap();
            if write {
                match control::write_invite_file(&dir, &invite) {
                    Ok(path) => {
                        println!("Wrote {}", path.display());
                    }
                    Err(e) => {
                        eprintln!("avrora invite: {e}");
                        std::process::exit(1);
                    }
                }
            }
            println!("{json}");
        }
        Err(e) => {
            eprintln!("avrora invite: {e}");
            std::process::exit(1);
        }
    }
}

async fn cmd_status() {
    println!("{}", format_status().await);
}

fn print_rotation(cfg: &CapabilityRotationConfig, path: &std::path::Path) {
    println!("enabled={}", cfg.enabled);
    println!("time={}", cfg.time);
    println!("last_run_at={}", cfg.last_run_at.as_deref().unwrap_or("-"));
    println!("last_result={}", cfg.last_result.as_deref().unwrap_or("-"));
    println!("pending_after_unlock={}", cfg.pending_after_unlock);
    println!("path={}", path.display());
}

fn cmd_rotation_show() {
    let paths = AvroraPaths::resolve();
    match load_capability_rotation(&paths.control_dir) {
        Ok(cfg) => print_rotation(&cfg, &control::config_path(&paths.control_dir)),
        Err(e) => {
            eprintln!("avrora auth rotation show: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_rotation_set(time: Option<String>, enabled: Option<bool>) {
    if time.is_none() && enabled.is_none() {
        eprintln!("avrora auth rotation set: pass --time HH:MM and/or --enabled true|false");
        std::process::exit(1);
    }
    let paths = AvroraPaths::resolve();
    let mut cfg = load_capability_rotation(&paths.control_dir).unwrap_or_default();
    if let Some(t) = time {
        cfg.time = t;
    }
    if let Some(e) = enabled {
        cfg.enabled = e;
    }
    match save_capability_rotation(&paths.control_dir, &cfg) {
        Ok(path) => {
            println!("wrote {}", path.display());
            print_rotation(&cfg, &path);
        }
        Err(e) => {
            eprintln!("avrora auth rotation set: {e}");
            std::process::exit(1);
        }
    }
}

async fn cmd_rotation_run_now() {
    let paths = AvroraPaths::resolve();
    let rt = Runtime::at_path(&paths.db_path);
    match control::capability_rotation_config::try_rotate_now(&paths.control_dir, &rt, true)
        .await
    {
        Ok(report) => {
            println!(
                "rotated_users={} rotated_capabilities={}",
                report.rotated_users, report.rotated_capabilities
            );
        }
        Err(e) => {
            eprintln!("avrora auth rotation run-now: {e}");
            std::process::exit(1);
        }
    }
}

async fn cmd_backup(cmd: BackupCmd) {
    let paths = AvroraPaths::resolve();
    let rt = Runtime::at_path(&paths.db_path);
    match cmd {
        BackupCmd::Create { id, include_rowstore } => {
            match dmc_core::backup::create_backup(&rt, &id, include_rowstore).await {
                Ok((backup_id, seq)) => {
                    println!("backup_id={backup_id} checkpoint_sequence={seq}");
                }
                Err(e) => {
                    eprintln!("avrora backup create: {e}");
                    eprintln!("hint: vault must be unlocked (avrora-client unlock) when server is running");
                    std::process::exit(1);
                }
            }
        }
        BackupCmd::Verify { id } => {
            let layout = dmc_journal::StorageLayout::from_db_path(&rt.db_path().await);
            let root = dmc_core::backup::backups_root(&layout.data_dir);
            match dmc_core::backup::verify_backup(&root, &id) {
                Ok((seq, valid, errors)) => {
                    println!("checkpoint_sequence={seq} valid={valid}");
                    for e in errors {
                        println!("error: {e}");
                    }
                }
                Err(e) => fail_backup(e),
            }
        }
        BackupCmd::List => {
            let layout = dmc_journal::StorageLayout::from_db_path(&rt.db_path().await);
            let root = dmc_core::backup::backups_root(&layout.data_dir);
            match dmc_core::backup::list_backups(&root) {
                Ok(items) => {
                    for i in items {
                        println!(
                            "{} seq={} valid={} state={} created={}",
                            i.backup_id, i.checkpoint_sequence, i.valid, i.state, i.created_at
                        );
                    }
                }
                Err(e) => fail_backup(e),
            }
        }
        BackupCmd::Restore { id, target } => {
            let layout = dmc_journal::StorageLayout::from_db_path(&rt.db_path().await);
            let backups = dmc_core::backup::backups_root(&layout.data_dir);
            let restores = dmc_core::backup::restores_root(&layout.data_dir);
            match dmc_core::backup::restore_backup(&backups, &restores, &id, &target) {
                Ok((bid, tid, seq)) => {
                    println!("backup_id={bid} target_id={tid} checkpoint_sequence={seq}");
                }
                Err(e) => fail_backup(e),
            }
        }
        BackupCmd::Recover { target } => {
            if rt.status().await != DbStatus::Locked {
                eprintln!("avrora backup recover: vault must be locked");
                std::process::exit(1);
            }
            let layout = dmc_journal::StorageLayout::from_db_path(&rt.db_path().await);
            let restores = dmc_core::backup::restores_root(&layout.data_dir);
            match dmc_core::backup::recover_backup(&rt, &restores, &target).await {
                Ok((tid, seq)) => {
                    println!(
                        "recovered target={tid} checkpoint_sequence={seq}; re-auth and unlock required"
                    );
                }
                Err(e) => fail_backup(e),
            }
        }
        BackupCmd::Status { target } => {
            let layout = dmc_journal::StorageLayout::from_db_path(&rt.db_path().await);
            let restores = dmc_core::backup::restores_root(&layout.data_dir);
            match dmc_core::backup::backup_status(&restores, &target) {
                Ok((state, seq, tid)) => {
                    println!("target={tid} state={state} checkpoint_sequence={seq}");
                }
                Err(e) => fail_backup(e),
            }
        }
        BackupCmd::Schedule { cmd } => match cmd {
            BackupScheduleCmd::Show => cmd_backup_schedule_show(),
            BackupScheduleCmd::Set {
                time,
                enabled,
                id_prefix,
            } => cmd_backup_schedule_set(time, enabled, id_prefix),
        },
    }
}

fn fail_backup(e: dmc_core::backup::BackupError) {
    eprintln!("avrora backup: {e}");
    std::process::exit(1);
}

fn cmd_backup_schedule_show() {
    let paths = AvroraPaths::resolve();
    match load_backup_config(&paths.control_dir) {
        Ok(cfg) => print_backup_config(
            &cfg,
            &control::backup_config::config_path(&paths.control_dir),
        ),
        Err(e) => {
            eprintln!("avrora backup schedule show: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_backup_schedule_set(
    time: Option<String>,
    enabled: Option<bool>,
    id_prefix: Option<String>,
) {
    let paths = AvroraPaths::resolve();
    let mut cfg = load_backup_config(&paths.control_dir).unwrap_or_default();
    if let Some(t) = time {
        cfg.schedule.time = t;
    }
    if let Some(e) = enabled {
        cfg.schedule.enabled = e;
    }
    if let Some(p) = id_prefix {
        cfg.schedule.id_prefix = p;
    }
    match save_backup_config(&paths.control_dir, &cfg) {
        Ok(path) => {
            println!("wrote {}", path.display());
            print_backup_config(&cfg, &path);
        }
        Err(e) => {
            eprintln!("avrora backup schedule set: {e}");
            std::process::exit(1);
        }
    }
}

fn print_backup_config(cfg: &BackupConfig, path: &std::path::Path) {
    println!("schedule.enabled={}", cfg.schedule.enabled);
    println!("schedule.time={}", cfg.schedule.time);
    println!("schedule.id_prefix={}", cfg.schedule.id_prefix);
    println!(
        "schedule.last_run_at={}",
        cfg.schedule.last_run_at.as_deref().unwrap_or("-")
    );
    println!(
        "schedule.last_result={}",
        cfg.schedule.last_result.as_deref().unwrap_or("-")
    );
    println!("s3.enabled={} bucket={}", cfg.s3.enabled, cfg.s3.bucket);
    println!("encryption.enabled={}", cfg.encryption.enabled);
    println!("incremental.enabled={}", cfg.incremental.enabled);
    println!("path={}", path.display());
}

async fn cmd_devo_init(
    data_dir: Option<PathBuf>,
    demo: bool,
    master_hex: Option<String>,
    ui_access_key: Option<String>,
    ui_totp_secret: Option<String>,
    no_write_master: bool,
) {
    let mut paths = AvroraPaths::resolve();
    if let Some(dir) = data_dir {
        paths.db_path = dir.join("avrora.dbs.json");
        paths.control_dir = control::control_dir(&dir);
    }
    let rt = Runtime::at_path(&paths.db_path);
    match run_devo_init_ex(
        &rt,
        demo,
        master_hex.as_deref(),
        !no_write_master,
        ui_access_key.as_deref(),
        ui_totp_secret.as_deref(),
    )
    .await
    {
        Ok(r) => print!("{}", format_devo_init(&r, demo)),
        Err(e) => {
            eprintln!("avrora devo-init: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_reset(yes: bool) {
    let paths = AvroraPaths::resolve();
    match reset_server_data(&paths, yes) {
        Ok(removed) => {
            if removed.is_empty() {
                println!("nothing to reset");
            } else {
                println!("reset:");
                for p in removed {
                    println!("  {}", p.display());
                }
            }
        }
        Err(e) => {
            eprintln!("avrora reset: {e}");
            std::process::exit(1);
        }
    }
}

async fn serve() {
    let paths = AvroraPaths::resolve();
    let cfg = ServerConfig::resolve(&paths.control_dir);
    let addr: SocketAddr = cfg.http_addr.parse().unwrap_or_else(|_| {
        eprintln!("avrora serve: invalid http_addr {}", cfg.http_addr);
        std::process::exit(1);
    });
    if let Err(msg) = check_http_port_available(addr) {
        eprintln!("{msg}");
        std::process::exit(1);
    }
    let ui = if cfg.ui_enabled {
        resolve_ui_dist()
    } else {
        None
    };
    println!("Starting Avrora on http://{addr}");
    if let Err(err) = server::run(addr, ui).await {
        eprintln!("Avrora error: {err}");
        std::process::exit(1);
    }
}

fn check_http_port_available(addr: SocketAddr) -> Result<(), String> {
    use std::net::TcpListener;
    match TcpListener::bind(addr) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            let port = addr.port();
            let hint = port_owner_hint(port);
            Err(format!(
                "avrora serve: port {port} already in use ({e}).\n\
                 Stop the other instance first:\n\
                   make down\n\
                 {hint}\n\
                 Or use another port: AVRORA_ADDR=127.0.0.1:PORT avrora serve"
            ))
        }
        Err(e) => Err(format!("avrora serve: cannot bind {addr}: {e}")),
    }
}

#[cfg(unix)]
fn port_owner_hint(port: u16) -> String {
    use std::process::{Command, Stdio};
    let out = Command::new("lsof")
        .args([&format!("-tiTCP:{port}"), "-sTCP:LISTEN"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let pids = String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| !l.trim().is_empty())
                .collect::<Vec<_>>()
                .join(" ");
            if pids.is_empty() {
                String::new()
            } else {
                format!("  listening pid(s): {pids}")
            }
        }
        _ => String::new(),
    }
}

#[cfg(not(unix))]
fn port_owner_hint(_port: u16) -> String {
    String::new()
}
