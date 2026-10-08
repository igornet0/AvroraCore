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
        /// Destinations, comma separated (`local`, BackupSAS target ids)
        #[arg(long, value_delimiter = ',')]
        targets: Vec<String>,
        /// Sections, comma separated (base,journal,runtime)
        #[arg(long, value_delimiter = ',')]
        sections: Vec<String>,
    },
    Verify { id: String },
    List,
    Restore {
        id: String,
        #[arg(long)]
        target: String,
        /// Restore from this location (`local` or a BackupSAS target id)
        #[arg(long)]
        from: Option<String>,
        /// Disaster recovery: derive the data key from the Master Key (hex file,
        /// or `-` for stdin) instead of an unlocked vault
        #[arg(long)]
        master_key_file: Option<PathBuf>,
    },
    /// Write a disaster-recovery kit (identity sealed by the Master Key,
    /// vault salt, targets, catalog). Never contains the Master Key.
    ExportKit {
        #[arg(long)]
        out: PathBuf,
        /// Master Key hex file (or `-` for stdin) when the vault is not
        /// unlocked in this process
        #[arg(long)]
        master_key_file: Option<PathBuf>,
    },
    /// Import a recovery kit on a new host (requires the Master Key)
    ImportKit {
        #[arg(long)]
        kit: PathBuf,
        /// Master Key hex file, or `-` for stdin
        #[arg(long)]
        master_key_file: PathBuf,
        /// Replace an existing identity/targets
        #[arg(long)]
        force: bool,
    },
    /// Manage backup destinations (BackupSAS nodes)
    Target {
        #[command(subcommand)]
        cmd: BackupTargetCmd,
    },
    /// Show every backup and where it is stored
    Catalog,
    /// Pull relocation notices from BackupSAS nodes and update locations
    Sync,
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
        /// ISO weekdays 1..7, comma separated (empty string = every day)
        #[arg(long)]
        weekdays: Option<String>,
        /// Destinations, comma separated
        #[arg(long, value_delimiter = ',')]
        targets: Option<Vec<String>>,
        /// Sections, comma separated (base,journal,runtime)
        #[arg(long, value_delimiter = ',')]
        sections: Option<Vec<String>>,
        /// Keep newest N scheduled backups per target (0 = keep all)
        #[arg(long)]
        retention_keep: Option<u32>,
    },
}

#[derive(Subcommand)]
enum BackupTargetCmd {
    /// Import a BackupSAS node from its connect JSON and enroll
    Add {
        id: String,
        /// File with the node's public connect JSON
        #[arg(long)]
        connect: PathBuf,
        /// One-time enrollment secret from the node operator (`-` reads stdin)
        #[arg(long)]
        secret: String,
        /// Repository on the node (default: first offered)
        #[arg(long)]
        repository: Option<String>,
    },
    List,
    Remove {
        id: String,
    },
    /// Connect and list backups stored on the node
    Test {
        id: String,
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
        BackupCmd::Create {
            id,
            include_rowstore: _,
            targets,
            sections,
        } => {
            let layout = dmc_journal::StorageLayout::from_db_path(&rt.db_path().await);
            let root = dmc_core::backup::backups_root(&layout.data_dir);
            let targets = if targets.is_empty() {
                control::backup_config::default_targets()
            } else {
                targets
            };
            let sections = if sections.is_empty() {
                control::backup_config::default_sections()
            } else {
                sections
            };
            match dmc_core::backup::remote::run_backup(
                &rt,
                &paths.control_dir,
                &root,
                &id,
                &targets,
                &sections,
            )
            .await
            {
                Ok(report) => {
                    println!("{}", report.summary());
                    if !report.all_ok() {
                        std::process::exit(2);
                    }
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
        BackupCmd::Restore {
            id,
            target,
            from,
            master_key_file,
        } => {
            let layout = dmc_journal::StorageLayout::from_db_path(&rt.db_path().await);
            let backups = dmc_core::backup::backups_root(&layout.data_dir);
            let restores = dmc_core::backup::restores_root(&layout.data_dir);
            let keys = match master_key_file {
                Some(f) => offline_keys(&paths.control_dir, &paths.db_path, &f),
                None => dmc_core::backup::keys::KeySource::Runtime(&rt),
            };
            match dmc_core::backup::remote::fetch_backup(
                &keys,
                &paths.control_dir,
                &backups,
                &restores,
                &id,
                &target,
                from.as_deref(),
            )
            .await
            {
                Ok((bid, tid, seq)) => {
                    println!("backup_id={bid} target_id={tid} checkpoint_sequence={seq}");
                }
                Err(e) => fail_backup(e),
            }
        }
        BackupCmd::Recover { target } if rt.status().await == DbStatus::Empty => {
            let layout = dmc_journal::StorageLayout::from_db_path(&rt.db_path().await);
            let restores = dmc_core::backup::restores_root(&layout.data_dir);
            match dmc_core::backup::recover_into_empty(&rt, &restores, &target).await {
                Ok((tid, seq)) => println!(
                    "disaster recovery: installed target={tid} checkpoint_sequence={seq}; \
                     start the server and unlock with the original Master Key"
                ),
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
                weekdays,
                targets,
                sections,
                retention_keep,
            } => cmd_backup_schedule_set(BackupScheduleUpdate {
                time,
                enabled,
                id_prefix,
                weekdays,
                targets,
                sections,
                retention_keep,
            }),
        },
        BackupCmd::Target { cmd } => cmd_backup_target(&paths.control_dir, cmd).await,
        BackupCmd::ExportKit {
            out,
            master_key_file,
        } => {
            use dmc_core::backup::{keys::KeySource, kit};
            let keys = match master_key_file {
                Some(f) => offline_keys(&paths.control_dir, &paths.db_path, &f),
                None if rt.status().await == DbStatus::Unlocked => KeySource::Runtime(&rt),
                None => {
                    eprintln!(
                        "avrora backup export-kit: vault is not unlocked in this process; \
                         pass --master-key-file (or use POST /api/backup/export-kit on the running server)"
                    );
                    std::process::exit(1);
                }
            };
            match kit::export_kit(&keys, &paths.control_dir, &paths.db_path).await {
                Ok(k) => match kit::write_kit(&out, &k) {
                    Ok(()) => println!(
                        "wrote {} (identity {}, {} target(s), {} catalogued backup(s)); \
                         keep it with the Master Key recovery material",
                        out.display(),
                        k.identity.id,
                        k.targets.targets.len(),
                        k.catalog.entries.len()
                    ),
                    Err(e) => fail_backup(e),
                },
                Err(e) => fail_backup(e),
            }
        }
        BackupCmd::ImportKit {
            kit: kit_path,
            master_key_file,
            force,
        } => {
            use dmc_core::backup::kit;
            let master = read_master(&master_key_file);
            let result = kit::read_kit(&kit_path)
                .and_then(|k| kit::import_kit(&paths.control_dir, &k, &master, force));
            match result {
                Ok(r) => {
                    println!(
                        "imported identity {} targets={} catalog_entries={}{}",
                        r.identity,
                        r.targets.join(","),
                        r.catalog_entries,
                        if r.wrote_backup_config {
                            " (backup.json written, schedule disabled)"
                        } else {
                            ""
                        }
                    );
                    println!(
                        "next: avrora backup restore <backup_id> --target <restore_id> --from <target> --master-key-file <file>"
                    );
                }
                Err(e) => fail_backup(e),
            }
        }
        BackupCmd::Catalog => match control::backup_catalog::load(&paths.control_dir) {
            Ok(catalog) => {
                if catalog.entries.is_empty() {
                    println!("catalog is empty");
                }
                for e in catalog.entries {
                    let locs: Vec<String> = e
                        .locations
                        .iter()
                        .map(|l| match &l.remote_backup_id {
                            Some(r) => format!("{}:{r}", l.target_id),
                            None => l.target_id.clone(),
                        })
                        .collect();
                    println!(
                        "{} seq={} created={} sections={} locations={}",
                        e.backup_id,
                        e.checkpoint_sequence,
                        e.created_at,
                        e.sections.join(","),
                        locs.join(" ")
                    );
                }
            }
            Err(e) => {
                eprintln!("avrora backup catalog: {e}");
                std::process::exit(1);
            }
        },
        BackupCmd::Sync => {
            match dmc_core::backup::remote::sync_relocations(&paths.control_dir).await {
                Ok(report) => {
                    println!(
                        "applied={} new_targets={:?} updated_backups={:?}",
                        report.applied.len(),
                        report.new_targets,
                        report.updated_backups
                    );
                    for e in &report.errors {
                        eprintln!("error: {e}");
                    }
                    if !report.errors.is_empty() {
                        std::process::exit(2);
                    }
                }
                Err(e) => fail_backup(e),
            }
        }
    }
}

/// Read a Master Key (hex) from a file or stdin (`-`). Never echoed.
fn read_master(path: &std::path::Path) -> dmc_vault::KeyMaterial {
    use std::io::Read;
    let mut text = zeroize::Zeroizing::new(String::new());
    let res = if path == std::path::Path::new("-") {
        std::io::stdin().read_to_string(&mut text).map(|_| ())
    } else {
        std::fs::File::open(path).and_then(|mut f| f.read_to_string(&mut text).map(|_| ()))
    };
    if let Err(e) = res {
        eprintln!(
            "avrora backup: cannot read master key from {}: {e}",
            path.display()
        );
        std::process::exit(1);
    }
    match dmc_core::backup::keys::parse_master_hex(&text) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("avrora backup: {e}");
            std::process::exit(1);
        }
    }
}

/// Offline key source: Master Key + vault salt from the local vault, or from
/// an imported recovery kit on a host without a vault.
fn offline_keys(
    control_dir: &std::path::Path,
    db_path: &std::path::Path,
    master_file: &std::path::Path,
) -> dmc_core::backup::keys::KeySource<'static> {
    let master = read_master(master_file);
    let salt = dmc_core::backup::keys::vault_salt(db_path)
        .ok()
        .or_else(|| {
            dmc_core::backup::kit::imported_salt(control_dir)
                .ok()
                .flatten()
        });
    let Some(salt) = salt else {
        eprintln!(
            "avrora backup: no vault here and no imported recovery kit (run `avrora backup import-kit`)"
        );
        std::process::exit(1);
    };
    dmc_core::backup::keys::KeySource::Offline { master, salt }
}

/// `-` reads a secret from stdin so it never appears in argv / shell history.
fn read_secret_arg(value: String) -> zeroize::Zeroizing<String> {
    if value != "-" {
        return zeroize::Zeroizing::new(value);
    }
    let mut line = zeroize::Zeroizing::new(String::new());
    if let Err(e) = std::io::stdin().read_line(&mut line) {
        eprintln!("avrora backup: cannot read secret from stdin: {e}");
        std::process::exit(1);
    }
    zeroize::Zeroizing::new(line.trim().to_string())
}

async fn cmd_backup_target(control_dir: &std::path::Path, cmd: BackupTargetCmd) {
    use dmc_core::backup::remote;
    use dmc_core::control::backup_targets;
    match cmd {
        BackupTargetCmd::Add {
            id,
            connect,
            secret,
            repository,
        } => {
            let descriptor = match std::fs::read_to_string(&connect)
                .map_err(|e| e.to_string())
                .and_then(|t| {
                    backupsas_core::ConnectDescriptor::from_json(&t).map_err(|e| e.to_string())
                }) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("avrora backup target add: {}: {e}", connect.display());
                    std::process::exit(1);
                }
            };
            let Some(repository) = repository.or_else(|| descriptor.repositories.first().cloned())
            else {
                eprintln!("avrora backup target add: node offers no repository");
                std::process::exit(1);
            };
            let secret = read_secret_arg(secret);
            match remote::add_remote_target(control_dir, &id, descriptor, &repository, &secret)
                .await
            {
                Ok(t) => println!(
                    "added target {} server={} repository={repository}",
                    t.id,
                    t.server_id().map(|s| s.to_string()).unwrap_or_default()
                ),
                Err(e) => fail_backup(e),
            }
        }
        BackupTargetCmd::List => match backup_targets::load(control_dir) {
            Ok(targets) => {
                for t in targets.all() {
                    match &t.kind {
                        backup_targets::TargetKind::Local => println!("{} local", t.id),
                        backup_targets::TargetKind::Backupsas {
                            descriptor,
                            repository,
                        } => println!(
                            "{} backupsas server={} fingerprint={} endpoints={} repository={}{}",
                            t.id,
                            descriptor.server_id,
                            descriptor.fingerprint,
                            descriptor.endpoints.join(","),
                            repository,
                            t.relocated_from
                                .as_deref()
                                .map(|r| format!(" relocated_from={r}"))
                                .unwrap_or_default()
                        ),
                    }
                }
            }
            Err(e) => {
                eprintln!("avrora backup target list: {e}");
                std::process::exit(1);
            }
        },
        BackupTargetCmd::Remove { id } => match remote::remove_target(control_dir, &id) {
            Ok(t) => println!("removed target {}", t.id),
            Err(e) => fail_backup(e),
        },
        BackupTargetCmd::Test { id } => match remote::list_remote(control_dir, &id).await {
            Ok(items) => {
                println!("target {id}: connected, {} backup(s)", items.len());
                for i in items {
                    println!(
                        "  {} {} size={} committed={}{}",
                        i.backup_id,
                        i.state,
                        i.total_size,
                        i.committed_at,
                        if i.relocated {
                            " (moved away, awaiting sync)"
                        } else {
                            ""
                        }
                    );
                }
            }
            Err(e) => fail_backup(e),
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

struct BackupScheduleUpdate {
    time: Option<String>,
    enabled: Option<bool>,
    id_prefix: Option<String>,
    weekdays: Option<String>,
    targets: Option<Vec<String>>,
    sections: Option<Vec<String>>,
    retention_keep: Option<u32>,
}

fn cmd_backup_schedule_set(u: BackupScheduleUpdate) {
    let paths = AvroraPaths::resolve();
    let mut cfg = load_backup_config(&paths.control_dir).unwrap_or_default();
    if let Some(t) = u.time {
        cfg.schedule.time = t;
    }
    if let Some(e) = u.enabled {
        cfg.schedule.enabled = e;
    }
    if let Some(p) = u.id_prefix {
        cfg.schedule.id_prefix = p;
    }
    if let Some(w) = u.weekdays {
        let parsed: Result<Vec<u8>, _> = w
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::parse::<u8>)
            .collect();
        match parsed {
            Ok(days) => cfg.schedule.weekdays = days,
            Err(e) => {
                eprintln!("avrora backup schedule set: --weekdays: {e}");
                std::process::exit(1);
            }
        }
    }
    if let Some(t) = u.targets {
        let known = control::backup_targets::load(&paths.control_dir).unwrap_or_default();
        if let Some(bad) = t.iter().find(|id| !known.exists(id)) {
            eprintln!(
                "avrora backup schedule set: unknown target `{bad}` (see `avrora backup target list`)"
            );
            std::process::exit(1);
        }
        cfg.schedule.targets = t;
    }
    if let Some(s) = u.sections {
        cfg.schedule.sections = s;
    }
    if let Some(k) = u.retention_keep {
        cfg.schedule.retention_keep = (k > 0).then_some(k);
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
        "schedule.weekdays={}",
        if cfg.schedule.weekdays.is_empty() {
            "every day".to_string()
        } else {
            cfg.schedule
                .weekdays
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(",")
        }
    );
    println!("schedule.targets={}", cfg.schedule.targets.join(","));
    println!("schedule.sections={}", cfg.schedule.sections.join(","));
    println!(
        "schedule.retention_keep={}",
        cfg.schedule
            .retention_keep
            .map(|k| k.to_string())
            .unwrap_or_else(|| "all".into())
    );
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
