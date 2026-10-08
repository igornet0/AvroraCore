mod encrypt;
mod identity;
mod serve;
mod session;
mod shell;
mod view;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use dmc_client::ExecuteOutcome;
use dmc_ipc::default_socket_path;

use crate::session::{print_diagnostics, print_sql_table, Session};
use crate::serve::spawn_server;
use crate::view::ViewLog;

#[derive(Parser)]
#[command(
    name = "dmc",
    about = "Avrora DMC — консольное управление СУБД (SQL, vault, backup)",
    after_help = "Режим --view выводит на stderr трассировку протокола и криптографии для демонстрации защиты данных."
)]
struct Cli {
    /// Подробная трассировка: запросы, ключи (без секретов), шифрование на диске
    #[arg(long, global = true)]
    view: bool,

    #[arg(long, global = true)]
    socket: Option<PathBuf>,

    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Запустить локальный Core (Unix socket IPC)
    Serve {
        #[arg(long, default_value = "./dmc-data")]
        data_dir: PathBuf,
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Dev bootstrap: analyst/pw + users table + .dmc-dev-master.hex (requires AVRORA_DEV=1)
        #[arg(long)]
        dev: bool,
        /// Production: wrap this run's unlock material into a KeyPass (Argon2id) in this
        /// directory. Password from DMC_KEYPASS_PASSWORD or an interactive prompt.
        /// Without it nothing is persisted and the vault stays Locked.
        #[arg(long)]
        keypass_dir: Option<PathBuf>,
        /// Co-host HTTP admin on this address (shared RuntimeHub with DMC IPC)
        #[arg(long)]
        http: Option<String>,
        /// Co-host production pgwire (PostgreSQL wire protocol over the SQL plane, SASL
        /// AVRORA-ED25519-V1) on this loopback address, e.g. 127.0.0.1:15432.
        #[arg(long)]
        pgwire: Option<String>,
    },
    /// Identity administration (local, offline)
    Identity {
        #[command(subcommand)]
        cmd: IdentityCmd,
    },
    /// Explicit offline migration: seal a protected SQL column with its owners' keys
    /// into a new store (`--target`). Source is kept unless --purge-source.
    EncryptMigrate {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        target: PathBuf,
        /// `flat` (dev root: rows/, state_events.json) or `ops` (dmc serve layout)
        #[arg(long, default_value = "ops")]
        layout: String,
        /// `schema.table` (schema defaults to public)
        #[arg(long)]
        table: String,
        #[arg(long)]
        column: String,
        /// Column holding the owner's subject id
        #[arg(long)]
        owner_column: String,
        /// Identity file (`AuthService::save_identities`)
        #[arg(long)]
        identities: PathBuf,
        #[arg(long)]
        keyring_dir: PathBuf,
        /// Owner identity name; repeat for every owner present in the table
        #[arg(long = "owner")]
        owners: Vec<String>,
        #[arg(long)]
        purge_source: bool,
    },
    /// Интерактивный SQL shell
    Shell {
        #[arg(long, default_value = "analyst")]
        user: String,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        unlock: bool,
        #[arg(long)]
        keypass_dir: Option<PathBuf>,
        #[arg(long)]
        master_file: Option<PathBuf>,
    },
    /// Выполнить SQL (DDL/DML без результата)
    Sql {
        query: String,
        #[arg(long, default_value = "analyst")]
        user: String,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        unlock: bool,
        #[arg(long)]
        keypass_dir: Option<PathBuf>,
        #[arg(long)]
        master_file: Option<PathBuf>,
    },
    /// SELECT и табличный вывод
    Query {
        query: String,
        #[arg(long, default_value = "analyst")]
        user: String,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        unlock: bool,
        #[arg(long)]
        keypass_dir: Option<PathBuf>,
        #[arg(long)]
        master_file: Option<PathBuf>,
    },
    /// Статус vault + diagnostics
    Status {
        #[arg(long, default_value = "analyst")]
        user: String,
        #[arg(long)]
        password: Option<String>,
    },
    /// Показать иерархию ключей (статическая схема)
    Keys,
    /// Hex-preview зашифрованных файлов в data_dir
    Inspect {
        #[arg(long)]
        data_dir: PathBuf,
    },
    Vault {
        #[command(subcommand)]
        cmd: VaultCmd,
    },
    /// ADR-024 backup / restore / recover (SQL Core control plane)
    Backup {
        #[command(subcommand)]
        cmd: BackupCmd,
    },
}

#[derive(Subcommand)]
enum IdentityCmd {
    /// One-time creation of the first administrator on a fresh installation. Refused
    /// forever once done; no force/reset. Password is read from stdin.
    BootstrapOperator {
        #[arg(long, default_value = "./dmc-data")]
        data_dir: PathBuf,
        #[arg(long)]
        socket: Option<PathBuf>,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "avrora")]
        database: String,
        #[arg(long, default_value = "public")]
        schema: String,
        /// Required acknowledgement that the password comes from stdin (never argv).
        #[arg(long, required = true)]
        password_stdin: bool,
    },
}

#[derive(Subcommand)]
enum VaultCmd {
    Status {
        #[arg(long, default_value = "analyst")]
        user: String,
        #[arg(long)]
        password: Option<String>,
    },
    Unlock {
        #[arg(long, default_value = "analyst")]
        user: String,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        keypass_dir: Option<PathBuf>,
        #[arg(long)]
        master_file: Option<PathBuf>,
        #[arg(long)]
        keypass_password: Option<String>,
        /// D4-D: accept storage older than this client has seen (e.g. after restoring an
        /// older backup); the anchor next to the KeyPass is reset. KeyPass only.
        #[arg(long, conflicts_with = "restore_authorized_backup")]
        accept_rollback: bool,
        /// D4-E: emergency restore — authorize exactly the backup recorded in this client's
        /// backup anchor (next to the KeyPass); nothing else is opened. KeyPass only.
        #[arg(long)]
        restore_authorized_backup: bool,
    },
    Lock {
        #[arg(long, default_value = "analyst")]
        user: String,
        #[arg(long)]
        password: Option<String>,
    },
    /// D4-A: explicit migration of a plaintext (pre-D4) SQL store to encrypted storage.
    /// Needs an administrator (GRANT on system) and the KeyPass of this installation;
    /// passwords are prompted, never taken from argv.
    MigrateStorage {
        #[arg(long)]
        user: String,
        #[arg(long)]
        keypass_dir: PathBuf,
        /// Delete plaintext backups / restore targets (otherwise their presence refuses
        /// the migration).
        #[arg(long)]
        purge_plaintext_backups: bool,
    },
}

#[derive(Subcommand)]
enum BackupCmd {
    Create {
        id: String,
        #[arg(long)]
        include_rowstore: bool,
        #[arg(long, default_value = "analyst")]
        user: String,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        unlock: bool,
        /// KeyPass directory: used to unlock (with --unlock) and, D4-E, to record the new
        /// backup as this client's backup anchor (the one backup it authorizes for an
        /// emergency restore).
        #[arg(long)]
        keypass_dir: Option<PathBuf>,
        #[arg(long)]
        master_file: Option<PathBuf>,
    },
    /// D4-E: offline, keyless — stage an encrypted backup (carrying its key store) as an
    /// empty data root on a host without the source installation. It opens only when the
    /// client unlocks with `vault unlock --restore-authorized-backup` for exactly this backup.
    StageEmergency {
        /// Published backup directory (`backup-<id>`).
        #[arg(long)]
        backup_dir: PathBuf,
        /// New data root (must be absent or empty).
        #[arg(long)]
        data_root: PathBuf,
    },
    Verify {
        id: String,
        #[arg(long, default_value = "analyst")]
        user: String,
        #[arg(long)]
        password: Option<String>,
    },
    List {
        #[arg(long, default_value = "analyst")]
        user: String,
        #[arg(long)]
        password: Option<String>,
    },
    Restore {
        id: String,
        #[arg(long)]
        target: String,
        #[arg(long, default_value = "analyst")]
        user: String,
        #[arg(long)]
        password: Option<String>,
    },
    Recover {
        #[arg(long)]
        target: String,
        #[arg(long, default_value = "analyst")]
        user: String,
        #[arg(long)]
        password: Option<String>,
    },
    Status {
        #[arg(long)]
        target: String,
        #[arg(long, default_value = "analyst")]
        user: String,
        #[arg(long)]
        password: Option<String>,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("dmc: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    let view = ViewLog::new(cli.view);
    let data_dir = cli.data_dir.clone();

    match cli.cmd {
        Cmd::Serve {
            data_dir,
            socket,
            dev,
            keypass_dir,
            http,
            pgwire,
        } => {
            // validated before anything touches the disk
            let pgwire_addr = match pgwire {
                Some(s) => {
                    let addr = s
                        .parse::<std::net::SocketAddr>()
                        .map_err(|e| format!("invalid --pgwire address: {e}"))?;
                    dmc_pgwire::require_loopback(&addr).map_err(|e| e.to_string())?;
                    Some(addr)
                }
                None => None,
            };
            std::fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;
            let sink = match (dev, keypass_dir) {
                (true, None) => serve::UnlockSink::DevPlainFile,
                (true, Some(_)) => {
                    return Err("--dev cannot be combined with --keypass-dir".into());
                }
                (false, Some(dir)) => {
                    let password = match std::env::var(serve::ENV_KEYPASS_PASSWORD) {
                        Ok(p) if !p.is_empty() => p,
                        _ => {
                            let a = rpassword::prompt_password("New KeyPass password: ")
                                .map_err(|e| e.to_string())?;
                            let b = rpassword::prompt_password("Repeat KeyPass password: ")
                                .map_err(|e| e.to_string())?;
                            if a != b {
                                return Err("KeyPass passwords do not match".into());
                            }
                            a
                        }
                    };
                    serve::UnlockSink::KeyPass {
                        dir,
                        password: zeroize::Zeroizing::new(password),
                    }
                }
                (false, None) => serve::UnlockSink::Discard,
            };
            let socket = socket.unwrap_or_else(default_socket_path);
            let http_addr = match http {
                Some(s) => Some(
                    s.parse::<std::net::SocketAddr>()
                        .map_err(|e| format!("invalid --http address: {e}"))?,
                ),
                None => None,
            };
            let (_handle, outcome) =
                spawn_server(data_dir, socket, dev, sink, http_addr, pgwire_addr, &view)?;
            println!("DMC Core listening on {}", outcome.socket.display());
            println!("data_root={}", outcome.data_root.display());
            if let Some(addr) = http_addr {
                println!("HTTP adapter on http://{addr} (shared RuntimeHub)");
            }
            if outcome.dev_users {
                println!("dev user: analyst / pw");
            }
            match (&outcome.master_file, outcome.dev_users) {
                (Some(m), true) => println!("dev master file: {}", m.display()),
                (Some(m), false) => println!("unlock: dmc ... --unlock --keypass-dir {}", m.display()),
                (None, _) => println!("vault Locked; no unlock material persisted (use --keypass-dir)"),
            }
            println!("Press Ctrl+C to stop.");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        Cmd::Identity {
            cmd:
                IdentityCmd::BootstrapOperator {
                    data_dir,
                    socket,
                    name,
                    database,
                    schema,
                    password_stdin: _,
                },
        } => {
            let args = identity::BootstrapArgs {
                socket: socket.unwrap_or_else(default_socket_path),
                data_dir,
                name,
                database,
                schema,
            };
            let id = identity::bootstrap_operator(&args, &mut std::io::stdin().lock())?;
            println!("first operator created: {id}");
            println!("bootstrap consumed — it can never be run again on this data directory");
            Ok(())
        }
        Cmd::EncryptMigrate {
            source,
            target,
            layout,
            table,
            column,
            owner_column,
            identities,
            keyring_dir,
            owners,
            purge_source,
        } => encrypt::run(encrypt::EncryptMigrateArgs {
            source,
            target,
            layout,
            table,
            column,
            owner_column,
            identities,
            keyring_dir,
            owners,
            purge_source,
        }),
        Cmd::Keys => {
            view::print_key_hierarchy_stdout();
            if view.is_enabled() {
                view::print_key_hierarchy(&view);
            }
            Ok(())
        }
        Cmd::Inspect { data_dir } => {
            view::inspect_data_root(&view, &data_dir);
            Ok(())
        }
        Cmd::Status { user, password } => {
            let password = password_or_prompt(password, "Password")?;
            let mut session = Session::connect_local(cli.socket, view, data_dir)?;
            session.authenticate(&user, &password)?;
            let vault = session.vault_status()?;
            println!("vault={vault:?}");
            let diag = session.diagnostics()?;
            print_diagnostics(&diag);
            Ok(())
        }
        Cmd::Vault { cmd } => match cmd {
            VaultCmd::Status { user, password } => {
                let password = password_or_prompt(password, "Password")?;
                let mut session = Session::connect_local(cli.socket, view, data_dir)?;
                session.authenticate(&user, &password)?;
                let v = session.vault_status()?;
                println!("{v:?}");
                Ok(())
            }
            VaultCmd::MigrateStorage {
                user,
                keypass_dir,
                purge_plaintext_backups,
            } => {
                let password = password_or_prompt(None, "Password")?;
                let kp_pass = password_or_prompt(None, "KeyPass password")?;
                let mut session = Session::connect_local(cli.socket, view, data_dir)?;
                session.authenticate(&user, &password)?;
                let (events, tables, purged) = session.storage_migrate_keypass(
                    &keypass_dir,
                    &kp_pass,
                    purge_plaintext_backups,
                )?;
                println!(
                    "storage migrated: events={events} tables={tables} purged_artifacts={purged}"
                );
                Ok(())
            }
            VaultCmd::Unlock {
                user,
                password,
                keypass_dir,
                master_file,
                keypass_password,
                accept_rollback,
                restore_authorized_backup,
            } => {
                let password = password_or_prompt(password, "Password")?;
                let mut session = Session::connect_local(cli.socket, view, data_dir)?;
                session.authenticate(&user, &password)?;
                let mode = if restore_authorized_backup {
                    UnlockMode::RestoreAuthorizedBackup
                } else if accept_rollback {
                    UnlockMode::AcceptRollback
                } else {
                    UnlockMode::Anchored
                };
                unlock_session(&mut session, keypass_dir, master_file, keypass_password, mode)?;
                Ok(())
            }
            VaultCmd::Lock { user, password } => {
                let password = password_or_prompt(password, "Password")?;
                let mut session = Session::connect_local(cli.socket, view, data_dir)?;
                session.authenticate(&user, &password)?;
                let v = session.vault_lock()?;
                println!("{v:?}");
                Ok(())
            }
        },
        Cmd::Backup { ref cmd } => run_backup(cmd, &cli, view, data_dir),
        Cmd::Shell {
            user,
            password,
            unlock,
            keypass_dir,
            master_file,
        } => {
            let password = password_or_prompt(password, "Password")?;
            let mut session = Session::connect_local(cli.socket, view, data_dir)?;
            session.authenticate(&user, &password)?;
            if unlock {
                unlock_session(&mut session, keypass_dir, master_file, None, UnlockMode::Anchored)?;
            }
            shell::run_shell(&mut session)?;
            Ok(())
        }
        Cmd::Sql {
            query,
            user,
            password,
            unlock,
            keypass_dir,
            master_file,
        } => {
            let password = password_or_prompt(password, "Password")?;
            let mut session = Session::connect_local(cli.socket, view, data_dir)?;
            session.authenticate(&user, &password)?;
            if unlock {
                unlock_session(&mut session, keypass_dir, master_file, None, UnlockMode::Anchored)?;
            }
            match session.sql_execute(&query)? {
                ExecuteOutcome::Ok => println!("OK"),
                ExecuteOutcome::Rows(rows) => print_sql_table(&rows),
            }
            Ok(())
        }
        Cmd::Query {
            query,
            user,
            password,
            unlock,
            keypass_dir,
            master_file,
        } => {
            let password = password_or_prompt(password, "Password")?;
            let mut session = Session::connect_local(cli.socket, view, data_dir)?;
            session.authenticate(&user, &password)?;
            if unlock {
                unlock_session(&mut session, keypass_dir, master_file, None, UnlockMode::Anchored)?;
            }
            let rows = session.sql_query(&query)?;
            print_sql_table(&rows);
            Ok(())
        }
    }
}

/// How a KeyPass unlock treats storage freshness.
#[derive(Clone, Copy, PartialEq, Eq)]
enum UnlockMode {
    /// D4-D: the client's anchor is enforced.
    Anchored,
    /// D4-D: explicit acceptance of older storage (anchor reset).
    AcceptRollback,
    /// D4-E: emergency restore of exactly the backup in the client's backup anchor.
    RestoreAuthorizedBackup,
}

fn unlock_session(
    session: &mut Session,
    keypass_dir: Option<PathBuf>,
    master_file: Option<PathBuf>,
    keypass_password: Option<String>,
    mode: UnlockMode,
) -> Result<(), String> {
    if mode != UnlockMode::Anchored && keypass_dir.is_none() {
        return Err("--accept-rollback / --restore-authorized-backup need --keypass-dir".into());
    }
    if let Some(dir) = keypass_dir {
        let kp_pass = password_or_prompt(keypass_password, "KeyPass password")?;
        if mode == UnlockMode::RestoreAuthorizedBackup {
            let (v, generation) = session.vault_unlock_keypass_restoring_backup(&dir, &kp_pass)?;
            eprintln!(
                "emergency restore of the client-authorized backup opened at generation \
                 {generation}; the anti-rollback anchor was reset to it"
            );
            println!("vault={v:?}");
            return Ok(());
        }
        if mode == UnlockMode::AcceptRollback {
            let (v, generation) = session.vault_unlock_keypass_accepting_rollback(&dir, &kp_pass)?;
            eprintln!(
                "WARNING: accepted storage generation {generation} without the anti-rollback \
                 check; the anchor was reset to it"
            );
            println!("vault={v:?}");
            return Ok(());
        }
        let v = session.vault_unlock_keypass(&dir, &kp_pass)?;
        println!("vault={v:?}");
        return Ok(());
    }
    let master_path = master_file
        .or_else(|| session.default_master_path())
        .ok_or_else(|| "укажите --master-file или --data-dir с .dmc-dev-master.hex".to_string())?;
    let v = session.vault_unlock_mock(&master_path)?;
    println!("vault={v:?}");
    Ok(())
}

fn password_or_prompt(value: Option<String>, label: &str) -> Result<String, String> {
    if let Some(v) = value {
        return Ok(v);
    }
    rpassword::prompt_password(format!("{label}: ")).map_err(|e| e.to_string())
}

fn run_backup(
    cmd: &BackupCmd,
    cli: &Cli,
    view: ViewLog,
    data_dir: Option<PathBuf>,
) -> Result<(), String> {
    match cmd {
        BackupCmd::Create {
            id,
            include_rowstore,
            user,
            password,
            unlock,
            keypass_dir,
            master_file,
        } => {
            let password = password_or_prompt(password.clone(), "Password")?;
            let mut session = Session::connect_local(cli.socket.clone(), view, data_dir)?;
            session.authenticate(user, &password)?;
            if *unlock {
                unlock_session(
                    &mut session,
                    keypass_dir.clone(),
                    master_file.clone(),
                    None,
                    UnlockMode::Anchored,
                )?;
            }
            let r = session.backup_create(id, *include_rowstore)?;
            println!(
                "backup_id={} checkpoint_sequence={} manifest_sealed_sha256={}",
                r.backup_id, r.checkpoint_sequence, r.manifest_sealed_sha256
            );
            if let Some(dir) = keypass_dir {
                if session.record_backup_anchor(dir, &r)? {
                    println!("backup anchor: this client now authorizes backup {}", r.backup_id);
                }
            }
            Ok(())
        }
        BackupCmd::StageEmergency {
            backup_dir,
            data_root,
        } => {
            let staged = dmc_ops::stage_emergency_restore(backup_dir, data_root)?;
            println!(
                "staged backup_id={} checkpoint_sequence={} manifest_sealed_sha256={}",
                staged.backup_id, staged.checkpoint_sequence, staged.manifest_sealed_sha256
            );
            println!(
                "start the server on this data root, then unlock with \
                 `dmc vault unlock --keypass-dir <dir> --restore-authorized-backup`"
            );
            Ok(())
        }
        BackupCmd::Verify { id, user, password } => {
            let password = password_or_prompt(password.clone(), "Password")?;
            let mut session = Session::connect_local(cli.socket.clone(), view, data_dir)?;
            session.authenticate(user, &password)?;
            let r = session.backup_verify(id)?;
            println!(
                "backup_id={} checkpoint_sequence={} valid={} errors={:?}",
                r.backup_id, r.checkpoint_sequence, r.valid, r.errors
            );
            Ok(())
        }
        BackupCmd::List { user, password } => {
            let password = password_or_prompt(password.clone(), "Password")?;
            let mut session = Session::connect_local(cli.socket.clone(), view, data_dir)?;
            session.authenticate(user, &password)?;
            for i in session.backup_list()? {
                println!(
                    "{} seq={} valid={} state={} created_at={}",
                    i.backup_id, i.checkpoint_sequence, i.valid, i.state, i.created_at
                );
            }
            Ok(())
        }
        BackupCmd::Restore {
            id,
            target,
            user,
            password,
        } => {
            let password = password_or_prompt(password.clone(), "Password")?;
            let mut session = Session::connect_local(cli.socket.clone(), view, data_dir)?;
            session.authenticate(user, &password)?;
            let r = session.backup_restore(id, target)?;
            println!(
                "backup_id={} target_id={} checkpoint_sequence={} vault_locked={} sessions_invalid={}",
                r.backup_id, r.target_id, r.checkpoint_sequence, r.vault_locked, r.sessions_invalid
            );
            Ok(())
        }
        BackupCmd::Recover {
            target,
            user,
            password,
        } => {
            let password = password_or_prompt(password.clone(), "Password")?;
            let mut session = Session::connect_local(cli.socket.clone(), view, data_dir)?;
            session.authenticate(user, &password)?;
            let r = session.backup_recover(target)?;
            println!(
                "target_id={} checkpoint_sequence={} state={} vault_locked={} sessions_invalid={}",
                r.target_id, r.checkpoint_sequence, r.state, r.vault_locked, r.sessions_invalid
            );
            Ok(())
        }
        BackupCmd::Status {
            target,
            user,
            password,
        } => {
            let password = password_or_prompt(password.clone(), "Password")?;
            let mut session = Session::connect_local(cli.socket.clone(), view, data_dir)?;
            session.authenticate(user, &password)?;
            let r = session.backup_status(target)?;
            println!(
                "target_id={} state={} checkpoint_sequence={} vault_locked={} sessions_invalid={}",
                r.target_id, r.state, r.checkpoint_sequence, r.vault_locked, r.sessions_invalid
            );
            Ok(())
        }
    }
}
