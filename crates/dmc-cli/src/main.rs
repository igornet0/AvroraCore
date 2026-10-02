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
        /// Dev bootstrap: analyst/pw + users table + .dmc-dev-master.hex
        #[arg(long)]
        dev: bool,
        /// Co-host HTTP admin on this address (shared RuntimeHub with DMC IPC)
        #[arg(long)]
        http: Option<String>,
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
    },
    Lock {
        #[arg(long, default_value = "analyst")]
        user: String,
        #[arg(long)]
        password: Option<String>,
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
        #[arg(long)]
        keypass_dir: Option<PathBuf>,
        #[arg(long)]
        master_file: Option<PathBuf>,
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
            http,
        } => {
            std::fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;
            let socket = socket.unwrap_or_else(default_socket_path);
            let http_addr = match http {
                Some(s) => Some(
                    s.parse::<std::net::SocketAddr>()
                        .map_err(|e| format!("invalid --http address: {e}"))?,
                ),
                None => None,
            };
            let (_handle, outcome) = spawn_server(data_dir, socket, dev, http_addr, &view)?;
            println!("DMC Core listening on {}", outcome.socket.display());
            println!("data_root={}", outcome.data_root.display());
            if let Some(addr) = http_addr {
                println!("HTTP adapter on http://{addr} (shared RuntimeHub)");
            }
            if outcome.dev_users {
                println!("dev user: analyst / pw");
            }
            if let Some(m) = &outcome.master_file {
                println!("dev master file: {}", m.display());
            }
            println!("Press Ctrl+C to stop.");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
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
            VaultCmd::Unlock {
                user,
                password,
                keypass_dir,
                master_file,
                keypass_password,
            } => {
                let password = password_or_prompt(password, "Password")?;
                let mut session = Session::connect_local(cli.socket, view, data_dir)?;
                session.authenticate(&user, &password)?;
                unlock_session(
                    &mut session,
                    keypass_dir,
                    master_file,
                    keypass_password,
                )?;
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
                unlock_session(&mut session, keypass_dir, master_file, None)?;
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
                unlock_session(&mut session, keypass_dir, master_file, None)?;
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
                unlock_session(&mut session, keypass_dir, master_file, None)?;
            }
            let rows = session.sql_query(&query)?;
            print_sql_table(&rows);
            Ok(())
        }
    }
}

fn unlock_session(
    session: &mut Session,
    keypass_dir: Option<PathBuf>,
    master_file: Option<PathBuf>,
    keypass_password: Option<String>,
) -> Result<(), String> {
    if let Some(dir) = keypass_dir {
        let kp_pass = password_or_prompt(keypass_password, "KeyPass password")?;
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
                )?;
            }
            let r = session.backup_create(id, *include_rowstore)?;
            println!(
                "backup_id={} checkpoint_sequence={}",
                r.backup_id, r.checkpoint_sequence
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
