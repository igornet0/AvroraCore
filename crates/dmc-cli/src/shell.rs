//! Interactive SQL shell.

use std::io::{self, Write};

use dmc_client::ExecuteOutcome;

use crate::session::{print_sql_table, Session};

pub fn run_shell(session: &mut Session) -> Result<(), String> {
    println!("DMC shell — SQL команды; мета: .help .status .vault .unlock .lock .keys .inspect .view on|off .quit");
    if session.view.is_enabled() {
        println!("(view mode ON — трассировка на stderr)");
    }
    let mut line = String::new();
    loop {
        line.clear();
        print!("dmc> ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        if io::stdin().read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('.') {
            match handle_meta(session, trimmed) {
                Ok(true) => break,
                Ok(false) => {}
                Err(e) => eprintln!("error: {e}"),
            }
            continue;
        }
        match session.sql_execute(trimmed) {
            Ok(ExecuteOutcome::Ok) => println!("OK"),
            Ok(ExecuteOutcome::Rows(rows)) => print_sql_table(&rows),
            Err(e) => eprintln!("error: {e}"),
        }
    }
    Ok(())
}

fn handle_meta(session: &mut Session, cmd: &str) -> Result<bool, String> {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    match parts.first().map(|s| *s) {
        Some(".help") | Some(".h") => {
            println!(".status  — vault + connection");
            println!(".vault    — vault_status");
            println!(".unlock   — dev unlock (--dev master file)");
            println!(".lock     — vault_lock");
            println!(".keys     — иерархия ключей");
            println!(".inspect  — hex preview файлов на диске");
            println!(".view on|off");
            println!(".quit     — выход");
            Ok(false)
        }
        Some(".quit") | Some(".exit") => Ok(true),
        Some(".status") => {
            println!("phase={:?}", session.phase());
            if let Ok(v) = session.vault_status() {
                println!("vault={v:?}");
            }
            Ok(false)
        }
        Some(".vault") => {
            let v = session.vault_status()?;
            println!("{v:?}");
            Ok(false)
        }
        Some(".unlock") => {
            let path = session
                .default_master_path()
                .ok_or_else(|| "нет --data-dir для dev master".to_string())?;
            let v = session.vault_unlock_mock(&path)?;
            println!("vault={v:?}");
            Ok(false)
        }
        Some(".lock") => {
            let v = session.vault_lock()?;
            println!("vault={v:?}");
            Ok(false)
        }
        Some(".keys") => {
            session.show_keys();
            Ok(false)
        }
        Some(".inspect") => {
            session.inspect_disk();
            Ok(false)
        }
        Some(".view") => {
            let on = parts.get(1).map(|s| *s == "on").unwrap_or(true);
            session.view.set_enabled(on);
            println!("view={}", if on { "on" } else { "off" });
            Ok(false)
        }
        _ => Err(format!("unknown meta command: {cmd}")),
    }
}
