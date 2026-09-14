//! Interactive operator menu (`avrora menu`).

pub mod daemon;

mod browse;
mod domain;
mod prompt;
mod roles;
mod server;
mod ui;
mod users;
mod vault;

use crate::control::{load_server_config, AvroraPaths};

fn warn_ide_terminal() {
    let term = std::env::var("TERM_PROGRAM").unwrap_or_default();
    if term.eq_ignore_ascii_case("vscode")
        || term.eq_ignore_ascii_case("cursor")
        || std::env::var_os("CURSOR_TRACE_ID").is_some()
        || std::env::var_os("VSCODE_IPC_HOOK").is_some()
    {
        eprintln!(
            "warning: встроенный терминал IDE может принудительно завершать TUI (~30s)."
        );
        eprintln!("         Надёжнее: Terminal.app / iTerm → avrora-serve menu");
        eprintln!();
    }
}

/// Run the interactive menu until the user exits (blocking thread — dialoguer + tokio).
pub fn run(handle: &tokio::runtime::Handle) -> Result<(), String> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return Err(
            "нужен интерактивный терминал (TTY); не запускайте через pipe/CI".into(),
        );
    }
    if !std::io::stdout().is_terminal() {
        return Err(
            "stdout должен быть терминалом; откройте Terminal.app / iTerm".into(),
        );
    }
    warn_ide_terminal();
    let paths = AvroraPaths::resolve();
    let _ = daemon::status(&paths.control_dir);
    println!("Avrora Menu");
    println!("  control {}", paths.control_dir.display());
    println!("  db      {}", paths.db_path.display());
    println!();
    println!("v1: один vault на инстанс. Смена UI требует перезапуска serve.");
    println!("Unlock production (USB KeyPass) — через avrora-client.");
    println!("Остановить serve: make down  или  scripts/build/avrora-down.sh");
    println!();

    loop {
        let ui = load_server_config(&paths.control_dir)
            .map(|c| c.ui_enabled)
            .unwrap_or(true);
        let serve = if daemon::is_running(&paths.control_dir) {
            "UP"
        } else {
            "DOWN"
        };
        let ui_label = format!("UI      [{}]", if ui { "вкл" } else { "выкл" });
        let serve_label = format!("Сервер  [{serve}]");
        let items = [
            serve_label.as_str(),
            ui_label.as_str(),
            "Домен / invite",
            "База данных",
            "Роли",
            "Пользователи",
            "Просмотр БД",
            "Выход",
        ];
        match prompt::select("Avrora", &items) {
            Ok(0) => handle.block_on(server::submenu(&paths))?,
            Ok(1) => ui::submenu(&paths)?,
            Ok(2) => domain::submenu(&paths)?,
            Ok(3) => handle.block_on(vault::submenu(&paths))?,
            Ok(4) => handle.block_on(roles::submenu(&paths))?,
            Ok(5) => handle.block_on(users::submenu(&paths))?,
            Ok(6) => handle.block_on(browse::submenu(&paths))?,
            Ok(_) => return Ok(()),
            Err(e) => {
                if e.contains("interrupted") || e.contains("canceled") {
                    return Ok(());
                }
                return Err(e);
            }
        }
    }
}
