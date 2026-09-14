//! Toggle HTTP admin UI (`server.json` `ui_enabled`) and reset UI login.

use crate::control::{
    format_ui_auth_reset, load_server_config, reset_ui_auth, resolve_ui_access_key,
    resolve_ui_dist, save_server_config, AvroraPaths, ServerConfig, DEFAULT_UI_ACCESS_KEY,
};
use crate::menu::daemon;
use crate::menu::prompt;

pub fn submenu(paths: &AvroraPaths) -> Result<(), String> {
    loop {
        let file = load_server_config(&paths.control_dir).unwrap_or_default();
        let dist = resolve_ui_dist();
        let state = if file.ui_enabled { "вкл" } else { "выкл" };
        let dist_s = dist
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "(не найден ui/dist)".into());
        let items = [
            "Включить UI",
            "Выключить UI",
            "Сброс UI access key (2FA)",
            "Назад",
        ];
        match prompt::select(&format!("UI [{state}]  dist={dist_s}"), &items)? {
            0 => set_ui(paths, true)?,
            1 => set_ui(paths, false)?,
            2 => reset_ui_login(paths)?,
            _ => return Ok(()),
        }
    }
}

fn set_ui(paths: &AvroraPaths, enabled: bool) -> Result<(), String> {
    let mut cfg = load_server_config(&paths.control_dir).unwrap_or_default();
    cfg.ui_enabled = enabled;
    if cfg.http_addr.trim().is_empty() {
        cfg.http_addr = ServerConfig::resolve(&paths.control_dir).http_addr;
    }
    if cfg.control_addr.trim().is_empty() {
        cfg.control_addr = ServerConfig::resolve(&paths.control_dir).control_addr;
    }
    let path = save_server_config(&paths.control_dir, &cfg)?;
    let mut msg = format!(
        "ui_enabled={}  wrote {}",
        if enabled { "yes" } else { "no" },
        path.display()
    );
    if daemon::is_running(&paths.control_dir) {
        msg.push_str("\nПерезапустите serve, чтобы применить.");
        if prompt::confirm("Перезапустить serve сейчас?", true)? {
            daemon::stop(&paths.control_dir)?;
            let pid = daemon::start(paths)?;
            msg.push_str(&format!("\nserve restarted pid={pid}"));
        }
    }
    prompt::show(&msg);
    Ok(())
}

fn reset_ui_login(paths: &AvroraPaths) -> Result<(), String> {
    if !prompt::confirm(
        "Сбросить UI access key и 2FA?\n\
         Текущие сессии браузера перестанут работать. Vault не трогаем.",
        false,
    )? {
        return Ok(());
    }
    if daemon::is_running(&paths.control_dir) {
        if !prompt::confirm("Остановить serve перед сбросом UI auth?", true)? {
            prompt::show("Сначала остановите serve — иначе в памяти останется старый auth.");
            return Ok(());
        }
        daemon::stop(&paths.control_dir)?;
    }

    let access_key = prompt_ui_access_key()?;
    match reset_ui_auth(&paths.db_path, Some(&access_key)) {
        Ok(r) => {
            let mut msg = format_ui_auth_reset(&r);
            if prompt::confirm("Запустить serve сейчас?", true)? {
                match daemon::start(paths) {
                    Ok(pid) => msg.push_str(&format!("\nserve started pid={pid}")),
                    Err(e) => msg.push_str(&format!("\nserve start failed: {e}")),
                }
            }
            prompt::show(&msg);
        }
        Err(e) => prompt::show_err(e),
    }
    Ok(())
}

fn prompt_ui_access_key() -> Result<String, String> {
    loop {
        let typed = prompt::input(
            "Новый UI access key (вход в браузер, ≥8 символов)",
            Some(DEFAULT_UI_ACCESS_KEY),
        )?;
        match resolve_ui_access_key(Some(&typed)) {
            Ok(k) => return Ok(k),
            Err(e) => prompt::show_err(e),
        }
    }
}
