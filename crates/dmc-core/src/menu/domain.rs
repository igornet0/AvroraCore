//! Invite host / control-plane init.

use crate::control::{
    control_port_from_env, export_invite, run_init, write_invite_file, AvroraPaths,
};
use crate::menu::prompt;

pub fn submenu(paths: &AvroraPaths) -> Result<(), String> {
    loop {
        let items = [
            "Показать invite",
            "Настроить домен (invite host)",
            "Инициализировать control plane",
            "Назад",
        ];
        match prompt::select("Домен / доступ", &items)? {
            0 => show_invite(paths),
            1 => set_domain(paths)?,
            2 => init_control(paths)?,
            _ => return Ok(()),
        }
    }
}

fn show_invite(paths: &AvroraPaths) {
    let path = paths.control_dir.join("invite.json");
    if !path.is_file() {
        prompt::show("invite.json отсутствует — сначала init или «настроить домен»");
        return;
    }
    match std::fs::read_to_string(&path) {
        Ok(body) => prompt::show(&format!("{}\n\n{}", path.display(), body)),
        Err(e) => prompt::show_err(e),
    }
}

fn set_domain(paths: &AvroraPaths) -> Result<(), String> {
    if !paths.control_initialized() {
        prompt::show("Control plane не инициализирован. Выберите «Инициализировать control plane».");
        return Ok(());
    }
    let host = prompt::input("Hostname / домен", Some("127.0.0.1"))?;
    let host = host.trim();
    if host.is_empty() {
        return Ok(());
    }
    let port = control_port_from_env();
    match export_invite(&paths.control_dir, host, port) {
        Ok(invite) => {
            let path = write_invite_file(&paths.control_dir, &invite)?;
            prompt::show(&format!(
                "wrote {}\n{}",
                path.display(),
                serde_json::to_string_pretty(&invite).unwrap_or_default()
            ));
        }
        Err(e) => {
            prompt::show(&format!(
                "{e}\n\nДля нового SAN в сертификате: `avrora init --invite-host {host}`\n\
                 (init откажется, если control уже инициализирован — нужен `avrora reset --yes`)."
            ));
        }
    }
    Ok(())
}

fn init_control(paths: &AvroraPaths) -> Result<(), String> {
    if paths.control_initialized() {
        prompt::show(&format!(
            "уже инициализирован: {}\nПовторный init требует `avrora reset --yes`.",
            paths.control_dir.display()
        ));
        return Ok(());
    }
    let host = prompt::input("Invite host", Some("127.0.0.1"))?;
    let host = host.trim();
    if host.is_empty() {
        return Ok(());
    }
    let port = control_port_from_env();
    match run_init(&paths.control_dir, host, port) {
        Ok(out) => prompt::show(&out),
        Err(e) => prompt::show_err(e),
    }
    Ok(())
}
