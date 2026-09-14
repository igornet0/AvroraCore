//! Vault create / unlock / lock / reset / devo-init.

use crate::control::{
    format_auth_init, format_devo_init, load_dev_master_hex, reset_server_data, run_auth_init,
    run_devo_init, AvroraPaths, DEFAULT_UI_ACCESS_KEY, DEV_MASTER_FILE, resolve_ui_access_key,
};
use crate::menu::daemon;
use crate::menu::prompt;
use crate::runtime::{DbStatus, Runtime};

pub async fn submenu(paths: &AvroraPaths) -> Result<(), String> {
    loop {
        let rt = Runtime::at_path(&paths.db_path);
        let status = rt.status().await;
        let items = [
            "Статус",
            "Создать пустую БД",
            "Создать БД + auth (devo-init)",
            "Dev provisioning (root + роли)",
            "Auth vault (отдельный файл)",
            "Разблокировать",
            "Заблокировать",
            "Сброс (wipe)",
            "Назад",
        ];
        match prompt::select(&format!("База данных [{status:?}]"), &items)? {
            0 => show_status(paths, &rt).await,
            1 => create_vault(paths, &rt).await?,
            2 => create_with_auth(paths, &rt).await?,
            3 => devo_init(paths, &rt).await?,
            4 => create_auth_vault(paths).await?,
            5 => unlock_vault(&rt).await?,
            6 => lock_vault(&rt).await?,
            7 => reset_vault(paths).await?,
            _ => return Ok(()),
        }
    }
}

async fn show_status(paths: &AvroraPaths, rt: &Runtime) {
    let status = rt.status().await;
    let provisioned = rt.is_dev_provisioned().await.unwrap_or(false);
    let mut body = format!(
        "db_path={}\nstatus={status:?}\ndev_provisioned={}\n",
        paths.db_path.display(),
        if provisioned { "yes" } else { "no" }
    );
    if let Some(id) = rt.db_id().await {
        body.push_str(&format!("db_id={id}\n"));
    }
    prompt::show(&body);
}

async fn require_stopped(paths: &AvroraPaths) -> Result<bool, String> {
    if !daemon::is_running(&paths.control_dir) {
        return Ok(true);
    }
    if prompt::confirm("Serve запущен. Остановить перед изменением vault?", true)? {
        daemon::stop(&paths.control_dir)?;
        Ok(true)
    } else {
        prompt::show("операция отменена");
        Ok(false)
    }
}

async fn create_vault(paths: &AvroraPaths, rt: &Runtime) -> Result<(), String> {
    if !require_stopped(paths).await? {
        return Ok(());
    }
    match rt.create().await {
        Ok((hex, db_id)) => {
            let parent = paths.db_path.parent();
            let mut extra = String::new();
            if let Some(dir) = parent {
                let path = dir.join(DEV_MASTER_FILE);
                if std::fs::write(&path, format!("{hex}\n")).is_ok() {
                    extra = format!("\nmaster saved {}", path.display());
                }
            }
            prompt::show(&format!(
                "vault created\ndb_id={db_id}\nmaster_key_hex={hex}{extra}\n\n\
                 Дальше: Dev provisioning, чтобы появились root role/user."
            ));
        }
        Err(e) => prompt::show_err(e),
    }
    Ok(())
}

async fn create_with_auth(paths: &AvroraPaths, rt: &Runtime) -> Result<(), String> {
    if !require_stopped(paths).await? {
        return Ok(());
    }
    let demo = prompt::confirm("Seed demo (company/finance, hr roles)?", false)?;
    let ui_access_key = prompt_ui_access_key()?;
    let rt = prepare_devo_init(paths, rt).await?;
    match run_devo_init(&rt, demo, None, true, Some(&ui_access_key)).await {
        Ok(r) => prompt::show(&format_devo_init(&r, demo)),
        Err(e) => prompt::show_err(e),
    }
    Ok(())
}

async fn create_auth_vault(paths: &AvroraPaths) -> Result<(), String> {
    let auth_path = paths.auth_db_path();
    if auth_path.is_file()
        || dmc_journal::StorageLayout::from_db_path(&auth_path).vault_exists()
    {
        prompt::show(&format!(
            "auth vault уже существует: {}\n\
             Подключите в сервисе: AVRORA_DATA={}",
            auth_path.display(),
            auth_path.display()
        ));
        return Ok(());
    }
    if !prompt::confirm(
        &format!("Создать auth vault в {}?", auth_path.display()),
        true,
    )? {
        return Ok(());
    }
    let rt = Runtime::at_path(&auth_path);
    let ui_access_key = prompt_ui_access_key()?;
    match run_auth_init(&rt, None, true, Some(&ui_access_key)).await {
        Ok(r) => prompt::show(&format!(
            "{}\n\
             embed: AVRORA_DATA={}",
            format_auth_init(&r),
            auth_path.display()
        )),
        Err(e) => prompt::show_err(e),
    }
    Ok(())
}

async fn devo_init(paths: &AvroraPaths, rt: &Runtime) -> Result<(), String> {
    if !require_stopped(paths).await? {
        return Ok(());
    }
    let demo = prompt::confirm("Seed demo (company/finance, hr roles)?", false)?;
    let ui_access_key = prompt_ui_access_key()?;
    let rt = prepare_devo_init(paths, rt).await?;
    match run_devo_init(&rt, demo, None, true, Some(&ui_access_key)).await {
        Ok(r) => prompt::show(&format_devo_init(&r, demo)),
        Err(e) => prompt::show_err(e),
    }
    Ok(())
}

fn prompt_ui_access_key() -> Result<String, String> {
    loop {
        let typed = prompt::input(
            "UI access key (вход в браузер, ≥8 символов)",
            Some(DEFAULT_UI_ACCESS_KEY),
        )?;
        match resolve_ui_access_key(Some(&typed)) {
            Ok(k) => return Ok(k),
            Err(e) => prompt::show_err(e),
        }
    }
}

async fn unlock_vault(rt: &Runtime) -> Result<(), String> {
    if rt.status().await != DbStatus::Locked {
        prompt::show(&format!("vault is {:?}", rt.status().await));
        return Ok(());
    }
    let hex = match prompt_master_hex(rt, None).await? {
        Some(h) => h,
        None => return Ok(()),
    };
    match rt.unlock(&hex).await {
        Ok(_) => prompt::show("unlocked"),
        Err(e) => prompt::show_err(e),
    }
    Ok(())
}

/// When vault is locked, unlock (or wipe) before devo-init. Returns a fresh runtime handle.
async fn prepare_devo_init(paths: &AvroraPaths, rt: &Runtime) -> Result<Runtime, String> {
    match rt.status().await {
        DbStatus::Empty | DbStatus::Unlocked => Ok(Runtime::at_path(&paths.db_path)),
        DbStatus::Locked => {
            match prompt_master_hex(rt, Some(paths)).await? {
                Some(hex) => {
                    rt.unlock(&hex).await.map_err(|e| e.to_string())?;
                    Ok(Runtime::at_path(&paths.db_path))
                }
                None => Ok(Runtime::at_path(&paths.db_path)),
            }
        }
    }
}

/// Prompt for master key hex. With `paths`, empty input can wipe the vault (devo-init recovery).
async fn prompt_master_hex(
    rt: &Runtime,
    paths: Option<&AvroraPaths>,
) -> Result<Option<String>, String> {
    if let Ok(h) = load_dev_master_hex(rt).await {
        if prompt::confirm("Vault locked. Разблокировать из .avrora-dev-master.hex?", true)? {
            return Ok(Some(h));
        }
    } else {
        prompt::show(
            "Vault locked.\n\
             Файл .avrora-dev-master.hex не найден.\n\
             Master key — 64 hex-символа (не TLS-сертификат, не пароль UI).\n\
             Сохраняется при «Создать пустую БД» / devo-init.",
        );
    }

    loop {
        let label = if paths.is_some() {
            "Master key hex (Enter = сброс vault)"
        } else {
            "Master key hex"
        };
        let typed = prompt::input(label, None)?;
        let t = typed.trim();
        if !t.is_empty() {
            return Ok(Some(t.to_string()));
        }
        if let Some(paths) = paths {
            if prompt::confirm(
                "Сбросить vault (wipe) и продолжить devo-init с новым master key?",
                false,
            )? {
                reset_server_data(paths, true).map_err(|e| e.to_string())?;
                prompt::show("vault сброшен — будет создан заново");
                return Ok(None);
            }
        }
        if !prompt::confirm("Повторить ввод?", true)? {
            return Err("отменено".into());
        }
    }
}

async fn lock_vault(rt: &Runtime) -> Result<(), String> {
    match rt.lock().await {
        Ok(()) => prompt::show("locked"),
        Err(e) => prompt::show_err(e),
    }
    Ok(())
}

async fn reset_vault(paths: &AvroraPaths) -> Result<(), String> {
    if !prompt::confirm("Удалить control plane, vault и UI auth? Необратимо.", false)? {
        return Ok(());
    }
    if daemon::is_running(&paths.control_dir) {
        daemon::stop(&paths.control_dir)?;
    }
    match reset_server_data(paths, true) {
        Ok(removed) => {
            if removed.is_empty() {
                prompt::show("nothing to reset");
            } else {
                let list = removed
                    .iter()
                    .map(|p| format!("  {}", p.display()))
                    .collect::<Vec<_>>()
                    .join("\n");
                prompt::show(&format!("reset:\n{list}"));
            }
        }
        Err(e) => prompt::show_err(e),
    }
    Ok(())
}

/// Unlock this process if needed (dev master file or prompt).
pub async fn ensure_unlocked(rt: &Runtime) -> Result<(), String> {
    match rt.status().await {
        DbStatus::Empty => Err("vault empty — сначала создайте БД".into()),
        DbStatus::Unlocked => Ok(()),
        DbStatus::Locked => {
            let hex = match load_dev_master_hex(rt).await {
                Ok(h) => h,
                Err(_) => match prompt_master_hex(rt, None).await? {
                    Some(h) => h,
                    None => return Err("no master key".into()),
                },
            };
            rt.unlock(&hex).await.map_err(|e| e.to_string())?;
            Ok(())
        }
    }
}

pub async fn ensure_admin(rt: &Runtime) -> Result<crate::ids::SessionId, String> {
    ensure_unlocked(rt).await?;
    if !rt.is_dev_provisioned().await.map_err(|e| e.to_string())? {
        return Err("нет root identity — сначала Dev provisioning (devo-init)".into());
    }
    rt.admin_session().await.map_err(|e| e.to_string())
}
