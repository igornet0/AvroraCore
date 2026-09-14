//! List / create vault roles.

use dmc_vault::access::PermissionSet;
use dmc_vault::key::KeyPath;

use crate::control::AvroraPaths;
use crate::menu::prompt;
use crate::menu::vault;
use crate::runtime::Runtime;

const PERM_NAMES: &[&str] = &["READ", "WRITE", "INSERT", "UPDATE", "DELETE", "GRANT"];

pub async fn submenu(paths: &AvroraPaths) -> Result<(), String> {
    loop {
        match prompt::select("Роли", &["Список", "Создать", "Назад"])? {
            0 => list(paths).await?,
            1 => create(paths).await?,
            _ => return Ok(()),
        }
    }
}

async fn list(paths: &AvroraPaths) -> Result<(), String> {
    let rt = Runtime::at_path(&paths.db_path);
    if let Err(e) = vault::ensure_admin(&rt).await {
        prompt::show_err(e);
        return Ok(());
    }
    match rt.list_roles().await {
        Ok(roles) => {
            let mut lines = vec!["id                    scope                 permissions".into()];
            for r in roles {
                lines.push(format!(
                    "{:<22}{:<22}{}",
                    r.id,
                    r.scope,
                    r.permissions.to_names().join(",")
                ));
            }
            prompt::show(&lines.join("\n"));
        }
        Err(e) => prompt::show_err(e),
    }
    Ok(())
}

async fn create(paths: &AvroraPaths) -> Result<(), String> {
    let rt = Runtime::at_path(&paths.db_path);
    let session = match vault::ensure_admin(&rt).await {
        Ok(s) => s,
        Err(e) => {
            prompt::show_err(e);
            return Ok(());
        }
    };
    let id = prompt::input("Role id", None)?;
    let id = id.trim();
    if id.is_empty() {
        return Ok(());
    }
    let name = prompt::input("Name", Some(id))?;
    let scope_raw = prompt::input("Scope path (/ = root)", Some("/"))?;
    let scope = parse_scope(&scope_raw)?;
    let defaults = [true, false, false, false, false, false];
    let chosen = prompt::multi_select("Permissions", PERM_NAMES, &defaults)?;
    if chosen.is_empty() {
        prompt::show("нужно выбрать хотя бы одно permission");
        return Ok(());
    }
    let names: Vec<String> = chosen.iter().map(|&i| PERM_NAMES[i].to_string()).collect();
    let perms = PermissionSet::from_names(&names).map_err(|e| e.to_string())?;
    match rt
        .create_role(&session, id.to_string(), name, scope, perms)
        .await
    {
        Ok(role) => prompt::show(&format!(
            "created {}  scope={}  {}",
            role.id,
            role.scope,
            role.permissions.to_names().join(",")
        )),
        Err(e) => prompt::show_err(e),
    }
    Ok(())
}

fn parse_scope(raw: &str) -> Result<KeyPath, String> {
    if raw.trim().is_empty() || raw.trim() == "/" {
        Ok(KeyPath::root())
    } else {
        KeyPath::parse(raw.trim_start_matches('/')).map_err(|e| e.to_string())
    }
}
