//! List / create vault users.

use crate::control::AvroraPaths;
use crate::menu::prompt;
use crate::menu::vault;
use crate::runtime::Runtime;

pub async fn submenu(paths: &AvroraPaths) -> Result<(), String> {
    loop {
        match prompt::select(
            "Пользователи",
            &[
                "Список",
                "Создать пользователя",
                "Назад",
            ],
        )? {
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
    match rt.list_users().await {
        Ok(users) => {
            let mut lines = vec!["id            status    roles".into()];
            for u in users {
                lines.push(format!(
                    "{:<14}{:<10}{}",
                    u.id.as_str(),
                    format!("{:?}", u.status).to_lowercase(),
                    u.roles.join(",")
                ));
            }
            lines.push(String::new());
            lines.push(
                "Control-plane operator (Access Key + TOTP) настраивается через:\n  avrora-client auth setup"
                    .into(),
            );
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
    let id = prompt::input("User id", None)?;
    let id = id.trim();
    if id.is_empty() {
        return Ok(());
    }
    let roles = match rt.list_roles().await {
        Ok(r) => r,
        Err(e) => {
            prompt::show_err(e);
            return Ok(());
        }
    };
    if roles.is_empty() {
        prompt::show("нет ролей — сначала создайте роль или devo-init");
        return Ok(());
    }
    let labels: Vec<String> = roles
        .iter()
        .map(|r| format!("{} ({})", r.id, r.scope))
        .collect();
    let label_refs: Vec<&str> = labels.iter().map(|s| s.as_str()).collect();
    let defaults = vec![false; roles.len()];
    let chosen = prompt::multi_select("Роли", &label_refs, &defaults)?;
    if chosen.is_empty() {
        prompt::show("нужно выбрать хотя бы одну роль");
        return Ok(());
    }
    let role_ids: Vec<String> = chosen.iter().map(|&i| roles[i].id.clone()).collect();
    match rt.create_user(&session, id.to_string(), role_ids).await {
        Ok(user) => prompt::show(&format!(
            "created {}  roles={}",
            user.id.as_str(),
            user.roles.join(",")
        )),
        Err(e) => prompt::show_err(e),
    }
    Ok(())
}
