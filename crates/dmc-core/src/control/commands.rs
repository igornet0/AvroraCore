//! Local status / init helpers shared by `avrora` CLI and `avrora menu`.

use std::path::Path;

use crate::control::{
    self, load_capability_rotation, load_server_config, AvroraPaths, DevoInitResult, ServerConfig,
};
use crate::runtime::{DbStatus, Runtime};

pub fn run_init(
    data_dir: &Path,
    invite_host: &str,
    invite_port: u16,
) -> Result<String, String> {
    let r = control::init_control_for_host(data_dir, invite_host)?;
    let mut out = String::new();
    out.push_str("Avrora server initialized.\n");
    out.push_str(&format!("Control data dir: {}\n", r.data_dir.display()));
    out.push_str(&format!(
        "Bootstrap token (0600): {}\n",
        r.token_path.display()
    ));
    out.push_str(&r.token);
    out.push('\n');
    match control::export_invite(&r.data_dir, invite_host, invite_port) {
        Ok(invite) => match control::write_invite_file(&r.data_dir, &invite) {
            Ok(path) => {
                out.push_str(&format!(
                    "Invite JSON (no private keys): {}\n",
                    path.display()
                ));
                out.push_str(&serde_json::to_string_pretty(&invite).unwrap_or_default());
                out.push('\n');
            }
            Err(e) => out.push_str(&format!("warn: could not write invite.json: {e}\n")),
        },
        Err(e) => out.push_str(&format!("warn: could not build invite: {e}\n")),
    }
    Ok(out)
}

pub async fn format_status() -> String {
    let paths = AvroraPaths::resolve();
    format_status_for(&paths).await
}

pub async fn format_status_for(paths: &AvroraPaths) -> String {
    let vault = if paths.vault_exists() {
        match Runtime::at_path(&paths.db_path).status().await {
            DbStatus::Empty => "empty",
            DbStatus::Locked => "locked",
            DbStatus::Unlocked => "unlocked",
        }
    } else {
        "empty"
    };
    let mut lines = Vec::new();
    lines.push(format!("control_dir={}", paths.control_dir.display()));
    lines.push(format!("db_path={}", paths.db_path.display()));
    if let Some(home) = &paths.home {
        lines.push(format!("avrora_home={}", home.display()));
    }
    lines.push(format!(
        "control_initialized={}",
        if paths.control_initialized() {
            "yes"
        } else {
            "no"
        }
    ));
    lines.push(format!(
        "bootstrap_token={}",
        if paths.bootstrap_token_present() {
            "present"
        } else {
            "absent"
        }
    ));
    lines.push(format!(
        "invite={}",
        if paths.invite_present() {
            "present"
        } else {
            "absent"
        }
    ));
    lines.push(format!("vault={vault}"));
    let rot = load_capability_rotation(&paths.control_dir).unwrap_or_default();
    lines.push(format!(
        "capability_rotation={} time={} last={}",
        if rot.enabled { "enabled" } else { "disabled" },
        rot.time,
        rot.last_run_at.as_deref().unwrap_or("-")
    ));
    let cfg = ServerConfig::resolve(&paths.control_dir);
    let file_cfg = load_server_config(&paths.control_dir).unwrap_or_default();
    lines.push(format!(
        "ui_enabled={}",
        if file_cfg.ui_enabled { "yes" } else { "no" }
    ));
    lines.push(format!("http={}", cfg.http_addr));
    lines.push(format!("control={}", cfg.control_addr));
    lines.join("\n")
}

pub fn format_ui_login_hint(db_path: &std::path::Path) -> String {
    use crate::control::{read_dev_ui_credentials, DEV_UI_CREDENTIALS_FILE};

    let mut out = String::from(
        "Вход в UI = Access key + код 2FA (Google Authenticator).\n\
         Master key (.avrora-dev-master.hex) — только unlock vault, не для браузера.\n\n",
    );
    if let Some((key, secret)) = read_dev_ui_credentials(db_path) {
        out.push_str(&format!("ui_access_key={key}\n"));
        out.push_str(&format!("ui_totp_secret={secret}\n"));
        if let Some(parent) = db_path.parent() {
            out.push_str(&format!(
                "ui_credentials_file={}\n",
                parent.join(DEV_UI_CREDENTIALS_FILE).display()
            ));
        }
        out.push_str(
            "\n1. Добавьте totp_secret в Authenticator\n\
             2. Откройте http://127.0.0.1:18787\n\
             3. Access key + текущий 6-значный код\n",
        );
    } else {
        out.push_str(
            "Dev UI credentials не найдены.\n\
             Либо меню «UI → Сброс UI access key (2FA)»,\n\
             либо настройте Access key в UI при первом входе.\n",
        );
    }
    out
}

pub fn format_ui_auth_reset(r: &super::UiAuthResetResult) -> String {
    let mut out = String::from("UI access key и 2FA пересозданы.\n");
    out.push_str(&format!("ui_access_key={}\n", r.access_key));
    out.push_str(&format!("ui_totp_secret={}\n", r.totp_secret));
    out.push_str(&format!("otpauth_url={}\n", r.otpauth_url));
    out.push_str(&format!(
        "ui_credentials_file={}\n",
        r.credentials_file.display()
    ));
    if !r.removed.is_empty() {
        out.push_str("\nУдалено:\n");
        for p in &r.removed {
            out.push_str(&format!("  {}\n", p.display()));
        }
    }
    out.push_str(
        "\n1. Добавьте totp_secret в Google Authenticator\n\
         2. Перезапустите serve (make down && avrora-serve)\n\
         3. Войдите: Access key + 6-значный код\n",
    );
    out
}

pub fn format_auth_init(r: &DevoInitResult) -> String {
    let mut out = format_devo_init(r, false);
    out.push_str("auth service layout: auth/{users,sessions,grants,keys}\n");
    out.push_str("roles: auth_admin, auth_service, auth_readonly\n");
    out
}

pub fn format_devo_init(r: &DevoInitResult, demo: bool) -> String {
    let mut out = String::new();
    if r.created_vault {
        out.push_str("vault created (crypto keys + journal)\n");
    }
    if r.provisioned_identity {
        out.push_str("dev identity provisioned (root role, root user, cap_root)\n");
    }
    if demo {
        out.push_str("demo seed applied (company/* sample data + finance/hr roles)\n");
    }
    if let Some(id) = &r.db_id {
        out.push_str(&format!("db_id={id}\n"));
    }
    if let Some(hex) = &r.master_hex {
        out.push_str(&format!("master_key_hex={hex}\n"));
    }
    if let Some(path) = &r.master_file {
        out.push_str(&format!("master_key_file={}\n", path.display()));
    }
    out.push_str("\n--- Вход в UI (http://127.0.0.1:18787) ---\n");
    if let Some(key) = &r.ui_access_key {
        out.push_str(&format!("ui_access_key={key}\n"));
        if let Some(secret) = &r.ui_totp_secret {
            out.push_str(&format!("ui_totp_secret={secret}\n"));
            out.push_str(
                "Добавьте секрет в Google Authenticator (вручную или otpauth URL из файла ниже).\n\
                 На экране входа: Access key + 6-значный код 2FA.\n",
            );
        }
        if let Some(path) = &r.ui_credentials_file {
            out.push_str(&format!("ui_credentials_file={}\n", path.display()));
        }
    } else {
        out.push_str(
            "UI auth не настроен автоматически.\n\
             При первом входе задайте Access key (≥8 символов) и подключите Google Authenticator.\n",
        );
    }
    out.push_str(
        "\n--- Master key (НЕ для UI) ---\n\
         master_key_hex — только для unlock vault (CLI/меню «Разблокировать»).\n\
         После devo-init serve автоматически unlock, если есть .avrora-dev-master.hex\n",
    );
    out
}
