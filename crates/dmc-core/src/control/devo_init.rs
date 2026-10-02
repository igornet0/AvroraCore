//! Dev vault provisioning (`avrora devo-init`): root role/user + optional demo data.

use std::fs;
use std::path::{Path, PathBuf};

use dmc_security::{dev_enroll_ui_auth_with_totp, ui_auth_path, DevUiCredentials};

use super::dev::{DEV_DEFAULT_UI_ACCESS_KEY, DEV_MASTER_FILE, DEV_UI_CREDENTIALS_FILE};
use crate::runtime::{DbStatus, Runtime};

pub fn resolve_ui_access_key(key: Option<&str>) -> Result<String, String> {
    let k = key
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEV_DEFAULT_UI_ACCESS_KEY);
    if k.len() < 8 {
        return Err("UI access key must be at least 8 characters".into());
    }
    Ok(k.to_string())
}

#[derive(Debug, Clone)]
pub struct DevoInitResult {
    pub created_vault: bool,
    pub provisioned_identity: bool,
    pub master_hex: Option<String>,
    pub db_id: Option<String>,
    pub master_file: Option<PathBuf>,
    pub ui_access_key: Option<String>,
    pub ui_totp_secret: Option<String>,
    pub ui_credentials_file: Option<PathBuf>,
}

pub async fn run_devo_init(
    rt: &Runtime,
    with_demo: bool,
    master_hex: Option<&str>,
    write_master_file: bool,
    ui_access_key: Option<&str>,
) -> Result<DevoInitResult, String> {
    run_devo_init_ex(
        rt,
        with_demo,
        master_hex,
        write_master_file,
        ui_access_key,
        None,
    )
    .await
}

/// Like [`run_devo_init`], with optional fixed UI TOTP secret (docker / env.dev).
pub async fn run_devo_init_ex(
    rt: &Runtime,
    with_demo: bool,
    master_hex: Option<&str>,
    write_master_file: bool,
    ui_access_key: Option<&str>,
    ui_totp_secret: Option<&str>,
) -> Result<DevoInitResult, String> {
    let status = rt.status().await;
    let mut created_vault = false;
    let mut master_out = None::<String>;
    let mut db_id_out = None::<String>;
    let mut master_file = None::<PathBuf>;

    match status {
        DbStatus::Empty => {
            let (hex, db_id) = rt
                .create_with_master(master_hex)
                .await
                .map_err(|e| e.to_string())?;
            created_vault = true;
            master_out = Some(hex.clone());
            db_id_out = Some(db_id);
            if write_master_file {
                master_file = Some(write_dev_master_file(rt, &hex).await?);
            }
        }
        DbStatus::Locked => {
            let hex = match master_hex {
                Some(h) if !h.trim().is_empty() => h.trim().to_string(),
                _ => read_dev_master_file(rt).await?,
            };
            rt.unlock(&hex).await.map_err(|e| e.to_string())?;
            master_out = Some(hex);
        }
        DbStatus::Unlocked => {
            if let Some(h) = master_hex.filter(|s| !s.trim().is_empty()) {
                master_out = Some(h.trim().to_string());
            }
        }
    }

    if rt.is_dev_provisioned().await.map_err(|e| e.to_string())? {
        return Err(
            "dev identity already provisioned (root role/user present); \
             run `avrora reset --yes` to wipe and start fresh"
                .into(),
        );
    }

    rt.devo_init(with_demo).await.map_err(|e| e.to_string())?;

    let access_key = resolve_ui_access_key(ui_access_key)?;
    let ui = if write_master_file {
        provision_dev_ui_auth(rt, &access_key, ui_totp_secret)
            .await
            .ok()
    } else {
        None
    };

    Ok(DevoInitResult {
        created_vault,
        provisioned_identity: true,
        master_hex: master_out,
        db_id: db_id_out,
        master_file,
        ui_access_key: ui.as_ref().map(|u| u.access_key.clone()),
        ui_totp_secret: ui.as_ref().map(|u| u.totp_secret.clone()),
        ui_credentials_file: ui.map(|u| u.credentials_file),
    })
}

/// Create vault (if needed), root identity, and standard `auth/*` embed layout.
pub async fn run_auth_init(
    rt: &Runtime,
    master_hex: Option<&str>,
    write_master_file: bool,
    ui_access_key: Option<&str>,
) -> Result<DevoInitResult, String> {
    let status = rt.status().await;
    let mut created_vault = false;
    let mut master_out = None::<String>;
    let mut db_id_out = None::<String>;
    let mut master_file = None::<PathBuf>;

    match status {
        DbStatus::Empty => {
            let (hex, db_id) = rt
                .create_with_master(master_hex)
                .await
                .map_err(|e| e.to_string())?;
            created_vault = true;
            master_out = Some(hex.clone());
            db_id_out = Some(db_id);
            if write_master_file {
                master_file = Some(write_dev_master_file(rt, &hex).await?);
            }
        }
        DbStatus::Locked => {
            let hex = match master_hex {
                Some(h) if !h.trim().is_empty() => h.trim().to_string(),
                _ => read_dev_master_file(rt).await?,
            };
            rt.unlock(&hex).await.map_err(|e| e.to_string())?;
            master_out = Some(hex);
        }
        DbStatus::Unlocked => {
            if let Some(h) = master_hex.filter(|s| !s.trim().is_empty()) {
                master_out = Some(h.trim().to_string());
            }
        }
    }

    if rt.is_dev_provisioned().await.map_err(|e| e.to_string())? {
        return Err(
            "auth vault already provisioned; run `avrora reset --yes` to wipe and start fresh"
                .into(),
        );
    }

    rt.auth_service_init().await.map_err(|e| e.to_string())?;

    let access_key = resolve_ui_access_key(ui_access_key)?;
    let ui = if write_master_file {
        provision_dev_ui_auth(rt, &access_key, None).await.ok()
    } else {
        None
    };

    Ok(DevoInitResult {
        created_vault,
        provisioned_identity: true,
        master_hex: master_out,
        db_id: db_id_out,
        master_file,
        ui_access_key: ui.as_ref().map(|u| u.access_key.clone()),
        ui_totp_secret: ui.as_ref().map(|u| u.totp_secret.clone()),
        ui_credentials_file: ui.map(|u| u.credentials_file),
    })
}

struct DevUiProvision {
    access_key: String,
    totp_secret: String,
    credentials_file: PathBuf,
}

#[derive(Debug, Clone)]
pub struct UiAuthResetResult {
    pub access_key: String,
    pub totp_secret: String,
    pub otpauth_url: String,
    pub credentials_file: PathBuf,
    pub removed: Vec<PathBuf>,
}

/// Remove `*.ui-auth.json` and `.avrora-dev-ui-credentials.txt` next to the vault.
pub fn clear_ui_auth(db_path: &Path) -> Result<Vec<PathBuf>, String> {
    let mut removed = Vec::new();
    let auth_path = ui_auth_path(db_path);
    if auth_path.is_file() {
        fs::remove_file(&auth_path).map_err(|e| e.to_string())?;
        removed.push(auth_path);
    }
    let cred_path = dev_ui_credentials_path(db_path);
    if cred_path.is_file() {
        fs::remove_file(&cred_path).map_err(|e| e.to_string())?;
        removed.push(cred_path);
    }
    Ok(removed)
}

/// Wipe UI login files and enroll a new access key + TOTP (vault unchanged).
pub fn reset_ui_auth(db_path: &Path, access_key: Option<&str>) -> Result<UiAuthResetResult, String> {
    let removed = clear_ui_auth(db_path)?;
    let access_key = resolve_ui_access_key(access_key)?;
    let auth_path = ui_auth_path(db_path);
    let creds = dev_enroll_ui_auth_with_totp(&auth_path, &access_key, None)
        .map_err(|e| e.to_string())?;
    let cred_path = dev_ui_credentials_path(db_path);
    write_dev_ui_credentials_file(&cred_path, &creds)?;
    Ok(UiAuthResetResult {
        access_key: creds.access_key,
        totp_secret: creds.totp_secret,
        otpauth_url: creds.otpauth_url,
        credentials_file: cred_path,
        removed,
    })
}

async fn provision_dev_ui_auth(
    rt: &Runtime,
    access_key: &str,
    totp_secret: Option<&str>,
) -> Result<DevUiProvision, String> {
    let db_path = rt.db_path().await;
    let auth_path = ui_auth_path(&db_path);
    if auth_path.is_file() {
        return Err("UI auth already enrolled".into());
    }
    let creds = dev_enroll_ui_auth_with_totp(&auth_path, access_key, totp_secret)
        .map_err(|e| e.to_string())?;
    let cred_path = dev_ui_credentials_path(&db_path);
    write_dev_ui_credentials_file(&cred_path, &creds)?;
    Ok(DevUiProvision {
        access_key: creds.access_key,
        totp_secret: creds.totp_secret,
        credentials_file: cred_path,
    })
}

fn dev_ui_credentials_path(db_path: &Path) -> PathBuf {
    db_path
        .parent()
        .map(|p| p.join(DEV_UI_CREDENTIALS_FILE))
        .unwrap_or_else(|| PathBuf::from(DEV_UI_CREDENTIALS_FILE))
}

fn write_dev_ui_credentials_file(path: &Path, creds: &DevUiCredentials) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let body = format!(
        "# Avrora dev UI login (local only)\n\
         access_key={}\n\
         totp_secret={}\n\
         otpauth_url={}\n\
         # Добавьте TOTP в Google Authenticator (QR: otpauth URL), затем войдите в UI.\n",
        creds.access_key, creds.totp_secret, creds.otpauth_url
    );
    fs::write(path, body).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub fn read_dev_ui_credentials(db_path: &Path) -> Option<(String, String)> {
    let path = dev_ui_credentials_path(db_path);
    let raw = fs::read_to_string(path).ok()?;
    let mut access_key = None;
    let mut totp_secret = None;
    for line in raw.lines() {
        if let Some(v) = line.strip_prefix("access_key=") {
            access_key = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("totp_secret=") {
            totp_secret = Some(v.trim().to_string());
        }
    }
    match (access_key, totp_secret) {
        (Some(k), Some(s)) => Some((k, s)),
        _ => None,
    }
}

async fn dev_master_path(rt: &Runtime) -> Result<PathBuf, String> {
    let db_path = rt.db_path().await;
    Ok(db_path
        .parent()
        .map(|p| p.join(DEV_MASTER_FILE))
        .unwrap_or_else(|| PathBuf::from(DEV_MASTER_FILE)))
}

async fn write_dev_master_file(rt: &Runtime, master_hex: &str) -> Result<PathBuf, String> {
    let path = dev_master_path(rt).await?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(&path, format!("{master_hex}\n")).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    }
    Ok(path)
}

pub async fn load_dev_master_hex(rt: &Runtime) -> Result<String, String> {
    read_dev_master_file(rt).await
}

async fn read_dev_master_file(rt: &Runtime) -> Result<String, String> {
    let path = dev_master_path(rt).await?;
    if !path.is_file() {
        return Err(format!(
            "vault is locked; pass --master-hex or create {} (0600)",
            path.display()
        ));
    }
    let raw = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let hex = raw.trim();
    if hex.is_empty() {
        return Err(format!("master key file is empty: {}", path.display()));
    }
    Ok(hex.to_string())
}
