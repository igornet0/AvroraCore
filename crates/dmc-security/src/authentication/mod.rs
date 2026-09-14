//! Access key + TOTP enrollment/login. Issues opaque Bearer tokens.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::Mutex;
use totp_rs::{Builder, Secret};

use crate::credentials::{load_file, save_file, AuthFile};
use crate::crypto::hash_access_key;
use crate::error::AuthError;
use crate::identity::{ISSUER, UI_OPERATOR};
use crate::sessions::BearerStore;
use crate::IdentityService;

#[derive(Clone)]
struct PendingSetup {
    salt: [u8; 16],
    access_key_hash: String,
    totp_secret_b32: String,
    created_at: Instant,
}

#[derive(Default)]
struct AuthInner {
    config: Option<AuthFile>,
    pending: Option<PendingSetup>,
    sessions: BearerStore,
}

/// In-process UI authentication manager.
#[derive(Clone)]
pub struct AuthManager {
    path: PathBuf,
    inner: Arc<Mutex<AuthInner>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthStatus {
    pub enrolled: bool,
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SetupBeginResponse {
    pub totp_secret: String,
    pub otpauth_url: String,
    pub qr_png_base64: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DevUiCredentials {
    pub access_key: String,
    pub totp_secret: String,
    pub otpauth_url: String,
}

/// Default UI access key when devo-init does not specify one.
pub const DEV_DEFAULT_UI_ACCESS_KEY: &str = "avrora-dev-ui-key";

/// Dev-only: enroll access key + random TOTP secret without browser setup.
pub fn dev_enroll_ui_auth(path: &Path, access_key: &str) -> Result<DevUiCredentials, AuthError> {
    use crate::credentials::{load_file, save_file, AuthFile};
    use crate::crypto::hash_access_key;
    use crate::identity::{ISSUER, UI_OPERATOR};
    use totp_rs::{Builder, Secret};

    if load_file(path)?.is_some() {
        return Err(AuthError::Conflict(
            "UI auth already enrolled; login with key + 2FA".into(),
        ));
    }

    let access_key = access_key.trim();
    if access_key.len() < 8 {
        return Err(AuthError::BadRequest(
            "access key must be at least 8 characters".into(),
        ));
    }

    let mut salt = [0u8; 16];
    rand::fill(&mut salt);
    let access_key_hash = hash_access_key(&salt, access_key);
    let secret = Secret::generate();
    let totp_secret_b32 = secret.to_base32();
    let totp = Builder::new()
        .with_secret(Secret::try_from_base32(&totp_secret_b32).map_err(|e| {
            AuthError::BadRequest(format!("totp secret: {e}"))
        })?)
        .with_account_name(UI_OPERATOR)
        .with_issuer(Some(ISSUER))
        .build()
        .map_err(|e| AuthError::BadRequest(e.to_string()))?;
    let otpauth_url = totp
        .to_url()
        .map_err(|e| AuthError::BadRequest(e.to_string()))?;

    let file = AuthFile {
        version: 1,
        salt_hex: hex::encode(salt),
        access_key_hash,
        totp_secret_b32: totp_secret_b32.clone(),
    };
    save_file(path, &file)?;

    Ok(DevUiCredentials {
        access_key: access_key.to_string(),
        totp_secret: totp_secret_b32,
        otpauth_url,
    })
}

impl AuthManager {
    pub fn open(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let config = load_file(&path).ok().flatten();
        Self {
            path,
            inner: Arc::new(Mutex::new(AuthInner {
                config,
                pending: None,
                sessions: BearerStore::default(),
            })),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn status(&self) -> AuthStatus {
        let g = self.inner.lock().await;
        AuthStatus {
            enrolled: g.config.is_some(),
            path: self.path.display().to_string(),
        }
    }

    pub async fn begin_setup(&self, access_key: &str) -> Result<SetupBeginResponse, AuthError> {
        let access_key = access_key.trim();
        if access_key.len() < 8 {
            return Err(AuthError::BadRequest(
                "access key must be at least 8 characters".into(),
            ));
        }

        let mut g = self.inner.lock().await;
        if g.config.is_some() {
            return Err(AuthError::Conflict(
                "UI auth already enrolled; login with key + 2FA".into(),
            ));
        }

        let mut salt = [0u8; 16];
        rand::fill(&mut salt);
        let access_key_hash = hash_access_key(&salt, access_key);

        let secret = Secret::generate();
        let totp_secret_b32 = secret.to_base32();
        let totp = Builder::new()
            .with_secret(Secret::try_from_base32(&totp_secret_b32).map_err(|e| {
                AuthError::BadRequest(format!("totp secret: {e}"))
            })?)
            .with_account_name(UI_OPERATOR)
            .with_issuer(Some(ISSUER))
            .build()
            .map_err(|e| AuthError::BadRequest(e.to_string()))?;
        let otpauth_url = totp
            .to_url()
            .map_err(|e| AuthError::BadRequest(e.to_string()))?;
        let qr_png_base64 = totp.to_qr_base64().ok();

        g.pending = Some(PendingSetup {
            salt,
            access_key_hash,
            totp_secret_b32: totp_secret_b32.clone(),
            created_at: Instant::now(),
        });

        Ok(SetupBeginResponse {
            totp_secret: totp_secret_b32,
            otpauth_url,
            qr_png_base64,
        })
    }

    pub async fn confirm_setup(
        &self,
        access_key: &str,
        totp_code: &str,
    ) -> Result<String, AuthError> {
        let access_key = access_key.trim();
        let totp_code = totp_code.trim();

        let mut g = self.inner.lock().await;
        if g.config.is_some() {
            return Err(AuthError::Conflict("UI auth already enrolled".into()));
        }
        let pending = g.pending.as_ref().ok_or_else(|| {
            AuthError::BadRequest("call /auth/setup/begin first".into())
        })?;
        if pending.created_at.elapsed() > Duration::from_secs(15 * 60) {
            g.pending = None;
            return Err(AuthError::BadRequest("setup expired; start again".into()));
        }

        let hash = hash_access_key(&pending.salt, access_key);
        if hash != pending.access_key_hash {
            return Err(AuthError::Unauthorized("invalid access key".into()));
        }
        if !verify_totp(&pending.totp_secret_b32, totp_code)? {
            return Err(AuthError::Unauthorized("invalid 2FA code".into()));
        }

        let file = AuthFile {
            version: 1,
            salt_hex: hex::encode(pending.salt),
            access_key_hash: pending.access_key_hash.clone(),
            totp_secret_b32: pending.totp_secret_b32.clone(),
        };
        save_file(&self.path, &file)?;
        g.config = Some(file);
        g.pending = None;
        Ok(g.sessions.issue())
    }

    pub async fn login(&self, access_key: &str, totp_code: &str) -> Result<String, AuthError> {
        let access_key = access_key.trim();
        let totp_code = totp_code.trim();

        let mut g = self.inner.lock().await;
        let cfg = g.config.as_ref().ok_or_else(|| {
            AuthError::BadRequest("UI auth not enrolled; complete setup first".into())
        })?;

        let salt = hex::decode(&cfg.salt_hex)
            .map_err(|_| AuthError::BadRequest("corrupt auth file".into()))?;
        let hash = hash_access_key(&salt, access_key);
        if hash != cfg.access_key_hash {
            return Err(AuthError::Unauthorized("invalid access key or 2FA".into()));
        }
        if !verify_totp(&cfg.totp_secret_b32, totp_code)? {
            return Err(AuthError::Unauthorized("invalid access key or 2FA".into()));
        }

        Ok(g.sessions.issue())
    }

    pub async fn logout(&self, token: &str) {
        let mut g = self.inner.lock().await;
        g.sessions.revoke(token);
    }

    pub async fn validate(&self, token: &str) -> bool {
        let mut g = self.inner.lock().await;
        g.sessions.validate(token)
    }
}

impl IdentityService for AuthManager {
    async fn enroll_begin(&self, access_key: &str) -> Result<SetupBeginResponse, AuthError> {
        self.begin_setup(access_key).await
    }

    async fn enroll_confirm(
        &self,
        access_key: &str,
        totp_code: &str,
    ) -> Result<String, AuthError> {
        self.confirm_setup(access_key, totp_code).await
    }

    async fn authenticate(&self, access_key: &str, totp_code: &str) -> Result<String, AuthError> {
        self.login(access_key, totp_code).await
    }

    async fn validate_session(&self, token: &str) -> bool {
        self.validate(token).await
    }

    async fn revoke_session(&self, token: &str) {
        self.logout(token).await
    }
}

fn verify_totp(secret_b32: &str, code: &str) -> Result<bool, AuthError> {
    let digits: String = code.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 6 {
        return Ok(false);
    }
    let secret = Secret::try_from_base32(secret_b32)
        .map_err(|e| AuthError::BadRequest(format!("corrupt totp secret: {e}")))?;
    let totp = Builder::new()
        .with_secret(secret)
        .with_account_name(UI_OPERATOR)
        .with_issuer(Some(ISSUER))
        .build()
        .map_err(|e| AuthError::BadRequest(e.to_string()))?;
    Ok(totp.check_current(&digits).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn dev_enroll_ui_auth_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("avrora.ui-auth.json");
        let creds =
            dev_enroll_ui_auth(&path, DEV_DEFAULT_UI_ACCESS_KEY).unwrap();
        assert_eq!(creds.access_key, DEV_DEFAULT_UI_ACCESS_KEY);
        let auth = AuthManager::open(&path);
        assert!(auth.status().await.enrolled);
    }

    #[tokio::test]
    async fn setup_and_login_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("t.ui-auth.json");
        let auth = AuthManager::open(&path);

        let begin = auth.begin_setup("secret-access-key").await.unwrap();
        assert!(!begin.totp_secret.is_empty());
        assert!(begin.otpauth_url.starts_with("otpauth://"));

        let totp = Builder::new()
            .with_secret(Secret::try_from_base32(&begin.totp_secret).unwrap())
            .with_account_name(UI_OPERATOR)
            .with_issuer(Some(ISSUER))
            .build()
            .unwrap();
        let code = totp.generate_current().to_string();

        let token = auth
            .confirm_setup("secret-access-key", &code)
            .await
            .unwrap();
        assert!(auth.validate(&token).await);

        let code2 = totp.generate_current().to_string();
        let token2 = auth.login("secret-access-key", &code2).await.unwrap();
        assert!(auth.validate(&token2).await);

        assert!(auth.login("wrong", &code2).await.is_err());
    }
}
