//! Access key + TOTP enrollment/login. Issues opaque Bearer tokens.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::Mutex;
use totp_rs::{Builder, Secret};

use crate::credentials::{load_file, save_file, AuthFile, AUTH_FILE_V2_ARGON2ID};
use crate::crypto::{auth_file_v2, new_access_key_record, verify_access_key, AccessKeyRecord};
use crate::error::AuthError;
use crate::identity::{ISSUER, UI_OPERATOR};
use crate::sessions::BearerStore;
use crate::IdentityService;

struct PendingSetup {
    record: AccessKeyRecord,
    totp_secret_b32: zeroize::Zeroizing<String>,
    created_at: Instant,
}

/// Same message for every login failure (no oracle for which factor was wrong).
const INVALID_LOGIN: &str = "invalid access key or 2FA";

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

/// Returned once to the enrolling operator. `Debug` is redacted; serialize only into the
/// enrollment HTTP response.
#[derive(Clone, Serialize)]
pub struct SetupBeginResponse {
    pub totp_secret: String,
    pub otpauth_url: String,
    pub qr_png_base64: Option<String>,
}

impl std::fmt::Debug for SetupBeginResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SetupBeginResponse([REDACTED])")
    }
}

#[derive(Clone, Serialize)]
pub struct DevUiCredentials {
    pub access_key: String,
    pub totp_secret: String,
    pub otpauth_url: String,
}

impl std::fmt::Debug for DevUiCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DevUiCredentials([REDACTED])")
    }
}

/// Dev-only: enroll access key + TOTP without browser setup (random TOTP).
pub fn dev_enroll_ui_auth(path: &Path, access_key: &str) -> Result<DevUiCredentials, AuthError> {
    dev_enroll_ui_auth_with_totp(path, access_key, None)
}

/// Dev-only: enroll with an optional fixed TOTP base32 secret (docker / env.dev).
pub fn dev_enroll_ui_auth_with_totp(
    path: &Path,
    access_key: &str,
    totp_secret_b32: Option<&str>,
) -> Result<DevUiCredentials, AuthError> {
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

    let record = new_access_key_record(access_key)
        .ok_or_else(|| AuthError::BadRequest("access key hashing failed".into()))?;
    let totp_secret_b32 = match totp_secret_b32.map(str::trim).filter(|s| !s.is_empty()) {
        Some(fixed) => {
            let _ = Secret::try_from_base32(fixed)
                .map_err(|e| AuthError::BadRequest(format!("totp secret: {e}")))?;
            fixed.to_string()
        }
        None => Secret::generate().to_base32(),
    };
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

    let file = auth_file_v2(record, totp_secret_b32.clone());
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

        let record = new_access_key_record(access_key)
            .ok_or_else(|| AuthError::BadRequest("access key hashing failed".into()))?;

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
            record,
            totp_secret_b32: zeroize::Zeroizing::new(totp_secret_b32.clone()),
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

        if !pending.record.verifier.matches(
            &dmc_vault::ownership::derive_credential_secrets(
                access_key,
                &pending.record.salt,
                &pending.record.kdf,
            )
            .map_err(|_| AuthError::Unauthorized(INVALID_LOGIN.into()))?
            .verifier,
        ) {
            return Err(AuthError::Unauthorized(INVALID_LOGIN.into()));
        }
        if !verify_totp(&pending.totp_secret_b32, totp_code)? {
            return Err(AuthError::Unauthorized(INVALID_LOGIN.into()));
        }

        let pending = g.pending.take().expect("checked above");
        let file = auth_file_v2(pending.record, pending.totp_secret_b32.to_string());
        save_file(&self.path, &file)?;
        g.config = Some(file);
        Ok(g.sessions.issue())
    }

    pub async fn login(&self, access_key: &str, totp_code: &str) -> Result<String, AuthError> {
        let access_key = access_key.trim();
        let totp_code = totp_code.trim();

        let mut g = self.inner.lock().await;
        let cfg = g.config.as_ref().ok_or_else(|| {
            AuthError::BadRequest("UI auth not enrolled; complete setup first".into())
        })?;

        // Both factors are always evaluated (no early exit revealing which one failed).
        let key_ok = verify_access_key(cfg, access_key);
        let totp_ok = verify_totp(&cfg.totp_secret_b32, totp_code)?;
        if !(key_ok && totp_ok) {
            return Err(AuthError::Unauthorized(INVALID_LOGIN.into()));
        }

        // Migration: a legacy SHA-256 (v1) file is rewritten as Argon2id (v2) after the
        // first successful login. The TOTP secret is carried over unchanged.
        if cfg.version != AUTH_FILE_V2_ARGON2ID {
            let record = new_access_key_record(access_key)
                .ok_or_else(|| AuthError::BadRequest("access key hashing failed".into()))?;
            let upgraded = auth_file_v2(record, cfg.totp_secret_b32.clone());
            save_file(&self.path, &upgraded)?;
            g.config = Some(upgraded);
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
    use crate::dev::{DEV_DEFAULT_UI_ACCESS_KEY, UI_TOTP_SECRET};
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
    async fn dev_enroll_fixed_totp_secret() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("avrora.ui-auth.json");
        let fixed = UI_TOTP_SECRET;
        let creds =
            dev_enroll_ui_auth_with_totp(&path, DEV_DEFAULT_UI_ACCESS_KEY, Some(fixed)).unwrap();
        assert_eq!(creds.totp_secret, fixed);
        let auth = AuthManager::open(&path);
        let totp = Builder::new()
            .with_secret(Secret::try_from_base32(fixed).unwrap())
            .with_account_name(UI_OPERATOR)
            .with_issuer(Some(ISSUER))
            .build()
            .unwrap();
        let code = totp.generate_current().to_string();
        assert!(auth.login(DEV_DEFAULT_UI_ACCESS_KEY, &code).await.is_ok());
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

    fn totp_now(secret: &str) -> String {
        Builder::new()
            .with_secret(Secret::try_from_base32(secret).unwrap())
            .with_account_name(UI_OPERATOR)
            .with_issuer(Some(ISSUER))
            .build()
            .unwrap()
            .generate_current()
            .to_string()
    }

    #[tokio::test]
    async fn access_key_stored_as_argon2id_verifier_with_owner_only_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.ui-auth.json");
        dev_enroll_ui_auth_with_totp(&path, "access-key-123", Some(UI_TOTP_SECRET)).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("access-key-123"));
        assert!(!raw.contains("access_key_hash"), "no legacy SHA-256 field");
        let file: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(file["version"], 2);
        assert_eq!(file["kdf"]["alg"], "argon2id-v19");
        #[cfg(unix)]
        assert_eq!(dmc_vault::secure_fs::mode_of(&path), Some(0o600));

        let auth = AuthManager::open(&path);
        assert!(auth.login("access-key-123", &totp_now(UI_TOTP_SECRET)).await.is_ok());
        let wrong_key = auth.login("access-key-xyz", &totp_now(UI_TOTP_SECRET)).await.unwrap_err();
        let wrong_totp = auth.login("access-key-123", "000000").await.unwrap_err();
        assert_eq!(wrong_key.to_string(), wrong_totp.to_string(), "generic error");
    }

    #[tokio::test]
    async fn legacy_sha256_file_upgrades_on_login_and_mode_is_tightened() {
        use sha2::{Digest, Sha256};
        let dir = tempdir().unwrap();
        let path = dir.path().join("legacy.ui-auth.json");
        let salt = [7u8; 16];
        let mut h = Sha256::new();
        h.update(salt);
        h.update(b"legacy-access-key");
        let legacy = serde_json::json!({
            "version": 1,
            "salt_hex": hex::encode(salt),
            "access_key_hash": hex::encode(h.finalize()),
            "totp_secret_b32": UI_TOTP_SECRET,
        });
        std::fs::write(&path, legacy.to_string()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        let auth = AuthManager::open(&path);
        #[cfg(unix)]
        assert_eq!(dmc_vault::secure_fs::mode_of(&path), Some(0o600), "tightened on load");
        assert!(auth.login("wrong-legacy-key", &totp_now(UI_TOTP_SECRET)).await.is_err());
        let still_v1: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(still_v1["version"], 1, "no upgrade on failed login");

        auth.login("legacy-access-key", &totp_now(UI_TOTP_SECRET)).await.unwrap();
        let upgraded: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(upgraded["version"], 2);
        assert!(upgraded.get("access_key_hash").is_none());
        assert_eq!(upgraded["totp_secret_b32"], UI_TOTP_SECRET, "TOTP preserved");

        let reopened = AuthManager::open(&path);
        assert!(reopened.login("legacy-access-key", &totp_now(UI_TOTP_SECRET)).await.is_ok());
    }

    #[test]
    fn secret_bearing_types_redact_debug() {
        let creds = DevUiCredentials {
            access_key: "access-key-123".into(),
            totp_secret: UI_TOTP_SECRET.into(),
            otpauth_url: format!("otpauth://totp/x?secret={UI_TOTP_SECRET}"),
        };
        let resp = SetupBeginResponse {
            totp_secret: UI_TOTP_SECRET.into(),
            otpauth_url: "otpauth://x".into(),
            qr_png_base64: None,
        };
        let shown = format!("{creds:?} {resp:?}");
        assert!(!shown.contains(UI_TOTP_SECRET) && !shown.contains("access-key-123"));
    }
}
