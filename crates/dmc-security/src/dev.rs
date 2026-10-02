//! Shared local/dev UI credentials (fixtures, `devo-init`, Docker `env.dev`).
//!
//! These values are intentionally public and weak — never use in production.
//! Keep in sync with `AvroraCore/docker/env.dev`.

/// Default UI access key when `devo-init` does not specify one.
pub const UI_ACCESS_KEY: &str = "avrora-dev-ui-key";

/// Fixed TOTP base32 secret (≥128 bit) for local Docker / fixture login.
pub const UI_TOTP_SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

/// Environment variable names (Docker / process env).
pub const ENV_UI_ACCESS_KEY: &str = "AVRORA_UI_ACCESS_KEY";
pub const ENV_UI_TOTP_SECRET: &str = "AVRORA_UI_TOTP_SECRET";

/// Backward-compatible alias.
#[doc(alias = "UI_ACCESS_KEY")]
pub const DEV_DEFAULT_UI_ACCESS_KEY: &str = UI_ACCESS_KEY;
