//! Local/dev vault + SQL fixtures (paths, master keys, UI defaults).
//!
//! Single place for Docker `env.dev`, `avrora devo-init`, and auto-unlock.
//! Values are intentionally public and weak — never use in production.
//! Keep in sync with `AvroraCore/docker/env.dev`.

pub use dmc_security::dev::{
    DEV_DEFAULT_UI_ACCESS_KEY, ENV_UI_ACCESS_KEY, ENV_UI_TOTP_SECRET, UI_ACCESS_KEY, UI_TOTP_SECRET,
};

/// Written next to the vault; `avrora serve` auto-unlocks when present.
pub const MASTER_FILE: &str = ".avrora-dev-master.hex";

/// Plaintext UI login hint written by `devo-init` (local only).
pub const UI_CREDENTIALS_FILE: &str = ".avrora-dev-ui-credentials.txt";

/// Fixed vault master key (32 bytes hex) for Docker DEV.
pub const MASTER_KEY_HEX: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// Fixed SQL / pgwire master key (32 bytes hex) for Docker DEV.
pub const SQL_MASTER_KEY_HEX: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// Environment variable names (Docker / process env).
pub const ENV_MASTER_KEY_HEX: &str = "AVRORA_MASTER_KEY_HEX";
pub const ENV_SQL_MASTER_KEY_HEX: &str = "SQL_MASTER_KEY_HEX";
pub const ENV_DEV: &str = "AVRORA_DEV";
pub const ENV_DEVO_DEMO: &str = "AVRORA_DEVO_DEMO";

/// Backward-compatible aliases used across the control plane.
pub const DEV_MASTER_FILE: &str = MASTER_FILE;
pub const DEV_UI_CREDENTIALS_FILE: &str = UI_CREDENTIALS_FILE;
pub const DEFAULT_UI_ACCESS_KEY: &str = UI_ACCESS_KEY;

/// True only when the process was explicitly started in dev mode (`AVRORA_DEV=1|true`).
///
/// Gates every path that would use a key stored in plaintext on disk (auto-unlock from
/// [`MASTER_FILE`]). Production never reads a stored Master Key.
pub fn dev_mode_enabled() -> bool {
    dev_mode_from(std::env::var(ENV_DEV).ok().as_deref())
}

pub fn dev_mode_from(value: Option<&str>) -> bool {
    matches!(value.map(str::trim), Some("1") | Some("true"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_mode_requires_explicit_opt_in() {
        assert!(!dev_mode_from(None));
        assert!(!dev_mode_from(Some("")));
        assert!(!dev_mode_from(Some("0")));
        assert!(!dev_mode_from(Some("yes")));
        assert!(dev_mode_from(Some("1")));
        assert!(dev_mode_from(Some("true")));
    }
}
