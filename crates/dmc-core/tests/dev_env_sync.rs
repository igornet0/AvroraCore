//! `docker/env.dev` must stay aligned with [`crate::control::dev`] fixtures.

use dmc_core::control::dev::{
    MASTER_KEY_HEX, SQL_MASTER_KEY_HEX, UI_ACCESS_KEY, UI_TOTP_SECRET,
};
use std::fs;
use std::path::PathBuf;

fn env_dev_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docker/env.dev")
}

fn parse_env_file(raw: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    map
}

#[test]
fn docker_env_dev_matches_control_dev_constants() {
    let path = env_dev_path();
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let env = parse_env_file(&raw);

    assert_eq!(
        env.get("AVRORA_UI_ACCESS_KEY").map(String::as_str),
        Some(UI_ACCESS_KEY),
        "AVRORA_UI_ACCESS_KEY drift vs dmc_security::dev::UI_ACCESS_KEY"
    );
    assert_eq!(
        env.get("AVRORA_UI_TOTP_SECRET").map(String::as_str),
        Some(UI_TOTP_SECRET),
        "AVRORA_UI_TOTP_SECRET drift vs dmc_security::dev::UI_TOTP_SECRET"
    );
    assert_eq!(
        env.get("AVRORA_MASTER_KEY_HEX").map(String::as_str),
        Some(MASTER_KEY_HEX),
        "AVRORA_MASTER_KEY_HEX drift vs dmc_core::control::dev::MASTER_KEY_HEX"
    );
    assert_eq!(
        env.get("SQL_MASTER_KEY_HEX").map(String::as_str),
        Some(SQL_MASTER_KEY_HEX),
        "SQL_MASTER_KEY_HEX drift vs dmc_core::control::dev::SQL_MASTER_KEY_HEX"
    );
}
