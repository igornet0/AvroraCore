//! Phase 7.10.1 — Production configuration contract (parse / validate / no secrets).

use std::path::PathBuf;

use dmc_ops::{
    assert_no_secrets_in_config, load_config_file, parse_config_json, parse_config_toml,
    validate_config, ConfigError, CoreConfig, LimitsConfig, Profile, RecoveryOnStartup,
    TransportMode, TlsPathsConfig, CONFIG_FORMAT_VERSION,
};
use tempfile::tempdir;

#[test]
fn defaults_apply_for_minimal_json() {
    let cfg = parse_config_json(r#"{ "data_root": "/var/lib/avrora" }"#).unwrap();
    assert_eq!(cfg.format_version, CONFIG_FORMAT_VERSION);
    assert_eq!(cfg.profile, Profile::Development);
    assert_eq!(cfg.transport.mode, TransportMode::Local);
    assert_eq!(cfg.recovery.on_startup, RecoveryOnStartup::Auto);
    assert_eq!(cfg.backup.backups_dirname, "backups");
    assert!(cfg.limits.max_connections > 0);
    validate_config(&cfg).unwrap();
    assert_no_secrets_in_config(&cfg).unwrap();
}

#[test]
fn toml_parse_and_partial_limits() {
    let text = r#"
data_root = "/data/avrora"
profile = "production"
[limits]
max_connections = 32
"#;
    let cfg = parse_config_toml(text).unwrap();
    assert_eq!(cfg.profile, Profile::Production);
    assert_eq!(cfg.limits.max_connections, 32);
    assert_eq!(
        cfg.limits.max_sql_size,
        LimitsConfig::default().max_sql_size
    );
}

#[test]
fn load_config_file_json_roundtrip() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("core.json");
    std::fs::write(
        &path,
        r#"{ "data_root": "./data", "profile": "development" }"#,
    )
    .unwrap();
    let cfg = load_config_file(&path).unwrap();
    assert_eq!(cfg.data_root, PathBuf::from("./data"));
}

#[test]
fn production_remote_requires_tls_paths() {
    let err = parse_config_json(
        r#"{
            "data_root": "/data",
            "profile": "production",
            "transport": { "mode": "remote", "remote_listen": "0.0.0.0:7443" }
        }"#,
    )
    .unwrap_err();
    assert!(matches!(err, ConfigError::Invalid(_)));
}

#[test]
fn remote_with_tls_paths_ok() {
    let cfg = parse_config_json(
        r#"{
            "data_root": "/data",
            "profile": "production",
            "transport": {
                "mode": "remote",
                "remote_listen": "0.0.0.0:7443",
                "tls": {
                    "ca_cert_path": "/etc/avrora/ca.pem",
                    "server_cert_path": "/etc/avrora/server.pem",
                    "server_key_path": "/etc/avrora/server.key"
                }
            }
        }"#,
    )
    .unwrap();
    assert_eq!(cfg.transport.mode, TransportMode::Remote);
    assert!(cfg.transport.tls.is_some());
    let remote = cfg.limits.to_remote_limits();
    assert_eq!(remote.frame.max_connections, cfg.limits.max_connections);
}

#[test]
fn rejects_password_field() {
    let err = parse_config_json(
        r#"{ "data_root": "/data", "password": "secret" }"#,
    )
    .unwrap_err();
    assert_eq!(err, ConfigError::ForbiddenSecret);
}

#[test]
fn rejects_master_key_and_pem_body() {
    assert_eq!(
        parse_config_json(r#"{ "data_root": "/data", "master_key": "abc" }"#).unwrap_err(),
        ConfigError::ForbiddenSecret
    );
    assert_eq!(
        parse_config_json(
            r#"{ "data_root": "/data", "extra": "-----BEGIN PRIVATE KEY-----\nMII\n-----END" }"#
        )
        .unwrap_err(),
        ConfigError::ForbiddenSecret
    );
    assert_eq!(
        parse_config_toml(
            r#"
data_root = "/data"
dek = "010203"
"#
        )
        .unwrap_err(),
        ConfigError::ForbiddenSecret
    );
}

#[test]
fn rejects_empty_data_root_and_zero_limits() {
    assert!(matches!(
        parse_config_json(r#"{ "data_root": "" }"#).unwrap_err(),
        ConfigError::Invalid(_)
    ));
    let mut cfg = CoreConfig::local_defaults("/data");
    cfg.limits.max_connections = 0;
    assert!(matches!(
        validate_config(&cfg).unwrap_err(),
        ConfigError::Invalid(_)
    ));
}

#[test]
fn rejects_backup_dirname_with_path_sep() {
    let mut cfg = CoreConfig::local_defaults("/data");
    cfg.backup.backups_dirname = "../escape".into();
    assert!(matches!(
        validate_config(&cfg).unwrap_err(),
        ConfigError::Invalid(_)
    ));
}

#[test]
fn rejects_zero_shutdown_drain() {
    let mut cfg = CoreConfig::local_defaults("/data");
    cfg.lifecycle.shutdown_drain_timeout_ms = 0;
    assert!(matches!(
        validate_config(&cfg).unwrap_err(),
        ConfigError::Invalid(_)
    ));
}

#[test]
fn dual_requires_listen_and_tls() {
    let err = parse_config_json(
        r#"{
            "data_root": "/data",
            "transport": { "mode": "dual" }
        }"#,
    )
    .unwrap_err();
    assert!(matches!(err, ConfigError::Invalid(_)));
}

#[test]
fn tls_path_refs_allowed_without_pem_body() {
    let cfg = CoreConfig {
        transport: dmc_ops::TransportConfig {
            mode: TransportMode::Remote,
            remote_listen: Some("127.0.0.1:7443".into()),
            tls: Some(TlsPathsConfig {
                ca_cert_path: PathBuf::from("certs/ca.pem"),
                server_cert_path: PathBuf::from("certs/server.pem"),
                server_key_path: PathBuf::from("certs/server.key"),
            }),
            ..Default::default()
        },
        ..CoreConfig::production_local("/var/lib/avrora")
    };
    validate_config(&cfg).unwrap();
    assert_no_secrets_in_config(&cfg).unwrap();
}
