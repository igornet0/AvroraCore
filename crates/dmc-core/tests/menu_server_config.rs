use dmc_core::control::{load_server_config, save_server_config, ServerConfig};

#[test]
fn server_config_ui_enabled_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = ServerConfig {
        ui_enabled: false,
        http_addr: "127.0.0.1:18787".into(),
        control_addr: "127.0.0.1:7432".into(),
    };
    let path = save_server_config(dir.path(), &cfg).unwrap();
    assert!(path.ends_with("server.json"));
    let loaded = load_server_config(dir.path()).unwrap();
    assert!(!loaded.ui_enabled);
    assert_eq!(loaded.http_addr, "127.0.0.1:18787");
    assert_eq!(loaded.control_addr, "127.0.0.1:7432");
}

#[test]
fn server_config_missing_file_defaults_ui_on() {
    let dir = tempfile::tempdir().unwrap();
    let loaded = load_server_config(dir.path()).unwrap();
    assert!(loaded.ui_enabled);
}
