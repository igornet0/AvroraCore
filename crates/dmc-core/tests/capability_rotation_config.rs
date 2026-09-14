use dmc_core::control::{
    CapabilityRotationConfig, load_capability_rotation, save_capability_rotation,
    write_capability_rotation_default,
};
use dmc_core::control::capability_rotation_config::parse_hhmm;

#[test]
fn defaults_enabled_at_0100() {
    let cfg = CapabilityRotationConfig::default();
    assert!(cfg.enabled);
    assert_eq!(cfg.time, "01:00");
    assert!(cfg.validate().is_ok());
}

#[test]
fn write_default_and_set_time() {
    let dir = tempfile::tempdir().unwrap();
    write_capability_rotation_default(dir.path()).unwrap();
    let mut cfg = load_capability_rotation(dir.path()).unwrap();
    assert!(cfg.enabled);
    cfg.time = "02:30".into();
    cfg.enabled = false;
    save_capability_rotation(dir.path(), &cfg).unwrap();
    let loaded = load_capability_rotation(dir.path()).unwrap();
    assert_eq!(loaded.time, "02:30");
    assert!(!loaded.enabled);
}

#[test]
fn rejects_invalid_time() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = CapabilityRotationConfig::default();
    cfg.time = "25:00".into();
    assert!(save_capability_rotation(dir.path(), &cfg).is_err());
    assert!(parse_hhmm("99:99").is_err());
}
