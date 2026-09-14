//! CLI smoke: `avrora init` / `status` / `reset --yes` against a temp AVRORA_HOME.

use std::path::PathBuf;
use std::process::Command;

fn avrora() -> Command {
    Command::new(env!("CARGO_BIN_EXE_avrora"))
}

#[test]
fn init_status_reset_and_reinit() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();

    let out = avrora()
        .env("AVRORA_HOME", home)
        .env_remove("AVRORA_DATA")
        .env_remove("AVRORA_CONTROL_DIR")
        .args(["init", "--invite-host", "127.0.0.1", "--invite-port", "7432"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("AVR-"), "{stdout}");
    assert!(home.join("control/tls/server.crt").is_file());
    assert!(home.join("control/invite.json").is_file());
    assert!(home.join("control/capability-rotation.json").is_file());

    let show = avrora()
        .env("AVRORA_HOME", home)
        .env_remove("AVRORA_DATA")
        .env_remove("AVRORA_CONTROL_DIR")
        .args(["auth", "rotation", "show"])
        .output()
        .unwrap();
    assert!(
        show.status.success(),
        "show failed: {}",
        String::from_utf8_lossy(&show.stderr)
    );
    let shown = String::from_utf8_lossy(&show.stdout);
    assert!(shown.contains("enabled=true"), "{shown}");
    assert!(shown.contains("time=01:00"), "{shown}");

    let set = avrora()
        .env("AVRORA_HOME", home)
        .env_remove("AVRORA_DATA")
        .env_remove("AVRORA_CONTROL_DIR")
        .args(["auth", "rotation", "set", "--time", "03:15", "--enabled", "false"])
        .output()
        .unwrap();
    assert!(
        set.status.success(),
        "set failed: {}",
        String::from_utf8_lossy(&set.stderr)
    );
    let set_out = String::from_utf8_lossy(&set.stdout);
    assert!(set_out.contains("time=03:15"), "{set_out}");
    assert!(set_out.contains("enabled=false"), "{set_out}");

    let st = avrora()
        .env("AVRORA_HOME", home)
        .env_remove("AVRORA_DATA")
        .env_remove("AVRORA_CONTROL_DIR")
        .arg("status")
        .output()
        .unwrap();
    assert!(st.status.success());
    let status_out = String::from_utf8_lossy(&st.stdout);
    assert!(
        status_out.contains("capability_rotation=disabled time=03:15"),
        "{status_out}"
    );

    let run = avrora()
        .env("AVRORA_HOME", home)
        .env_remove("AVRORA_DATA")
        .env_remove("AVRORA_CONTROL_DIR")
        .args(["auth", "rotation", "run-now"])
        .output()
        .unwrap();
    assert!(!run.status.success());

    let st = avrora()
        .env("AVRORA_HOME", home)
        .env_remove("AVRORA_DATA")
        .env_remove("AVRORA_CONTROL_DIR")
        .arg("status")
        .output()
        .unwrap();
    assert!(st.status.success());
    let s = String::from_utf8_lossy(&st.stdout);
    assert!(s.contains("control_initialized=yes"), "{s}");
    assert!(s.contains("vault=empty"), "{s}");
    assert!(s.contains("bootstrap_token=present"), "{s}");

    let refused = avrora()
        .env("AVRORA_HOME", home)
        .arg("reset")
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(home.join("control/tls/server.crt").is_file());

    let reset = avrora()
        .env("AVRORA_HOME", home)
        .env_remove("AVRORA_DATA")
        .env_remove("AVRORA_CONTROL_DIR")
        .args(["reset", "--yes"])
        .output()
        .unwrap();
    assert!(
        reset.status.success(),
        "reset failed: {}",
        String::from_utf8_lossy(&reset.stderr)
    );
    assert!(!home.join("control").exists());

    let again = avrora()
        .env("AVRORA_HOME", home)
        .env_remove("AVRORA_DATA")
        .env_remove("AVRORA_CONTROL_DIR")
        .args(["init", "--invite-host", "127.0.0.1"])
        .output()
        .unwrap();
    assert!(
        again.status.success(),
        "re-init failed: {}",
        String::from_utf8_lossy(&again.stderr)
    );
    assert!(home.join("control/tls/server.crt").is_file());
}

#[test]
fn avrora_serve_dispatcher_maps_init_not_serve() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let script = manifest.join("../../../scripts/build/avrora-serve");
    assert!(script.is_file(), "missing {}", script.display());
    let out = Command::new("bash")
        .arg(&script)
        .arg("init")
        .args(["--invite-host", "127.0.0.1"])
        .env("AVRORA_BIN", "/usr/bin/true")
        .env("AVRORA_SERVE_DRY_RUN", "1")
        .output()
        .unwrap();
    assert!(out.status.success());
    let line = String::from_utf8_lossy(&out.stdout);
    assert!(
        line.contains(" init"),
        "dispatcher must forward init, got {line}"
    );
    assert!(
        !line.contains(" serve"),
        "dispatcher must not inject serve, got {line}"
    );
}
