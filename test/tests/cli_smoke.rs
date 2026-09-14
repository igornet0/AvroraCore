//! Smoke: `dmc` binary subcommands (keys, sql against dev server).

use std::path::PathBuf;
use std::process::Command;

fn dmc() -> Command {
    let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/debug/dmc");
    Command::new(bin)
}

#[test]
fn dmc_keys_prints_hierarchy() {
    let out = dmc().arg("keys").output().expect("run dmc keys");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Master Key") || stdout.contains("root-kek"),
        "stdout={stdout}"
    );
}

#[cfg(unix)]
#[test]
fn dmc_query_against_dev_server() {
    let server = dmc_integration_tests::support::TestServer::spawn(false);
    let out = dmc()
        .args([
            "--data-dir",
            server.data_root.to_str().expect("utf8 path"),
            "--socket",
            server.socket.to_str().expect("utf8 path"),
            "sql",
            "CREATE TABLE cli_probe (id BIGINT PRIMARY KEY)",
            "--user",
            dmc_integration_tests::support::ANALYST,
            "--password",
            dmc_integration_tests::support::ANALYST_PW,
            "--unlock",
        ])
        .output()
        .expect("run dmc sql");
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
