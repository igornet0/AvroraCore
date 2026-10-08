//! `dmc identity bootstrap-operator` through the real binary (Administrator-A).

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

/// Fresh per run: never a fixed credential in the source.
fn fresh_passphrase() -> String {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    format!("op-{:x}-{:x}-{:x}", std::process::id(), nanos, nanos.rotate_left(17))
}

fn run(data_dir: &Path, socket: &Path, name: &str, stdin: &str, extra: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_dmc"))
        .args(["identity", "bootstrap-operator", "--data-dir"])
        .arg(data_dir)
        .arg("--socket")
        .arg(socket)
        .args(["--name", name])
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

#[test]
fn bootstrap_is_local_one_time_and_never_exposes_the_password() {
    let passphrase = fresh_passphrase();
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let socket = dir.path().join("no-server.sock");

    // the stdin acknowledgement is mandatory (no way to pass a password in argv)
    let o = run(&data, &socket, "root-op", &format!("{passphrase}\n"), &[]);
    assert!(!o.status.success(), "{}", text(&o));

    // weak password: refused, and the bootstrap is NOT consumed
    let o = run(&data, &socket, "root-op", "short\n", &["--password-stdin"]);
    assert!(!o.status.success());
    assert!(!data.join("ownership/bootstrap.consumed").exists());

    // the real bootstrap
    let o = run(&data, &socket, "root-op", &format!("{passphrase}\n"), &["--password-stdin"]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(!text(&o).contains(&passphrase), "password echoed");
    let file = data.join("ownership/identities.json");
    let raw = std::fs::read_to_string(&file).unwrap();
    assert!(!raw.contains(&passphrase), "only a verifier is stored");
    assert!(raw.contains("\"bootstrap\"") && raw.contains("\"Grant\""), "{raw}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for f in [&file, &data.join("ownership/bootstrap.consumed")] {
            assert_eq!(std::fs::metadata(f).unwrap().permissions().mode() & 0o777, 0o600, "{}", f.display());
        }
    }

    // a second bootstrap is refused — with the same or another name
    for name in ["root-op", "another-op"] {
        let o = run(&data, &socket, name, &format!("{passphrase}\n"), &["--password-stdin"]);
        assert!(!o.status.success(), "{}", text(&o));
        assert!(text(&o).contains("refused"), "{}", text(&o));
    }
    // even after the identity file is removed (the marker is permanent)
    std::fs::remove_file(&file).unwrap();
    let o = run(&data, &socket, "root-op", &format!("{passphrase}\n"), &["--password-stdin"]);
    assert!(!o.status.success());
    // and there is no force / reset flag
    let o = run(&data, &socket, "root-op", &format!("{passphrase}\n"), &["--password-stdin", "--force"]);
    assert!(!o.status.success());
}
