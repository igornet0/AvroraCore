//! D4-F through the real `dmc serve --dev`: the dev server runs the production storage path
//! (`start_core`): a persistent key store, SQL storage not opened before `VaultUnlock` (so
//! nothing of it is on disk yet), and a restart on the same data root starts normally —
//! no plaintext store, no migration path.

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn serve_dev(data: &Path, socket: &Path) -> Server {
    let child = Command::new(env!("CARGO_BIN_EXE_dmc"))
        .arg("serve")
        .arg("--dev")
        .arg("--data-dir")
        .arg(data)
        .arg("--socket")
        .arg(socket)
        .env("AVRORA_DEV", "1")
        .env_remove("DMC_KEYPASS_PASSWORD")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    Server(child)
}

/// Wait until the IPC socket exists while the process is still running.
fn wait_ready(server: &mut Server, socket: &Path) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Some(status) = server.0.try_wait().unwrap() {
            panic!("dmc serve --dev exited early: {status}");
        }
        if socket.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("dmc serve --dev did not become ready");
}

fn sql_files(data: &Path) -> Vec<std::path::PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p
                    .file_name()
                    .is_some_and(|n| n == "state_events.json" || n == "materialized_snapshot.json")
                {
                    out.push(p);
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(data, &mut out);
    out
}

#[test]
fn dev_server_uses_the_encrypted_production_path_and_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let socket = dir.path().join("dev.sock");

    let mut first = serve_dev(&data, &socket);
    wait_ready(&mut first, &socket);
    assert!(
        data.join("vault/keytree.json").is_file(),
        "persistent key store"
    );
    assert!(
        data.join(".dmc-dev-master.hex").is_file(),
        "dev unlock file"
    );
    assert!(
        sql_files(&data).is_empty(),
        "storage not opened before unlock: {:?}",
        sql_files(&data)
    );
    let key_store = std::fs::read(data.join("vault/keytree.json")).unwrap();
    let master = std::fs::read(data.join(".dmc-dev-master.hex")).unwrap();
    drop(first);
    let _ = std::fs::remove_file(&socket);

    // restart on the same data root: same key store, same dev file, starts normally
    let mut second = serve_dev(&data, &socket);
    wait_ready(&mut second, &socket);
    assert_eq!(
        std::fs::read(data.join("vault/keytree.json")).unwrap(),
        key_store
    );
    assert_eq!(
        std::fs::read(data.join(".dmc-dev-master.hex")).unwrap(),
        master
    );
    assert!(sql_files(&data).is_empty());
}
