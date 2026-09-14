//! Spawn locked Core + connected SDK client for integration tests.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use dmc_client::{
    Client, ConnectionTarget, MockKeyPassProvider, ProtocolErrorCode, UnlockMaterial,
};
use dmc_ipc::{CoreServer, SocketPathOptions};
use dmc_server::bootstrap_core_state_locked;

pub const DEV_MASTER_FILE: &str = ".dmc-dev-master.hex";

pub const ANALYST: &str = "analyst";
pub const ANALYST_PW: &str = "pw";

use tempfile::TempDir;

pub struct TestServer {
    _dir: TempDir,
    pub data_root: PathBuf,
    pub socket: PathBuf,
    pub master: UnlockMaterial,
    handle: thread::JoinHandle<()>,
}

impl TestServer {
    /// Dev bootstrap: catalog `avrora`, user `analyst/pw`, optional `users` table.
    pub fn spawn(users_table: bool) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let data_root = dir.path().to_path_buf();
        let socket = data_root.join("dmc.sock");
        let (master, handle) = spawn_locked_server(&data_root, socket.clone(), users_table);
        write_master_hex(&data_root.join(DEV_MASTER_FILE), &master);
        Self {
            _dir: dir,
            data_root,
            socket,
            master,
            handle,
        }
    }
}

fn spawn_locked_server(
    data_root: &Path,
    socket_path: PathBuf,
    users_table: bool,
) -> (UnlockMaterial, thread::JoinHandle<()>) {
    let (state, master) = bootstrap_core_state_locked(data_root, users_table);
    let state = Arc::new(Mutex::new(state));
    let options = SocketPathOptions {
        allow_custom_path: true,
    };
    let handle = thread::spawn(move || {
        let server = CoreServer::bind(&socket_path, &options).expect("bind socket");
        loop {
            let mut guard = state.lock().expect("state lock");
            if server.accept_and_serve_one(&mut guard).is_err() {
                break;
            }
        }
    });
    thread::sleep(Duration::from_millis(40));
    (master, handle)
}

pub fn connect(socket: &Path) -> Client {
    let mut client = Client::with_client_id(
        ConnectionTarget::Local {
            socket: socket.to_path_buf(),
        },
        "dmc-integration-test",
    );
    client.connect().expect("connect");
    client
}

pub fn auth(client: &mut Client) {
    client
        .control()
        .authenticate(ANALYST, ANALYST_PW)
        .expect("authenticate");
}

pub fn unlock(client: &mut Client, master: &UnlockMaterial) {
    let provider = MockKeyPassProvider::with_material(master.clone());
    client
        .control()
        .vault_unlock(&provider)
        .expect("vault unlock");
}

pub fn expect_protocol_code(err: &dmc_client::ClientError, code: ProtocolErrorCode) {
    assert_eq!(
        err.protocol_code(),
        Some(code),
        "expected {code:?}, got {err}"
    );
}

fn write_master_hex(path: &Path, material: &UnlockMaterial) {
    std::fs::write(path, hex::encode(material.0)).expect("write master hex");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
}
