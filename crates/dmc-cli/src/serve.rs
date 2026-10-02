//! Local Core server (dev / demo).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

use dmc_core::runtime::Runtime;
use dmc_core::server as http_server;
use dmc_ipc::{CoreServer, SocketPathOptions};
use dmc_ops::{start_core, CoreConfig, StartupOptions};
use dmc_runtime::RuntimeHub;
use dmc_server::{bootstrap_core_state_locked_with_hub, UnlockMaterial};

use crate::view::ViewLog;

pub const DEV_MASTER_FILE: &str = ".dmc-dev-master.hex";

pub struct ServeOutcome {
    pub socket: PathBuf,
    pub data_root: PathBuf,
    pub master_file: Option<PathBuf>,
    pub dev_users: bool,
    pub runtime_hub: RuntimeHub,
}

/// Start blocking IPC server loop on a background thread handle.
///
/// One [`RuntimeHub`] is created for this process and injected into Core state so a
/// co-hosted HTTP adapter (`http_addr`) shares channels/streams/triggers/events.
pub fn spawn_server(
    data_root: PathBuf,
    socket: PathBuf,
    dev: bool,
    http_addr: Option<SocketAddr>,
    view: &ViewLog,
) -> Result<(thread::JoinHandle<()>, ServeOutcome), String> {
    let socket_options = SocketPathOptions {
        allow_custom_path: true,
    };

    let hub = RuntimeHub::new();

    let (state, master_file, dev_users) = if dev {
        let snapshot = data_root.join("materialized_snapshot.json");
        if snapshot.is_file() {
            view.line(
                "serve",
                "режим --dev: существующий data_root + dev auth (analyst/pw)",
            );
            let mut started = start_core(
                CoreConfig::local_defaults(&data_root),
                StartupOptions {
                    bootstrap_empty_catalog: false,
                    runtime_hub: Some(hub.clone()),
                },
            )
            .map_err(|e| e.to_string())?;
            *started.server.auth_mut() = dmc_server::dev_auth_service();
            let master_path = data_root.join(DEV_MASTER_FILE);
            if !master_path.is_file() {
                write_master_hex(&master_path, &started.unlock_material)?;
                view.crypto(format!(
                    "Master Key (dev) сохранён в {} (mode 0600) — только для лаборатории",
                    master_path.display()
                ));
            }
            (started.server, Some(master_path), true)
        } else {
            view.line(
                "serve",
                "режим --dev: bootstrap analyst/pw + таблица users",
            );
            let (state, master) =
                bootstrap_core_state_locked_with_hub(&data_root, true, hub.clone());
            let master_path = data_root.join(DEV_MASTER_FILE);
            write_master_hex(&master_path, &master)?;
            view.crypto(format!(
                "Master Key (dev) сохранён в {} (mode 0600) — только для лаборатории",
                master_path.display()
            ));
            (state, Some(master_path), true)
        }
    } else {
        view.line(
            "serve",
            "production start_core: vault Locked, пустой AuthService",
        );
        let started = start_core(
            CoreConfig::local_defaults(&data_root),
            StartupOptions::production().with_runtime_hub(hub.clone()),
        )
        .map_err(|e| e.to_string())?;
        let master_path = data_root.join(DEV_MASTER_FILE);
        write_master_hex(&master_path, &started.unlock_material)?;
        view.crypto(format!(
            "unlock material (one-time) → {}",
            master_path.display()
        ));
        (started.server, Some(master_path), false)
    };

    debug_assert!(state.runtime_hub().same_as(&hub));

    if let Some(addr) = http_addr {
        spawn_http_adapter(data_root.clone(), hub.clone(), addr, view);
    }

    let state = Arc::new(Mutex::new(state));
    let socket_clone = socket.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let handle = thread::spawn(move || {
        let server = match CoreServer::bind(&socket_clone, &socket_options) {
            Ok(server) => server,
            Err(e) => {
                let _ = ready_tx.send(Err(e.to_string()));
                return;
            }
        };
        if ready_tx.send(Ok(())).is_err() {
            return;
        }
        loop {
            let mut guard = state.lock().expect("state lock");
            if server.accept_and_serve_one(&mut guard).is_err() {
                break;
            }
        }
    });

    match ready_rx.recv_timeout(std::time::Duration::from_secs(5)) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(format!("bind socket: {e}")),
        Err(_) => return Err("bind socket: timed out waiting for listener".into()),
    }

    Ok((
        handle,
        ServeOutcome {
            socket,
            data_root,
            master_file,
            dev_users,
            runtime_hub: hub,
        },
    ))
}

fn spawn_http_adapter(data_root: PathBuf, hub: RuntimeHub, addr: SocketAddr, view: &ViewLog) {
    // Vault file next to DMC data so HTTP Runtime can share a path; hub is what must match.
    let db_path = data_root.join("avrora.db");
    view.line(
        "serve",
        format!(
            "HTTP adapter on http://{addr} (shared RuntimeHub with DMC IPC)"
        ),
    );
    thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime for HTTP adapter");
        rt.block_on(async move {
            // Ensure Runtime uses the same hub; HTTP listen is via server::run_with_runtime.
            if let Err(e) = http_server::run_with_runtime(
                addr,
                None,
                Runtime::at_path_with_hub(&db_path, hub),
            )
            .await
            {
                eprintln!("HTTP adapter error: {e}");
            }
        });
    });
}

fn write_master_hex(path: &Path, material: &UnlockMaterial) -> Result<(), String> {
    std::fs::create_dir_all(
        path.parent()
            .ok_or_else(|| "master path has no parent".to_string())?,
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(path, hex::encode(material.0)).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub fn load_master_hex(path: &Path) -> Result<UnlockMaterial, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read master: {e}"))?;
    let bytes = hex::decode(raw.trim()).map_err(|e| format!("hex decode: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "expected 32-byte master key, got {} bytes",
            bytes.len()
        ));
    }
    let mut mat = [0u8; 32];
    mat.copy_from_slice(&bytes);
    Ok(UnlockMaterial(mat))
}
