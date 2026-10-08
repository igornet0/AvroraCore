mod capability_rotation_scheduler;
mod backup_scheduler;
pub mod error;
mod middleware;
mod routes;
pub mod state;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

use axum::Router;
use tower_http::services::ServeDir;

use crate::channel::ChannelSpec;
use crate::control;
use crate::control::DEV_MASTER_FILE;
use crate::control::sessions::ControlSessions;
use crate::runtime::{DbStatus, Runtime};
use crate::server::state::AppState;
use dmc_ipc::{default_socket_path, CoreServer, SocketPathOptions};
use dmc_security::{AuthManager, ui_auth_path};
use dmc_server::{bootstrap_core_state_persistent_with_hub, UnlockMaterial};

/// HTTP admin + control plane, and co-host DMC IPC on the same [`Runtime::hub`].
pub async fn run(addr: SocketAddr, ui_dist: Option<PathBuf>) -> Result<(), std::io::Error> {
    let paths = control::AvroraPaths::resolve();
    let db_path = paths.db_path.clone();
    let rt = Runtime::at_path(Path::new(&db_path));
    rt.set_capability_rotation_dir(paths.control_dir.clone());
    try_dev_unlock(&rt, &db_path);
    spawn_dmc_ipc_adapter(&paths, rt.hub());
    run_with_runtime(addr, ui_dist, rt).await
}

/// HTTP admin using an already-composed [`Runtime`] (shared hub owned by the caller).
///
/// Does **not** spawn DMC IPC — use this from `dmc serve --http` where IPC is primary.
pub async fn run_with_runtime(
    addr: SocketAddr,
    ui_dist: Option<PathBuf>,
    rt: Runtime,
) -> Result<(), std::io::Error> {
    let paths = control::AvroraPaths::resolve();

    let sched_rt = rt.clone();
    let sched_dir = paths.control_dir.clone();
    tokio::spawn(async move {
        capability_rotation_scheduler::run(sched_dir, sched_rt).await;
    });
    let backup_sched_rt = rt.clone();
    let backup_sched_dir = paths.control_dir.clone();
    tokio::spawn(async move {
        backup_scheduler::run(backup_sched_dir, backup_sched_rt).await;
    });
    let sessions = ControlSessions::new();
    let auth = AuthManager::open(ui_auth_path(&paths.db_path));
    let state = AppState {
        runtime: rt.clone(),
        auth: auth.clone(),
        sessions: sessions.clone(),
    };

    let _ = rt.configure_channel(ChannelSpec::internal("bus")).await;
    let _ = rt.configure_channel(ChannelSpec::http("admin", addr)).await;
    let _ = rt.start_channel(&"admin".into()).await;

    let data_dir = paths.control_dir.clone();
    if let Err(e) = control::require_inited(&data_dir) {
        eprintln!("{e}");
    } else {
        let control_addr: SocketAddr = control::ServerConfig::resolve(&data_dir)
            .control_addr
            .parse()
            .expect("AVRORA_CONTROL_ADDR / server.json control_addr");
        let rt_c = rt.clone();
        let auth_c = auth.clone();
        let dir_c = data_dir.clone();
        tokio::spawn(async move {
            if let Err(e) = control::serve(control_addr, dir_c, rt_c, auth_c, sessions).await {
                eprintln!("control plane error: {e}");
            }
        });
    }

    let api = routes::router(state);

    // No CORS layer (D3): the UI is served from this origin (and the Vite dev server
    // proxies `/api` same-origin), so no cross-origin page may call the management API.
    let mut app = Router::new().nest("/api", api);

    if let Some(dist) = ui_dist {
        if dist.is_dir() {
            println!("UI enabled  dist={}", dist.display());
            app = app.fallback_service(ServeDir::new(dist));
        }
    } else {
        println!("UI disabled (API only)");
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("Avrora listening on http://{addr}");
    axum::serve(listener, app).await
}

/// Co-host DMC IPC on the process-local RuntimeHub (P7.1).
///
/// Disable with `AVRORA_DMC_IPC=0`. Socket defaults to [`default_socket_path`],
/// override with `AVRORA_DMC_SOCKET`.
fn spawn_dmc_ipc_adapter(paths: &control::AvroraPaths, hub: dmc_runtime::RuntimeHub) {
    // The co-hosted SQL core is bootstrapped with demo credentials (analyst/pw) and a
    // plaintext unlock file: dev only. Production runs `dmc serve` explicitly instead.
    if !control::dev::dev_mode_enabled() {
        println!("DMC IPC co-host disabled (dev-only; set AVRORA_DEV=1 or run `dmc serve`)");
        return;
    }
    if std::env::var("AVRORA_DMC_IPC")
        .map(|v| matches!(v.as_str(), "0" | "false" | "off" | "no"))
        .unwrap_or(false)
    {
        println!("DMC IPC adapter disabled (AVRORA_DMC_IPC=0)");
        return;
    }

    let dmc_root = paths.control_dir.join("dmc-data");
    if let Err(e) = std::fs::create_dir_all(&dmc_root) {
        eprintln!("DMC IPC: cannot create {}: {e}", dmc_root.display());
        return;
    }

    let socket = std::env::var_os("AVRORA_DMC_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(default_socket_path);

    // D4-F: persistent key store; storage opened only on VaultUnlock, sealed at rest. The
    // dev unlock file is written when the key store is created and stays valid after.
    let (state, master) = match bootstrap_core_state_persistent_with_hub(&dmc_root, true, hub) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("DMC IPC: vault key store unusable: {e}");
            return;
        }
    };
    if let Some(master) = master {
        let master_path = dmc_root.join(".dmc-dev-master.hex");
        if let Err(e) = write_master_hex(&master_path, &master) {
            eprintln!("DMC IPC: write master failed: {e}");
        }
    }

    let state = Arc::new(Mutex::new(state));
    let socket_clone = socket.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    thread::spawn(move || {
        let options = SocketPathOptions {
            allow_custom_path: true,
        };
        let server = match CoreServer::bind(&socket_clone, &options) {
            Ok(s) => s,
            Err(e) => {
                let _ = ready_tx.send(Err(e.to_string()));
                return;
            }
        };
        if ready_tx.send(Ok(())).is_err() {
            return;
        }
        // One failing client must not stop the adapter; only a broken listener does.
        if let Err(e) = server.serve_forever_shared(&state, |e| eprintln!("DMC IPC: connection closed with error: {e}")) {
            eprintln!("DMC IPC: listener failed, adapter stopping: {e}");
        }
    });

    match ready_rx.recv_timeout(std::time::Duration::from_secs(5)) {
        Ok(Ok(())) => {
            println!(
                "DMC IPC listening on {} (shared RuntimeHub with HTTP)",
                socket.display()
            );
            println!("DMC data root {}", dmc_root.display());
        }
        Ok(Err(e)) => eprintln!("DMC IPC bind failed: {e}"),
        Err(_) => eprintln!("DMC IPC bind timed out"),
    }
}

/// Dev only (caller is gated by `dev_mode_enabled`): 0600 from creation.
fn write_master_hex(path: &Path, material: &UnlockMaterial) -> Result<(), String> {
    let hex = zeroize::Zeroizing::new(hex::encode(material.0));
    dmc_vault::secure_fs::write_secret_file(path, hex.as_bytes()).map_err(|e| e.to_string())
}

fn try_dev_unlock(rt: &Runtime, db_path: &Path) {
    let Some(parent) = db_path.parent() else {
        return;
    };
    let master_path = parent.join(DEV_MASTER_FILE);
    // A Master Key stored in plaintext is a dev convenience only. Without explicit
    // AVRORA_DEV=1 the file is ignored and the vault stays Locked (fail closed).
    if !control::dev::dev_mode_enabled() {
        if master_path.is_file() {
            eprintln!(
                "ignoring {} (set AVRORA_DEV=1 for dev auto-unlock); vault stays locked",
                master_path.display()
            );
        }
        return;
    }
    let Ok(raw) = std::fs::read_to_string(&master_path) else {
        return;
    };
    let hex = raw.trim();
    if hex.is_empty() {
        return;
    }
    let rt = rt.clone();
    let hex = hex.to_string();
    let master_display = master_path.display().to_string();
    tokio::spawn(async move {
        if rt.status().await != DbStatus::Locked {
            return;
        }
        match rt.unlock(&hex).await {
            Ok(_) => println!("dev auto-unlock from {master_display}"),
            Err(e) => eprintln!("dev auto-unlock failed: {e}"),
        }
    });
}
