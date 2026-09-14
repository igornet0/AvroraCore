mod capability_rotation_scheduler;
mod backup_scheduler;
pub mod error;
mod middleware;
mod routes;
pub mod state;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use axum::Router;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;

use crate::channel::ChannelSpec;
use crate::control;
use crate::control::DEV_MASTER_FILE;
use crate::control::sessions::ControlSessions;
use crate::runtime::{DbStatus, Runtime};
use crate::server::state::AppState;
use dmc_security::{AuthManager, ui_auth_path};

pub async fn run(addr: SocketAddr, ui_dist: Option<PathBuf>) -> Result<(), std::io::Error> {
    let paths = control::AvroraPaths::resolve();
    let db_path = paths.db_path.clone();
    let rt = Runtime::at_path(Path::new(&db_path));
    rt.set_capability_rotation_dir(paths.control_dir.clone());
    try_dev_unlock(&rt, &db_path);
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
    let auth = AuthManager::open(ui_auth_path(&db_path));
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

    let mut app = Router::new().nest("/api", api).layer(
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any),
    );

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

fn try_dev_unlock(rt: &Runtime, db_path: &Path) {
    let Some(parent) = db_path.parent() else {
        return;
    };
    let master_path = parent.join(DEV_MASTER_FILE);
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
