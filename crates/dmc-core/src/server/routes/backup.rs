use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use avrora_proto::BackupListItem;
use backupsas_core::{ConnectDescriptor, RemoteBackupInfo};
use dmc_journal::StorageLayout;
use serde::{Deserialize, Serialize};

use crate::backup;
use crate::control::{backup_catalog, backup_config, backup_targets};
use crate::runtime::Runtime;
use crate::server::error::{ApiError, ApiResult};
use crate::server::state::AppState;

async fn require_root(rt: &Runtime) -> ApiResult<()> {
    let role = rt.active_role().await.map_err(ApiError::from)?;
    if role.id != "root" {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "backup operations require root role",
        ));
    }
    Ok(())
}

#[derive(Serialize)]
struct BackupVerifyDto {
    backup_id: String,
    checkpoint_sequence: u64,
    valid: bool,
    errors: Vec<String>,
}

#[derive(Serialize)]
struct BackupRestoreDto {
    backup_id: String,
    target_id: String,
    checkpoint_sequence: u64,
    vault_locked: bool,
    sessions_invalid: bool,
}

#[derive(Serialize)]
struct BackupRecoverDto {
    target_id: String,
    checkpoint_sequence: u64,
    state: String,
    vault_locked: bool,
    sessions_invalid: bool,
}

#[derive(Serialize)]
struct BackupStatusDto {
    target_id: String,
    state: String,
    checkpoint_sequence: u64,
    vault_locked: bool,
    sessions_invalid: bool,
}

#[derive(Deserialize)]
struct CreateBody {
    backup_id: String,
    #[serde(default)]
    #[allow(dead_code)]
    include_rowstore: bool,
    /// Destinations (`local` and/or BackupSAS target ids); default: `["local"]`.
    #[serde(default)]
    targets: Option<Vec<String>>,
    /// Layout sections; default: all.
    #[serde(default)]
    sections: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct RestoreBody {
    backup_id: String,
    target_id: String,
    /// Location to restore from (`local` or a BackupSAS target id).
    #[serde(default)]
    from_target: Option<String>,
}

#[derive(Deserialize)]
struct AddTargetBody {
    id: String,
    /// Public connect JSON printed by `backupsas connect-info`.
    connect: ConnectDescriptor,
    /// One-time enrollment secret issued by the node operator.
    secret: String,
    #[serde(default)]
    repository: Option<String>,
}

#[derive(Serialize)]
struct TargetDto {
    id: String,
    kind: &'static str,
    server_id: Option<String>,
    fingerprint: Option<String>,
    endpoints: Vec<String>,
    repository: Option<String>,
    added_at: String,
    relocated_from: Option<String>,
}

impl From<backup_targets::BackupTarget> for TargetDto {
    fn from(t: backup_targets::BackupTarget) -> Self {
        match t.kind {
            backup_targets::TargetKind::Local => Self {
                id: t.id,
                kind: "local",
                server_id: None,
                fingerprint: None,
                endpoints: vec![],
                repository: None,
                added_at: t.added_at,
                relocated_from: t.relocated_from,
            },
            backup_targets::TargetKind::Backupsas {
                descriptor,
                repository,
            } => Self {
                id: t.id,
                kind: "backupsas",
                server_id: Some(descriptor.server_id.to_string()),
                fingerprint: Some(descriptor.fingerprint),
                endpoints: descriptor.endpoints,
                repository: Some(repository),
                added_at: t.added_at,
                relocated_from: t.relocated_from,
            },
        }
    }
}

#[derive(Deserialize)]
struct ScheduleBody {
    enabled: Option<bool>,
    time: Option<String>,
    id_prefix: Option<String>,
    weekdays: Option<Vec<u8>>,
    targets: Option<Vec<String>>,
    sections: Option<Vec<String>>,
    /// `0` clears retention.
    retention_keep: Option<u32>,
}

fn control_dir() -> std::path::PathBuf {
    crate::control::AvroraPaths::resolve().control_dir
}

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

fn map_err(e: backup::BackupError) -> ApiError {
    let (code, msg) = match e {
        backup::BackupError::NotFound => (StatusCode::NOT_FOUND, e.to_string()),
        backup::BackupError::VaultLocked | backup::BackupError::VaultNotLocked => {
            (StatusCode::CONFLICT, e.to_string())
        }
        backup::BackupError::AlreadyExists | backup::BackupError::TargetNotEmpty => {
            (StatusCode::CONFLICT, e.to_string())
        }
        backup::BackupError::Remote(_) => (StatusCode::BAD_GATEWAY, e.to_string()),
        _ => (StatusCode::BAD_REQUEST, e.to_string()),
    };
    ApiError::new(code, msg)
}

async fn layout_roots(rt: &Runtime) -> (std::path::PathBuf, std::path::PathBuf) {
    let db_path = rt.db_path().await;
    let layout = StorageLayout::from_db_path(&db_path);
    (
        backup::backups_root(&layout.data_dir),
        backup::restores_root(&layout.data_dir),
    )
}

async fn create(
    State(state): State<AppState>,
    Json(body): Json<CreateBody>,
) -> ApiResult<Json<backup::remote::RunReport>> {
    require_root(&state.runtime).await?;
    let (backups_root, _) = layout_roots(&state.runtime).await;
    let targets = body.targets.unwrap_or_else(backup_config::default_targets);
    let sections = body
        .sections
        .unwrap_or_else(backup_config::default_sections);
    let report = backup::remote::run_backup(
        &state.runtime,
        &control_dir(),
        &backups_root,
        &body.backup_id,
        &targets,
        &sections,
    )
    .await
    .map_err(map_err)?;
    Ok(Json(report))
}

async fn verify(
    State(state): State<AppState>,
    Path(backup_id): Path<String>,
) -> ApiResult<Json<BackupVerifyDto>> {
    require_root(&state.runtime).await?;
    let (backups_root, _) = layout_roots(&state.runtime).await;
    let (checkpoint_sequence, valid, errors) =
        backup::verify_backup(&backups_root, &backup_id).map_err(map_err)?;
    Ok(Json(BackupVerifyDto {
        backup_id,
        checkpoint_sequence,
        valid,
        errors,
    }))
}

async fn list(State(state): State<AppState>) -> ApiResult<Json<Vec<BackupListItem>>> {
    require_root(&state.runtime).await?;
    let (backups_root, _) = layout_roots(&state.runtime).await;
    let items = backup::list_backups(&backups_root).map_err(map_err)?;
    Ok(Json(items))
}

async fn restore(
    State(state): State<AppState>,
    Json(body): Json<RestoreBody>,
) -> ApiResult<Json<BackupRestoreDto>> {
    require_root(&state.runtime).await?;
    let (backups_root, restores_root) = layout_roots(&state.runtime).await;
    let (backup_id, target_id, checkpoint_sequence) = backup::remote::fetch_backup(
        &backup::keys::KeySource::Runtime(&state.runtime),
        &control_dir(),
        &backups_root,
        &restores_root,
        &body.backup_id,
        &body.target_id,
        body.from_target.as_deref(),
    )
    .await
    .map_err(map_err)?;
    Ok(Json(BackupRestoreDto {
        backup_id,
        target_id,
        checkpoint_sequence,
        vault_locked: true,
        sessions_invalid: true,
    }))
}

async fn recover(
    State(state): State<AppState>,
    Path(target_id): Path<String>,
) -> ApiResult<Json<BackupRecoverDto>> {
    require_root(&state.runtime).await?;
    let (_, restores_root) = layout_roots(&state.runtime).await;
    let (target_id, checkpoint_sequence) =
        backup::recover_backup(&state.runtime, &restores_root, &target_id)
            .await
            .map_err(map_err)?;
    state.sessions.revoke_all().await;
    Ok(Json(BackupRecoverDto {
        target_id,
        checkpoint_sequence,
        state: "ready".into(),
        vault_locked: true,
        sessions_invalid: true,
    }))
}

async fn status(
    State(state): State<AppState>,
    Path(target_id): Path<String>,
) -> ApiResult<Json<BackupStatusDto>> {
    require_root(&state.runtime).await?;
    let (_, restores_root) = layout_roots(&state.runtime).await;
    let (state_label, checkpoint_sequence, target_id) =
        backup::backup_status(&restores_root, &target_id).map_err(map_err)?;
    Ok(Json(BackupStatusDto {
        target_id,
        state: state_label,
        checkpoint_sequence,
        vault_locked: true,
        sessions_invalid: true,
    }))
}

async fn config_get(State(state): State<AppState>) -> ApiResult<Json<backup_config::BackupConfig>> {
    require_root(&state.runtime).await?;
    let paths = crate::control::AvroraPaths::resolve();
    let cfg = backup_config::load(&paths.control_dir).map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let _ = &state;
    Ok(Json(cfg))
}

async fn config_put(
    State(state): State<AppState>,
    Json(body): Json<ScheduleBody>,
) -> ApiResult<Json<backup_config::BackupConfig>> {
    require_root(&state.runtime).await?;
    let dir = control_dir();
    let mut cfg = backup_config::load(&dir).map_err(internal)?;
    let s = &mut cfg.schedule;
    if let Some(v) = body.enabled {
        s.enabled = v;
    }
    if let Some(v) = body.time {
        s.time = v;
    }
    if let Some(v) = body.id_prefix {
        s.id_prefix = v;
    }
    if let Some(v) = body.weekdays {
        s.weekdays = v;
    }
    if let Some(v) = body.targets {
        let known = backup_targets::load(&dir).map_err(internal)?;
        if let Some(bad) = v.iter().find(|t| !known.exists(t)) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                format!("unknown backup target `{bad}`"),
            ));
        }
        s.targets = v;
    }
    if let Some(v) = body.sections {
        s.sections = v;
    }
    if let Some(v) = body.retention_keep {
        s.retention_keep = (v > 0).then_some(v);
    }
    backup_config::save(&dir, &cfg).map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e))?;
    Ok(Json(cfg))
}

async fn targets_list(State(state): State<AppState>) -> ApiResult<Json<Vec<TargetDto>>> {
    require_root(&state.runtime).await?;
    let targets = backup_targets::load(&control_dir()).map_err(internal)?;
    Ok(Json(
        targets.all().into_iter().map(TargetDto::from).collect(),
    ))
}

async fn targets_add(
    State(state): State<AppState>,
    Json(body): Json<AddTargetBody>,
) -> ApiResult<Json<TargetDto>> {
    require_root(&state.runtime).await?;
    let repository = body
        .repository
        .or_else(|| body.connect.repositories.first().cloned())
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "node offers no repository"))?;
    let target = backup::remote::add_remote_target(
        &control_dir(),
        &body.id,
        body.connect,
        &repository,
        &body.secret,
    )
    .await
    .map_err(map_err)?;
    Ok(Json(target.into()))
}

async fn targets_remove(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<TargetDto>> {
    require_root(&state.runtime).await?;
    let removed = backup::remote::remove_target(&control_dir(), &id).map_err(map_err)?;
    Ok(Json(removed.into()))
}

async fn targets_test(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<RemoteBackupInfo>>> {
    require_root(&state.runtime).await?;
    let items = backup::remote::list_remote(&control_dir(), &id)
        .await
        .map_err(map_err)?;
    Ok(Json(items))
}

async fn catalog_get(
    State(state): State<AppState>,
) -> ApiResult<Json<backup_catalog::BackupCatalog>> {
    require_root(&state.runtime).await?;
    let catalog = backup_catalog::load(&control_dir()).map_err(internal)?;
    Ok(Json(catalog))
}

async fn sync_now(State(state): State<AppState>) -> ApiResult<Json<backup::remote::SyncReport>> {
    require_root(&state.runtime).await?;
    let report = backup::remote::sync_relocations(&control_dir())
        .await
        .map_err(map_err)?;
    Ok(Json(report))
}

async fn export_kit(State(state): State<AppState>) -> ApiResult<Json<backup::kit::RecoveryKit>> {
    require_root(&state.runtime).await?;
    let db_path = state.runtime.db_path().await;
    let kit = backup::kit::export_kit(
        &backup::keys::KeySource::Runtime(&state.runtime),
        &control_dir(),
        &db_path,
    )
    .await
    .map_err(map_err)?;
    Ok(Json(kit))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/backup", post(create).get(list))
        .route("/backup/config", get(config_get).put(config_put))
        .route("/backup/targets", get(targets_list).post(targets_add))
        .route(
            "/backup/targets/{id}",
            axum::routing::delete(targets_remove),
        )
        .route("/backup/targets/{id}/test", post(targets_test))
        .route("/backup/catalog", get(catalog_get))
        .route("/backup/sync", post(sync_now))
        .route("/backup/export-kit", post(export_kit))
        .route("/backup/{backup_id}/verify", post(verify))
        .route("/backup/restore", post(restore))
        .route("/backup/recover/{target_id}", post(recover))
        .route("/backup/status/{target_id}", get(status))
}

#[cfg(test)]
mod tests {
    #[test]
    fn router_has_no_conflicting_routes() {
        // axum panics on overlapping routes when the router is built.
        let _ = super::router();
    }
}
