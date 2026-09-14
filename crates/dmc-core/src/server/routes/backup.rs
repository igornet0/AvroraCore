use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use avrora_proto::BackupListItem;
use dmc_journal::StorageLayout;
use serde::{Deserialize, Serialize};

use crate::backup;
use crate::control::backup_config;
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
struct BackupCreateDto {
    backup_id: String,
    checkpoint_sequence: u64,
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
    include_rowstore: bool,
}

#[derive(Deserialize)]
struct RestoreBody {
    backup_id: String,
    target_id: String,
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
) -> ApiResult<Json<BackupCreateDto>> {
    require_root(&state.runtime).await?;
    let (backup_id, checkpoint_sequence) =
        backup::create_backup(&state.runtime, &body.backup_id, body.include_rowstore)
            .await
            .map_err(map_err)?;
    Ok(Json(BackupCreateDto {
        backup_id,
        checkpoint_sequence,
    }))
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
    let (backup_id, target_id, checkpoint_sequence) = backup::restore_backup(
        &backups_root,
        &restores_root,
        &body.backup_id,
        &body.target_id,
    )
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

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/backup", post(create).get(list))
        .route("/backup/config", get(config_get))
        .route("/backup/{backup_id}/verify", post(verify))
        .route("/backup/restore", post(restore))
        .route("/backup/recover/{target_id}", post(recover))
        .route("/backup/status/{target_id}", get(status))
}
