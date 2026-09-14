use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;

use crate::runtime::{DbStatus, Runtime};
use crate::server::error::{ApiError, ApiResult};

#[derive(Serialize)]
struct StatusDto {
    status: String,
    path: String,
}

fn status_name(s: DbStatus) -> &'static str {
    match s {
        DbStatus::Empty => "empty",
        DbStatus::Locked => "locked",
        DbStatus::Unlocked => "unlocked",
    }
}

async fn status(State(rt): State<Runtime>) -> ApiResult<Json<StatusDto>> {
    Ok(Json(StatusDto {
        status: status_name(rt.status().await).to_string(),
        path: rt.db_path().await.display().to_string(),
    }))
}

fn use_client() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "vault create/unlock is only available via Avrora Client (control plane)",
    )
}

async fn create() -> ApiResult<Json<StatusDto>> {
    Err(use_client())
}

async fn unlock() -> ApiResult<Json<StatusDto>> {
    Err(use_client())
}

async fn lock(State(rt): State<Runtime>) -> ApiResult<Json<StatusDto>> {
    rt.lock().await?;
    Ok(Json(StatusDto {
        status: "locked".into(),
        path: rt.db_path().await.display().to_string(),
    }))
}

pub fn router() -> Router<crate::server::state::AppState> {
    Router::new()
        .route("/db/status", get(status))
        .route("/db/create", post(create))
        .route("/db/unlock", post(unlock))
        .route("/db/lock", post(lock))
}
