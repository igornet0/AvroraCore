use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::runtime::Runtime;
use crate::server::error::{ApiError, ApiResult};
use crate::server::routes::roles::RoleDto;

#[derive(Serialize)]
struct SessionDto {
    active_role: RoleDto,
}

#[derive(Deserialize)]
struct ActivateBody {
    role_id: String,
}

async fn get_session(
    axum::extract::State(rt): axum::extract::State<Runtime>,
) -> ApiResult<Json<SessionDto>> {
    let role = rt.active_role().await?;
    Ok(Json(SessionDto {
        active_role: RoleDto::from(&role),
    }))
}

async fn activate(
    axum::extract::State(rt): axum::extract::State<Runtime>,
    Json(body): Json<ActivateBody>,
) -> ApiResult<Json<SessionDto>> {
    let session = rt.admin_session().await?;
    rt.bind_role(session, &body.role_id).await.map_err(|e| {
        if matches!(e, crate::error::Error::UnknownRole(_)) {
            ApiError::new(
                axum::http::StatusCode::NOT_FOUND,
                format!("role not found: {}", body.role_id),
            )
        } else {
            ApiError::from(e)
        }
    })?;
    let role = rt.active_role().await?;
    Ok(Json(SessionDto {
        active_role: RoleDto::from(&role),
    }))
}

pub fn router() -> Router<crate::server::state::AppState> {
    Router::new()
        .route("/session", get(get_session))
        .route("/session/activate", post(activate))
}
