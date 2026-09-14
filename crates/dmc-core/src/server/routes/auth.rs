use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use crate::server::error::{ApiError, ApiResult};
use crate::server::middleware::{bearer_token, optional_logout_token};
use crate::server::state::AppState;
use dmc_security::{AuthError, AuthManager, AuthStatus, SetupBeginResponse};

#[derive(Deserialize)]
struct AccessKeyBody {
    access_key: String,
}

#[derive(Deserialize)]
struct LoginBody {
    access_key: String,
    totp_code: String,
}

#[derive(serde::Serialize)]
struct TokenResponse {
    token: String,
    token_type: &'static str,
}

async fn status(State(auth): State<AuthManager>) -> ApiResult<Json<AuthStatus>> {
    Ok(Json(auth.status().await))
}

async fn setup_begin(
    State(auth): State<AuthManager>,
    Json(body): Json<AccessKeyBody>,
) -> ApiResult<Json<SetupBeginResponse>> {
    Ok(Json(auth.begin_setup(&body.access_key).await?))
}

async fn setup_confirm(
    State(auth): State<AuthManager>,
    Json(body): Json<LoginBody>,
) -> ApiResult<Json<TokenResponse>> {
    let token = auth
        .confirm_setup(&body.access_key, &body.totp_code)
        .await?;
    Ok(Json(TokenResponse {
        token,
        token_type: "Bearer",
    }))
}

async fn login(
    State(auth): State<AuthManager>,
    Json(body): Json<LoginBody>,
) -> ApiResult<Json<TokenResponse>> {
    let token = auth.login(&body.access_key, &body.totp_code).await?;
    Ok(Json(TokenResponse {
        token,
        token_type: "Bearer",
    }))
}

async fn logout(
    State(auth): State<AuthManager>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let h = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok());
    optional_logout_token(&auth, h).await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn me(
    State(auth): State<AuthManager>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let token = bearer_token(headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()))
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "missing Bearer token"))?;
    if !auth.validate(&token).await {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid or expired session",
        ));
    }
    Ok(Json(serde_json::json!({ "ok": true })))
}

impl From<AuthError> for ApiError {
    fn from(err: AuthError) -> Self {
        let status = match &err {
            AuthError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AuthError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AuthError::Conflict(_) => StatusCode::CONFLICT,
            AuthError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        ApiError::new(status, err.to_string())
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/status", get(status))
        .route("/auth/setup/begin", post(setup_begin))
        .route("/auth/setup/confirm", post(setup_confirm))
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
}
