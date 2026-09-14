use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::Response;

use crate::server::error::ApiError;
use crate::server::state::AppState;
use dmc_security::AuthManager;

pub async fn require_ui_auth(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let token = bearer_token(
        req.headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok()),
    );
    let Some(token) = token else {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "UI auth required: Bearer token missing",
        ));
    };
    if !state.auth.validate(&token).await {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "UI session expired or invalid; login again",
        ));
    }
    Ok(next.run(req).await)
}

pub fn bearer_token(header: Option<&str>) -> Option<String> {
    let h = header?.trim();
    let rest = h
        .strip_prefix("Bearer ")
        .or_else(|| h.strip_prefix("bearer "))?;
    let t = rest.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

pub async fn optional_logout_token(auth: &AuthManager, header: Option<&str>) {
    if let Some(token) = bearer_token(header) {
        auth.logout(&token).await;
    }
}
