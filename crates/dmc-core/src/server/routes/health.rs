use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::server::state::AppState;

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

pub fn router() -> Router<AppState> {
    Router::new().route("/health", get(health))
}
