mod auth;
mod backup;
mod data;
mod db;
mod health;
mod roles;
mod runtime_mgmt;
mod session;
mod tree;

use axum::Router;
use axum::middleware;

use crate::server::middleware::require_ui_auth;
use crate::server::state::AppState;

pub fn router(state: AppState) -> Router {
    let public = Router::new().merge(health::router()).merge(auth::router());

    let protected = Router::new()
        .merge(db::router())
        .merge(session::router())
        .merge(roles::router())
        .merge(tree::router())
        .merge(data::router())
        .merge(backup::router())
        .merge(runtime_mgmt::router())
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_ui_auth,
        ));

    Router::new()
        .merge(public)
        .merge(protected)
        .with_state(state)
}
