use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use dmc_vault::key::NodeState;

use crate::runtime::Runtime;
use crate::server::error::ApiResult;

#[derive(Serialize)]
struct NodeDto {
    path: String,
    id: String,
    generation: u64,
    state: String,
}

#[derive(Deserialize)]
struct PathBody {
    path: String,
}

fn to_dto(n: dmc_vault::KeyNodeMeta) -> NodeDto {
    NodeDto {
        path: n.path,
        id: n.id_hex,
        generation: n.generation,
        state: match n.state {
            NodeState::Active => "Active".to_string(),
            NodeState::Revoked => "Revoked".to_string(),
        },
    }
}

async fn list_tree(State(rt): State<Runtime>) -> ApiResult<Json<Vec<NodeDto>>> {
    Ok(Json(
        rt.list_nodes().await?.into_iter().map(to_dto).collect(),
    ))
}

async fn ensure_node(
    State(rt): State<Runtime>,
    Json(body): Json<PathBody>,
) -> ApiResult<Json<NodeDto>> {
    let session = rt.admin_session().await?;
    let meta = rt.ensure_node(&session, &body.path).await?;
    rt.persist().await?;
    Ok(Json(to_dto(meta)))
}

async fn revoke_node(
    State(rt): State<Runtime>,
    Json(body): Json<PathBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let session = rt.admin_session().await?;
    rt.revoke_node(&session, &body.path).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn rotate_node(
    State(rt): State<Runtime>,
    Json(body): Json<PathBody>,
) -> ApiResult<Json<NodeDto>> {
    let session = rt.admin_session().await?;
    let meta = rt.rotate_node(&session, &body.path).await?;
    Ok(Json(to_dto(meta)))
}

pub fn router() -> Router<crate::server::state::AppState> {
    Router::new()
        .route("/tree", get(list_tree))
        .route("/tree/ensure", post(ensure_node))
        .route("/tree/revoke", post(revoke_node))
        .route("/tree/rotate", post(rotate_node))
}
