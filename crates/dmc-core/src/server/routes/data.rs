use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::runtime::Runtime;
use crate::server::error::ApiResult;

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    prefix: String,
}

#[derive(Serialize)]
struct ListResponse {
    keys: Vec<String>,
}

#[derive(Serialize)]
struct ValueResponse {
    path: String,
    value: String,
    encoding: String,
}

fn join_path(parts: &str) -> String {
    parts.trim_matches('/').to_string()
}

async fn list_data(
    State(rt): State<Runtime>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<ListResponse>> {
    let session = rt.admin_session().await?;
    let keys = rt.list_keys(&session, &q.prefix).await?;
    Ok(Json(ListResponse { keys }))
}

async fn get_data(
    State(rt): State<Runtime>,
    Path(path): Path<String>,
) -> ApiResult<Json<ValueResponse>> {
    let path = join_path(&path);
    let session = rt.admin_session().await?;
    let bytes = rt.get_data(&session, &path).await?;
    match String::from_utf8(bytes.clone()) {
        Ok(value) => Ok(Json(ValueResponse {
            path,
            value,
            encoding: "utf-8".into(),
        })),
        Err(_) => {
            let value = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
            Ok(Json(ValueResponse {
                path,
                value,
                encoding: "hex".into(),
            }))
        }
    }
}

async fn put_data(
    State(rt): State<Runtime>,
    Path(path): Path<String>,
    body: Bytes,
) -> ApiResult<impl IntoResponse> {
    let path = join_path(&path);
    let session = rt.admin_session().await?;
    let value: Vec<u8> = if let Ok(text) = std::str::from_utf8(&body) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(s) = v.get("value").and_then(|x| x.as_str()) {
                s.as_bytes().to_vec()
            } else {
                body.to_vec()
            }
        } else {
            body.to_vec()
        }
    } else {
        body.to_vec()
    };
    rt.put_data(&session, &path, &value).await?;
    Ok((
        [(header::CONTENT_TYPE, "application/json")],
        Json(serde_json::json!({ "ok": true, "path": path })),
    ))
}

async fn delete_data(
    State(rt): State<Runtime>,
    Path(path): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let path = join_path(&path);
    let session = rt.admin_session().await?;
    rt.delete_data(&session, &path).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub fn router() -> Router<crate::server::state::AppState> {
    Router::new().route("/data", get(list_data)).route(
        "/data/{*path}",
        get(get_data).put(put_data).delete(delete_data),
    )
}
