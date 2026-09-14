use axum::extract::{Path, State};
use axum::routing::{get, patch};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use dmc_vault::access::{PermissionSet, Role};
use dmc_vault::key::KeyPath;

use crate::runtime::Runtime;
use crate::server::error::{ApiError, ApiResult};

#[derive(Clone, Serialize)]
pub struct RoleDto {
    pub id: String,
    pub name: String,
    pub scope: String,
    pub permissions: Vec<String>,
}

impl From<&Role> for RoleDto {
    fn from(role: &Role) -> Self {
        Self {
            id: role.id.clone(),
            name: role.name.clone(),
            scope: role.scope.to_string(),
            permissions: role
                .permissions
                .to_names()
                .into_iter()
                .map(str::to_string)
                .collect(),
        }
    }
}

#[derive(Deserialize)]
pub struct CreateRoleBody {
    pub id: String,
    pub name: String,
    pub scope: String,
    pub permissions: Vec<String>,
}

#[derive(Deserialize)]
pub struct PatchRoleBody {
    pub name: Option<String>,
    pub scope: Option<String>,
    pub permissions: Option<Vec<String>>,
}

fn parse_scope(raw: &str) -> Result<KeyPath, dmc_vault::Error> {
    if raw.trim().is_empty() || raw.trim() == "/" {
        Ok(KeyPath::root())
    } else {
        KeyPath::parse(raw.trim_start_matches('/'))
    }
}

async fn list_roles(State(rt): State<Runtime>) -> ApiResult<Json<Vec<RoleDto>>> {
    Ok(Json(
        rt.list_roles().await?.iter().map(RoleDto::from).collect(),
    ))
}

async fn create_role(
    State(rt): State<Runtime>,
    Json(body): Json<CreateRoleBody>,
) -> ApiResult<Json<RoleDto>> {
    let session = rt.admin_session().await?;
    let scope = parse_scope(&body.scope)?;
    let perms = PermissionSet::from_names(&body.permissions)?;
    let role = rt
        .create_role(&session, body.id, body.name, scope, perms)
        .await?;
    Ok(Json(RoleDto::from(&role)))
}

async fn patch_role(
    State(rt): State<Runtime>,
    Path(id): Path<String>,
    Json(body): Json<PatchRoleBody>,
) -> ApiResult<Json<RoleDto>> {
    let session = rt.admin_session().await?;
    let scope = match body.scope {
        Some(s) => Some(parse_scope(&s)?),
        None => None,
    };
    let perms = match body.permissions {
        Some(names) => Some(PermissionSet::from_names(&names)?),
        None => None,
    };
    let role = rt
        .update_role(&session, &id, body.name, scope, perms)
        .await?;
    Ok(Json(RoleDto::from(&role)))
}

async fn delete_role(
    State(rt): State<Runtime>,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let session = rt.admin_session().await?;
    rt.delete_role(&session, &id).await.map_err(|e| {
        if matches!(e, crate::error::Error::Invalid(_)) {
            ApiError::new(axum::http::StatusCode::BAD_REQUEST, e.to_string())
        } else {
            ApiError::from(e)
        }
    })?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub fn router() -> Router<crate::server::state::AppState> {
    Router::new()
        .route("/roles", get(list_roles).post(create_role))
        .route("/roles/{id}", patch(patch_role).delete(delete_role))
}
