use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::channel::ChannelSpec;
use crate::event::EventKind;
use crate::ids::{StreamId, SubsystemId, TriggerId};
use crate::runtime::Runtime;
use crate::server::error::ApiResult;
use crate::stream::{StreamDirection, StreamSpec};
use crate::subsystem::SubsystemSpec;
use crate::trigger::{TriggerAction, TriggerDef};
use dmc_vault::PermissionSet;
use dmc_vault::key::KeyPath;

#[derive(Deserialize)]
struct LimitQuery {
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    100
}

#[derive(Deserialize)]
struct PrefixQuery {
    #[serde(default)]
    prefix: String,
}

use crate::error::Error;

fn json_val<T: serde::Serialize>(v: T) -> Result<serde_json::Value, Error> {
    serde_json::to_value(v).map_err(|e| Error::Invalid(e.to_string()))
}

async fn list_channels(State(rt): State<Runtime>) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json_val(rt.list_channels().await)?))
}

#[derive(Deserialize)]
struct ChannelBody {
    id: String,
    kind: String,
    bind: Option<String>,
    #[serde(default = "default_cap")]
    capacity: usize,
}

fn default_cap() -> usize {
    256
}

async fn create_channel(
    State(rt): State<Runtime>,
    Json(body): Json<ChannelBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let kind = match body.kind.to_ascii_lowercase().as_str() {
        "internal" => crate::channel::ChannelKind::Internal,
        "tcp" => crate::channel::ChannelKind::Tcp,
        "http" => crate::channel::ChannelKind::Http,
        other => return Err(crate::error::Error::Invalid(format!("unknown kind: {other}")).into()),
    };
    let id = rt
        .configure_channel(ChannelSpec {
            id: body.id.into(),
            kind,
            bind: body.bind,
            capacity: body.capacity,
        })
        .await?;
    Ok(Json(
        serde_json::json!({ "ok": true, "id": id.to_string() }),
    ))
}

async fn start_channel(
    State(rt): State<Runtime>,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    rt.start_channel(&id.into()).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn stop_channel(
    State(rt): State<Runtime>,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    rt.stop_channel(&id.into()).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn list_streams(State(rt): State<Runtime>) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json_val(rt.list_streams().await)?))
}

#[derive(Deserialize)]
struct StreamBody {
    id: String,
    direction: String,
    channel_id: String,
    path_scope: String,
    #[serde(default)]
    required_perms: Vec<String>,
}

async fn create_stream(
    State(rt): State<Runtime>,
    Json(body): Json<StreamBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let direction = match body.direction.to_ascii_lowercase().as_str() {
        "inbound" => StreamDirection::Inbound,
        "outbound" => StreamDirection::Outbound,
        other => {
            return Err(crate::error::Error::Invalid(format!("bad direction: {other}")).into());
        }
    };
    let scope = {
        let t = body.path_scope.trim().trim_matches('/');
        if t.is_empty() {
            KeyPath::root()
        } else {
            KeyPath::parse(t)?
        }
    };
    let perms = if body.required_perms.is_empty() {
        PermissionSet::read_write()
    } else {
        PermissionSet::from_names(&body.required_perms)?
    };
    let id = rt
        .create_stream(StreamSpec {
            id: StreamId::from(body.id),
            direction,
            channel_id: body.channel_id.into(),
            path_scope: scope,
            required_perms: perms,
        })
        .await?;
    Ok(Json(
        serde_json::json!({ "ok": true, "id": id.to_string() }),
    ))
}

#[derive(Deserialize)]
struct IngestBody {
    stream_id: String,
    path: String,
    value: String,
}

async fn ingest(
    State(rt): State<Runtime>,
    Json(body): Json<IngestBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let session = rt.admin_session().await?;
    rt.ingest(
        session,
        StreamId::from(body.stream_id),
        &body.path,
        body.value.as_bytes(),
    )
    .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn list_triggers(State(rt): State<Runtime>) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json_val(rt.list_triggers().await)?))
}

#[derive(Deserialize)]
struct TriggerBody {
    id: String,
    on: String,
    path_prefix: String,
    forward_stream_id: String,
}

async fn create_trigger(
    State(rt): State<Runtime>,
    Json(body): Json<TriggerBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let on = parse_event_kind(&body.on)?;
    let id = rt
        .register_trigger(TriggerDef {
            id: TriggerId::from(body.id),
            on,
            path_prefix: body.path_prefix,
            action: TriggerAction::forward(StreamId::from(body.forward_stream_id)),
        })
        .await?;
    Ok(Json(
        serde_json::json!({ "ok": true, "id": id.to_string() }),
    ))
}

fn parse_event_kind(raw: &str) -> crate::error::Result<EventKind> {
    Ok(match raw {
        "DataPut" | "data_put" => EventKind::DataPut,
        "DataDelete" | "data_delete" => EventKind::DataDelete,
        "KeyRevoke" | "key_revoke" => EventKind::KeyRevoke,
        "KeyRotate" | "key_rotate" => EventKind::KeyRotate,
        "StreamMessage" | "stream_message" => EventKind::StreamMessage,
        "OverlayApply" | "overlay_apply" => EventKind::OverlayApply,
        "SubsystemTick" | "subsystem_tick" => EventKind::SubsystemTick,
        other => {
            return Err(crate::error::Error::Invalid(format!(
                "unknown event: {other}"
            )));
        }
    })
}

async fn list_events(
    State(rt): State<Runtime>,
    Query(q): Query<LimitQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let events = rt.recent_events(q.limit).await;
    let out: Vec<_> = events
        .into_iter()
        .map(|e| {
            serde_json::json!({
                "kind": format!("{:?}", e.kind),
                "path": e.path,
                "payload": String::from_utf8_lossy(&e.payload),
                "session": e.session,
                "role_id": e.role_id,
                "source_stream": e.source_stream,
                "ts": e.ts,
            })
        })
        .collect();
    Ok(Json(serde_json::json!(out)))
}

async fn schema(State(rt): State<Runtime>) -> ApiResult<Json<serde_json::Value>> {
    let snap = rt.schema_snapshot().await?;
    Ok(Json(json_val(snap)?))
}

async fn list_overlays(
    State(rt): State<Runtime>,
    Query(q): Query<PrefixQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let layers = rt.list_overlays(&q.prefix).await;
    let out: Vec<_> = layers
        .into_iter()
        .map(|p| {
            serde_json::json!({
                "path": p.path,
                "deleted": p.deleted,
                "payload": String::from_utf8_lossy(&p.payload),
                "source": p.source,
                "seq": p.seq,
            })
        })
        .collect();
    Ok(Json(serde_json::json!(out)))
}

#[derive(Deserialize)]
struct ResolveBody {
    path: String,
}

async fn resolve(
    State(rt): State<Runtime>,
    Json(body): Json<ResolveBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let session = rt.admin_session().await?;
    let view = rt.resolve(&session, &body.path).await?;
    Ok(Json(serde_json::json!({
        "path": view.path,
        "base_present": view.base_present,
        "overlay_present": view.overlay_present,
        "deleted": view.deleted,
        "payload": view.payload.as_ref().map(|b| String::from_utf8_lossy(b).to_string()),
        "layer_seq": view.layer_seq,
    })))
}

#[derive(Deserialize)]
struct SealBody {
    path: String,
    value: String,
}

async fn seal_base(
    State(rt): State<Runtime>,
    Json(body): Json<SealBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let session = rt.admin_session().await?;
    rt.seal_base(&session, &body.path, body.value.as_bytes())
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn list_subsystems(State(rt): State<Runtime>) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json_val(rt.list_subsystems().await)?))
}

#[derive(Deserialize)]
struct SubsystemBody {
    id: String,
    name: String,
    stream_id: String,
    path_template: String,
    payload_template: String,
    #[serde(default = "default_interval")]
    interval_ms: u64,
}

fn default_interval() -> u64 {
    1000
}

async fn create_subsystem(
    State(rt): State<Runtime>,
    Json(body): Json<SubsystemBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let id = rt
        .register_subsystem(SubsystemSpec {
            id: SubsystemId::from(body.id),
            name: body.name,
            stream_id: StreamId::from(body.stream_id),
            path_template: body.path_template,
            interval_ms: body.interval_ms,
            payload_template: body.payload_template,
        })
        .await?;
    Ok(Json(
        serde_json::json!({ "ok": true, "id": id.to_string() }),
    ))
}

async fn start_subsystem(
    State(rt): State<Runtime>,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    rt.start_subsystem(&SubsystemId::from(id)).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn stop_subsystem(
    State(rt): State<Runtime>,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    rt.stop_subsystem(&SubsystemId::from(id)).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn delete_subsystem(
    State(rt): State<Runtime>,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    rt.remove_subsystem(&SubsystemId::from(id)).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Serialize)]
struct ProductDto {
    name: &'static str,
}

async fn product() -> Json<ProductDto> {
    Json(ProductDto {
        name: Runtime::product_name(),
    })
}

pub fn router() -> Router<crate::server::state::AppState> {
    Router::new()
        .route("/product", get(product))
        .route("/channels", get(list_channels).post(create_channel))
        .route("/channels/{id}/start", post(start_channel))
        .route("/channels/{id}/stop", post(stop_channel))
        .route("/streams", get(list_streams).post(create_stream))
        .route("/streams/ingest", post(ingest))
        .route("/triggers", get(list_triggers).post(create_trigger))
        .route("/events", get(list_events))
        .route("/schema", get(schema))
        .route("/overlays", get(list_overlays))
        .route("/resolve", post(resolve))
        .route("/seal", post(seal_base))
        .route("/subsystems", get(list_subsystems).post(create_subsystem))
        .route("/subsystems/{id}/start", post(start_subsystem))
        .route("/subsystems/{id}/stop", post(stop_subsystem))
        .route("/subsystems/{id}", axum::routing::delete(delete_subsystem))
}
