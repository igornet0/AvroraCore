use dmc_protocol::{
    ChannelInfoWire, ChannelKindWire, ChannelSpecWire, ControlRequest, ControlResponse,
    ProtocolErrorCode, ResponseEnvelope, RuntimeEventWire, SchemaSnapshotWire, ServerCapabilities,
    StreamDirectionWire, StreamSpecWire, TriggerActionWire, TriggerDefWire,
};
use dmc_runtime::{
    parse_event_kind, parse_key_path, parse_perms, ChannelInfo, ChannelKind, ChannelSpec, CoreEvent,
    StreamDirection, StreamSpec, TriggerAction, TriggerDef,
};

use crate::state::CoreServerState;

pub fn capabilities() -> ServerCapabilities {
    ServerCapabilities::core_v1()
}

pub fn handle_runtime(
    state: &mut CoreServerState,
    request_id: u64,
    body: ControlRequest,
) -> ResponseEnvelope<ControlResponse> {
    match body {
        ControlRequest::GetCapabilities => {
            ResponseEnvelope::ok(request_id, ControlResponse::Capabilities(capabilities()))
        }
        ControlRequest::ChannelList { .. } => ResponseEnvelope::ok(
            request_id,
            ControlResponse::ChannelList {
                items: state.runtime.list_channels().into_iter().map(channel_to_wire).collect(),
            },
        ),
        ControlRequest::ChannelGet { id, .. } => match state.runtime.channel(&id.as_str().into()) {
            Ok(info) => ResponseEnvelope::ok(request_id, ControlResponse::ChannelInfo(channel_to_wire(info))),
            Err(err) => map_hub_err(request_id, err),
        },
        ControlRequest::ChannelConfigure { spec, .. } => match wire_to_channel_spec(spec)
            .and_then(|s| state.runtime.configure_channel(s))
        {
            Ok(id) => ResponseEnvelope::ok(
                request_id,
                ControlResponse::ChannelConfigured { id: id.to_string() },
            ),
            Err(err) => map_hub_err(request_id, err),
        },
        ControlRequest::ChannelStart { id, .. } => {
            match state.runtime.start_channel(&id.as_str().into()) {
                Ok(()) => ResponseEnvelope::ok(request_id, ControlResponse::RuntimeOk),
                Err(err) => map_hub_err(request_id, err),
            }
        }
        ControlRequest::ChannelStop { id, .. } => {
            match state.runtime.stop_channel(&id.as_str().into()) {
                Ok(()) => ResponseEnvelope::ok(request_id, ControlResponse::RuntimeOk),
                Err(err) => map_hub_err(request_id, err),
            }
        }
        ControlRequest::StreamList { .. } => ResponseEnvelope::ok(
            request_id,
            ControlResponse::StreamList {
                items: state.runtime.list_streams().into_iter().map(stream_to_wire).collect(),
            },
        ),
        ControlRequest::StreamGet { id, .. } => match state.runtime.stream(&id.as_str().into()) {
            Ok(spec) => ResponseEnvelope::ok(request_id, ControlResponse::StreamInfo(stream_to_wire(spec))),
            Err(err) => map_hub_err(request_id, err),
        },
        ControlRequest::StreamCreate { spec, .. } => match wire_to_stream_spec(spec)
            .and_then(|s| state.runtime.create_stream(s))
        {
            Ok(id) => ResponseEnvelope::ok(
                request_id,
                ControlResponse::StreamCreated { id: id.to_string() },
            ),
            Err(err) => map_hub_err(request_id, err),
        },
        ControlRequest::StreamIngest {
            stream_id,
            path,
            payload,
            session_id,
            ..
        } => match state
            .runtime
            .ingest(&stream_id.as_str().into(), &path, payload.as_bytes(), &session_id)
        {
            Ok(()) => ResponseEnvelope::ok(request_id, ControlResponse::RuntimeOk),
            Err(err) => map_hub_err(request_id, err),
        },
        ControlRequest::TriggerList { .. } => ResponseEnvelope::ok(
            request_id,
            ControlResponse::TriggerList {
                items: state.runtime.list_triggers().into_iter().map(trigger_to_wire).collect(),
            },
        ),
        ControlRequest::TriggerGet { id, .. } => match state.runtime.trigger(&id.as_str().into()) {
            Ok(def) => ResponseEnvelope::ok(request_id, ControlResponse::TriggerInfo(trigger_to_wire(def))),
            Err(err) => map_hub_err(request_id, err),
        },
        ControlRequest::TriggerCreate { def, .. } => match wire_to_trigger(def)
            .and_then(|t| state.runtime.register_trigger(t))
        {
            Ok(id) => ResponseEnvelope::ok(
                request_id,
                ControlResponse::TriggerCreated { id: id.to_string() },
            ),
            Err(err) => map_hub_err(request_id, err),
        },
        ControlRequest::EventList { limit, .. } => ResponseEnvelope::ok(
            request_id,
            ControlResponse::EventList {
                items: state
                    .runtime
                    .recent_events(limit as usize)
                    .into_iter()
                    .map(event_to_wire)
                    .collect(),
            },
        ),
        ControlRequest::RuntimeSchema { .. } => {
            let snap = state.runtime.schema_snapshot();
            ResponseEnvelope::ok(
                request_id,
                ControlResponse::RuntimeSchema(SchemaSnapshotWire {
                    product: snap.product,
                    channels: snap.channels.into_iter().map(channel_to_wire).collect(),
                    streams: snap.streams.into_iter().map(stream_to_wire).collect(),
                    triggers: snap.triggers.into_iter().map(trigger_to_wire).collect(),
                }),
            )
        }
        ControlRequest::CatalogList { .. }
        | ControlRequest::DatabaseList { .. }
        | ControlRequest::SchemaList { .. }
        | ControlRequest::TableList { .. }
        | ControlRequest::TableGet { .. }
        | ControlRequest::ColumnList { .. }
        | ControlRequest::IndexList { .. }
        | ControlRequest::ConstraintList { .. } => {
            crate::catalog_ops::handle_catalog(state, request_id, body)
        }
        req if crate::ddl_ops::is_ddl_request(&req) => {
            crate::ddl_ops::handle_ddl(state, request_id, req)
        }
        other => ResponseEnvelope::err(
            request_id,
            ProtocolErrorCode::InvalidRequest,
            format!("not a runtime request: {other:?}"),
        ),
    }
}

fn channel_to_wire(info: ChannelInfo) -> ChannelInfoWire {
    ChannelInfoWire {
        spec: ChannelSpecWire {
            id: info.spec.id.to_string(),
            kind: match info.spec.kind {
                ChannelKind::Internal => ChannelKindWire::Internal,
                ChannelKind::Tcp => ChannelKindWire::Tcp,
                ChannelKind::Http => ChannelKindWire::Http,
            },
            bind: info.spec.bind,
            capacity: info.spec.capacity as u32,
        },
        started: info.started,
    }
}

fn wire_to_channel_spec(spec: ChannelSpecWire) -> dmc_runtime::Result<ChannelSpec> {
    Ok(ChannelSpec {
        id: spec.id.into(),
        kind: match spec.kind {
            ChannelKindWire::Internal => ChannelKind::Internal,
            ChannelKindWire::Tcp => ChannelKind::Tcp,
            ChannelKindWire::Http => ChannelKind::Http,
        },
        bind: spec.bind,
        capacity: spec.capacity as usize,
    })
}

fn stream_to_wire(spec: StreamSpec) -> StreamSpecWire {
    StreamSpecWire {
        id: spec.id.to_string(),
        direction: match spec.direction {
            StreamDirection::Inbound => StreamDirectionWire::Inbound,
            StreamDirection::Outbound => StreamDirectionWire::Outbound,
        },
        channel_id: spec.channel_id.to_string(),
        path_scope: spec.path_scope.to_string(),
        required_perms: spec.required_perms.to_names().into_iter().map(str::to_string).collect(),
    }
}

fn wire_to_stream_spec(spec: StreamSpecWire) -> dmc_runtime::Result<StreamSpec> {
    let direction = match spec.direction {
        StreamDirectionWire::Inbound => StreamDirection::Inbound,
        StreamDirectionWire::Outbound => StreamDirection::Outbound,
    };
    Ok(StreamSpec {
        id: spec.id.into(),
        direction,
        channel_id: spec.channel_id.into(),
        path_scope: parse_key_path(&spec.path_scope)?,
        required_perms: parse_perms(&spec.required_perms)?,
    })
}

fn trigger_to_wire(def: TriggerDef) -> TriggerDefWire {
    let stream_id = match def.action {
        TriggerAction::ForwardToStream { stream_id } => stream_id.to_string(),
    };
    TriggerDefWire {
        id: def.id.to_string(),
        on: def.on.as_wire().into(),
        path_prefix: def.path_prefix,
        action: TriggerActionWire { stream_id },
    }
}

fn wire_to_trigger(def: TriggerDefWire) -> dmc_runtime::Result<TriggerDef> {
    Ok(TriggerDef {
        id: def.id.into(),
        on: parse_event_kind(&def.on)?,
        path_prefix: def.path_prefix,
        action: TriggerAction::forward(def.action.stream_id.into()),
    })
}

fn event_to_wire(event: CoreEvent) -> RuntimeEventWire {
    RuntimeEventWire {
        kind: event.kind.as_wire().into(),
        path: event.path,
        payload: String::from_utf8_lossy(&event.payload).into_owned(),
        session: event.session,
        role_id: event.role_id,
        source_stream: event.source_stream,
        ts: event.ts,
    }
}

fn map_hub_err(request_id: u64, err: dmc_runtime::Error) -> ResponseEnvelope<ControlResponse> {
    let (code, msg) = match &err {
        dmc_runtime::Error::UnknownChannel(_)
        | dmc_runtime::Error::UnknownStream(_)
        | dmc_runtime::Error::UnknownTrigger(_) => (ProtocolErrorCode::ResourceNotFound, err.to_string()),
        dmc_runtime::Error::ChannelExists(_)
        | dmc_runtime::Error::StreamExists(_)
        | dmc_runtime::Error::Invalid(_)
        | dmc_runtime::Error::NotInbound(_)
        | dmc_runtime::Error::OutsideScope(_) => (ProtocolErrorCode::InvalidRequest, err.to_string()),
        dmc_runtime::Error::Vault(_) => (ProtocolErrorCode::InvalidRequest, "request rejected".into()),
    };
    ResponseEnvelope::err(request_id, code, msg)
}
