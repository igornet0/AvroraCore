use dmc_vault::access::PermissionSet;
use dmc_vault::key::KeyPath;

use crate::channel::ChannelKind;
use crate::error::{Error, Result};
use crate::event::EventKind;
use crate::stream::StreamDirection;

pub fn parse_channel_kind(raw: &str) -> Result<ChannelKind> {
    match raw.to_ascii_lowercase().as_str() {
        "internal" => Ok(ChannelKind::Internal),
        "tcp" => Ok(ChannelKind::Tcp),
        "http" => Ok(ChannelKind::Http),
        other => Err(Error::Invalid(format!("unknown kind: {other}"))),
    }
}

pub fn parse_stream_direction(raw: &str) -> Result<StreamDirection> {
    match raw.to_ascii_lowercase().as_str() {
        "inbound" => Ok(StreamDirection::Inbound),
        "outbound" => Ok(StreamDirection::Outbound),
        other => Err(Error::Invalid(format!("bad direction: {other}"))),
    }
}

pub fn parse_event_kind(raw: &str) -> Result<EventKind> {
    Ok(match raw {
        "DataPut" | "data_put" => EventKind::DataPut,
        "DataDelete" | "data_delete" => EventKind::DataDelete,
        "KeyRevoke" | "key_revoke" => EventKind::KeyRevoke,
        "KeyRotate" | "key_rotate" => EventKind::KeyRotate,
        "StreamMessage" | "stream_message" => EventKind::StreamMessage,
        "OverlayApply" | "overlay_apply" => EventKind::OverlayApply,
        "SubsystemTick" | "subsystem_tick" => EventKind::SubsystemTick,
        other => {
            return Err(Error::Invalid(format!("unknown event: {other}")));
        }
    })
}

pub fn parse_key_path(raw: &str) -> Result<KeyPath> {
    let t = raw.trim().trim_matches('/');
    if t.is_empty() {
        Ok(KeyPath::root())
    } else {
        KeyPath::parse(t).map_err(Error::from_vault)
    }
}

pub fn parse_perms(names: &[String]) -> Result<PermissionSet> {
    if names.is_empty() {
        Ok(PermissionSet::read_write())
    } else {
        PermissionSet::from_names(names).map_err(Error::from_vault)
    }
}
