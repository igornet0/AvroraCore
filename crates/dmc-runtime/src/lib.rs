//! Shared Runtime domain: channels, streams, triggers, events.
//!
//! HTTP admin (`dmc-core`) and DMC Control (`dmc-server`) both call [`RuntimeHub`].

pub mod channel;
pub mod error;
pub mod event;
pub mod hub;
pub mod ids;
pub mod parse;
pub mod stream;
pub mod trigger;

pub use channel::{ChannelInfo, ChannelKind, ChannelRegistry, ChannelSpec};
pub use error::{Error, Result};
pub use event::{CoreEvent, EventKind, EventLog};
pub use hub::{RuntimeHub, RuntimeSchemaSnapshot};
pub use ids::{ChannelId, StreamId, TriggerId};
pub use parse::{parse_channel_kind, parse_event_kind, parse_key_path, parse_perms, parse_stream_direction};
pub use stream::{StreamDirection, StreamEntry, StreamManager, StreamMessage, StreamSpec};
pub use trigger::{parse_prefix, TriggerAction, TriggerDef, TriggerEngine};
