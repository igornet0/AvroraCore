use std::sync::{Arc, Mutex};

use dmc_vault::key::KeyPath;
use tokio::sync::broadcast;

use crate::channel::{ChannelInfo, ChannelRegistry, ChannelSpec};
use crate::error::{Error, Result};
use crate::event::{CoreEvent, EventKind, EventLog};
use crate::ids::{ChannelId, StreamId, TriggerId};
use crate::parse::parse_key_path;
use crate::stream::{StreamDirection, StreamEntry, StreamManager, StreamMessage, StreamSpec};
use crate::trigger::{TriggerAction, TriggerDef, TriggerEngine};

struct HubInner {
    channels: ChannelRegistry,
    streams: StreamManager,
    triggers: TriggerEngine,
    events: EventLog,
}

/// Shared in-memory domain for channels, streams, triggers, and the event ring.
///
/// `Clone` shares the same registries (Arc). HTTP (`dmc-core`) and DMC (`dmc-server`)
/// must inject the same handle so both transports see one RuntimeHub per process.
#[derive(Clone)]
pub struct RuntimeHub {
    inner: Arc<Mutex<HubInner>>,
}

impl Default for RuntimeHub {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeHub {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HubInner {
                channels: ChannelRegistry::new(),
                streams: StreamManager::new(),
                triggers: TriggerEngine::new(),
                events: EventLog::new(500),
            })),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HubInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn same_as(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    pub fn configure_channel(&self, spec: ChannelSpec) -> Result<ChannelId> {
        self.lock().channels.configure(spec)
    }

    /// Idempotent install used by journal replay / materializer.
    pub fn ensure_channel(&self, spec: ChannelSpec) -> Result<ChannelId> {
        let mut g = self.lock();
        if g.channels.get(&spec.id).is_ok() {
            return Ok(spec.id);
        }
        g.channels.configure(spec)
    }

    pub fn start_channel(&self, id: &ChannelId) -> Result<()> {
        self.lock().channels.start(id)
    }

    pub fn stop_channel(&self, id: &ChannelId) -> Result<()> {
        self.lock().channels.stop(id)
    }

    pub fn restart_channel(&self, id: &ChannelId) -> Result<()> {
        let mut g = self.lock();
        g.channels.stop(id)?;
        g.channels.start(id)
    }

    pub fn delete_channel(&self, id: &ChannelId) -> Result<()> {
        self.lock().channels.delete(id)
    }

    pub fn update_channel(&self, spec: ChannelSpec) -> Result<()> {
        self.lock().channels.update(spec)
    }

    pub fn channel(&self, id: &ChannelId) -> Result<ChannelInfo> {
        self.lock().channels.get(id).cloned()
    }

    pub fn list_channels(&self) -> Vec<ChannelInfo> {
        self.lock().channels.list()
    }

    pub fn create_stream(&self, spec: StreamSpec) -> Result<StreamId> {
        let mut g = self.lock();
        g.channels.get(&spec.channel_id)?;
        g.streams.create(spec)
    }

    pub fn ensure_stream(&self, spec: StreamSpec) -> Result<StreamId> {
        let mut g = self.lock();
        if g.streams.get(&spec.id).is_ok() {
            return Ok(spec.id);
        }
        g.channels.get(&spec.channel_id)?;
        g.streams.create(spec)
    }

    pub fn stream(&self, id: &StreamId) -> Result<StreamSpec> {
        Ok(self.lock().streams.get(id)?.spec.clone())
    }

    pub fn stream_entry(&self, id: &StreamId) -> Result<StreamEntry> {
        self.lock().streams.get(id).cloned()
    }

    pub fn list_streams(&self) -> Vec<StreamSpec> {
        self.lock().streams.list()
    }

    pub fn update_stream(&self, spec: StreamSpec) -> Result<()> {
        let mut g = self.lock();
        g.channels.get(&spec.channel_id)?;
        g.streams.update(spec)
    }

    pub fn delete_stream(&self, id: &StreamId) -> Result<()> {
        self.lock().streams.delete(id)
    }

    pub fn subscribe_stream(
        &self,
        id: &StreamId,
    ) -> Result<broadcast::Receiver<StreamMessage>> {
        self.lock().streams.subscribe(id)
    }

    pub fn publish_stream(&self, id: &StreamId, msg: StreamMessage) -> Result<usize> {
        self.lock().streams.publish(id, msg)
    }

    pub fn register_trigger(&self, trigger: TriggerDef) -> Result<TriggerId> {
        self.lock().triggers.register(trigger)
    }

    pub fn ensure_trigger(&self, trigger: TriggerDef) -> Result<TriggerId> {
        let mut g = self.lock();
        if g.triggers.list().iter().any(|t| t.id == trigger.id) {
            return Ok(trigger.id);
        }
        g.triggers.register(trigger)
    }

    pub fn trigger(&self, id: &TriggerId) -> Result<TriggerDef> {
        self.lock().triggers.get(id).cloned()
    }

    pub fn list_triggers(&self) -> Vec<TriggerDef> {
        self.lock().triggers.list().to_vec()
    }

    pub fn update_trigger(&self, trigger: TriggerDef) -> Result<()> {
        self.lock().triggers.update(trigger)
    }

    pub fn delete_trigger(&self, id: &TriggerId) -> Result<()> {
        self.lock().triggers.delete(id)
    }

    pub fn matching_triggers(&self, event: &CoreEvent) -> Vec<TriggerDef> {
        self.lock().triggers.matching(event)
    }

    pub fn recent_events(&self, limit: usize) -> Vec<CoreEvent> {
        self.lock().events.list(limit)
    }

    pub fn push_event(&self, event: CoreEvent) {
        self.lock().events.push(event);
    }

    pub fn schema_snapshot(&self) -> RuntimeSchemaSnapshot {
        let g = self.lock();
        RuntimeSchemaSnapshot {
            product: "Avrora".into(),
            channels: g.channels.list(),
            streams: g.streams.list(),
            triggers: g.triggers.list().to_vec(),
        }
    }

    /// Domain ingest: inbound stream + path scope + event ring + trigger forward.
    /// Vault overlay / AuthZ stay in `dmc-core::Runtime::ingest`.
    pub fn ingest(
        &self,
        stream: &StreamId,
        path: &str,
        payload: &[u8],
        session: &str,
    ) -> Result<()> {
        let mut g = self.lock();
        let entry = g.streams.get(stream)?.clone();
        if entry.spec.direction != StreamDirection::Inbound {
            return Err(Error::NotInbound(stream.to_string()));
        }
        let key_path = parse_key_path(path)?;
        if !scope_covers(&entry.spec.path_scope, &key_path) {
            return Err(Error::OutsideScope(path.to_string()));
        }
        let event = CoreEvent::new(
            EventKind::DataPut,
            path,
            payload.to_vec(),
            session,
            "",
            Some(stream),
        );
        g.events.push(event.clone());
        let _ = g.streams.publish(
            stream,
            StreamMessage {
                stream_id: stream.clone(),
                path: path.to_string(),
                payload: payload.to_vec(),
                event: EventKind::DataPut,
            },
        );
        let matched = g.triggers.matching(&event);
        for trigger in matched {
            let TriggerAction::ForwardToStream { stream_id } = trigger.action;
            let fwd = CoreEvent::new(
                EventKind::StreamMessage,
                path,
                payload.to_vec(),
                session,
                "",
                Some(&stream_id),
            );
            g.events.push(fwd);
            let _ = g.streams.publish(
                &stream_id,
                StreamMessage {
                    stream_id: stream_id.clone(),
                    path: path.to_string(),
                    payload: payload.to_vec(),
                    event: EventKind::StreamMessage,
                },
            );
        }
        Ok(())
    }
}

fn scope_covers(scope: &KeyPath, path: &KeyPath) -> bool {
    scope.is_prefix_of(path)
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RuntimeSchemaSnapshot {
    pub product: String,
    pub channels: Vec<ChannelInfo>,
    pub streams: Vec<StreamSpec>,
    pub triggers: Vec<TriggerDef>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::ChannelKind;
    use crate::parse::{parse_event_kind, parse_key_path, parse_perms};

    #[test]
    fn clone_shares_state() {
        let a = RuntimeHub::new();
        let b = a.clone();
        assert!(a.same_as(&b));
        a.configure_channel(ChannelSpec {
            id: "ch1".into(),
            kind: ChannelKind::Internal,
            bind: None,
            capacity: 8,
        })
        .unwrap();
        assert_eq!(b.list_channels().len(), 1);
    }

    #[test]
    fn channel_stream_trigger_ingest() {
        let hub = RuntimeHub::new();
        hub.configure_channel(ChannelSpec {
            id: "ch1".into(),
            kind: ChannelKind::Internal,
            bind: None,
            capacity: 16,
        })
        .unwrap();
        hub.start_channel(&"ch1".into()).unwrap();
        hub.create_stream(StreamSpec {
            id: "in".into(),
            direction: StreamDirection::Inbound,
            channel_id: "ch1".into(),
            path_scope: KeyPath::root(),
            required_perms: parse_perms(&[]).unwrap(),
        })
        .unwrap();
        hub.create_stream(StreamSpec {
            id: "out".into(),
            direction: StreamDirection::Outbound,
            channel_id: "ch1".into(),
            path_scope: parse_key_path("/").unwrap(),
            required_perms: parse_perms(&[]).unwrap(),
        })
        .unwrap();
        hub.register_trigger(TriggerDef {
            id: "t1".into(),
            on: parse_event_kind("DataPut").unwrap(),
            path_prefix: "/".into(),
            action: TriggerAction::forward("out".into()),
        })
        .unwrap();
        hub.ingest(&"in".into(), "orders/1", b"{}", "sess").unwrap();
        assert_eq!(hub.list_channels().len(), 1);
        assert_eq!(hub.list_streams().len(), 2);
        assert_eq!(hub.list_triggers().len(), 1);
        assert!(hub.recent_events(10).len() >= 2);
        hub.delete_trigger(&"t1".into()).unwrap();
        hub.delete_stream(&"in".into()).unwrap();
        hub.delete_channel(&"ch1".into()).unwrap();
        assert!(hub.list_channels().is_empty());
    }

    #[test]
    fn unknown_channel_is_error() {
        let hub = RuntimeHub::new();
        let err = hub.start_channel(&"missing".into()).unwrap_err();
        assert!(matches!(err, Error::UnknownChannel(_)));
    }
}
