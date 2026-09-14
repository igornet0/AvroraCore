use std::collections::HashMap;

use dmc_vault::access::PermissionSet;
use dmc_vault::key::KeyPath;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::error::{Error, Result};
use crate::event::EventKind;
use crate::ids::{ChannelId, StreamId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StreamDirection {
    Inbound,
    Outbound,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamSpec {
    pub id: StreamId,
    pub direction: StreamDirection,
    pub channel_id: ChannelId,
    #[serde(with = "keypath_serde")]
    pub path_scope: KeyPath,
    #[serde(with = "permset_serde")]
    pub required_perms: PermissionSet,
}

mod keypath_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(path: &KeyPath, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&path.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<KeyPath, D::Error> {
        let raw = String::deserialize(d)?;
        let t = raw.trim().trim_matches('/');
        if t.is_empty() {
            Ok(KeyPath::root())
        } else {
            KeyPath::parse(t).map_err(serde::de::Error::custom)
        }
    }
}

mod permset_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        set: &PermissionSet,
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        s.collect_seq(set.to_names())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> std::result::Result<PermissionSet, D::Error> {
        let names: Vec<String> = Vec::deserialize(d)?;
        PermissionSet::from_names(&names).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug)]
pub struct StreamMessage {
    pub stream_id: StreamId,
    pub path: String,
    pub payload: Vec<u8>,
    pub event: EventKind,
}

pub struct StreamEntry {
    pub spec: StreamSpec,
    pub tx: broadcast::Sender<StreamMessage>,
}

impl Clone for StreamEntry {
    fn clone(&self) -> Self {
        Self {
            spec: self.spec.clone(),
            tx: self.tx.clone(),
        }
    }
}

#[derive(Clone, Default)]
pub struct StreamManager {
    streams: HashMap<String, StreamEntry>,
}

impl StreamManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create(&mut self, spec: StreamSpec) -> Result<StreamId> {
        let id = spec.id.clone();
        if self.streams.contains_key(id.as_str()) {
            return Err(Error::StreamExists(id.to_string()));
        }
        let (tx, _) = broadcast::channel(256);
        self.streams.insert(id.0.clone(), StreamEntry { spec, tx });
        Ok(id)
    }

    pub fn get(&self, id: &StreamId) -> Result<&StreamEntry> {
        self.streams
            .get(id.as_str())
            .ok_or_else(|| Error::UnknownStream(id.to_string()))
    }

    pub fn subscribe(&self, id: &StreamId) -> Result<broadcast::Receiver<StreamMessage>> {
        Ok(self.get(id)?.tx.subscribe())
    }

    pub fn publish(&self, id: &StreamId, msg: StreamMessage) -> Result<usize> {
        let entry = self.get(id)?;
        Ok(entry.tx.send(msg).unwrap_or(0))
    }

    pub fn list(&self) -> Vec<StreamSpec> {
        self.streams.values().map(|s| s.spec.clone()).collect()
    }
}
