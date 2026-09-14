use std::collections::HashMap;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::ids::ChannelId;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChannelKind {
    Internal,
    Tcp,
    Http,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelSpec {
    pub id: ChannelId,
    pub kind: ChannelKind,
    #[serde(default)]
    pub bind: Option<String>,
    #[serde(default = "default_cap")]
    pub capacity: usize,
}

fn default_cap() -> usize {
    256
}

impl ChannelSpec {
    pub fn internal(id: impl Into<String>) -> Self {
        Self {
            id: ChannelId::from(id.into()),
            kind: ChannelKind::Internal,
            bind: None,
            capacity: 256,
        }
    }

    pub fn tcp(id: impl Into<String>, bind: SocketAddr) -> Self {
        Self {
            id: ChannelId::from(id.into()),
            kind: ChannelKind::Tcp,
            bind: Some(bind.to_string()),
            capacity: 256,
        }
    }

    pub fn http(id: impl Into<String>, bind: SocketAddr) -> Self {
        Self {
            id: ChannelId::from(id.into()),
            kind: ChannelKind::Http,
            bind: Some(bind.to_string()),
            capacity: 256,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelInfo {
    pub spec: ChannelSpec,
    pub started: bool,
}

#[derive(Clone, Default)]
pub struct ChannelRegistry {
    channels: HashMap<String, ChannelInfo>,
}

impl ChannelRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn configure(&mut self, spec: ChannelSpec) -> Result<ChannelId> {
        let id = spec.id.clone();
        if self.channels.contains_key(id.as_str()) {
            return Err(Error::ChannelExists(id.to_string()));
        }
        let started = spec.kind == ChannelKind::Internal;
        self.channels
            .insert(id.0.clone(), ChannelInfo { spec, started });
        Ok(id)
    }

    pub fn start(&mut self, id: &ChannelId) -> Result<()> {
        let ch = self
            .channels
            .get_mut(id.as_str())
            .ok_or_else(|| Error::UnknownChannel(id.to_string()))?;
        ch.started = true;
        Ok(())
    }

    pub fn stop(&mut self, id: &ChannelId) -> Result<()> {
        let ch = self
            .channels
            .get_mut(id.as_str())
            .ok_or_else(|| Error::UnknownChannel(id.to_string()))?;
        ch.started = false;
        Ok(())
    }

    pub fn get(&self, id: &ChannelId) -> Result<&ChannelInfo> {
        self.channels
            .get(id.as_str())
            .ok_or_else(|| Error::UnknownChannel(id.to_string()))
    }

    pub fn list(&self) -> Vec<ChannelInfo> {
        self.channels.values().cloned().collect()
    }
}
