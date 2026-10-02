use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::event::{CoreEvent, EventKind};
use crate::ids::{StreamId, TriggerId};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TriggerAction {
    ForwardToStream { stream_id: StreamId },
}

impl TriggerAction {
    pub fn forward(stream_id: StreamId) -> Self {
        Self::ForwardToStream { stream_id }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TriggerDef {
    pub id: TriggerId,
    pub on: EventKind,
    pub path_prefix: String,
    pub action: TriggerAction,
}

#[derive(Clone, Default)]
pub struct TriggerEngine {
    triggers: Vec<TriggerDef>,
}

impl TriggerEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, def: TriggerDef) -> Result<TriggerId> {
        if self.triggers.iter().any(|t| t.id == def.id) {
            return Err(Error::Invalid(format!("trigger exists: {}", def.id)));
        }
        let id = def.id.clone();
        self.triggers.push(def);
        Ok(id)
    }

    pub fn matching(&self, event: &CoreEvent) -> Vec<TriggerDef> {
        self.triggers
            .iter()
            .filter(|t| t.on == event.kind && path_matches(&t.path_prefix, &event.path))
            .cloned()
            .collect()
    }

    pub fn get(&self, id: &TriggerId) -> Result<&TriggerDef> {
        self.triggers
            .iter()
            .find(|t| t.id == *id)
            .ok_or_else(|| Error::UnknownTrigger(id.to_string()))
    }

    pub fn list(&self) -> &[TriggerDef] {
        &self.triggers
    }

    pub fn update(&mut self, def: TriggerDef) -> Result<()> {
        let Some(slot) = self.triggers.iter_mut().find(|t| t.id == def.id) else {
            return Err(Error::UnknownTrigger(def.id.to_string()));
        };
        *slot = def;
        Ok(())
    }

    pub fn delete(&mut self, id: &TriggerId) -> Result<()> {
        let before = self.triggers.len();
        self.triggers.retain(|t| t.id != *id);
        if self.triggers.len() == before {
            return Err(Error::UnknownTrigger(id.to_string()));
        }
        Ok(())
    }
}

fn path_matches(prefix: &str, path: &str) -> bool {
    if prefix.is_empty() || prefix == "/" {
        return true;
    }
    let prefix = prefix.trim_matches('/');
    let path = path.trim_matches('/');
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

pub fn parse_prefix(raw: &str) -> Result<dmc_vault::key::KeyPath> {
    let t = raw.trim().trim_matches('/');
    if t.is_empty() {
        Ok(dmc_vault::key::KeyPath::root())
    } else {
        dmc_vault::key::KeyPath::parse(t).map_err(Error::from_vault)
    }
}
