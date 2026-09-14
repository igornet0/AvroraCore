//! Runnable data producers that emit into inbound streams (reference/overlay path).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::ids::{SessionId, StreamId, SubsystemId};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubsystemSpec {
    pub id: SubsystemId,
    pub name: String,
    pub stream_id: StreamId,
    /// Path template; `{n}` replaced with tick counter.
    pub path_template: String,
    pub interval_ms: u64,
    /// Static JSON/text payload template; `{n}` and `{ts}` substituted.
    pub payload_template: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SubsystemInfo {
    pub spec: SubsystemSpec,
    pub running: bool,
    pub ticks: u64,
}

struct LiveSubsystem {
    spec: SubsystemSpec,
    running: Arc<AtomicBool>,
    ticks: u64,
    handle: Option<JoinHandle<()>>,
}

#[derive(Clone)]
pub struct SubsystemManager {
    // managed under Runtime mutex; this type is only held there
}

impl Default for SubsystemManager {
    fn default() -> Self {
        Self {}
    }
}

/// Registry held inside RuntimeInner.
pub struct SubsystemRegistry {
    items: HashMap<String, LiveSubsystem>,
}

impl Default for SubsystemRegistry {
    fn default() -> Self {
        Self {
            items: HashMap::new(),
        }
    }
}

impl SubsystemRegistry {
    pub fn register(&mut self, spec: SubsystemSpec) -> Result<SubsystemId, String> {
        let id = spec.id.clone();
        if self.items.contains_key(id.as_str()) {
            return Err(format!("subsystem exists: {id}"));
        }
        self.items.insert(
            id.0.clone(),
            LiveSubsystem {
                spec,
                running: Arc::new(AtomicBool::new(false)),
                ticks: 0,
                handle: None,
            },
        );
        Ok(id)
    }

    pub fn list(&self) -> Vec<SubsystemInfo> {
        self.items
            .values()
            .map(|s| SubsystemInfo {
                spec: s.spec.clone(),
                running: s.running.load(Ordering::SeqCst),
                ticks: s.ticks,
            })
            .collect()
    }

    pub fn remove(&mut self, id: &SubsystemId) -> Result<(), String> {
        let Some(mut item) = self.items.remove(id.as_str()) else {
            return Err(format!("unknown subsystem: {id}"));
        };
        item.running.store(false, Ordering::SeqCst);
        if let Some(h) = item.handle.take() {
            h.abort();
        }
        Ok(())
    }

    pub fn take_for_start(
        &mut self,
        id: &SubsystemId,
    ) -> Result<(SubsystemSpec, Arc<AtomicBool>), String> {
        let item = self
            .items
            .get_mut(id.as_str())
            .ok_or_else(|| format!("unknown subsystem: {id}"))?;
        if item.running.load(Ordering::SeqCst) {
            return Err(format!("already running: {id}"));
        }
        item.running.store(true, Ordering::SeqCst);
        Ok((item.spec.clone(), Arc::clone(&item.running)))
    }

    pub fn attach_handle(&mut self, id: &SubsystemId, handle: JoinHandle<()>) {
        if let Some(item) = self.items.get_mut(id.as_str()) {
            item.handle = Some(handle);
        }
    }

    pub fn stop(&mut self, id: &SubsystemId) -> Result<(), String> {
        let item = self
            .items
            .get_mut(id.as_str())
            .ok_or_else(|| format!("unknown subsystem: {id}"))?;
        item.running.store(false, Ordering::SeqCst);
        if let Some(h) = item.handle.take() {
            h.abort();
        }
        Ok(())
    }

    pub fn bump_tick(&mut self, id: &SubsystemId) {
        if let Some(item) = self.items.get_mut(id.as_str()) {
            item.ticks += 1;
        }
    }
}

pub fn render_template(tpl: &str, n: u64) -> String {
    let ts = chrono::Utc::now().to_rfc3339();
    tpl.replace("{n}", &n.to_string()).replace("{ts}", &ts)
}

pub fn interval(spec: &SubsystemSpec) -> Duration {
    Duration::from_millis(spec.interval_ms.max(50))
}

/// Context passed into subsystem tick loop.
pub struct TickCtx {
    pub session: SessionId,
    pub stream: StreamId,
    pub path: String,
    pub payload: Vec<u8>,
}
