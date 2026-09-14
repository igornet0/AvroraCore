use serde::{Deserialize, Serialize};

use crate::ids::{SessionId, StreamId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventKind {
    DataPut,
    DataDelete,
    KeyRevoke,
    KeyRotate,
    StreamMessage,
    OverlayApply,
    SubsystemTick,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoreEvent {
    pub kind: EventKind,
    pub path: String,
    pub payload: Vec<u8>,
    pub session: String,
    pub role_id: String,
    pub source_stream: Option<String>,
    pub ts: String,
}

impl CoreEvent {
    pub fn new(
        kind: EventKind,
        path: impl Into<String>,
        payload: Vec<u8>,
        session: &SessionId,
        role_id: impl Into<String>,
        source_stream: Option<&StreamId>,
    ) -> Self {
        Self {
            kind,
            path: path.into(),
            payload,
            session: session.to_string(),
            role_id: role_id.into(),
            source_stream: source_stream.map(|s| s.to_string()),
            ts: chrono::Utc::now().to_rfc3339(),
        }
    }
}

#[derive(Clone, Default)]
pub struct EventLog {
    events: Vec<CoreEvent>,
    cap: usize,
}

impl EventLog {
    pub fn new(cap: usize) -> Self {
        Self {
            events: Vec::new(),
            cap: cap.max(32),
        }
    }

    pub fn push(&mut self, event: CoreEvent) {
        self.events.push(event);
        if self.events.len() > self.cap {
            let drop_n = self.events.len() - self.cap;
            self.events.drain(0..drop_n);
        }
    }

    pub fn list(&self, limit: usize) -> Vec<CoreEvent> {
        let n = limit.min(self.events.len());
        self.events[self.events.len() - n..].to_vec()
    }

    pub fn clear(&mut self) {
        self.events.clear();
    }
}
