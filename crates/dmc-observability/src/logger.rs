//! Failure-isolated observability facade.

use std::sync::{Arc, Mutex, OnceLock};

use crate::event::ObservabilityEvent;
use crate::sanitize::sanitize_event;

/// Sink error — never propagated to SQL/Auth callers.
#[derive(Clone, Debug)]
pub struct ObservabilityError(pub String);

pub trait EventSink: Send + Sync {
    fn emit(&self, event: &ObservabilityEvent) -> Result<(), ObservabilityError>;

    /// Sink can accept events. Default true; FailingSink overrides.
    fn available(&self) -> bool {
        true
    }
}

/// Default production sink — structured `tracing` fields (subscriber decides JSON/text).
#[derive(Clone, Debug, Default)]
pub struct TracingSink;

impl EventSink for TracingSink {
    fn emit(&self, event: &ObservabilityEvent) -> Result<(), ObservabilityError> {
        tracing::info!(
            event = event.name(),
            category = ?event.category,
            outcome = ?event.outcome,
            timestamp_ms = event.timestamp_ms,
            request_id = event.context.request_id.as_deref().unwrap_or(""),
            connection_id = event.context.connection_id.as_deref().unwrap_or(""),
            session_id = event.context.session_id.as_deref().unwrap_or(""),
            transaction_id = event.context.transaction_id.as_deref().unwrap_or(""),
            journal_sequence = event.context.journal_sequence.unwrap_or(0),
            fields = %serde_json::to_string(&event.fields).unwrap_or_else(|_| "{}".into()),
            "observability"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct NoopSink;

impl EventSink for NoopSink {
    fn emit(&self, _event: &ObservabilityEvent) -> Result<(), ObservabilityError> {
        Ok(())
    }
}

/// Always fails — for failure-isolation tests.
#[derive(Clone, Debug, Default)]
pub struct FailingSink;

impl EventSink for FailingSink {
    fn emit(&self, _event: &ObservabilityEvent) -> Result<(), ObservabilityError> {
        Err(ObservabilityError("observer unavailable".into()))
    }

    fn available(&self) -> bool {
        false
    }
}

/// In-memory capture for tests.
#[derive(Clone, Debug, Default)]
pub struct MemorySink {
    events: Arc<Mutex<Vec<ObservabilityEvent>>>,
}

impl MemorySink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn shared(events: Arc<Mutex<Vec<ObservabilityEvent>>>) -> Self {
        Self { events }
    }

    pub fn events(&self) -> Arc<Mutex<Vec<ObservabilityEvent>>> {
        Arc::clone(&self.events)
    }

    pub fn snapshot(&self) -> Vec<ObservabilityEvent> {
        self.events.lock().map(|g| g.clone()).unwrap_or_default()
    }

    pub fn clear(&self) {
        if let Ok(mut g) = self.events.lock() {
            g.clear();
        }
    }
}

impl EventSink for MemorySink {
    fn emit(&self, event: &ObservabilityEvent) -> Result<(), ObservabilityError> {
        let mut g = self
            .events
            .lock()
            .map_err(|_| ObservabilityError("lock".into()))?;
        g.push(event.clone());
        Ok(())
    }
}

#[derive(Clone)]
pub struct Observability {
    sink: Arc<dyn EventSink>,
}

impl Default for Observability {
    fn default() -> Self {
        Self::tracing()
    }
}

impl Observability {
    pub fn new(sink: Arc<dyn EventSink>) -> Self {
        Self { sink }
    }

    pub fn tracing() -> Self {
        Self::new(Arc::new(TracingSink))
    }

    pub fn noop() -> Self {
        Self::new(Arc::new(NoopSink))
    }

    pub fn failing() -> Self {
        Self::new(Arc::new(FailingSink))
    }

    pub fn memory(sink: MemorySink) -> Self {
        Self::new(Arc::new(sink))
    }

    /// Emit a structured event. **Never** returns an error to the caller.
    pub fn emit(&self, event: ObservabilityEvent) {
        let event = sanitize_event(event);
        let _ = self.sink.emit(&event);
    }

    /// Probe sink availability for diagnostics (failure ≠ Core NotReady).
    pub fn probe(&self) -> crate::diagnostics::ObservabilityComponentStatus {
        use crate::diagnostics::ObservabilityComponentStatus;
        if self.sink.available() {
            ObservabilityComponentStatus::Available
        } else {
            ObservabilityComponentStatus::Degraded
        }
    }
}

static GLOBAL: OnceLock<Observability> = OnceLock::new();

/// Process-global facade (optional). Prefer `CoreServerState.observability` when available.
pub fn set_global(obs: Observability) {
    let _ = GLOBAL.set(obs);
}

pub fn log_event(event: ObservabilityEvent) {
    GLOBAL
        .get_or_init(Observability::tracing)
        .emit(event);
}
