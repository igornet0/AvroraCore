//! Single fan-out point after a journal append/replay.
//!
//! `dmc-journal` remains durable ordered storage. Dispatch, materialization,
//! triggers and consumers live in `dmc-core`.

use dmc_journal::JournalEntry;

use crate::error::Result;
use crate::materializer::{ApplyMode, Materializer};

/// Downstream of the journal. Implementors must not append to the journal.
pub trait EventSink {
    fn on_event(&mut self, event: &JournalEntry) -> Result<()>;
}

pub struct MaterializerSink<'a> {
    pub materializer: Materializer<'a>,
    pub mode: ApplyMode,
}

impl EventSink for MaterializerSink<'_> {
    fn on_event(&mut self, event: &JournalEntry) -> Result<()> {
        self.materializer.apply(event, self.mode)
    }
}

/// Ordered fan-out: materializer, then any additional sinks (triggers, consumers).
pub fn fan_out(sinks: &mut [&mut dyn EventSink], event: &JournalEntry) -> Result<()> {
    for sink in sinks {
        sink.on_event(event)?;
    }
    Ok(())
}

/// Consumers read the journal by offset (pull). This sink only records that
/// a sequence was dispatched, so delivery itself stays ACK-driven.
#[derive(Default)]
pub struct ConsumerSink {
    pub last_sequence: u64,
}

impl EventSink for ConsumerSink {
    fn on_event(&mut self, event: &JournalEntry) -> Result<()> {
        self.last_sequence = event.sequence;
        Ok(())
    }
}
