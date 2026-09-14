use serde::{Deserialize, Serialize};

use crate::data_event::DataEvent;
use crate::event::CatalogEvent;
use crate::ids::TransactionId;
use crate::transaction_event::TransactionEvent;

/// Unified materialized-state event — global journal ordering across DDL and DML.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum StateEvent {
    Catalog(CatalogEvent),
    Data(DataEvent),
    /// Atomic transaction commit — all nested events share one journal sequence.
    TransactionCommit {
        transaction_id: TransactionId,
        events: Vec<TransactionEvent>,
    },
}

impl StateEvent {
    pub fn validate(&self) -> crate::error::Result<()> {
        match self {
            StateEvent::Catalog(event) => event.validate(),
            StateEvent::Data(event) => event.validate(),
            StateEvent::TransactionCommit { events, .. } => {
                if events.is_empty() {
                    return Err(crate::error::Error::InvalidEvent(
                        "transaction commit requires at least one event".into(),
                    ));
                }
                for event in events {
                    event.validate()?;
                }
                Ok(())
            }
        }
    }
}
