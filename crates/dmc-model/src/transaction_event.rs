use serde::{Deserialize, Serialize};

use crate::data_event::DataEvent;
use crate::event::CatalogEvent;

/// One event staged inside an explicit SQL transaction (DDL or DML).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum TransactionEvent {
    Catalog(CatalogEvent),
    Data(DataEvent),
}

impl TransactionEvent {
    pub fn validate(&self) -> crate::error::Result<()> {
        match self {
            Self::Catalog(event) => event.validate(),
            Self::Data(event) => event.validate(),
        }
    }

    pub fn as_data(&self) -> Option<&DataEvent> {
        match self {
            Self::Data(event) => Some(event),
            _ => None,
        }
    }

    pub fn as_catalog(&self) -> Option<&CatalogEvent> {
        match self {
            Self::Catalog(event) => Some(event),
            _ => None,
        }
    }
}
