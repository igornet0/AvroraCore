//! Correlation context — opaque ids only; never secrets.

use serde::{Deserialize, Serialize};

/// Optional correlation fields for a single observability emission.
///
/// `session_id` is **not** an authentication proof.
/// `request_id` is **not** a security credential.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservabilityContext {
    pub request_id: Option<String>,
    pub connection_id: Option<String>,
    pub session_id: Option<String>,
    pub transaction_id: Option<String>,
    pub journal_sequence: Option<u64>,
}

impl ObservabilityContext {
    pub fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    pub fn with_session_id(mut self, id: impl Into<String>) -> Self {
        self.session_id = Some(id.into());
        self
    }

    pub fn with_connection_id(mut self, id: impl Into<String>) -> Self {
        self.connection_id = Some(id.into());
        self
    }

    pub fn with_transaction_id(mut self, id: impl Into<String>) -> Self {
        self.transaction_id = Some(id.into());
        self
    }

    pub fn with_journal_sequence(mut self, seq: u64) -> Self {
        self.journal_sequence = Some(seq);
        self
    }
}
