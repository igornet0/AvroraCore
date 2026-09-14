use serde::{Deserialize, Serialize};

use crate::ids::SessionId;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditRecord {
    pub ts: String,
    pub session: String,
    pub role: String,
    pub path: String,
    pub op: String,
    pub outcome: String,
    #[serde(default)]
    pub event_id: String,
    #[serde(default)]
    pub sequence: u64,
    #[serde(default)]
    pub key_version: u64,
    #[serde(default)]
    pub result: String,
    #[serde(default)]
    pub audit_id: String,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub capability_id: Option<String>,
}

#[derive(Clone, Default)]
pub struct AuditLog {
    records: Vec<AuditRecord>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(
        &mut self,
        session: &SessionId,
        role: &str,
        path: &str,
        op: &str,
        outcome: &str,
    ) -> AuditRecord {
        self.record_full(session, role, path, op, outcome, "", 0, 0)
    }

    pub fn record_full(
        &mut self,
        session: &SessionId,
        role: &str,
        path: &str,
        op: &str,
        outcome: &str,
        event_id: &str,
        sequence: u64,
        key_version: u64,
    ) -> AuditRecord {
        let rec = AuditRecord {
            ts: chrono::Utc::now().to_rfc3339(),
            session: session.to_string(),
            role: role.to_string(),
            path: path.to_string(),
            op: op.to_string(),
            outcome: outcome.to_string(),
            event_id: event_id.to_string(),
            sequence,
            key_version,
            result: outcome.to_string(),
            audit_id: format!("aud_{}", uuid::Uuid::new_v4().as_simple()),
            user_id: None,
            device_id: None,
            capability_id: None,
        };
        self.records.push(rec.clone());
        rec
    }

    pub fn record_security(
        &mut self,
        session: Option<&SessionId>,
        user_id: Option<&str>,
        device_id: Option<&str>,
        capability_id: Option<&str>,
        op: &str,
        outcome: &str,
        path: &str,
    ) -> AuditRecord {
        let rec = AuditRecord {
            ts: chrono::Utc::now().to_rfc3339(),
            session: session.map(|s| s.to_string()).unwrap_or_default(),
            role: String::new(),
            path: path.to_string(),
            op: op.to_string(),
            outcome: outcome.to_string(),
            event_id: String::new(),
            sequence: 0,
            key_version: 0,
            result: outcome.to_string(),
            audit_id: format!("aud_{}", uuid::Uuid::new_v4().as_simple()),
            user_id: user_id.map(str::to_string),
            device_id: device_id.map(str::to_string),
            capability_id: capability_id.map(str::to_string),
        };
        self.records.push(rec.clone());
        rec
    }

    pub fn attach_identity(
        &mut self,
        user_id: Option<String>,
        device_id: Option<String>,
        capability_id: Option<String>,
    ) {
        if let Some(last) = self.records.last_mut() {
            if last.user_id.is_none() {
                last.user_id = user_id;
            }
            if last.device_id.is_none() {
                last.device_id = device_id;
            }
            if last.capability_id.is_none() {
                last.capability_id = capability_id;
            }
        }
    }

    pub fn list(&self) -> &[AuditRecord] {
        &self.records
    }

    pub fn seq(&self) -> usize {
        self.records.len()
    }
}
