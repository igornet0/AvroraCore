//! Secret / path sanitization for observability payloads.

use crate::event::ObservabilityEvent;

const FORBIDDEN_KEYS: &[&str] = &[
    "master_key",
    "masterkey",
    "password",
    "unlock_material",
    "unlockmaterial",
    "unlock_blob",
    "unlockblob",
    "dek",
    "kek",
    "keypass",
    "private_key",
    "binding_key",
    "sql",
    "statement",
    "query",
];

const FORBIDDEN_VALUE_MARKERS: &[&str] = &[
    "master_key",
    "unlockmaterial",
    "unlock_material",
    "keypass",
    "private_key",
    "-----begin",
];

/// Redact forbidden field keys and scrub values that look like secrets/paths.
pub fn sanitize_event(mut event: ObservabilityEvent) -> ObservabilityEvent {
    event.fields.retain(|k, _| !is_forbidden_key(k));
    for v in event.fields.values_mut() {
        *v = sanitize_value(v);
    }
    if let Some(sid) = event.context.session_id.as_mut() {
        *sid = truncate_id(sid);
    }
    if let Some(rid) = event.context.request_id.as_mut() {
        *rid = truncate_id(rid);
    }
    if let Some(cid) = event.context.connection_id.as_mut() {
        *cid = truncate_id(cid);
    }
    if let Some(tid) = event.context.transaction_id.as_mut() {
        *tid = truncate_id(tid);
    }
    event
}

pub fn sanitize_value(value: &str) -> String {
    let lower = value.to_lowercase();
    if FORBIDDEN_VALUE_MARKERS.iter().any(|m| lower.contains(m))
        || value.contains('/')
        || value.contains('\\')
        || looks_like_long_hex(value)
    {
        return "redacted".into();
    }
    if value.len() > 128 {
        value.chars().take(128).collect()
    } else {
        value.to_string()
    }
}

fn is_forbidden_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    FORBIDDEN_KEYS.iter().any(|k| lower == *k || lower.contains(k))
}

fn truncate_id(id: &str) -> String {
    if id.len() > 64 {
        id.chars().take(64).collect()
    } else {
        id.to_string()
    }
}

pub(crate) fn truncate_id_pub(id: &str) -> String {
    truncate_id(id)
}

fn looks_like_long_hex(s: &str) -> bool {
    let mut run = 0usize;
    for c in s.chars() {
        if c.is_ascii_hexdigit() {
            run += 1;
            if run >= 64 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// Test/helper: ensure sanitized JSON/Debug would not contain secret markers.
pub fn assert_no_secrets_in_event(event: &ObservabilityEvent) -> Result<(), String> {
    let json = serde_json::to_string(event).map_err(|e| e.to_string())?;
    let lower = json.to_lowercase();
    for needle in [
        "master_key",
        "unlockmaterial",
        "unlock_material",
        "\"dek\"",
        "\"kek\"",
        "keypass",
        "private_key",
        "-----begin",
    ] {
        if lower.contains(needle) {
            return Err(format!("secret marker `{needle}` in event JSON"));
        }
    }
    // Detect full-SQL *field keys*, not category "sql".
    if lower.contains("\"sql\":")
        || lower.contains("\"statement\":")
        || lower.contains("\"query\":")
    {
        return Err("full SQL field present in event".into());
    }
    Ok(())
}
