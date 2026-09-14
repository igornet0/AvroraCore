//! Reference-level overlay: base vault data stays immutable; mutations live as layers.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OverlayPatch {
    pub path: String,
    /// When true, path is treated as deleted in the resolved view.
    pub deleted: bool,
    pub payload: Vec<u8>,
    pub source: String,
    pub seq: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedView {
    pub path: String,
    pub base_present: bool,
    pub overlay_present: bool,
    pub deleted: bool,
    pub payload: Option<Vec<u8>>,
    pub layer_seq: Option<u64>,
}

#[derive(Clone, Default)]
pub struct OverlayStore {
    /// path → latest patch (higher seq wins)
    layers: BTreeMap<String, OverlayPatch>,
    next_seq: u64,
}

impl OverlayStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply(&mut self, path: &str, payload: Vec<u8>, source: &str) -> OverlayPatch {
        self.next_seq += 1;
        self.apply_at(path, payload, source, self.next_seq)
    }

    pub fn apply_at(&mut self, path: &str, payload: Vec<u8>, source: &str, seq: u64) -> OverlayPatch {
        self.next_seq = self.next_seq.max(seq);
        let patch = OverlayPatch {
            path: path.to_string(),
            deleted: false,
            payload,
            source: source.to_string(),
            seq,
        };
        self.layers.insert(path.to_string(), patch.clone());
        patch
    }

    pub fn mark_deleted(&mut self, path: &str, source: &str) -> OverlayPatch {
        self.next_seq += 1;
        self.mark_deleted_at(path, source, self.next_seq)
    }

    pub fn mark_deleted_at(&mut self, path: &str, source: &str, seq: u64) -> OverlayPatch {
        self.next_seq = self.next_seq.max(seq);
        let patch = OverlayPatch {
            path: path.to_string(),
            deleted: true,
            payload: Vec::new(),
            source: source.to_string(),
            seq,
        };
        self.layers.insert(path.to_string(), patch.clone());
        patch
    }

    pub fn restore(&mut self, patches: Vec<OverlayPatch>) {
        self.layers.clear();
        self.next_seq = 0;
        for p in patches {
            self.next_seq = self.next_seq.max(p.seq);
            self.layers.insert(p.path.clone(), p);
        }
    }

    pub fn get(&self, path: &str) -> Option<&OverlayPatch> {
        self.layers.get(path)
    }

    pub fn list(&self) -> Vec<OverlayPatch> {
        self.layers.values().cloned().collect()
    }

    pub fn list_under(&self, prefix: &str) -> Vec<OverlayPatch> {
        let prefix = prefix.trim_matches('/');
        self.layers
            .values()
            .filter(|p| {
                if prefix.is_empty() {
                    true
                } else {
                    p.path == prefix || p.path.starts_with(&format!("{prefix}/"))
                }
            })
            .cloned()
            .collect()
    }

    pub fn clear(&mut self) {
        self.layers.clear();
    }
}
