use std::collections::BTreeMap;

use dmc_model::RowId;

use crate::error::{Error, Result};
use crate::index::key::IndexKey;

/// Ordered index structure: encoded key → row ids (non-unique allows duplicates).
#[derive(Clone, Debug, Default)]
pub struct BTree {
    entries: BTreeMap<Vec<u8>, Vec<u64>>,
}

impl BTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_entries(entries: BTreeMap<Vec<u8>, Vec<u64>>) -> Self {
        Self { entries }
    }

    pub fn entries(&self) -> &BTreeMap<Vec<u8>, Vec<u64>> {
        &self.entries
    }

    pub fn into_entries(self) -> BTreeMap<Vec<u8>, Vec<u64>> {
        self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.values().map(|v| v.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn insert(&mut self, key: &IndexKey, row_id: RowId, unique: bool) -> Result<()> {
        let encoded = key.encode();
        if unique && !key.has_null() {
            if let Some(existing) = self.entries.get(&encoded) {
                if existing.iter().any(|id| *id != row_id.raw()) {
                    return Err(Error::UniqueViolation {
                        key: format!("{key:?}"),
                    });
                }
            }
        }
        let slot = self.entries.entry(encoded).or_default();
        slot.retain(|id| *id != row_id.raw());
        slot.push(row_id.raw());
        Ok(())
    }

    pub fn delete(&mut self, key: &IndexKey, row_id: RowId) {
        let encoded = key.encode();
        if let Some(ids) = self.entries.get_mut(&encoded) {
            ids.retain(|id| *id != row_id.raw());
            if ids.is_empty() {
                self.entries.remove(&encoded);
            }
        }
    }

    pub fn lookup(&self, key: &IndexKey) -> Vec<RowId> {
        self.entries
            .get(&key.encode())
            .map(|ids| ids.iter().map(|id| RowId::new(*id)).collect())
            .unwrap_or_default()
    }

    pub fn range_scan(&self, lower: Option<&IndexKey>, upper: Option<&IndexKey>) -> Vec<RowId> {
        use std::ops::Bound;
        let start = lower
            .map(|k| Bound::Included(k.encode()))
            .unwrap_or(Bound::Unbounded);
        let end = upper
            .map(|k| Bound::Included(k.encode()))
            .unwrap_or(Bound::Unbounded);
        self.range_scan_bounds(start, end)
    }

    /// Range scan with explicit inclusive/exclusive encoded-key bounds.
    pub fn range_scan_bounds(
        &self,
        lower: std::ops::Bound<Vec<u8>>,
        upper: std::ops::Bound<Vec<u8>>,
    ) -> Vec<RowId> {
        let mut out = Vec::new();
        for ids in self.entries.range((lower, upper)).map(|(_, ids)| ids) {
            for id in ids {
                out.push(RowId::new(*id));
            }
        }
        out
    }
}
