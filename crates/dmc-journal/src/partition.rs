//! Path partitioning routing (Phase 5.7.2).
//!
//! Partition is a physical distribution primitive — not ACL, not encryption scope.
//! See `docs/ru/adr-013-path-partitioning.md`.

use dmc_vault::key::KeyPath;

use crate::error::{Error, Result};

/// Physical journal partition identifier (`0 .. partition_count-1`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct PartitionId(pub u32);

/// Optional explicit routing key. When present, all events with the same key
/// route to the same partition (ordering guarantee within key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartitionKey {
    pub value: Vec<u8>,
}

impl PartitionKey {
    pub fn new(value: impl Into<Vec<u8>>) -> Self {
        Self {
            value: value.into(),
        }
    }
}

/// Static partition topology descriptor (single-node; cluster extensions in Phase 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartitionSpec {
    pub id: PartitionId,
    pub partition_count: u32,
}

impl PartitionId {
    pub fn as_u32(self) -> u32 {
        self.0
    }

    /// Directory name for on-disk layout: `p-000`, `p-001`, …
    pub fn dir_name(self) -> String {
        format!("p-{:03}", self.0)
    }
}

/// Stable 32-bit hash for routing (crc32c — deterministic across platforms).
pub fn routing_hash(bytes: &[u8]) -> u32 {
    crc32c::crc32c(bytes)
}

/// Resolve target partition from path and optional explicit key.
///
/// - With `partition_key`: `hash(key) % N`
/// - Without: `hash(canonical_path_bytes) % N` where path is normalized via `KeyPath::parse`
pub fn resolve_partition(
    path: &KeyPath,
    partition_key: Option<&PartitionKey>,
    partition_count: u32,
) -> Result<PartitionId> {
    if partition_count == 0 {
        return Err(Error::format("partition_count must be > 0"));
    }
    let hash = match partition_key {
        Some(key) => routing_hash(&key.value),
        None => routing_hash(path.as_str().as_bytes()),
    };
    Ok(PartitionId(hash % partition_count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_key_same_partition() {
        let path_a = KeyPath::parse("company/finance/invoices/1").unwrap();
        let path_b = KeyPath::parse("company/hr/employees/2").unwrap();
        let key = PartitionKey::new(b"customer-123");
        let p1 = resolve_partition(&path_a, Some(&key), 8).unwrap();
        let p2 = resolve_partition(&path_b, Some(&key), 8).unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn same_path_deterministic_without_key() {
        let path = KeyPath::parse("company/finance/x").unwrap();
        let p1 = resolve_partition(&path, None, 4).unwrap();
        let p2 = resolve_partition(&path, None, 4).unwrap();
        assert_eq!(p1, p2);
        assert!(p1.0 < 4);
    }

    #[test]
    fn path_normalization_stable() {
        let p1 = KeyPath::parse("company/finance/x").unwrap();
        let p2 = KeyPath::parse("/company/finance/x/").unwrap();
        assert_eq!(
            resolve_partition(&p1, None, 8).unwrap(),
            resolve_partition(&p2, None, 8).unwrap()
        );
    }

    #[test]
    fn different_keys_may_differ() {
        let path = KeyPath::parse("company/x").unwrap();
        let keys: Vec<_> = (0..32)
            .map(|i| PartitionKey::new(format!("key-{i}")))
            .collect();
        let partitions: std::collections::HashSet<_> = keys
            .iter()
            .map(|k| resolve_partition(&path, Some(k), 8).unwrap())
            .collect();
        assert!(partitions.len() > 1, "expected spread across partitions");
    }

    #[test]
    fn zero_partition_count_rejected() {
        let path = KeyPath::parse("a").unwrap();
        assert!(resolve_partition(&path, None, 0).is_err());
    }

    #[test]
    fn dir_name_format() {
        assert_eq!(PartitionId(0).dir_name(), "p-000");
        assert_eq!(PartitionId(12).dir_name(), "p-012");
    }
}
