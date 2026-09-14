//! Table/column statistics for the cost-based optimizer (Phase 6.15).
//!
//! Statistics are **performance hints only** — not journal-backed, not MVCC, not used for
//! constraint or transaction correctness. Missing statistics is valid.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::ids::{ColumnId, TableId};

pub const STATISTICS_SNAPSHOT_FORMAT_VERSION: u32 = 1;

/// Comparable bound for min/max column statistics (numeric, temporal, text).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum StatValue {
    Int64(i64),
    Float64(f64),
    String(String),
    Date(i32),
    Timestamp(i64),
}

/// Per-column optimizer statistics derived from RowStore (not authoritative).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ColumnStatistics {
    /// Fraction of rows where the column is NULL, in `[0.0, 1.0]`.
    pub null_fraction: f64,
    /// Number of distinct non-null values; `<= table row_count`.
    pub ndv: u64,
    pub min: Option<StatValue>,
    pub max: Option<StatValue>,
}

impl ColumnStatistics {
    pub fn empty() -> Self {
        Self {
            null_fraction: 0.0,
            ndv: 0,
            min: None,
            max: None,
        }
    }

    pub fn validate(&self, row_count: u64) -> Result<()> {
        if self.null_fraction.is_nan() || !(0.0..=1.0).contains(&self.null_fraction) {
            return Err(stats_error(format!(
                "null_fraction must be in [0, 1], got {}",
                self.null_fraction
            )));
        }
        if self.ndv > row_count {
            return Err(stats_error(format!(
                "ndv {} exceeds row_count {}",
                self.ndv, row_count
            )));
        }
        Ok(())
    }
}

/// Per-table optimizer statistics (derived, optional, rebuildable).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TableStatistics {
    pub table_id: TableId,
    pub row_count: u64,
    pub columns: BTreeMap<ColumnId, ColumnStatistics>,
}

impl TableStatistics {
    pub fn empty(table_id: TableId) -> Self {
        Self {
            table_id,
            row_count: 0,
            columns: BTreeMap::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        for column in self.columns.values() {
            column.validate(self.row_count)?;
        }
        Ok(())
    }
}

/// On-disk statistics catalog body — tables sorted by `table_id` for deterministic JSON.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StatisticsSnapshot {
    pub format_version: u32,
    pub tables: Vec<TableStatistics>,
}

impl StatisticsSnapshot {
    pub fn from_tables(
        tables: impl IntoIterator<Item = TableStatistics>,
    ) -> Result<Self> {
        let mut tables: Vec<TableStatistics> = tables.into_iter().collect();
        for table in &tables {
            table.validate()?;
        }
        tables.sort_by_key(|t| t.table_id.raw());
        Ok(Self {
            format_version: STATISTICS_SNAPSHOT_FORMAT_VERSION,
            tables,
        })
    }

    pub fn into_map(self) -> Result<BTreeMap<TableId, TableStatistics>> {
        if self.format_version != STATISTICS_SNAPSHOT_FORMAT_VERSION {
            return Err(Error::Corrupt(format!(
                "unsupported statistics snapshot version {}",
                self.format_version
            )));
        }
        let mut map = BTreeMap::new();
        for table in self.tables {
            table.validate()?;
            let table_id = table.table_id;
            if map.insert(table_id, table).is_some() {
                return Err(stats_error(format!(
                    "duplicate table statistics for table_id {}",
                    table_id.raw()
                )));
            }
        }
        Ok(map)
    }
}

/// Canonical JSON bytes for deterministic persistence and tests.
pub fn statistics_snapshot_to_bytes(snapshot: &StatisticsSnapshot) -> Result<Vec<u8>> {
    serde_json::to_vec(snapshot).map_err(|e| Error::Corrupt(e.to_string()))
}

pub fn statistics_snapshot_from_bytes(raw: &[u8]) -> Result<StatisticsSnapshot> {
    serde_json::from_slice(raw).map_err(|e| Error::Corrupt(e.to_string()))
}

fn stats_error(message: impl Into<String>) -> Error {
    Error::InvalidEvent(format!("invalid statistics: {}", message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_statistics_empty_table() {
        let stats = TableStatistics::empty(TableId::new(1));
        assert_eq!(stats.row_count, 0);
        assert!(stats.columns.is_empty());
        stats.validate().unwrap();
    }

    #[test]
    fn table_statistics_multiple_columns() {
        let mut stats = TableStatistics {
            table_id: TableId::new(2),
            row_count: 100,
            columns: BTreeMap::new(),
        };
        stats.columns.insert(
            ColumnId::new(10),
            ColumnStatistics {
                null_fraction: 0.1,
                ndv: 50,
                min: Some(StatValue::Int64(1)),
                max: Some(StatValue::Int64(99)),
            },
        );
        stats.columns.insert(
            ColumnId::new(11),
            ColumnStatistics {
                null_fraction: 0.0,
                ndv: 100,
                min: Some(StatValue::String("a".into())),
                max: Some(StatValue::String("z".into())),
            },
        );
        stats.validate().unwrap();
    }

    #[test]
    fn nullable_column_fraction() {
        let col = ColumnStatistics {
            null_fraction: 0.25,
            ndv: 3,
            min: Some(StatValue::Int64(1)),
            max: None,
        };
        col.validate(4).unwrap();
    }

    #[test]
    fn ndv_cannot_exceed_row_count() {
        let col = ColumnStatistics {
            null_fraction: 0.0,
            ndv: 5,
            min: None,
            max: None,
        };
        assert!(col.validate(4).is_err());
    }

    #[test]
    fn min_max_roundtrip_json() {
        let snapshot = StatisticsSnapshot::from_tables([TableStatistics {
            table_id: TableId::new(1),
            row_count: 2,
            columns: BTreeMap::from([(
                ColumnId::new(1),
                ColumnStatistics {
                    null_fraction: 0.5,
                    ndv: 1,
                    min: Some(StatValue::Timestamp(1_700_000_000_000)),
                    max: Some(StatValue::Date(19_000)),
                },
            )]),
        }])
        .unwrap();
        let raw = statistics_snapshot_to_bytes(&snapshot).unwrap();
        let back = statistics_snapshot_from_bytes(&raw).unwrap();
        assert_eq!(snapshot, back);
    }

    #[test]
    fn deterministic_serialization_bytes() {
        let make = || {
            statistics_snapshot_to_bytes(
                &StatisticsSnapshot::from_tables([
                    TableStatistics {
                        table_id: TableId::new(2),
                        row_count: 10,
                        columns: BTreeMap::from([(
                            ColumnId::new(5),
                            ColumnStatistics {
                                null_fraction: 0.0,
                                ndv: 10,
                                min: Some(StatValue::Int64(0)),
                                max: Some(StatValue::Int64(9)),
                            },
                        )]),
                    },
                    TableStatistics {
                        table_id: TableId::new(1),
                        row_count: 0,
                        columns: BTreeMap::new(),
                    },
                ])
                .unwrap(),
            )
            .unwrap()
        };
        assert_eq!(make(), make());
    }
}
