//! Statistics lifecycle after successful materialized apply (Phase 6.15.3).
//!
//! Statistics are **derived performance metadata** — never consulted for transaction
//! apply decisions. Refresh runs only after materializer commit succeeds.

use std::collections::HashSet;

use dmc_model::{CatalogEvent, DataEvent, StateEvent, TableId, TransactionEvent};

use crate::event_log::StateEventRecord;

/// Lifecycle action for one table after a successful materialized apply.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum StatisticsLifecycleAction {
    /// `CREATE TABLE` — empty statistics entry (full collect on empty RowStore).
    Create,
    /// `INSERT` / `UPDATE` / `DELETE` — full recompute from live RowStore.
    Refresh,
    /// `DROP TABLE` — remove statistics entry.
    Remove,
}

/// Deduped plan: each table appears at most once per action class.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StatisticsRefreshPlan {
    create: HashSet<TableId>,
    refresh: HashSet<TableId>,
    remove: HashSet<TableId>,
}

impl StatisticsRefreshPlan {
    pub fn is_empty(&self) -> bool {
        self.create.is_empty() && self.refresh.is_empty() && self.remove.is_empty()
    }

    /// Tables that need full recompute (`Create` ∪ `Refresh`, minus `Remove`).
    pub fn recompute_tables(&self) -> Vec<TableId> {
        let mut ids: Vec<_> = self
            .create
            .iter()
            .chain(self.refresh.iter())
            .copied()
            .filter(|id| !self.remove.contains(id))
            .collect();
        ids.sort_by_key(|id| id.raw());
        ids.dedup();
        ids
    }

    pub fn remove_tables(&self) -> Vec<TableId> {
        let mut ids: Vec<_> = self
            .remove
            .iter()
            .copied()
            .filter(|id| !self.create.contains(id) && !self.refresh.contains(id))
            .collect();
        ids.sort_by_key(|id| id.raw());
        ids
    }

    /// Deterministic ordered actions: removes first, then creates/refreshes.
    pub fn ordered_actions(&self) -> Vec<(StatisticsLifecycleAction, TableId)> {
        let mut out = Vec::new();
        for id in self.remove_tables() {
            out.push((StatisticsLifecycleAction::Remove, id));
        }
        for id in self.recompute_tables() {
            let action = if self.create.contains(&id) {
                StatisticsLifecycleAction::Create
            } else {
                StatisticsLifecycleAction::Refresh
            };
            out.push((action, id));
        }
        out
    }
}

pub fn statistics_refresh_plan(record: &StateEventRecord) -> StatisticsRefreshPlan {
    statistics_refresh_plan_for_event(&record.event)
}

pub fn statistics_refresh_plan_for_event(event: &StateEvent) -> StatisticsRefreshPlan {
    let mut plan = StatisticsRefreshPlan::default();
    match event {
        StateEvent::Catalog(catalog_event) => {
            apply_catalog_to_plan(catalog_event, &mut plan);
        }
        StateEvent::Data(data_event) => {
            apply_data_to_plan(data_event, &mut plan);
        }
        StateEvent::TransactionCommit { events, .. } => {
            for event in events {
                match event {
                    TransactionEvent::Catalog(catalog_event) => {
                        apply_catalog_to_plan(catalog_event, &mut plan);
                    }
                    TransactionEvent::Data(data_event) => {
                        apply_data_to_plan(data_event, &mut plan);
                    }
                }
            }
        }
    }
    plan
}

fn apply_catalog_to_plan(event: &CatalogEvent, plan: &mut StatisticsRefreshPlan) {
    match event {
        CatalogEvent::CreateTable { id, .. } => {
            plan.create.insert(*id);
        }
        CatalogEvent::DropTable { table_id } => {
            plan.remove.insert(*table_id);
        }
        CatalogEvent::CreateIndex { .. } | CatalogEvent::DropIndex { .. } => {}
        _ => {}
    }
}

fn apply_data_to_plan(event: &DataEvent, plan: &mut StatisticsRefreshPlan) {
    plan.refresh.insert(event.table_id());
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmc_model::{ColumnSnapshot, RowValue, SqlDataType, TransactionId};

    #[test]
    fn plan_data_event_refreshes_table() {
        let record = StateEventRecord {
            sequence: 1,
            event_id: [0; 16],
            event: StateEvent::Data(DataEvent::InsertRow {
                table_id: TableId::new(7),
                row_id: dmc_model::RowId::new(1),
                values: vec![RowValue::Int64(1)],
            }),
        };
        let plan = statistics_refresh_plan(&record);
        assert_eq!(plan.recompute_tables(), vec![TableId::new(7)]);
        assert!(plan.remove_tables().is_empty());
    }

    #[test]
    fn plan_drop_table_removes_without_refresh() {
        let record = StateEventRecord {
            sequence: 1,
            event_id: [0; 16],
            event: StateEvent::Catalog(CatalogEvent::DropTable {
                table_id: TableId::new(3),
            }),
        };
        let plan = statistics_refresh_plan(&record);
        assert!(plan.recompute_tables().is_empty());
        assert_eq!(plan.remove_tables(), vec![TableId::new(3)]);
    }

    #[test]
    fn plan_transaction_commit_dedupes_same_table() {
        let t1 = TableId::new(1);
        let t2 = TableId::new(2);
        let record = StateEventRecord {
            sequence: 1,
            event_id: [0; 16],
            event: StateEvent::TransactionCommit {
                transaction_id: TransactionId::new(1),
                events: vec![
                    TransactionEvent::Data(DataEvent::InsertRow {
                        table_id: t1,
                        row_id: dmc_model::RowId::new(1),
                        values: vec![RowValue::Int64(1)],
                    }),
                    TransactionEvent::Data(DataEvent::UpdateRow {
                        table_id: t1,
                        row_id: dmc_model::RowId::new(1),
                        values: vec![RowValue::Int64(2)],
                    }),
                    TransactionEvent::Data(DataEvent::InsertRow {
                        table_id: t2,
                        row_id: dmc_model::RowId::new(1),
                        values: vec![RowValue::Int64(1)],
                    }),
                    TransactionEvent::Data(DataEvent::DeleteRow {
                        table_id: t1,
                        row_id: dmc_model::RowId::new(9),
                    }),
                ],
            },
        };
        let plan = statistics_refresh_plan(&record);
        assert_eq!(plan.recompute_tables(), vec![t1, t2]);
        assert_eq!(plan.recompute_tables().len(), 2);
    }

    #[test]
    fn plan_create_table_plus_dml_is_single_recompute() {
        let table_id = TableId::new(10);
        let record = StateEventRecord {
            sequence: 1,
            event_id: [0; 16],
            event: StateEvent::TransactionCommit {
                transaction_id: TransactionId::new(1),
                events: vec![
                    TransactionEvent::Catalog(CatalogEvent::CreateTable {
                        id: table_id,
                        schema_id: dmc_model::SchemaId::new(1),
                        name: "t".into(),
                        columns: vec![ColumnSnapshot {
                            id: dmc_model::ColumnId::new(1),
                            name: "id".into(),
                            data_type: SqlDataType::BigInt,
                            nullable: false,
                            default: None,
                            ordinal: 0,
                        }],
                        primary_key: None,
                    }),
                    TransactionEvent::Data(DataEvent::InsertRow {
                        table_id,
                        row_id: dmc_model::RowId::new(1),
                        values: vec![RowValue::Int64(1)],
                    }),
                ],
            },
        };
        let plan = statistics_refresh_plan(&record);
        assert_eq!(plan.recompute_tables(), vec![table_id]);
        assert_eq!(
            plan.ordered_actions(),
            vec![(StatisticsLifecycleAction::Create, table_id)]
        );
    }

    #[test]
    fn plan_create_index_is_noop() {
        let record = StateEventRecord {
            sequence: 1,
            event_id: [0; 16],
            event: StateEvent::Catalog(CatalogEvent::CreateIndex {
                id: dmc_model::IndexId::new(1),
                table_id: TableId::new(5),
                name: "idx".into(),
                columns: vec![dmc_model::ColumnId::new(1)],
                unique: false,
            }),
        };
        let plan = statistics_refresh_plan(&record);
        assert!(plan.is_empty());
    }
}
