//! Phase 6.11 — journal-backed materialized state.

use dmc_materialized::{
    merge_state_event_records, rebuild_materialized_from_event_log, Materializer,
    StateEventRecord, StateMaterializer,
};
use dmc_model::{
    ApplyMode, Catalog, CatalogApplier, ColumnDef, DataEvent, RowId, RowValue, SqlDataType,
    StateEvent, TableId,
};
use dmc_storage::table_dir;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

fn bootstrap_users_events(catalog: &mut Catalog) -> (TableId, Vec<dmc_model::CatalogEvent>) {
    let mut events = catalog.bootstrap_default().unwrap();
    let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
    let columns = vec![
        ColumnDef {
            name: "id".into(),
            data_type: SqlDataType::BigInt,
            nullable: false,
            default: None,
        },
        ColumnDef {
            name: "name".into(),
            data_type: SqlDataType::Text,
            nullable: true,
            default: None,
        },
    ];
    let create = catalog
        .create_table_event(schema, "users", columns, Some(vec!["id".into()]))
        .unwrap();
    catalog.apply(&create, ApplyMode::Live).unwrap();
    let table_id = match &create {
        dmc_model::CatalogEvent::CreateTable { id, .. } => *id,
        _ => panic!("expected create table"),
    };
    events.push(create);
    (table_id, events)
}

fn materialize_bootstrap(
    mat: &mut StateMaterializer<impl dmc_materialized::StateEventLog>,
    events: &[dmc_model::CatalogEvent],
) {
    for event in events {
        mat.mutate_catalog(event.clone()).unwrap();
    }
}

fn open_file_materializer(root: &Path) -> StateMaterializer<dmc_materialized::FileStateEventLog> {
    let snapshot = root.join("materialized_snapshot.json");
    let log = root.join("state_events.json");
    StateMaterializer::open(root.join("rows"), snapshot, log).unwrap()
}

fn row_values(id: i64, name: &str) -> Vec<RowValue> {
    vec![RowValue::Int64(id), RowValue::String(name.into())]
}

#[test]
fn insert_event_materializes_row() {
    let dir = tempdir().unwrap();
    let mut catalog = Catalog::new();
    let (table_id, events) = bootstrap_users_events(&mut catalog);
    let mut mat = open_file_materializer(dir.path());
    materialize_bootstrap(&mut mat, &events);
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: RowId::new(1),
        values: row_values(1, "alice"),
    })
    .unwrap();
    let store = mat.shared_table_store(table_id).unwrap();
    assert_eq!(store.lock().unwrap().row_count(), 1);
    assert_eq!(mat.watermark().sequence, 4);
}

#[test]
fn update_and_delete_events() {
    let dir = tempdir().unwrap();
    let mut catalog = Catalog::new();
    let (table_id, events) = bootstrap_users_events(&mut catalog);
    let mut mat = open_file_materializer(dir.path());
    materialize_bootstrap(&mut mat, &events);
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: RowId::new(1),
        values: row_values(1, "bob"),
    })
    .unwrap();
    mat.mutate_data(DataEvent::UpdateRow {
        table_id,
        row_id: RowId::new(1),
        values: row_values(1, "bobby"),
    })
    .unwrap();
    mat.mutate_data(DataEvent::DeleteRow {
        table_id,
        row_id: RowId::new(1),
    })
    .unwrap();
    assert!(mat.shared_table_store(table_id).unwrap().lock().unwrap().row_count() == 0);
    assert_eq!(mat.watermark().sequence, 6);
}

#[test]
fn ddl_must_precede_dml_in_global_order() {
    let dir = tempdir().unwrap();
    let mut catalog = Catalog::new();
    let (table_id, events) = bootstrap_users_events(&mut catalog);
    let mut mat = StateMaterializer::in_memory(dir.path().join("rows"));
    materialize_bootstrap(&mut mat, &events);
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: RowId::new(1),
        values: row_values(1, "x"),
    })
    .unwrap();
    assert_eq!(mat.shared_table_store(table_id).unwrap().lock().unwrap().row_count(), 1);
}

#[test]
fn rejects_out_of_order_sequences() {
    let dir = tempdir().unwrap();
    let mut mat = StateMaterializer::in_memory(dir.path());
    mat.mutate_catalog(dmc_model::CatalogEvent::CreateDatabase {
        id: dmc_model::DatabaseId::new(1),
        name: "db".into(),
    })
    .unwrap();
    let gap = StateEventRecord {
        sequence: 3,
        event_id: [9; 16],
        event: StateEvent::Catalog(dmc_model::CatalogEvent::CreateDatabase {
            id: dmc_model::DatabaseId::new(2),
            name: "db2".into(),
        }),
    };
    assert!(mat.apply_record(&gap, ApplyMode::Replay).is_err());
}

#[test]
fn replay_is_idempotent_for_inserts() {
    let dir = tempdir().unwrap();
    let mut catalog = Catalog::new();
    let (table_id, events) = bootstrap_users_events(&mut catalog);
    let mut mat = open_file_materializer(dir.path());
    materialize_bootstrap(&mut mat, &events);
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: RowId::new(1),
        values: row_values(1, "once"),
    })
    .unwrap();
    mat.replay_from_log().unwrap();
    assert_eq!(mat.shared_table_store(table_id).unwrap().lock().unwrap().row_count(), 1);
}

#[test]
fn recover_from_watermark_replays_tail() {
    let dir = tempdir().unwrap();
    let mut catalog = Catalog::new();
    let (table_id, events) = bootstrap_users_events(&mut catalog);
    let mut mat = open_file_materializer(dir.path());
    materialize_bootstrap(&mut mat, &events);
    for i in 1..=5 {
        mat.mutate_data(DataEvent::InsertRow {
            table_id,
            row_id: RowId::new(i),
            values: row_values(i as i64, "r"),
        })
        .unwrap();
    }
    mat.override_watermark(dmc_model::MaterializedWatermark::at(3));
    mat.recover_from_watermark().unwrap();
    assert_eq!(mat.watermark().sequence, 8);
    assert_eq!(mat.shared_table_store(table_id).unwrap().lock().unwrap().row_count(), 5);
}

#[test]
fn restart_loads_snapshot_and_recovers_tail() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let mut catalog = Catalog::new();
    let (table_id, events) = bootstrap_users_events(&mut catalog);
    {
        let mut mat = open_file_materializer(root);
        materialize_bootstrap(&mut mat, &events);
        mat.mutate_data(DataEvent::InsertRow {
            table_id,
            row_id: RowId::new(1),
            values: row_values(1, "persist"),
        })
        .unwrap();
        mat.close().unwrap();
    }
    let mut mat2 = open_file_materializer(root);
    assert_eq!(mat2.watermark().sequence, 4);
    mat2.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: RowId::new(2),
        values: row_values(2, "more"),
    })
    .unwrap();
    assert_eq!(
        mat2.shared_table_store(table_id).unwrap().lock().unwrap().row_count(),
        2
    );
}

#[test]
fn crash_before_apply_recovers_event() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let mut catalog = Catalog::new();
    let (table_id, events) = bootstrap_users_events(&mut catalog);
    let log_path = root.join("state_events.json");
    {
        let mut mat = open_file_materializer(root);
        materialize_bootstrap(&mut mat, &events);
        mat.mutate_data(DataEvent::InsertRow {
            table_id,
            row_id: RowId::new(1),
            values: row_values(1, "late"),
        })
        .unwrap();
    }
    let mut mat = StateMaterializer::open(
        root.join("rows"),
        root.join("materialized_snapshot.json"),
        log_path,
    )
    .unwrap();
    assert_eq!(mat.watermark().sequence, 4);
    assert_eq!(
        mat.shared_table_store(table_id).unwrap().lock().unwrap().row_count(),
        1
    );
}

#[test]
fn crash_after_row_before_watermark_no_duplicate() {
    let dir = tempdir().unwrap();
    let mut catalog = Catalog::new();
    let (table_id, events) = bootstrap_users_events(&mut catalog);
    let mut mat = StateMaterializer::in_memory(dir.path().join("rows"));
    materialize_bootstrap(&mut mat, &events);
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: RowId::new(1),
        values: row_values(1, "dup"),
    })
    .unwrap();
    mat.override_watermark(dmc_model::MaterializedWatermark::default());
    mat.replay_from_log().unwrap();
    assert_eq!(
        mat.shared_table_store(table_id).unwrap().lock().unwrap().row_count(),
        1
    );
}

#[test]
fn crash_after_watermark_skips_event() {
    let dir = tempdir().unwrap();
    let mut catalog = Catalog::new();
    let (table_id, events) = bootstrap_users_events(&mut catalog);
    let mut mat = StateMaterializer::in_memory(dir.path().join("rows"));
    materialize_bootstrap(&mut mat, &events);
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: RowId::new(1),
        values: row_values(1, "done"),
    })
    .unwrap();
    let wm = mat.watermark().sequence;
    mat.recover_from_watermark().unwrap();
    assert_eq!(mat.watermark().sequence, wm);
}

#[test]
fn rebuild_from_journal_matches_incremental() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let mut catalog = Catalog::new();
    let (table_id, events) = bootstrap_users_events(&mut catalog);
    let log_path = root.join("state_events.json");
    {
        let mut mat = open_file_materializer(root);
        materialize_bootstrap(&mut mat, &events);
        for i in 1..=10 {
            mat.mutate_data(DataEvent::InsertRow {
                table_id,
                row_id: RowId::new(i),
                values: row_values(i as i64, "v"),
            })
            .unwrap();
        }
    }
    let mut incremental = open_file_materializer(root);
    let (rebuilt_catalog, rebuilt_wm) =
        rebuild_materialized_from_event_log(&root.join("rows"), &log_path).unwrap();
    assert_eq!(incremental.watermark(), rebuilt_wm);
    assert_eq!(
        incremental.catalog().table(table_id).unwrap().name,
        rebuilt_catalog.table(table_id).unwrap().name
    );
    assert_eq!(
        incremental
            .shared_table_store(table_id)
            .unwrap()
            .lock()
            .unwrap()
            .row_count(),
        10
    );
}

#[test]
fn destroy_and_rebuild_produces_same_rows() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let mut catalog = Catalog::new();
    let (table_id, events) = bootstrap_users_events(&mut catalog);
    let log_path = root.join("state_events.json");
    let mut mat = open_file_materializer(root);
    materialize_bootstrap(&mut mat, &events);
    for i in 1..=3 {
        mat.mutate_data(DataEvent::InsertRow {
            table_id,
            row_id: RowId::new(i),
            values: row_values(i as i64, "same"),
        })
        .unwrap();
    }
    let before = mat.shared_table_store(table_id).unwrap().lock().unwrap().row_count();
    mat.destroy_materialized_state().unwrap();
    assert!(!table_dir(&root.join("rows"), table_id).exists());
    mat.replay_from_log().unwrap();
    let after = mat.shared_table_store(table_id).unwrap().lock().unwrap().row_count();
    assert_eq!(before, after);
    let _ = log_path;
}

#[test]
fn partition_merge_matches_single_log() {
    let dir = tempdir().unwrap();
    let mut catalog = Catalog::new();
    let (table_id, events) = bootstrap_users_events(&mut catalog);

    let mut single = StateMaterializer::in_memory(dir.path().join("single"));
    materialize_bootstrap(&mut single, &events);
    for i in 1..=8 {
        single
            .mutate_data(DataEvent::InsertRow {
                table_id,
                row_id: RowId::new(i),
                values: row_values(i as i64, "m"),
            })
            .unwrap();
    }

    let mk = |seq: u64, event: StateEvent| StateEventRecord {
        sequence: seq,
        event_id: dmc_materialized::event_id_for_sequence(seq),
        event,
    };
    let p0 = vec![
        mk(1, StateEvent::Catalog(events[0].clone())),
        mk(2, StateEvent::Catalog(events[1].clone())),
        mk(3, StateEvent::Catalog(events[2].clone())),
        mk(8, StateEvent::Data(DataEvent::InsertRow {
            table_id,
            row_id: RowId::new(5),
            values: row_values(5, "m"),
        })),
        mk(11, StateEvent::Data(DataEvent::InsertRow {
            table_id,
            row_id: RowId::new(8),
            values: row_values(8, "m"),
        })),
    ];
    let p1 = vec![
        mk(4, StateEvent::Data(DataEvent::InsertRow {
            table_id,
            row_id: RowId::new(1),
            values: row_values(1, "m"),
        })),
        mk(5, StateEvent::Data(DataEvent::InsertRow {
            table_id,
            row_id: RowId::new(2),
            values: row_values(2, "m"),
        })),
        mk(9, StateEvent::Data(DataEvent::InsertRow {
            table_id,
            row_id: RowId::new(6),
            values: row_values(6, "m"),
        })),
    ];
    let p2 = vec![
        mk(6, StateEvent::Data(DataEvent::InsertRow {
            table_id,
            row_id: RowId::new(3),
            values: row_values(3, "m"),
        })),
        mk(7, StateEvent::Data(DataEvent::InsertRow {
            table_id,
            row_id: RowId::new(4),
            values: row_values(4, "m"),
        })),
        mk(10, StateEvent::Data(DataEvent::InsertRow {
            table_id,
            row_id: RowId::new(7),
            values: row_values(7, "m"),
        })),
    ];
    let merged = merge_state_event_records(&[&p0, &p1, &p2]).unwrap();
    let mut merged_mat = StateMaterializer::in_memory(dir.path().join("merged"));
    for record in merged {
        merged_mat.apply_record(&record, ApplyMode::Replay).unwrap();
    }
    assert_eq!(
        merged_mat
            .shared_table_store(table_id)
            .unwrap()
            .lock()
            .unwrap()
            .row_count(),
        single
            .shared_table_store(table_id)
            .unwrap()
            .lock()
            .unwrap()
            .row_count()
    );
}

#[test]
fn row_id_stable_on_replay() {
    let dir = tempdir().unwrap();
    let mut catalog = Catalog::new();
    let (table_id, events) = bootstrap_users_events(&mut catalog);
    let mut mat = StateMaterializer::in_memory(dir.path());
    materialize_bootstrap(&mut mat, &events);
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: RowId::new(42),
        values: row_values(42, "stable"),
    })
    .unwrap();
    mat.replay_from_log().unwrap();
    let store = mat.shared_table_store(table_id).unwrap();
    assert_eq!(store.lock().unwrap().live_row_ids(), vec![RowId::new(42)]);
}

#[test]
fn materializer_trait_applies_data_event() {
    let dir = tempdir().unwrap();
    let mut catalog = Catalog::new();
    let (table_id, events) = bootstrap_users_events(&mut catalog);
    let mut mat = StateMaterializer::in_memory(dir.path());
    materialize_bootstrap(&mut mat, &events);
    let event = DataEvent::InsertRow {
        table_id,
        row_id: RowId::new(1),
        values: row_values(1, "trait"),
    };
    mat.apply(&event, ApplyMode::Live).unwrap();
    assert_eq!(
        mat.shared_table_store(table_id).unwrap().lock().unwrap().row_count(),
        1
    );
}

#[test]
fn allocate_row_id_from_table_store() {
    let dir = tempdir().unwrap();
    let mut catalog = Catalog::new();
    let (table_id, events) = bootstrap_users_events(&mut catalog);
    let mut mat = StateMaterializer::in_memory(dir.path());
    materialize_bootstrap(&mut mat, &events);
    assert_eq!(mat.allocate_row_id(table_id).unwrap(), RowId::new(1));
    mat.mutate_data(DataEvent::InsertRow {
        table_id,
        row_id: RowId::new(1),
        values: row_values(1, "a"),
    })
    .unwrap();
    assert_eq!(mat.allocate_row_id(table_id).unwrap(), RowId::new(2));
}

#[test]
fn watermark_is_independent_type() {
    let wm = dmc_model::MaterializedWatermark::at(7);
    assert_eq!(wm.sequence, 7);
    let _: dmc_model::MaterializedWatermark = wm;
}

#[test]
fn empty_values_rejected() {
    let event = DataEvent::InsertRow {
        table_id: TableId::new(1),
        row_id: RowId::new(1),
        values: vec![],
    };
    assert!(event.validate().is_err());
}

fn append_only_log(dir: &Path) -> PathBuf {
    dir.join("state_events.json")
}

#[test]
fn file_log_persists_across_open() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let log = append_only_log(root);
    {
        let mut mat = StateMaterializer::open(
            root.join("rows"),
            root.join("snap.json"),
            log.clone(),
        )
        .unwrap();
        mat.mutate_catalog(dmc_model::CatalogEvent::CreateDatabase {
            id: dmc_model::DatabaseId::new(1),
            name: "d".into(),
        })
        .unwrap();
    }
    let mat2 = StateMaterializer::open(root.join("rows"), root.join("snap.json"), log).unwrap();
    assert_eq!(mat2.watermark().sequence, 1);
}
