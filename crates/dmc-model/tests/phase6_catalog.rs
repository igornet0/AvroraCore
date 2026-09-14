//! Phase 6.2 — catalog data model, events, deterministic apply, recovery.

use dmc_model::{
    rebuild_catalog_from_event_log, validate_catalog_event_bytes, ApplyMode, ApplyOutcome,
    Catalog, CatalogApplier, CatalogEvent, CatalogEventLog, CatalogMaterializer, CatalogWatermark,
    ColumnDef, Error, FileCatalogEventLog, SqlDataType,
};

fn users_table_columns() -> Vec<ColumnDef> {
    vec![
        ColumnDef {
            name: "id".into(),
            data_type: SqlDataType::BigInt,
            nullable: false,
            default: None,
        },
        ColumnDef {
            name: "email".into(),
            data_type: SqlDataType::Text,
            nullable: false,
            default: None,
        },
    ]
}

fn basic_ddl<L: CatalogEventLog>(mat: &mut CatalogMaterializer<L>) -> Vec<CatalogEvent> {
    let mut planner = Catalog::new();
    let db_ev = planner.create_database_event("app").unwrap();
    mat.mutate(db_ev.clone()).unwrap();
    planner.apply(&db_ev, ApplyMode::Live).unwrap();
    let db_id = match &db_ev {
        CatalogEvent::CreateDatabase { id, .. } => *id,
        _ => panic!("db event"),
    };
    let schema_ev = planner.create_schema_event(db_id, "public").unwrap();
    mat.mutate(schema_ev.clone()).unwrap();
    planner.apply(&schema_ev, ApplyMode::Live).unwrap();
    let schema_id = match &schema_ev {
        CatalogEvent::CreateSchema { id, .. } => *id,
        _ => panic!("schema event"),
    };
    let table_ev = planner
        .create_table_event(
            schema_id,
            "users",
            users_table_columns(),
            Some(vec!["id".into()]),
        )
        .unwrap();
    mat.mutate(table_ev.clone()).unwrap();
    planner.apply(&table_ev, ApplyMode::Live).unwrap();
    vec![db_ev, schema_ev, table_ev]
}

fn planner_from_materializer<L: CatalogEventLog>(
    mat: &CatalogMaterializer<L>,
) -> Catalog {
    let mut planner = Catalog::new();
    for record in mat.event_log().events() {
        planner.apply(&record.event, ApplyMode::Replay).unwrap();
    }
    planner
}

#[test]
fn basic_create_database_schema_table() {
    let mut mat = CatalogMaterializer::in_memory();
    basic_ddl(&mut mat);
    let cat = mat.catalog();
    let db = cat.database_by_name("app").unwrap();
    assert_eq!(db.schemas.len(), 1);
    let schema = cat.schema(db.schemas[0]).unwrap();
    assert_eq!(schema.name, "public");
    let table = cat.table_by_name(schema.id, "users").unwrap();
    assert_eq!(table.columns.len(), 2);
    assert!(table.primary_key.is_some());
}

#[test]
fn restart_preserves_catalog() {
    let dir = tempfile::tempdir().unwrap();
    let snapshot = dir.path().join("catalog.meta.json");
    let events = dir.path().join("catalog.events.json");
    {
        let mut mat =
            CatalogMaterializer::<FileCatalogEventLog>::open(snapshot.clone(), events.clone())
                .unwrap();
        basic_ddl(&mut mat);
        mat.close().unwrap();
    }
    let mat2 =
        CatalogMaterializer::<FileCatalogEventLog>::open(snapshot, events).unwrap();
    assert_eq!(mat2.watermark(), CatalogWatermark::at(3));
    assert!(mat2.catalog().database_by_name("app").is_some());
    assert_eq!(mat2.catalog().tables().count(), 1);
}

#[test]
fn replay_from_fresh_catalog_matches_live() {
    let mut live = CatalogMaterializer::in_memory();
    let events = basic_ddl(&mut live);
    let mut replay = CatalogMaterializer::in_memory();
    for (i, event) in events.into_iter().enumerate() {
        let record = dmc_model::CatalogEventRecord {
            sequence: (i + 1) as u64,
            event,
        };
        replay.apply_record(&record, ApplyMode::Replay).unwrap();
    }
    assert_eq!(live.watermark(), replay.watermark());
    assert_eq!(
        live.catalog().database_by_name("app").unwrap().id,
        replay.catalog().database_by_name("app").unwrap().id
    );
}

#[test]
fn ordering_create_add_drop_column_is_deterministic() {
    let mut mat = CatalogMaterializer::in_memory();
    basic_ddl(&mut mat);
    let table_id = mat.catalog().tables().next().unwrap().id;
    let mut planner = planner_from_materializer(&mat);
    let add_ev = planner
        .add_column_event(
            table_id,
            ColumnDef {
                name: "nickname".into(),
                data_type: SqlDataType::Text,
                nullable: true,
                default: None,
            },
        )
        .unwrap();
    mat.mutate(add_ev).unwrap();
    let col_id = mat
        .catalog()
        .table(table_id)
        .unwrap()
        .columns
        .iter()
        .find(|c| c.name == "nickname")
        .unwrap()
        .id;
    planner = planner_from_materializer(&mat);
    let drop_ev = planner.drop_column_event(table_id, col_id).unwrap();
    mat.mutate(drop_ev).unwrap();
    assert!(
        mat.catalog()
            .table(table_id)
            .unwrap()
            .columns
            .iter()
            .all(|c| c.name != "nickname")
    );
    assert_eq!(mat.watermark().sequence, 5);
}

#[test]
fn duplicate_live_sequence_is_rejected() {
    let mut mat = CatalogMaterializer::in_memory();
    let mut planner = Catalog::new();
    let ev = planner.create_database_event("dup").unwrap();
    mat.mutate(ev.clone()).unwrap();
    let record = dmc_model::CatalogEventRecord {
        sequence: 1,
        event: ev,
    };
    let err = mat.apply_record(&record, ApplyMode::Live).unwrap_err();
    assert!(matches!(err, Error::DuplicateSequence(1)));
}

#[test]
fn replay_skips_already_applied_conflicts() {
    let mut mat = CatalogMaterializer::in_memory();
    let mut planner = Catalog::new();
    let ev = planner.create_database_event("once").unwrap();
    mat.mutate(ev.clone()).unwrap();
    let mut cat = Catalog::new();
    for record in mat.event_log().events() {
        cat.apply(&record.event, ApplyMode::Replay).unwrap();
    }
    let outcome = cat.apply(&ev, ApplyMode::Replay).unwrap();
    assert_eq!(outcome, ApplyOutcome::Skipped);
}

#[test]
fn corrupt_event_bytes_is_fatal() {
    let err = validate_catalog_event_bytes(b"{ not json").unwrap_err();
    assert!(matches!(err, Error::Corrupt(_)));
}

#[test]
fn rebuild_from_event_log_without_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let events = dir.path().join("catalog.events.json");
    {
        let mut mat = CatalogMaterializer::<FileCatalogEventLog>::open(
            dir.path().join("unused.json"),
            events.clone(),
        )
        .unwrap();
        basic_ddl(&mut mat);
    }
    let (catalog, watermark) = rebuild_catalog_from_event_log(&events).unwrap();
    assert_eq!(watermark, CatalogWatermark::at(3));
    assert!(catalog.database_by_name("app").is_some());
}

#[test]
fn catalog_watermark_is_separate_type() {
    let wm = CatalogWatermark::at(42);
    assert_eq!(wm.sequence, 42);
    assert_ne!(
        std::any::type_name::<CatalogWatermark>(),
        std::any::type_name::<u64>()
    );
}
