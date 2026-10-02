#[cfg(test)]
mod tests {
    use dmc_model::{ApplyMode, Catalog, CatalogApplier, ColumnDef, SqlDataType};

    use crate::{
        CatalogConstraintKind, CatalogError, CatalogProvider, CatalogService, CatalogTableKind,
        ModelCatalogProvider, PageQuery, TableRef, MAX_PAGE_LIMIT,
    };

    fn seeded() -> Catalog {
        let mut catalog = Catalog::new();
        let _ = catalog.bootstrap_default().unwrap();
        let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
        let create = catalog
            .create_table_event(
                schema,
                "users",
                vec![
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
                ],
                Some(vec!["id".into()]),
            )
            .unwrap();
        catalog.apply(&create, ApplyMode::Live).unwrap();
        catalog
    }

    #[test]
    fn lazy_table_list_has_no_columns() {
        let catalog = seeded();
        let svc = CatalogService::new(ModelCatalogProvider::new(&catalog));
        let page = svc
            .list_tables("avrora", "public", &PageQuery::default())
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].kind, CatalogTableKind::Table);
        assert_eq!(page.items[0].name, "users");
    }

    #[test]
    fn columns_indexes_constraints() {
        let catalog = seeded();
        let svc = CatalogService::new(ModelCatalogProvider::new(&catalog));
        let table = TableRef {
            database: "avrora".into(),
            schema: "public".into(),
            table: "users".into(),
        };
        let cols = svc.list_columns(&table, &PageQuery::default()).unwrap();
        assert_eq!(cols.items.len(), 2);
        assert!(cols.items.iter().any(|c| c.primary_key && c.name == "id"));
        let constraints = svc.list_constraints(&table, &PageQuery::default()).unwrap();
        assert!(constraints
            .items
            .iter()
            .any(|c| matches!(c.kind, CatalogConstraintKind::PrimaryKey)));
    }

    #[test]
    fn pagination_bounds_large_catalog() {
        let mut catalog = Catalog::new();
        let _ = catalog.bootstrap_default().unwrap();
        let schema = catalog.schemas().find(|s| s.name == "public").unwrap().id;
        for i in 0..1_200 {
            let create = catalog
                .create_table_event(
                    schema,
                    format!("t_{i:04}"),
                    vec![ColumnDef {
                        name: "id".into(),
                        data_type: SqlDataType::Integer,
                        nullable: false,
                        default: None,
                    }],
                    None,
                )
                .unwrap();
            catalog.apply(&create, ApplyMode::Live).unwrap();
        }
        let provider = ModelCatalogProvider::new(&catalog);
        let page = provider
            .list_tables(
                "avrora",
                "public",
                &PageQuery {
                    cursor: None,
                    limit: Some(100),
                    name_filter: None,
                },
            )
            .unwrap();
        assert_eq!(page.items.len(), 100);
        assert!(page.truncated);
        assert!(page.next_cursor.is_some());

        let mut total = page.items.len();
        let mut cursor = page.next_cursor;
        while let Some(c) = cursor {
            let next = provider
                .list_tables(
                    "avrora",
                    "public",
                    &PageQuery {
                        cursor: Some(c),
                        limit: Some(100),
                        name_filter: None,
                    },
                )
                .unwrap();
            total += next.items.len();
            cursor = next.next_cursor;
            if !next.truncated {
                break;
            }
        }
        assert_eq!(total, 1_200);
        assert!(MAX_PAGE_LIMIT >= 100);
    }

    #[test]
    fn not_found_is_typed() {
        let catalog = seeded();
        let svc = CatalogService::new(ModelCatalogProvider::new(&catalog));
        let err = svc
            .get_table(&TableRef {
                database: "avrora".into(),
                schema: "public".into(),
                table: "missing".into(),
            })
            .unwrap_err();
        assert!(matches!(err, CatalogError::NotFound(_)));
    }
}
