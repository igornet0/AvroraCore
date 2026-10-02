use crate::error::Result;
use crate::page::{CatalogPage, PageQuery};
use crate::provider::CatalogProvider;
use crate::types::{
    CatalogColumn, CatalogConstraint, CatalogDatabase, CatalogIndex, CatalogSchema, CatalogTable,
    TableRef,
};

/// Facade used by protocol adapters (DMC / future HTTP).
pub struct CatalogService<P: CatalogProvider> {
    provider: P,
}

impl<P: CatalogProvider> CatalogService<P> {
    pub fn new(provider: P) -> Self {
        Self { provider }
    }

    pub fn list_databases(&self) -> Result<Vec<CatalogDatabase>> {
        self.provider.list_databases()
    }

    pub fn list_schemas(
        &self,
        database: Option<&str>,
        page: &PageQuery,
    ) -> Result<CatalogPage<CatalogSchema>> {
        self.provider.list_schemas(database, page)
    }

    pub fn list_tables(
        &self,
        database: &str,
        schema: &str,
        page: &PageQuery,
    ) -> Result<CatalogPage<CatalogTable>> {
        self.provider.list_tables(database, schema, page)
    }

    pub fn get_table(&self, table: &TableRef) -> Result<CatalogTable> {
        self.provider.get_table(table)
    }

    pub fn list_columns(
        &self,
        table: &TableRef,
        page: &PageQuery,
    ) -> Result<CatalogPage<CatalogColumn>> {
        self.provider.list_columns(table, page)
    }

    pub fn list_indexes(
        &self,
        table: &TableRef,
        page: &PageQuery,
    ) -> Result<CatalogPage<CatalogIndex>> {
        self.provider.list_indexes(table, page)
    }

    pub fn list_constraints(
        &self,
        table: &TableRef,
        page: &PageQuery,
    ) -> Result<CatalogPage<CatalogConstraint>> {
        self.provider.list_constraints(table, page)
    }
}
