use dmc_model::Catalog;
use dmc_sql_front::{parse_sql, Statement};

use crate::bound::BoundStatement;
use crate::ddl::bind_ddl;
use crate::dml::{bind_delete, bind_insert, bind_update};
use crate::error::Result;
use crate::select::bind_select;

/// Binds a parsed SQL statement against catalog state.
///
/// DDL statements allocate ids via [`Catalog`] planners but do **not** apply events
/// or write journal records.
pub struct Binder<'a> {
    catalog: &'a mut Catalog,
}

impl<'a> Binder<'a> {
    pub fn new(catalog: &'a mut Catalog) -> Self {
        Self { catalog }
    }

    pub fn bind(&mut self, stmt: Statement) -> Result<BoundStatement> {
        bind_statement(self.catalog, stmt)
    }
}

pub fn bind_statement(catalog: &mut Catalog, stmt: Statement) -> Result<BoundStatement> {
    match stmt {
        Statement::Select(s) => bind_select(catalog, s),
        Statement::Insert(s) => bind_insert(catalog, s),
        Statement::Update(s) => bind_update(catalog, s),
        Statement::Delete(s) => bind_delete(catalog, s),
        Statement::Begin => Ok(BoundStatement::Begin),
        Statement::Commit => Ok(BoundStatement::Commit),
        Statement::Rollback => Ok(BoundStatement::Rollback),
        ddl => bind_ddl(catalog, ddl),
    }
}

/// Convenience: parse + bind in one step.
pub fn bind_sql(catalog: &mut Catalog, sql: &str) -> Result<BoundStatement> {
    let stmt = parse_sql(sql).map_err(|e| crate::error::BindError::Catalog {
        message: e.to_string(),
        span: e.span().unwrap_or_default(),
    })?;
    bind_statement(catalog, stmt)
}
