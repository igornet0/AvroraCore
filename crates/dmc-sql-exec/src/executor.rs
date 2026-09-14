use std::cell::RefCell;
use std::rc::Rc;

use dmc_sql_phys::PhysicalPlan;

use dmc_sql_bind::{bind_sql, BoundCatalogEvent, BoundStatement};
use dmc_security::auth::{AuthPrincipal, AuthService, CatalogAuthorizer, SessionManager};
use dmc_model::CatalogApplier;
use dmc_sql_phys::{plan_physical, plan_physical_with_cbo};
use dmc_sql_plan::{optimize_plan, plan_cbo_decisions, plan_statement, CostModel, StatisticsProvider};

use crate::auth_gate::{authorize_sql, map_security_error};
use crate::journal::journal_result;
use crate::aggregate::AggregateExecutor;
use crate::chunk::DataChunk;
use crate::context::ExecutionContext;
use crate::delete::DeleteExecutor;
use crate::error::{ExecutionError, Result};
use crate::filter::{filter_follows_aggregate, FilterExecutor};
use crate::index_scan::IndexScanExecutor;
use crate::insert::InsertExecutor;
use crate::join::HashJoinExecutor;
use crate::limit::LimitExecutor;
use crate::project::{project_follows_aggregate, ProjectExecutor};
use crate::scan::ScanExecutor;
use crate::sort::SortExecutor;
use crate::update::UpdateExecutor;

pub trait Executor {
    fn next(&mut self) -> Result<Option<DataChunk>>;
}

struct EmptyExecutor;

impl Executor for EmptyExecutor {
    fn next(&mut self) -> Result<Option<DataChunk>> {
        Ok(None)
    }
}

pub type SharedContext = Rc<RefCell<ExecutionContext>>;

pub fn build_executor(plan: PhysicalPlan, ctx: SharedContext) -> Result<Box<dyn Executor>> {
    build_executor_inner(plan, ctx)
}

fn build_executor_inner(plan: PhysicalPlan, ctx: SharedContext) -> Result<Box<dyn Executor>> {
    let chunk_size = ctx.borrow().chunk_size;
    match plan {
        PhysicalPlan::Empty => Ok(Box::new(EmptyExecutor)),
        PhysicalPlan::Scan(scan) => Ok(Box::new(ScanExecutor::new(&scan, &ctx.borrow())?)),
        PhysicalPlan::IndexScan(scan) => {
            match IndexScanExecutor::try_new(&scan, &ctx.borrow()) {
                Ok(exec) => Ok(Box::new(exec)),
                Err(ExecutionError::IndexScanFallback(reason)) => {
                    let seq = dmc_sql_phys::PhysicalScan {
                        table_id: scan.table_id,
                        columns: scan.columns.clone(),
                        access_note: Some(format!("index scan fallback: {reason}")),
                    };
                    let child = ScanExecutor::new(&seq, &ctx.borrow())?;
                    Ok(Box::new(FilterExecutor::new(
                        scan.filter_predicate.clone(),
                        Box::new(child),
                    )))
                }
                Err(err) => Err(err),
            }
        }
        PhysicalPlan::Filter(filter) => {
            let predicate = filter.predicate.clone();
            let aggregate = filter_follows_aggregate(filter.input.as_ref()).cloned();
            let child = build_executor_inner(*filter.input, ctx.clone())?;
            Ok(if let Some(agg) = aggregate {
                Box::new(FilterExecutor::with_aggregate_context(
                    predicate, child, &agg,
                ))
            } else {
                Box::new(FilterExecutor::new(predicate, child))
            })
        }
        PhysicalPlan::Project(project) => {
            let expressions = project.expressions.clone();
            let aggregate = project_follows_aggregate(project.input.as_ref()).cloned();
            let child = build_executor_inner(*project.input, ctx.clone())?;
            Ok(if let Some(agg) = aggregate {
                Box::new(ProjectExecutor::from_parts_with_aggregate(
                    expressions,
                    child,
                    Some((agg.group_exprs.len(), agg.aggregates.clone())),
                ))
            } else {
                Box::new(ProjectExecutor::from_parts(expressions, child))
            })
        }
        PhysicalPlan::HashJoin(join) => {
            let kind = join.kind;
            let build_side = join.build_side;
            let condition = join.condition.clone();
            let left = build_executor_inner(*join.left, ctx.clone())?;
            let right = build_executor_inner(*join.right, ctx.clone())?;
            Ok(Box::new(HashJoinExecutor::from_parts(
                kind,
                build_side,
                condition,
                left,
                right,
                chunk_size,
            )?))
        }
        PhysicalPlan::Aggregate(agg) => {
            let group_exprs = agg.group_exprs.clone();
            let aggregates = agg.aggregates.clone();
            let child = build_executor_inner(*agg.input, ctx.clone())?;
            Ok(Box::new(AggregateExecutor::from_parts(
                group_exprs,
                aggregates,
                child,
                chunk_size,
            )))
        }
        PhysicalPlan::Sort(sort) => {
            let keys = sort.keys.clone();
            let child = build_executor_inner(*sort.input, ctx.clone())?;
            Ok(Box::new(SortExecutor::from_parts(keys, child, chunk_size)))
        }
        PhysicalPlan::Limit(limit) => {
            let limit_val = limit.limit;
            let offset = limit.offset;
            let child = build_executor_inner(*limit.input, ctx.clone())?;
            Ok(Box::new(LimitExecutor::from_parts(limit_val, offset, child)))
        }
        PhysicalPlan::Insert(insert) => Ok(Box::new(InsertExecutor::new(&insert, ctx)?)),
        PhysicalPlan::Update(update) => Ok(Box::new(UpdateExecutor::new(&update, ctx))),
        PhysicalPlan::Delete(delete) => Ok(Box::new(DeleteExecutor::new(&delete, ctx))),
    }
}

pub fn execute_plan(plan: PhysicalPlan, ctx: &mut ExecutionContext) -> Result<Vec<DataChunk>> {
    let shared = Rc::new(RefCell::new(std::mem::take(ctx)));
    let mut out = Vec::new();
    {
        let mut executor = build_executor(plan, shared.clone())?;
        while let Some(chunk) = executor.next()? {
            out.push(chunk);
        }
    }
    *ctx = Rc::try_unwrap(shared)
        .map_err(|_| ExecutionError::Executor("shared context still borrowed".into()))?
        .into_inner();
    Ok(out)
}

pub fn collect_rows(chunks: &[DataChunk]) -> Vec<Vec<crate::value::Value>> {
    let mut rows = Vec::new();
    for chunk in chunks {
        for idx in 0..chunk.row_count {
            rows.push(chunk.row(idx));
        }
    }
    rows
}

pub fn execute_sql_pipeline(
    plan: PhysicalPlan,
    ctx: &mut ExecutionContext,
) -> Result<Vec<DataChunk>> {
    execute_plan(plan, ctx)
}

/// Handles transaction control statements; returns `None` when the caller should plan/execute SQL.
pub fn execute_transaction_statement(
    statement: BoundStatement,
    ctx: &mut ExecutionContext,
) -> Result<Option<Vec<DataChunk>>> {
    match statement {
        BoundStatement::Begin => {
            ctx.begin_transaction()?;
            Ok(Some(Vec::new()))
        }
        BoundStatement::Commit => {
            ctx.commit_transaction()?;
            Ok(Some(Vec::new()))
        }
        BoundStatement::Rollback => {
            ctx.rollback_transaction()?;
            Ok(Some(Vec::new()))
        }
        _ => Ok(None),
    }
}

pub fn execute_catalog_statement(
    event: BoundCatalogEvent,
    ctx: &mut ExecutionContext,
) -> Result<Vec<DataChunk>> {
    if ctx.in_transaction() {
        let catalog_event = event.event.clone();
        ctx.push_transaction_catalog(catalog_event.clone());
        let catalog = ctx.session_catalog_mut()?;
        catalog
            .apply(&catalog_event, dmc_model::ApplyMode::Live)
            .map_err(|e| ExecutionError::Storage(e.to_string()))?;
        return Ok(Vec::new());
    }
    let catalog = ctx.session_catalog()?.clone();
    let journal = ctx
        .journal_mut()
        .ok_or_else(|| ExecutionError::InvalidPlan("journal required for DDL".into()))?;
    journal_result(journal.mutate_catalog_validated(&catalog, event.event.clone()))?;
    ctx.session_catalog_mut()?
        .apply(&event.event, dmc_model::ApplyMode::Live)
        .map_err(|e| ExecutionError::Storage(e.to_string()))?;
    ctx.register_materialized_tables_from_journal()?;
    Ok(Vec::new())
}

/// Phase 7.2 entry point: validate session → authorize → bind → execute.
pub fn execute_authorized_sql(
    sql: &str,
    auth: &AuthService,
    principal: &AuthPrincipal,
    ctx: &mut ExecutionContext,
) -> Result<Vec<DataChunk>> {
    auth.validate_session(&principal.session_id)
        .map_err(map_security_error)?;
    let authorizer = auth.authorizer();
    authorize_sql(&authorizer, principal, sql)?;
    let bound = {
        let catalog = ctx
            .session_catalog_mut()
            .map_err(|e| ExecutionError::InvalidPlan(e.to_string()))?;
        bind_sql(catalog, sql).map_err(|e| ExecutionError::InvalidPlan(e.to_string()))?
    };
    execute_bound_statement(bound, ctx)
}

pub fn execute_bound_statement(
    statement: BoundStatement,
    ctx: &mut ExecutionContext,
) -> Result<Vec<DataChunk>> {
    match statement {
        BoundStatement::Begin | BoundStatement::Commit | BoundStatement::Rollback => {
            execute_transaction_statement(statement, ctx).map(|opt| opt.unwrap_or_default())
        }
        BoundStatement::CreateIndex(ev)
        | BoundStatement::DropIndex(ev)
        | BoundStatement::CreateTable(ev)
        | BoundStatement::CreateSchema(ev)
        | BoundStatement::CreateDatabase(ev)
        | BoundStatement::DropTable(ev) => execute_catalog_statement(ev, ctx),
        stmt => {
            let logical = plan_statement(stmt)
                .map_err(|e| ExecutionError::InvalidPlan(e.to_string()))?;
            let optimized =
                optimize_plan(logical).map_err(|e| ExecutionError::InvalidPlan(e.to_string()))?;
            let catalog = ctx
                .session_catalog()
                .map_err(|e| ExecutionError::InvalidPlan(e.to_string()))?;
            let stats = statistics_provider(ctx);
            let cbo = plan_cbo_decisions(&optimized, catalog, &stats, &CostModel::default());
            let physical = plan_physical_with_cbo(&optimized, &cbo)
                .map_err(|e| ExecutionError::InvalidPlan(e.to_string()))?;
            execute_plan(physical, ctx)
        }
    }
}

fn statistics_provider(ctx: &ExecutionContext) -> StatisticsProvider {
    ctx.journal()
        .and_then(|journal| journal.statistics().snapshot().ok())
        .map(|snapshot| StatisticsProvider::from_tables(snapshot.tables))
        .unwrap_or_default()
}

pub fn plan_and_execute_query(
    catalog: &dmc_model::Catalog,
    stats: &StatisticsProvider,
    stmt: dmc_sql_bind::BoundStatement,
    ctx: &mut ExecutionContext,
) -> Result<Vec<DataChunk>> {
    let logical =
        plan_statement(stmt).map_err(|e| ExecutionError::InvalidPlan(e.to_string()))?;
    let optimized =
        optimize_plan(logical).map_err(|e| ExecutionError::InvalidPlan(e.to_string()))?;
    let cbo = plan_cbo_decisions(&optimized, catalog, stats, &CostModel::default());
    let physical = plan_physical_with_cbo(&optimized, &cbo)
        .map_err(|e| ExecutionError::InvalidPlan(e.to_string()))?;
    execute_plan(physical, ctx)
}
