use dmc_sql_phys::PhysicalScan;

use crate::datasource::DataScanner;
use crate::error::{ExecutionError, Result};
use crate::executor::Executor;

pub struct ScanExecutor {
    scanner: Box<dyn DataScanner>,
}

impl ScanExecutor {
    pub fn new(scan: &PhysicalScan, ctx: &crate::context::ExecutionContext) -> Result<Self> {
        let source = ctx
            .data_source(scan.table_id)
            .ok_or(ExecutionError::TableNotFound(scan.table_id.raw()))?;
        let projection = scan.columns.clone();
        let scan_ctx = ctx.scan_context();
        let scanner = source.scan(&projection, ctx.chunk_size, &scan_ctx)?;
        Ok(Self { scanner })
    }
}

impl Executor for ScanExecutor {
    fn next(&mut self) -> Result<Option<crate::chunk::DataChunk>> {
        self.scanner.next()
    }
}
