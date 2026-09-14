use crate::chunk::DataChunk;
use crate::error::Result;
use crate::executor::Executor;

pub struct LimitExecutor {
    child: Box<dyn Executor>,
    limit: u64,
    offset: u64,
    skipped: u64,
    emitted: u64,
    finished: bool,
}

impl LimitExecutor {
    pub fn from_parts(limit: u64, offset: u64, child: Box<dyn Executor>) -> Self {
        Self {
            child,
            limit,
            offset,
            skipped: 0,
            emitted: 0,
            finished: false,
        }
    }
}

impl Executor for LimitExecutor {
    fn next(&mut self) -> Result<Option<DataChunk>> {
        if self.finished {
            return Ok(None);
        }
        if self.limit == 0 {
            self.finished = true;
            return Ok(None);
        }

        loop {
            let Some(mut chunk) = self.child.next()? else {
                self.finished = true;
                return Ok(None);
            };
            if chunk.row_count == 0 {
                continue;
            }

            let mut start = 0usize;
            while start < chunk.row_count && self.skipped < self.offset {
                self.skipped += 1;
                start += 1;
            }
            if start >= chunk.row_count {
                continue;
            }

            let remaining = self.limit.saturating_sub(self.emitted) as usize;
            let end = (start + remaining).min(chunk.row_count);
            let keep: Vec<bool> = (0..chunk.row_count)
                .map(|idx| idx >= start && idx < end)
                .collect();
            let filtered = chunk.filter_rows(&keep)?;
            self.emitted += filtered.row_count as u64;
            if self.emitted >= self.limit {
                self.finished = true;
            }
            if filtered.row_count > 0 {
                return Ok(Some(filtered));
            }
            if self.finished {
                return Ok(None);
            }
        }
    }
}
