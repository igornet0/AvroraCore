use dmc_sql_plan::{NullOrder, SortDirection};

use crate::chunk::DataChunk;
use crate::error::Result;
use crate::executor::Executor;
use crate::expression::evaluate;
use crate::schema::ChunkSchema;
use crate::value::Value;

pub struct SortExecutor {
    child: Box<dyn Executor>,
    keys: Vec<dmc_sql_plan::SortKey>,
    rows: Vec<Vec<Value>>,
    output_schema: ChunkSchema,
    cursor: usize,
    chunk_size: usize,
    built: bool,
}

impl SortExecutor {
    pub fn from_parts(
        keys: Vec<dmc_sql_plan::SortKey>,
        child: Box<dyn Executor>,
        chunk_size: usize,
    ) -> Self {
        Self {
            child,
            keys,
            rows: Vec::new(),
            output_schema: ChunkSchema::empty(),
            cursor: 0,
            chunk_size,
            built: false,
        }
    }

    fn build(&mut self) -> Result<()> {
        let input = drain_executor(&mut self.child)?;
        self.output_schema = input
            .first()
            .map(|c| c.schema.clone())
            .unwrap_or_default();
        let schema = self.output_schema.clone();
        let mut rows = flatten_rows(&input);
        rows.sort_by(|a, b| compare_rows(a, b, &self.keys, &schema));
        self.rows = rows;
        self.built = true;
        Ok(())
    }
}

impl Executor for SortExecutor {
    fn next(&mut self) -> Result<Option<DataChunk>> {
        if !self.built {
            self.build()?;
        }
        if self.cursor >= self.rows.len() {
            return Ok(None);
        }
        let end = (self.cursor + self.chunk_size).min(self.rows.len());
        let batch = self.rows[self.cursor..end].to_vec();
        self.cursor = end;
        Ok(Some(DataChunk::from_rows(
            self.output_schema.clone(),
            batch,
        )?))
    }
}

fn compare_rows(
    a: &[Value],
    b: &[Value],
    keys: &[dmc_sql_plan::SortKey],
    schema: &ChunkSchema,
) -> std::cmp::Ordering {
    for key in keys {
        let chunk_a = DataChunk::single_row(schema.clone(), a.to_vec()).expect("sort row");
        let chunk_b = DataChunk::single_row(schema.clone(), b.to_vec()).expect("sort row");
        let va = evaluate(&key.expr, &chunk_a, 0).unwrap_or(Value::Null);
        let vb = evaluate(&key.expr, &chunk_b, 0).unwrap_or(Value::Null);
        let ord = compare_sort_values(&va, &vb, key.direction, key.nulls);
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }
    std::cmp::Ordering::Equal
}

fn compare_sort_values(
    a: &Value,
    b: &Value,
    direction: SortDirection,
    nulls: NullOrder,
) -> std::cmp::Ordering {
    let mut ord = match (a.is_null(), b.is_null()) {
        (true, true) => std::cmp::Ordering::Equal,
        (true, false) => match nulls {
            NullOrder::First => std::cmp::Ordering::Less,
            NullOrder::Last => std::cmp::Ordering::Greater,
        },
        (false, true) => match nulls {
            NullOrder::First => std::cmp::Ordering::Greater,
            NullOrder::Last => std::cmp::Ordering::Less,
        },
        (false, false) => a.compare_order(b).unwrap_or(std::cmp::Ordering::Equal),
    };
    if matches!(direction, SortDirection::Desc) {
        ord = ord.reverse();
    }
    ord
}

fn flatten_rows(chunks: &[DataChunk]) -> Vec<Vec<Value>> {
    let mut rows = Vec::new();
    for chunk in chunks {
        for row_idx in 0..chunk.row_count {
            rows.push(chunk.row(row_idx));
        }
    }
    rows
}

fn drain_executor(exec: &mut Box<dyn Executor>) -> Result<Vec<DataChunk>> {
    let mut out = Vec::new();
    while let Some(chunk) = exec.as_mut().next()? {
        out.push(chunk);
    }
    Ok(out)
}
