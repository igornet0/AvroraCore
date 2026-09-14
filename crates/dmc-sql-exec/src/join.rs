use std::collections::{HashMap, HashSet};

use dmc_sql_bind::BoundExpr;
use dmc_sql_front::BinaryOp;
use dmc_sql_plan::{JoinBuildSide, JoinType};

use crate::chunk::DataChunk;
use crate::error::{ExecutionError, Result};
use crate::executor::Executor;
use crate::expression::evaluate;
use crate::schema::ChunkSchema;
use crate::value::{Value, ValueKey};

enum JoinMode {
    Cross,
    Equi {
        left_key: BoundExpr,
        right_key: BoundExpr,
    },
}

impl Clone for JoinMode {
    fn clone(&self) -> Self {
        match self {
            JoinMode::Cross => JoinMode::Cross,
            JoinMode::Equi {
                left_key,
                right_key,
            } => JoinMode::Equi {
                left_key: left_key.clone(),
                right_key: right_key.clone(),
            },
        }
    }
}

pub struct HashJoinExecutor {
    kind: JoinType,
    build_side: JoinBuildSide,
    mode: JoinMode,
    output_schema: ChunkSchema,
    rows: Vec<Vec<Value>>,
    cursor: usize,
    chunk_size: usize,
    built: bool,
    left_child: Box<dyn Executor>,
    right_child: Box<dyn Executor>,
}

impl HashJoinExecutor {
    pub fn from_parts(
        kind: JoinType,
        build_side: JoinBuildSide,
        condition: Option<BoundExpr>,
        left: Box<dyn Executor>,
        right: Box<dyn Executor>,
        chunk_size: usize,
    ) -> Result<Self> {
        let mode = match condition.as_ref() {
            None => JoinMode::Cross,
            Some(BoundExpr::Binary {
                op: BinaryOp::Eq,
                left,
                right,
                ..
            }) => JoinMode::Equi {
                left_key: (**left).clone(),
                right_key: (**right).clone(),
            },
            Some(_) => {
                return Err(ExecutionError::Unsupported(
                    "only equality join conditions supported".into(),
                ))
            }
        };
        Ok(Self {
            kind,
            build_side,
            mode,
            output_schema: ChunkSchema::empty(),
            rows: Vec::new(),
            cursor: 0,
            chunk_size,
            built: false,
            left_child: left,
            right_child: right,
        })
    }

    fn build(&mut self) -> Result<()> {
        let left_rows = drain_executor(&mut self.left_child)?;
        let right_rows = drain_executor(&mut self.right_child)?;
        let left_flat = flatten_rows(&left_rows);
        let right_flat = flatten_rows(&right_rows);
        let left_schema = left_rows
            .first()
            .map(|c| c.schema.clone())
            .unwrap_or_default();
        let right_schema = right_rows
            .first()
            .map(|c| c.schema.clone())
            .unwrap_or_default();
        let mut output_columns = left_schema.columns.clone();
        output_columns.extend(right_schema.columns.clone());
        self.output_schema = ChunkSchema::new(output_columns);

        match self.mode.clone() {
            JoinMode::Cross => {
                for left_row in &left_flat {
                    for right_row in &right_flat {
                        self.rows.push(join_rows(left_row, right_row));
                    }
                }
            }
            JoinMode::Equi {
                left_key,
                right_key,
            } => {
                self.build_equi(
                    &left_flat,
                    &right_flat,
                    &left_schema,
                    &right_schema,
                    &left_key,
                    &right_key,
                )?;
            }
        }
        self.built = true;
        Ok(())
    }

    fn build_equi(
        &mut self,
        left_flat: &[Vec<Value>],
        right_flat: &[Vec<Value>],
        left_schema: &ChunkSchema,
        right_schema: &ChunkSchema,
        left_key: &BoundExpr,
        right_key: &BoundExpr,
    ) -> Result<()> {
        let (build_rows, build_schema, build_key, probe_rows, probe_schema, probe_key) =
            match self.build_side {
                JoinBuildSide::Right => (
                    right_flat,
                    right_schema,
                    right_key,
                    left_flat,
                    left_schema,
                    left_key,
                ),
                JoinBuildSide::Left => (
                    left_flat,
                    left_schema,
                    left_key,
                    right_flat,
                    right_schema,
                    right_key,
                ),
            };

        let mut build_by_key: HashMap<ValueKey, Vec<usize>> = HashMap::new();
        for (idx, row) in build_rows.iter().enumerate() {
            let chunk = DataChunk::single_row(build_schema.clone(), row.clone())?;
            if let Some(key) = join_key(build_key, &chunk, 0)? {
                build_by_key.entry(key).or_default().push(idx);
            }
        }

        let mut matched_probe: HashSet<usize> = HashSet::new();
        let mut matched_build: HashSet<usize> = HashSet::new();

        for (probe_idx, probe_row) in probe_rows.iter().enumerate() {
            let probe_chunk = DataChunk::single_row(probe_schema.clone(), probe_row.clone())?;
            let key = join_key(probe_key, &probe_chunk, 0)?;
            let mut any = false;
            if let Some(key) = key {
                if let Some(indices) = build_by_key.get(&key) {
                    for &build_idx in indices {
                        any = true;
                        matched_probe.insert(probe_idx);
                        matched_build.insert(build_idx);
                        let (left_row, right_row) = match self.build_side {
                            JoinBuildSide::Right => (probe_row, &build_rows[build_idx]),
                            JoinBuildSide::Left => (&build_rows[build_idx], probe_row),
                        };
                        self.rows.push(join_rows(left_row, right_row));
                    }
                }
            }
            let preserve_probe = matches!(self.kind, JoinType::Right | JoinType::Full)
                || (matches!(self.kind, JoinType::Left | JoinType::Full)
                    && matches!(self.build_side, JoinBuildSide::Right));
            if !any && preserve_probe {
                let (left_row, right_row) = match self.build_side {
                    JoinBuildSide::Right => (probe_row, &null_row(right_schema.len())),
                    JoinBuildSide::Left => (&null_row(left_schema.len()), probe_row),
                };
                self.rows.push(join_rows(left_row, right_row));
            }
        }

        let preserve_build = matches!(self.kind, JoinType::Right | JoinType::Full)
            || (matches!(self.kind, JoinType::Left | JoinType::Full)
                && matches!(self.build_side, JoinBuildSide::Left));
        if preserve_build {
            for (build_idx, build_row) in build_rows.iter().enumerate() {
                if matched_build.contains(&build_idx) {
                    continue;
                }
                let (left_row, right_row) = match self.build_side {
                    JoinBuildSide::Right => (&null_row(left_schema.len()), build_row),
                    JoinBuildSide::Left => (build_row, &null_row(right_schema.len())),
                };
                self.rows.push(join_rows(left_row, right_row));
            }
        }

        Ok(())
    }
}

impl Executor for HashJoinExecutor {
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

fn join_key(expr: &BoundExpr, chunk: &DataChunk, row: usize) -> Result<Option<ValueKey>> {
    let value = evaluate(expr, chunk, row)?;
    Ok(ValueKey::try_from_value(&value))
}

fn join_rows(left: &[Value], right: &[Value]) -> Vec<Value> {
    left.iter().chain(right.iter()).cloned().collect()
}

fn null_row(len: usize) -> Vec<Value> {
    vec![Value::Null; len]
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
