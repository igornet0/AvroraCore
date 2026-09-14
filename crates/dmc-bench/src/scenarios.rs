use std::sync::Arc;
use std::time::Instant;

use dmc_core::PutOptions;
use dmc_core::runtime::Runtime;
use dmc_journal::{set_test_partition_count, set_test_segment_max_bytes};
use dmc_sql::SqlEngine;

use crate::harness::{
    bench_path, finance_path, reopen_runtime, BenchConfig, BenchEnv, ConsumerEnv,
};
use crate::metrics::{BenchResult, LatencyStats, Timer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScenarioKind {
    WriteSequential,
    WriteParallel,
    ReadHot,
    ReadScattered,
    MixedReadWrite,
    CrudCycle,
    DeleteTombstone,
    ListKeys,
    ConsumerPipeline,
    IdempotentProducer,
    PartitionedJournal,
    RecoveryUnlock,
    ForceSnapshot,
    SqlBulkInsert,
    CompactionUnderLoad,
}

impl ScenarioKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::WriteSequential => "write_sequential",
            Self::WriteParallel => "write_parallel",
            Self::ReadHot => "read_hot",
            Self::ReadScattered => "read_scattered",
            Self::MixedReadWrite => "mixed_rw",
            Self::CrudCycle => "crud_cycle",
            Self::DeleteTombstone => "delete",
            Self::ListKeys => "list_keys",
            Self::ConsumerPipeline => "consumer_pipeline",
            Self::IdempotentProducer => "idempotent",
            Self::PartitionedJournal => "partitioned",
            Self::RecoveryUnlock => "recovery",
            Self::ForceSnapshot => "snapshot",
            Self::SqlBulkInsert => "sql_insert",
            Self::CompactionUnderLoad => "compaction",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        all_scenario_names()
            .iter()
            .find(|(name, _)| *name == s)
            .map(|(_, kind)| *kind)
    }
}

pub fn all_scenario_names() -> &'static [(&'static str, ScenarioKind)] {
    &[
        ("write_sequential", ScenarioKind::WriteSequential),
        ("write_parallel", ScenarioKind::WriteParallel),
        ("read_hot", ScenarioKind::ReadHot),
        ("read_scattered", ScenarioKind::ReadScattered),
        ("mixed_rw", ScenarioKind::MixedReadWrite),
        ("crud_cycle", ScenarioKind::CrudCycle),
        ("delete", ScenarioKind::DeleteTombstone),
        ("list_keys", ScenarioKind::ListKeys),
        ("consumer_pipeline", ScenarioKind::ConsumerPipeline),
        ("idempotent", ScenarioKind::IdempotentProducer),
        ("partitioned", ScenarioKind::PartitionedJournal),
        ("recovery", ScenarioKind::RecoveryUnlock),
        ("snapshot", ScenarioKind::ForceSnapshot),
        ("sql_insert", ScenarioKind::SqlBulkInsert),
        ("compaction", ScenarioKind::CompactionUnderLoad),
    ]
}

pub async fn run_scenario(kind: ScenarioKind, cfg: &BenchConfig) -> BenchResult {
    match kind {
        ScenarioKind::WriteSequential => write_sequential(cfg).await,
        ScenarioKind::WriteParallel => write_parallel(cfg).await,
        ScenarioKind::ReadHot => read_hot(cfg).await,
        ScenarioKind::ReadScattered => read_scattered(cfg).await,
        ScenarioKind::MixedReadWrite => mixed_rw(cfg).await,
        ScenarioKind::CrudCycle => crud_cycle(cfg).await,
        ScenarioKind::DeleteTombstone => delete_tombstone(cfg).await,
        ScenarioKind::ListKeys => list_keys(cfg).await,
        ScenarioKind::ConsumerPipeline => consumer_pipeline(cfg).await,
        ScenarioKind::IdempotentProducer => idempotent_producer(cfg).await,
        ScenarioKind::PartitionedJournal => partitioned_journal(cfg).await,
        ScenarioKind::RecoveryUnlock => recovery_unlock(cfg).await,
        ScenarioKind::ForceSnapshot => force_snapshot(cfg).await,
        ScenarioKind::SqlBulkInsert => sql_bulk_insert(cfg).await,
        ScenarioKind::CompactionUnderLoad => compaction_under_load(cfg).await,
    }
}

struct TestHooks {
    _partition: Option<PartitionHook>,
    _segment: Option<SegmentHook>,
}

struct PartitionHook;

impl Drop for PartitionHook {
    fn drop(&mut self) {
        set_test_partition_count(None);
    }
}

struct SegmentHook;

impl Drop for SegmentHook {
    fn drop(&mut self) {
        set_test_segment_max_bytes(None);
    }
}

fn enable_small_segments() -> TestHooks {
    set_test_segment_max_bytes(Some(900));
    TestHooks {
        _partition: None,
        _segment: Some(SegmentHook),
    }
}

fn enable_partitioned_small_segments(parts: u32) -> TestHooks {
    set_test_partition_count(Some(parts));
    set_test_segment_max_bytes(Some(900));
    TestHooks {
        _partition: Some(PartitionHook),
        _segment: Some(SegmentHook),
    }
}

async fn write_sequential(cfg: &BenchConfig) -> BenchResult {
    let env = BenchEnv::create().await;
    let ops = cfg.effective_ops();
    let payload = cfg.payload();
    let bytes = payload.len() as u64;
    let mut stats = LatencyStats::new();
    let timer = Timer::start();
    let mut errors = 0u64;

    for i in 0..ops {
        let t0 = Instant::now();
        if env
            .rt
            .put_data(&env.admin, &bench_path("company/bench", i), &payload)
            .await
            .is_err()
        {
            errors += 1;
        }
        stats.record(t0.elapsed());
    }

    BenchResult::from_stats(
        ScenarioKind::WriteSequential.name(),
        ops,
        errors,
        timer.elapsed(),
        &stats,
        ops * bytes,
        Some(format!("payload={}B, fsync per write", bytes)),
    )
}

async fn write_parallel(cfg: &BenchConfig) -> BenchResult {
    let env = Arc::new(BenchEnv::create().await);
    let ops = cfg.effective_ops();
    let concurrency = cfg.effective_concurrency();
    let payload = Arc::new(cfg.payload());
    let bytes = payload.len() as u64;
    let per_task = ops / concurrency as u64;
    let remainder = ops % concurrency as u64;
    let timer = Timer::start();
    let mut handles = Vec::with_capacity(concurrency);

    for task in 0..concurrency {
        let env = Arc::clone(&env);
        let payload = Arc::clone(&payload);
        let count = per_task + u64::from(task == 0) * remainder;
        let base = task as u64 * (ops / concurrency as u64 + 1);
        handles.push(tokio::spawn(async move {
            let mut stats = LatencyStats::new();
            let mut errors = 0u64;
            for i in 0..count {
                let path = bench_path("company/par", base + i);
                let t0 = Instant::now();
                if env.rt.put_data(&env.admin, &path, &payload).await.is_err() {
                    errors += 1;
                }
                stats.record(t0.elapsed());
            }
            (stats, errors, count)
        }));
    }

    let mut merged = LatencyStats::new();
    let mut errors = 0u64;
    let mut total_ops = 0u64;
    for h in handles {
        let (stats, err, count) = h.await.expect("task join");
        for s in stats.samples() {
            merged.record(*s);
        }
        errors += err;
        total_ops += count;
    }

    BenchResult::from_stats(
        ScenarioKind::WriteParallel.name(),
        total_ops,
        errors,
        timer.elapsed(),
        &merged,
        total_ops * bytes,
        Some(format!("concurrency={concurrency}, payload={bytes}B")),
    )
}

async fn prepopulate(env: &BenchEnv, ops: u64, payload: &[u8]) {
    for i in 0..ops {
        env.rt
            .put_data(&env.admin, &bench_path("company/read", i), payload)
            .await
            .expect("prepopulate");
    }
}

async fn read_hot(cfg: &BenchConfig) -> BenchResult {
    let env = BenchEnv::create().await;
    let ops = cfg.effective_ops();
    let payload = cfg.payload();
    prepopulate(&env, 1, &payload).await;
    let hot_path = bench_path("company/read", 0);
    let mut stats = LatencyStats::new();
    let timer = Timer::start();
    let mut errors = 0u64;

    for _ in 0..ops {
        let t0 = Instant::now();
        if env.rt.get_data(&env.admin, &hot_path).await.is_err() {
            errors += 1;
        }
        stats.record(t0.elapsed());
    }

    BenchResult::from_stats(
        ScenarioKind::ReadHot.name(),
        ops,
        errors,
        timer.elapsed(),
        &stats,
        ops * payload.len() as u64,
        Some("single key, overlay cache hot".into()),
    )
}

async fn read_scattered(cfg: &BenchConfig) -> BenchResult {
    let env = BenchEnv::create().await;
    let ops = cfg.effective_ops();
    let payload = cfg.payload();
    let key_count = ops.min(500).max(10);
    prepopulate(&env, key_count, &payload).await;
    let mut stats = LatencyStats::new();
    let timer = Timer::start();
    let mut errors = 0u64;

    for i in 0..ops {
        let path = bench_path("company/read", i % key_count);
        let t0 = Instant::now();
        if env.rt.get_data(&env.admin, &path).await.is_err() {
            errors += 1;
        }
        stats.record(t0.elapsed());
    }

    BenchResult::from_stats(
        ScenarioKind::ReadScattered.name(),
        ops,
        errors,
        timer.elapsed(),
        &stats,
        ops * payload.len() as u64,
        Some(format!("{key_count} distinct keys")),
    )
}

async fn mixed_rw(cfg: &BenchConfig) -> BenchResult {
    let env = Arc::new(BenchEnv::create().await);
    let ops = cfg.effective_ops();
    let payload = Arc::new(cfg.payload());
    let bytes = payload.len() as u64;
    prepopulate(&env, ops.min(200).max(10), &payload).await;
    let timer = Timer::start();
    let mut stats = LatencyStats::new();
    let mut errors = 0u64;

    for i in 0..ops {
        let t0 = Instant::now();
        let res = if i % 10 < 7 {
            let path = bench_path("company/read", i % 50);
            env.rt.get_data(&env.admin, &path).await.map(|_| ())
        } else {
            env.rt
                .put_data(&env.admin, &bench_path("company/mixed", i), &payload)
                .await
        };
        if res.is_err() {
            errors += 1;
        }
        stats.record(t0.elapsed());
    }

    BenchResult::from_stats(
        ScenarioKind::MixedReadWrite.name(),
        ops,
        errors,
        timer.elapsed(),
        &stats,
        ops * bytes,
        Some("70% read / 30% write".into()),
    )
}

async fn crud_cycle(cfg: &BenchConfig) -> BenchResult {
    let env = BenchEnv::create().await;
    let cycles = cfg.effective_ops() / 4;
    let payload = cfg.payload();
    let mut stats = LatencyStats::new();
    let timer = Timer::start();
    let mut errors = 0u64;
    let mut ops = 0u64;

    for i in 0..cycles {
        let path = bench_path("company/crud", i);
        for (f, data) in [
            ("create", payload.as_slice()),
            ("read", payload.as_slice()),
            ("update", b"updated-payload"),
            ("delete", &[] as &[u8]),
        ] {
            let t0 = Instant::now();
            let res = match f {
                "create" | "update" => env.rt.put_data(&env.admin, &path, data).await,
                "read" => env.rt.get_data(&env.admin, &path).await.map(|_| ()),
                "delete" => env.rt.delete_data(&env.admin, &path).await,
                _ => unreachable!(),
            };
            if res.is_err() {
                errors += 1;
            }
            stats.record(t0.elapsed());
            ops += 1;
        }
    }

    BenchResult::from_stats(
        ScenarioKind::CrudCycle.name(),
        ops,
        errors,
        timer.elapsed(),
        &stats,
        cycles * payload.len() as u64,
        Some(format!("{cycles} full CRUD cycles")),
    )
}

async fn delete_tombstone(cfg: &BenchConfig) -> BenchResult {
    let env = BenchEnv::create().await;
    let ops = cfg.effective_ops();
    let payload = cfg.payload();
    for i in 0..ops {
        env.rt
            .put_data(&env.admin, &bench_path("company/del", i), &payload)
            .await
            .expect("setup put");
    }
    let mut stats = LatencyStats::new();
    let timer = Timer::start();
    let mut errors = 0u64;

    for i in 0..ops {
        let t0 = Instant::now();
        if env
            .rt
            .delete_data(&env.admin, &bench_path("company/del", i))
            .await
            .is_err()
        {
            errors += 1;
        }
        stats.record(t0.elapsed());
    }

    BenchResult::from_stats(
        ScenarioKind::DeleteTombstone.name(),
        ops,
        errors,
        timer.elapsed(),
        &stats,
        0,
        Some("delete after pre-populated keys".into()),
    )
}

async fn list_keys(cfg: &BenchConfig) -> BenchResult {
    let env = BenchEnv::create().await;
    let key_count = cfg.effective_ops().min(500).max(20);
    let payload = cfg.payload();
    for i in 0..key_count {
        env.rt
            .put_data(&env.admin, &bench_path("company/list", i), &payload)
            .await
            .expect("setup");
    }
    let list_ops = if cfg.quick { 10 } else { 50 };
    let mut stats = LatencyStats::new();
    let timer = Timer::start();
    let mut errors = 0u64;

    for _ in 0..list_ops {
        let t0 = Instant::now();
        if env
            .rt
            .list_keys(&env.admin, "company/list/")
            .await
            .is_err()
        {
            errors += 1;
        }
        stats.record(t0.elapsed());
    }

    BenchResult::from_stats(
        ScenarioKind::ListKeys.name(),
        list_ops,
        errors,
        timer.elapsed(),
        &stats,
        0,
        Some(format!("prefix scan over {key_count} keys")),
    )
}

async fn consumer_pipeline(cfg: &BenchConfig) -> BenchResult {
    let env = ConsumerEnv::create().await;
    let ops = cfg.effective_ops();
    let payload = cfg.payload();
    let admin = env.base.admin.clone();
    let rt = &env.base.rt;
    let sub = env.subscription.clone();
    let mut stats = LatencyStats::new();
    let timer = Timer::start();
    let mut errors = 0u64;
    let mut pipeline_ops = 0u64;

    for i in 0..ops {
        let t0 = Instant::now();
        let ok = async {
            rt.put_data(&admin, &finance_path(i), &payload).await?;
            let events = rt.consume(&sub, 1).await?;
            let delivery_id = events
                .first()
                .ok_or_else(|| std::io::Error::other("no event"))?
                .delivery
                .delivery_id
                .clone();
            rt.ack(&env.alice, &sub, &delivery_id).await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        }
        .await;
        if ok.is_err() {
            errors += 1;
        }
        stats.record(t0.elapsed());
        pipeline_ops += 1;
    }

    BenchResult::from_stats(
        ScenarioKind::ConsumerPipeline.name(),
        pipeline_ops,
        errors,
        timer.elapsed(),
        &stats,
        ops * payload.len() as u64,
        Some("put → consume → ack per event".into()),
    )
}

async fn idempotent_producer(cfg: &BenchConfig) -> BenchResult {
    let env = BenchEnv::create().await;
    let ops = cfg.effective_ops();
    let payload = cfg.payload();
    let opts = PutOptions {
        producer_id: "bench-producer".into(),
        idempotency_key: "stable-key".into(),
    };
    let mut stats = LatencyStats::new();
    let timer = Timer::start();
    let mut errors = 0u64;
    let mut replays = 0u64;

    for i in 0..ops {
        let t0 = Instant::now();
        match env
            .rt
            .put_data_with(
                &env.admin,
                &bench_path("company/idempotent", i % 10),
                &payload,
                Some(opts.clone()),
            )
            .await
        {
            Ok(r) if r.replay => replays += 1,
            Ok(_) => {}
            Err(_) => errors += 1,
        }
        stats.record(t0.elapsed());
    }

    BenchResult::from_stats(
        ScenarioKind::IdempotentProducer.name(),
        ops,
        errors,
        timer.elapsed(),
        &stats,
        ops * payload.len() as u64,
        Some(format!("{replays} dedup replays out of {ops} puts")),
    )
}

async fn partitioned_journal(cfg: &BenchConfig) -> BenchResult {
    let _hooks = enable_partitioned_small_segments(8);
    let env = BenchEnv::create().await;
    let ops = cfg.effective_ops();
    let payload = cfg.payload();
    let bytes = payload.len() as u64;
    let mut stats = LatencyStats::new();
    let timer = Timer::start();
    let mut errors = 0u64;

    for i in 0..ops {
        let t0 = Instant::now();
        if env
            .rt
            .put_data(&env.admin, &finance_path(i), &payload)
            .await
            .is_err()
        {
            errors += 1;
        }
        stats.record(t0.elapsed());
    }

    let seq = env.base_or_last_sequence(&env.rt).await;
    BenchResult::from_stats(
        ScenarioKind::PartitionedJournal.name(),
        ops,
        errors,
        timer.elapsed(),
        &stats,
        ops * bytes,
        Some(format!(
            "8 partitions, 900B segments, journal_head={seq}"
        )),
    )
}

async fn recovery_unlock(cfg: &BenchConfig) -> BenchResult {
    let env = BenchEnv::create().await;
    let ops = cfg.effective_ops();
    let payload = cfg.payload();
    for i in 0..ops {
        env.rt
            .put_data(&env.admin, &bench_path("company/recovery", i), &payload)
            .await
            .expect("write before recovery");
    }
    env.rt.force_snapshot().await.expect("snapshot before recovery");
    let path = env.path.clone();
    let master = env.master_hex.clone();
    // Keep TempDir alive — dropping `env` would delete on-disk state.
    let _guard = env._dir;

    let mut stats = LatencyStats::new();
    let timer = Timer::start();
    let t0 = Instant::now();
    let rt = reopen_runtime(&path, &master).await;
    stats.record(t0.elapsed());
    let admin = rt.admin_session().await.expect("admin after unlock");
    let seq = rt.last_sequence().await;

    BenchResult::from_stats(
        ScenarioKind::RecoveryUnlock.name(),
        1,
        0,
        timer.elapsed(),
        &stats,
        0,
        Some(format!(
            "unlock+replay after {ops} writes, head={seq}, admin={admin:?}"
        )),
    )
}

async fn force_snapshot(cfg: &BenchConfig) -> BenchResult {
    let env = BenchEnv::create().await;
    let prep = cfg.effective_ops().min(200).max(20);
    let payload = cfg.payload();
    for i in 0..prep {
        env.rt
            .put_data(&env.admin, &bench_path("company/snap", i), &payload)
            .await
            .expect("prep");
    }
    let snap_count = if cfg.quick { 3 } else { 10 };
    let mut stats = LatencyStats::new();
    let timer = Timer::start();
    let mut errors = 0u64;

    for _ in 0..snap_count {
        let t0 = Instant::now();
        if env.rt.force_snapshot().await.is_err() {
            errors += 1;
        }
        stats.record(t0.elapsed());
    }

    BenchResult::from_stats(
        ScenarioKind::ForceSnapshot.name(),
        snap_count,
        errors,
        timer.elapsed(),
        &stats,
        0,
        Some(format!("after {prep} writes")),
    )
}

async fn sql_bulk_insert(cfg: &BenchConfig) -> BenchResult {
    let env = BenchEnv::create().await;
    let sql_path = env.data_path("sql.dbs.json");
    let (mut engine, _master) = SqlEngine::create(&sql_path).expect("sql create");
    engine
        .execute(
            "CREATE TABLE bench_rows (id INT PRIMARY KEY, payload TEXT);",
        )
        .expect("create table");

    let rows = cfg.effective_ops();
    let payload = "x".repeat(cfg.payload().len().min(128));
    let batch_size = if cfg.quick { 10 } else { 50 };
    let mut stats = LatencyStats::new();
    let timer = Timer::start();
    let mut errors = 0u64;
    let mut committed = 0u64;

    let mut i = 0u64;
    while i < rows {
        let end = (i + batch_size).min(rows);
        let t0 = Instant::now();
        let sql = build_insert_batch(i, end, &payload);
        let res = engine.execute(&format!("BEGIN; {sql} COMMIT;"));
        if res.is_err() {
            errors += 1;
        } else {
            committed += end - i;
        }
        stats.record(t0.elapsed());
        i = end;
    }

    BenchResult::from_stats(
        ScenarioKind::SqlBulkInsert.name(),
        committed,
        errors,
        timer.elapsed(),
        &stats,
        committed * payload.len() as u64,
        Some(format!("batch_size={batch_size}, txn per batch")),
    )
}

fn build_insert_batch(from: u64, to: u64, payload: &str) -> String {
    let mut sql = String::from("INSERT INTO bench_rows (id, payload) VALUES ");
    for i in from..to {
        if i > from {
            sql.push_str(", ");
        }
        sql.push_str(&format!("({i}, '{payload}')"));
    }
    sql.push(';');
    sql
}

async fn compaction_under_load(cfg: &BenchConfig) -> BenchResult {
    let _hooks = enable_small_segments();
    let env = BenchEnv::create().await;
    let write_ops = cfg.effective_ops();
    let payload = cfg.payload();
    let mut stats = LatencyStats::new();
    let timer = Timer::start();
    let mut errors = 0u64;
    let mut ops = 0u64;

    for i in 0..write_ops {
        let t0 = Instant::now();
        if env
            .rt
            .put_data(&env.admin, &bench_path("company/compact", i), &payload)
            .await
            .is_err()
        {
            errors += 1;
        }
        stats.record(t0.elapsed());
        ops += 1;
    }

    let compact_runs = if cfg.quick { 1 } else { 3 };
    for _ in 0..compact_runs {
        let t0 = Instant::now();
        match env.rt.compact_journal().await {
            Ok(artifact) => {
                stats.record(t0.elapsed());
                ops += 1;
                let _ = artifact;
            }
            Err(_) => errors += 1,
        }
    }

    BenchResult::from_stats(
        ScenarioKind::CompactionUnderLoad.name(),
        ops,
        errors,
        timer.elapsed(),
        &stats,
        write_ops * payload.len() as u64,
        Some(format!(
            "{write_ops} writes + {compact_runs} compaction runs, 900B segments"
        )),
    )
}

trait LastSequenceExt {
    async fn base_or_last_sequence(&self, rt: &Runtime) -> u64;
}

impl LastSequenceExt for BenchEnv {
    async fn base_or_last_sequence(&self, rt: &Runtime) -> u64 {
        rt.last_sequence().await
    }
}
