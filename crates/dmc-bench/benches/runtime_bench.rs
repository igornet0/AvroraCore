//! Criterion micro-benchmarks for hot paths in DataModelCore.

use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use dmc_bench::harness::{bench_path, BenchConfig, BenchEnv};
use tokio::runtime::Runtime as TokioRuntime;

fn tokio_rt() -> TokioRuntime {
    TokioRuntime::new().expect("tokio runtime")
}

fn bench_put_sequential(c: &mut Criterion) {
    let rt = tokio_rt();
    let mut group = c.benchmark_group("put_sequential");
    for size in [64usize, 256, 1024, 4096] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let env = rt.block_on(BenchEnv::create());
            let payload: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let mut i = 0u64;
            b.iter(|| {
                let path = bench_path("company/crit", i);
                i += 1;
                rt.block_on(env.rt.put_data(&env.admin, &path, black_box(&payload)))
                    .expect("put");
            });
        });
    }
    group.finish();
}

fn bench_get_hot(c: &mut Criterion) {
    let rt = tokio_rt();
    let env = rt.block_on(async {
        let env = BenchEnv::create().await;
        env.rt
            .put_data(&env.admin, "company/hot/key", b"payload")
            .await
            .expect("setup");
        env
    });
    c.bench_function("get_hot", |b| {
        b.iter(|| {
            rt.block_on(env.rt.get_data(&env.admin, "company/hot/key"))
                .expect("get");
        });
    });
}

fn bench_mixed_rw(c: &mut Criterion) {
    let rt = tokio_rt();
    let env = Arc::new(rt.block_on(BenchEnv::create()));
    let payload = vec![0u8; 256];
    for i in 0..100 {
        rt.block_on(env.rt.put_data(
            &env.admin,
            &bench_path("company/mix", i),
            &payload,
        ))
        .expect("prep");
    }
    let mut i = 0u64;
    c.bench_function("mixed_rw_70_30", |b| {
        b.iter(|| {
            i += 1;
            if i % 10 < 7 {
                let path = bench_path("company/mix", i % 100);
                rt.block_on(env.rt.get_data(&env.admin, &path)).expect("get");
            } else {
                rt.block_on(env.rt.put_data(
                    &env.admin,
                    &bench_path("company/mix-new", i),
                    black_box(&payload),
                ))
                .expect("put");
            }
        });
    });
}

fn bench_unlock_recovery(c: &mut Criterion) {
    let rt = tokio_rt();
    let cfg = BenchConfig {
        ops: 200,
        concurrency: 1,
        payload_bytes: 128,
        quick: true,
    };
    let (_dir, path, master) = rt.block_on(async {
        let env = BenchEnv::create().await;
        let payload = cfg.payload();
        for i in 0..cfg.effective_ops() {
            env.rt
                .put_data(&env.admin, &bench_path("company/rec", i), &payload)
                .await
                .expect("write");
        }
        env.rt.force_snapshot().await.expect("snapshot");
        (env._dir, env.path.clone(), env.master_hex.clone())
    });

    c.bench_function("unlock_replay_200", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _ in 0..iters {
                let start = Instant::now();
                let reopened = rt.block_on(async {
                    let runtime = dmc_bench::harness::reopen_runtime(&path, &master).await;
                    runtime.last_sequence().await
                });
                black_box(reopened);
                total += start.elapsed();
            }
            total
        });
    });
    drop(_dir);
}

criterion_group!(
    benches,
    bench_put_sequential,
    bench_get_hot,
    bench_mixed_rw,
    bench_unlock_recovery
);
criterion_main!(benches);
