//! Full-system stress test runner for DataModelCore (Avrora).
//!
//! ```bash
//! cargo run -p dmc-bench --bin avrora-stress -- --quick
//! cargo run -p dmc-bench --bin avrora-stress -- --ops 5000 --concurrency 8
//! ```

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Instant, SystemTime};

use clap::Parser;
use dmc_bench::metrics::print_result;
use dmc_bench::report::{
    build_report, make_report_id, write_report, ReportVerdict, StressConfigReport,
};
use dmc_bench::scenarios::{all_scenario_names, run_scenario, ScenarioKind};
use dmc_bench::BenchConfig;

#[derive(Parser, Debug)]
#[command(
    name = "avrora-stress",
    about = "Stress-test DataModelCore (Avrora) under diverse workloads"
)]
struct Args {
    /// Reduced workload for smoke/CI runs
    #[arg(long)]
    quick: bool,

    /// Operations per scenario (where applicable)
    #[arg(long, default_value_t = 1000)]
    ops: u64,

    /// Parallel tasks for concurrent scenarios
    #[arg(long, default_value_t = 4)]
    concurrency: usize,

    /// Payload size in bytes for write scenarios
    #[arg(long, default_value_t = 256)]
    payload_bytes: usize,

    /// Comma-separated scenario names, or "all"
    #[arg(long, default_value = "all")]
    scenarios: String,

    /// Directory for markdown/json reports (created if missing)
    #[arg(long, default_value = "target/stress-reports")]
    report_dir: PathBuf,

    /// Skip writing report files
    #[arg(long)]
    no_report: bool,

    /// Emit JSON report to stdout (in addition to files unless --no-report)
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    let cfg = BenchConfig {
        ops: args.ops,
        concurrency: args.concurrency,
        payload_bytes: args.payload_bytes,
        quick: args.quick,
    };

    let selected = parse_scenarios(&args.scenarios);
    if selected.is_empty() {
        eprintln!("No matching scenarios. Available:");
        for (name, _) in all_scenario_names() {
            eprintln!("  - {name}");
        }
        return ExitCode::from(1);
    }

    let scenario_names: Vec<String> = selected.iter().map(|k| k.name().to_string()).collect();
    let started_at = SystemTime::now();
    let report_id = make_report_id(started_at);

    eprintln!("Avrora stress test — DataModelCore");
    eprintln!(
        "config: ops={} concurrency={} payload={}B quick={}",
        cfg.effective_ops(),
        cfg.effective_concurrency(),
        cfg.payload().len(),
        cfg.quick
    );
    eprintln!("scenarios: {}", selected.len());
    if !args.no_report {
        eprintln!("report id: {report_id}");
    }
    eprintln!();

    let wall_start = Instant::now();
    let mut results = Vec::with_capacity(selected.len());

    for kind in &selected {
        eprintln!("▶ {}", kind.name());
        let result = run_scenario(*kind, &cfg).await;
        print_result(&result);
        eprintln!();
        results.push(result);
    }

    let finished_at = SystemTime::now();
    let document = build_report(
        &report_id,
        started_at,
        finished_at,
        StressConfigReport {
            ops: cfg.effective_ops(),
            concurrency: cfg.effective_concurrency(),
            payload_bytes: cfg.payload().len(),
            quick: cfg.quick,
            scenarios_requested: scenario_names,
        },
        results,
    );

    if args.json {
        match serde_json::to_string_pretty(&document) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("failed to serialize JSON: {e}"),
        }
    }

    eprintln!("═══════════════════════════════════════════");
    eprintln!(
        "{} {} — {} passed, {} warnings, {} failed",
        document.verdict.emoji(),
        document.verdict.label(),
        document.summary.scenarios_passed,
        document.summary.scenarios_warned,
        document.summary.scenarios_failed,
    );
    eprintln!(
        "Total wall time: {:.2}s across {} scenarios",
        wall_start.elapsed().as_secs_f64(),
        document.scenarios.len()
    );
    eprintln!();
    eprintln!("{:<24} {:>8} {:>10} {:>10} {:>10}", "Scenario", "Status", "ops/s", "p50", "p99");
    eprintln!("{:-<66}", "");
    for s in &document.scenarios {
        eprintln!(
            "{:<24} {:>8} {:>10.1} {:>9}µs {:>9}µs",
            s.name,
            s.status.label(),
            s.ops_per_sec,
            s.latency_p50_us,
            s.latency_p99_us
        );
    }

    if !args.no_report {
        eprintln!();
        match write_report(&args.report_dir, &document) {
            Ok(written) => {
                eprintln!("Report written:");
                eprintln!("  markdown: {}", written.markdown_path.display());
                eprintln!("  json:     {}", written.json_path.display());
            }
            Err(e) => {
                eprintln!("Failed to write report: {e}");
                return ExitCode::from(1);
            }
        }
    }

    match document.verdict {
        ReportVerdict::Pass => ExitCode::from(0),
        ReportVerdict::PassWithWarnings => ExitCode::from(0),
        ReportVerdict::Fail => ExitCode::from(1),
    }
}

fn parse_scenarios(raw: &str) -> Vec<ScenarioKind> {
    if raw.trim().eq_ignore_ascii_case("all") {
        return all_scenario_names()
            .iter()
            .map(|(_, k)| *k)
            .collect();
    }
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(ScenarioKind::from_name)
        .collect()
}
