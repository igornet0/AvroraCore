use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::metrics::{format_duration, BenchResult};
use crate::scenarios::ScenarioKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReportVerdict {
    Pass,
    PassWithWarnings,
    Fail,
}

impl ReportVerdict {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::PassWithWarnings => "PASS WITH WARNINGS",
            Self::Fail => "FAIL",
        }
    }

    pub fn emoji(self) -> &'static str {
        match self {
            Self::Pass => "✅",
            Self::PassWithWarnings => "⚠️",
            Self::Fail => "❌",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScenarioStatus {
    Pass,
    Warning,
    Fail,
}

impl ScenarioStatus {
    fn from_errors(errors: u64, operations: u64) -> Self {
        if operations == 0 && errors > 0 {
            Self::Fail
        } else if errors > 0 {
            Self::Warning
        } else {
            Self::Pass
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warning => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScenarioResultReport {
    pub name: String,
    pub description: String,
    pub category: String,
    pub status: ScenarioStatus,
    pub operations: u64,
    pub errors: u64,
    pub ops_per_sec: f64,
    pub throughput_mib_s: f64,
    pub bytes_processed: u64,
    pub wall_time_secs: f64,
    pub latency_min_us: u64,
    pub latency_mean_us: u64,
    pub latency_p50_us: u64,
    pub latency_p95_us: u64,
    pub latency_p99_us: u64,
    pub latency_max_us: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StressConfigReport {
    pub ops: u64,
    pub concurrency: usize,
    pub payload_bytes: usize,
    pub quick: bool,
    pub scenarios_requested: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnvironmentReport {
    pub os: String,
    pub arch: String,
    pub hostname: String,
    pub git_commit: String,
    pub rust_profile: String,
    pub crate_version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StressSummary {
    pub scenarios_total: usize,
    pub scenarios_passed: usize,
    pub scenarios_warned: usize,
    pub scenarios_failed: usize,
    pub total_operations: u64,
    pub total_errors: u64,
    pub total_wall_time_secs: f64,
    pub fastest_scenario: Option<String>,
    pub slowest_scenario: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StressReportDocument {
    pub report_id: String,
    pub started_at_unix_ms: u64,
    pub finished_at_unix_ms: u64,
    pub started_at_rfc3339: String,
    pub finished_at_rfc3339: String,
    pub verdict: ReportVerdict,
    pub environment: EnvironmentReport,
    pub config: StressConfigReport,
    pub summary: StressSummary,
    pub scenarios: Vec<ScenarioResultReport>,
    pub observations: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct WrittenReport {
    pub markdown_path: PathBuf,
    pub json_path: PathBuf,
    pub document: StressReportDocument,
}

pub fn build_report(
    report_id: &str,
    started_at: SystemTime,
    finished_at: SystemTime,
    config: StressConfigReport,
    results: Vec<BenchResult>,
) -> StressReportDocument {
    let scenarios: Vec<ScenarioResultReport> = results
        .iter()
        .map(|r| scenario_from_bench(r))
        .collect();

    let summary = summarize(&scenarios, started_at, finished_at);
    let verdict = compute_verdict(&scenarios);
    let observations = analyze(&scenarios);

    StressReportDocument {
        report_id: report_id.to_string(),
        started_at_unix_ms: unix_ms(started_at),
        finished_at_unix_ms: unix_ms(finished_at),
        started_at_rfc3339: format_rfc3339(started_at),
        finished_at_rfc3339: format_rfc3339(finished_at),
        verdict,
        environment: collect_environment(),
        config,
        summary,
        scenarios,
        observations,
    }
}

pub fn write_report(
    report_dir: impl AsRef<Path>,
    document: &StressReportDocument,
) -> std::io::Result<WrittenReport> {
    let dir = report_dir.as_ref();
    fs::create_dir_all(dir)?;

    let base = dir.join(&document.report_id);
    let markdown_path = base.with_extension("md");
    let json_path = base.with_extension("json");

    fs::write(&markdown_path, render_markdown(document))?;
    fs::write(
        &json_path,
        serde_json::to_string_pretty(document).expect("serialize report"),
    )?;

    Ok(WrittenReport {
        markdown_path,
        json_path,
        document: document.clone(),
    })
}

fn scenario_from_bench(r: &BenchResult) -> ScenarioResultReport {
    let kind = ScenarioKind::from_name(&r.scenario);
    ScenarioResultReport {
        name: r.scenario.clone(),
        description: kind
            .map(scenario_description)
            .unwrap_or("Custom scenario")
            .into(),
        category: kind.map(scenario_category).unwrap_or("other").into(),
        status: ScenarioStatus::from_errors(r.errors, r.operations),
        operations: r.operations,
        errors: r.errors,
        ops_per_sec: r.ops_per_sec,
        throughput_mib_s: r.throughput_mib_s,
        bytes_processed: r.bytes_processed,
        wall_time_secs: r.wall_time.as_secs_f64(),
        latency_min_us: r.latency_min_us,
        latency_mean_us: r.latency_mean_us,
        latency_p50_us: r.latency_p50_us,
        latency_p95_us: r.latency_p95_us,
        latency_p99_us: r.latency_p99_us,
        latency_max_us: r.latency_max_us,
        notes: r.notes.clone(),
    }
}

fn compute_verdict(scenarios: &[ScenarioResultReport]) -> ReportVerdict {
    if scenarios.iter().any(|s| s.status == ScenarioStatus::Fail) {
        ReportVerdict::Fail
    } else if scenarios.iter().any(|s| s.status == ScenarioStatus::Warning) {
        ReportVerdict::PassWithWarnings
    } else {
        ReportVerdict::Pass
    }
}

fn summarize(
    scenarios: &[ScenarioResultReport],
    started_at: SystemTime,
    finished_at: SystemTime,
) -> StressSummary {
    let scenarios_passed = scenarios
        .iter()
        .filter(|s| s.status == ScenarioStatus::Pass)
        .count();
    let scenarios_warned = scenarios
        .iter()
        .filter(|s| s.status == ScenarioStatus::Warning)
        .count();
    let scenarios_failed = scenarios
        .iter()
        .filter(|s| s.status == ScenarioStatus::Fail)
        .count();

    let fastest = scenarios
        .iter()
        .max_by(|a, b| a.ops_per_sec.partial_cmp(&b.ops_per_sec).unwrap())
        .map(|s| s.name.clone());
    let slowest = scenarios
        .iter()
        .filter(|s| s.ops_per_sec.is_finite() && s.ops_per_sec > 0.0)
        .min_by(|a, b| a.ops_per_sec.partial_cmp(&b.ops_per_sec).unwrap())
        .map(|s| s.name.clone());

    StressSummary {
        scenarios_total: scenarios.len(),
        scenarios_passed,
        scenarios_warned,
        scenarios_failed,
        total_operations: scenarios.iter().map(|s| s.operations).sum(),
        total_errors: scenarios.iter().map(|s| s.errors).sum(),
        total_wall_time_secs: finished_at
            .duration_since(started_at)
            .unwrap_or(Duration::ZERO)
            .as_secs_f64(),
        fastest_scenario: fastest,
        slowest_scenario: slowest,
    }
}

fn analyze(scenarios: &[ScenarioResultReport]) -> Vec<String> {
    let mut notes = Vec::new();

    let write = find(scenarios, "write_sequential");
    let read = find(scenarios, "read_hot");
    if let (Some(w), Some(r)) = (write, read) {
        if w.ops_per_sec > 0.0 && r.ops_per_sec / w.ops_per_sec > 100.0 {
            notes.push(format!(
                "Read path ({:.0} ops/s) is {:.0}x faster than durable write ({:.0} ops/s); \
                 writes are journal+fsync bound.",
                r.ops_per_sec,
                r.ops_per_sec / w.ops_per_sec,
                w.ops_per_sec
            ));
        }
    }

    if let (Some(seq), Some(par)) = (write, find(scenarios, "write_parallel")) {
        if seq.ops_per_sec > 0.0 {
            let ratio = par.ops_per_sec / seq.ops_per_sec;
            if ratio < 1.2 {
                notes.push(format!(
                    "Parallel writes ({:.0} ops/s) did not exceed sequential ({:.0} ops/s); \
                     Runtime Mutex serializes mutations.",
                    par.ops_per_sec, seq.ops_per_sec
                ));
            }
        }
    }

    if let Some(c) = find(scenarios, "consumer_pipeline") {
        if let Some(w) = write {
            if w.ops_per_sec > 0.0 && c.ops_per_sec < w.ops_per_sec * 0.5 {
                notes.push(format!(
                    "Consumer pipeline ({:.0} ops/s) is slower than raw writes ({:.0} ops/s) \
                     due to put + merge consume + ack per event.",
                    c.ops_per_sec, w.ops_per_sec
                ));
            }
        }
    }

    if let Some(p) = find(scenarios, "partitioned") {
        if let Some(w) = write {
            if w.ops_per_sec > 0.0 && p.ops_per_sec < w.ops_per_sec * 0.7 {
                notes.push(format!(
                    "Partitioned journal with small segments ({:.0} ops/s) is slower than \
                     default layout ({:.0} ops/s) because of segment rotation churn.",
                    p.ops_per_sec, w.ops_per_sec
                ));
            }
        }
    }

    if let Some(idem) = find(scenarios, "idempotent") {
        if let Some(w) = write {
            if w.ops_per_sec > 0.0 && idem.ops_per_sec > w.ops_per_sec * 5.0 {
                notes.push(format!(
                    "Idempotent dedup ({:.0} ops/s) is much faster than first-time writes \
                     ({:.0} ops/s) because replays skip journal append.",
                    idem.ops_per_sec, w.ops_per_sec
                ));
            }
        }
    }

    let total_errors: u64 = scenarios.iter().map(|s| s.errors).sum();
    if total_errors > 0 {
        let failed: Vec<_> = scenarios
            .iter()
            .filter(|s| s.errors > 0)
            .map(|s| format!("{} ({} errors)", s.name, s.errors))
            .collect();
        notes.push(format!(
            "Scenarios with errors: {}. Review notes and logs for those runs.",
            failed.join(", ")
        ));
    }

    if notes.is_empty() {
        notes.push(
            "All scenarios completed without anomalies detected by automatic analysis.".into(),
        );
    }

    notes
}

fn find<'a>(scenarios: &'a [ScenarioResultReport], name: &str) -> Option<&'a ScenarioResultReport> {
    scenarios.iter().find(|s| s.name == name)
}

pub fn scenario_description(kind: ScenarioKind) -> &'static str {
    match kind {
        ScenarioKind::WriteSequential => {
            "Sequential durable puts through Runtime API (journal append + fsync per operation)."
        }
        ScenarioKind::WriteParallel => {
            "Concurrent puts from multiple tokio tasks; measures Mutex contention on Runtime."
        }
        ScenarioKind::ReadHot => "Repeated reads of a single hot key from in-memory overlay.",
        ScenarioKind::ReadScattered => {
            "Reads spread across many distinct keys to measure scattered lookup cost."
        }
        ScenarioKind::MixedReadWrite => "Mixed workload: 70% reads / 30% writes.",
        ScenarioKind::CrudCycle => {
            "Full CRUD cycle per key: create, read, update, delete (tombstone)."
        }
        ScenarioKind::DeleteTombstone => {
            "Delete operations on pre-populated keys (overlay tombstones + journal)."
        }
        ScenarioKind::ListKeys => "Prefix scan via list_keys over a populated key space.",
        ScenarioKind::ConsumerPipeline => {
            "End-to-end delivery: put event, consume from subscription, ack delivery."
        }
        ScenarioKind::IdempotentProducer => {
            "Repeated puts with the same idempotency key to measure dedup fast path."
        }
        ScenarioKind::PartitionedJournal => {
            "Writes with 8 journal partitions and 900-byte segment rotation threshold."
        }
        ScenarioKind::RecoveryUnlock => {
            "Drop runtime, reopen, unlock and replay journal after snapshot + writes."
        }
        ScenarioKind::ForceSnapshot => {
            "Materialized snapshot publish after a pre-populated overlay state."
        }
        ScenarioKind::SqlBulkInsert => {
            "SQL bulk INSERT batches inside BEGIN/COMMIT transactions (dmc-sql path)."
        }
        ScenarioKind::CompactionUnderLoad => {
            "Sustained writes with small segments followed by journal compaction."
        }
    }
}

fn scenario_category(kind: ScenarioKind) -> &'static str {
    match kind {
        ScenarioKind::WriteSequential | ScenarioKind::WriteParallel => "write",
        ScenarioKind::ReadHot | ScenarioKind::ReadScattered | ScenarioKind::ListKeys => "read",
        ScenarioKind::MixedReadWrite | ScenarioKind::CrudCycle => "mixed",
        ScenarioKind::DeleteTombstone => "delete",
        ScenarioKind::ConsumerPipeline => "consumer",
        ScenarioKind::IdempotentProducer => "idempotency",
        ScenarioKind::PartitionedJournal | ScenarioKind::CompactionUnderLoad => "journal",
        ScenarioKind::RecoveryUnlock | ScenarioKind::ForceSnapshot => "lifecycle",
        ScenarioKind::SqlBulkInsert => "sql",
    }
}

fn collect_environment() -> EnvironmentReport {
    EnvironmentReport {
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        hostname: hostname(),
        git_commit: git_commit(),
        rust_profile: if cfg!(debug_assertions) {
            "debug".into()
        } else {
            "release".into()
        },
        crate_version: env!("CARGO_PKG_VERSION").into(),
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".into())
}

fn git_commit() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn unix_ms(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

fn format_rfc3339(t: SystemTime) -> String {
    use chrono::{DateTime, Utc};
    let ms = unix_ms(t) as i64;
    DateTime::<Utc>::from_timestamp_millis(ms)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| ms.to_string())
}

pub fn make_report_id(started_at: SystemTime) -> String {
    let ms = unix_ms(started_at);
    format!("stress-{ms}")
}

pub fn render_markdown(doc: &StressReportDocument) -> String {
    let mut out = String::new();

    out.push_str("# Avrora Stress Test Report\n\n");
    out.push_str(&format!(
        "**Verdict:** {} {}\n\n",
        doc.verdict.emoji(),
        doc.verdict.label()
    ));
    out.push_str(&format!("**Report ID:** `{}`\n\n", doc.report_id));
    out.push_str(&format!(
        "**Started:** {} (`{}`)\n\n",
        doc.started_at_rfc3339, doc.started_at_unix_ms
    ));
    out.push_str(&format!(
        "**Finished:** {} (`{}`)\n\n",
        doc.finished_at_rfc3339, doc.finished_at_unix_ms
    ));
    out.push_str(&format!(
        "**Duration:** {:.2}s\n\n",
        doc.summary.total_wall_time_secs
    ));

    out.push_str("## Executive Summary\n\n");
    out.push_str(&format!(
        "- Scenarios run: **{}** ({} passed, {} warnings, {} failed)\n",
        doc.summary.scenarios_total,
        doc.summary.scenarios_passed,
        doc.summary.scenarios_warned,
        doc.summary.scenarios_failed
    ));
    out.push_str(&format!(
        "- Total operations: **{}**\n",
        doc.summary.total_operations
    ));
    out.push_str(&format!("- Total errors: **{}**\n", doc.summary.total_errors));
    if let Some(f) = &doc.summary.fastest_scenario {
        out.push_str(&format!("- Fastest scenario: **{f}**\n"));
    }
    if let Some(s) = &doc.summary.slowest_scenario {
        out.push_str(&format!("- Slowest scenario: **{s}**\n"));
    }
    out.push('\n');

    out.push_str("## Environment\n\n");
    out.push_str("| Parameter | Value |\n");
    out.push_str("|-----------|-------|\n");
    out.push_str(&format!("| OS | {} |\n", doc.environment.os));
    out.push_str(&format!("| Arch | {} |\n", doc.environment.arch));
    out.push_str(&format!("| Host | {} |\n", doc.environment.hostname));
    out.push_str(&format!("| Git commit | `{}` |\n", doc.environment.git_commit));
    out.push_str(&format!("| Build profile | {} |\n", doc.environment.rust_profile));
    out.push_str(&format!("| dmc-bench version | {} |\n\n", doc.environment.crate_version));

    out.push_str("## Configuration\n\n");
    out.push_str("| Parameter | Value |\n");
    out.push_str("|-----------|-------|\n");
    out.push_str(&format!("| ops | {} |\n", doc.config.ops));
    out.push_str(&format!("| concurrency | {} |\n", doc.config.concurrency));
    out.push_str(&format!("| payload_bytes | {} |\n", doc.config.payload_bytes));
    out.push_str(&format!("| quick mode | {} |\n", doc.config.quick));
    out.push_str(&format!(
        "| scenarios | {} |\n\n",
        doc.config.scenarios_requested.join(", ")
    ));

    out.push_str("## Results Overview\n\n");
    out.push_str("| Scenario | Status | ops/s | p50 | p99 | errors |\n");
    out.push_str("|----------|--------|------:|----:|----:|-------:|\n");
    for s in &doc.scenarios {
        out.push_str(&format!(
            "| {} | {} | {:.1} | {} | {} | {} |\n",
            s.name,
            s.status.label(),
            s.ops_per_sec,
            format_duration(Duration::from_micros(s.latency_p50_us)),
            format_duration(Duration::from_micros(s.latency_p99_us)),
            s.errors
        ));
    }
    out.push('\n');

    out.push_str("## Scenario Details\n\n");
    for s in &doc.scenarios {
        out.push_str(&format!("### `{}` — {}\n\n", s.name, s.status.label()));
        out.push_str(&format!("{}\n\n", s.description));
        out.push_str(&format!("- **Category:** {}\n", s.category));
        out.push_str(&format!("- **Operations:** {}\n", s.operations));
        out.push_str(&format!("- **Errors:** {}\n", s.errors));
        out.push_str(&format!("- **Throughput:** {:.1} ops/s", s.ops_per_sec));
        if s.bytes_processed > 0 {
            out.push_str(&format!(" ({:.2} MiB/s)", s.throughput_mib_s));
        }
        out.push('\n');
        out.push_str(&format!(
            "- **Wall time:** {:.2}s\n",
            s.wall_time_secs
        ));
        out.push_str(&format!(
            "- **Latency:** min={} mean={} p50={} p95={} p99={} max={}\n",
            format_duration(Duration::from_micros(s.latency_min_us)),
            format_duration(Duration::from_micros(s.latency_mean_us)),
            format_duration(Duration::from_micros(s.latency_p50_us)),
            format_duration(Duration::from_micros(s.latency_p95_us)),
            format_duration(Duration::from_micros(s.latency_p99_us)),
            format_duration(Duration::from_micros(s.latency_max_us)),
        ));
        if let Some(notes) = &s.notes {
            out.push_str(&format!("- **Notes:** {notes}\n"));
        }
        out.push('\n');
    }

    out.push_str("## Analysis\n\n");
    for (i, note) in doc.observations.iter().enumerate() {
        out.push_str(&format!("{}. {note}\n", i + 1));
    }
    out.push('\n');

    out.push_str("## Artifacts\n\n");
    out.push_str(&format!("- Markdown: `{}`.md\n", doc.report_id));
    out.push_str(&format!("- JSON: `{}`.json\n", doc.report_id));

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::{BenchResult, LatencyStats};

    #[test]
    fn report_marks_warnings_on_errors() {
        let started = SystemTime::now();
        let stats = LatencyStats::new();
        let result = BenchResult::from_stats(
            "compaction",
            100,
            1,
            Duration::from_secs(2),
            &stats,
            6400,
            Some("test".into()),
        );
        let doc = build_report(
            "stress-test",
            started,
            started + Duration::from_secs(2),
            StressConfigReport {
                ops: 100,
                concurrency: 2,
                payload_bytes: 64,
                quick: true,
                scenarios_requested: vec!["compaction".into()],
            },
            vec![result],
        );
        assert_eq!(doc.verdict, ReportVerdict::PassWithWarnings);
        assert_eq!(doc.summary.scenarios_warned, 1);
    }

    #[test]
    fn markdown_contains_verdict_and_table() {
        let started = SystemTime::now();
        let stats = LatencyStats::new();
        let result = BenchResult::from_stats(
            "write_sequential",
            10,
            0,
            Duration::from_millis(100),
            &stats,
            640,
            None,
        );
        let doc = build_report(
            "stress-1",
            started,
            started + Duration::from_millis(100),
            StressConfigReport {
                ops: 10,
                concurrency: 1,
                payload_bytes: 64,
                quick: true,
                scenarios_requested: vec!["write_sequential".into()],
            },
            vec![result],
        );
        let md = render_markdown(&doc);
        assert!(md.contains("# Avrora Stress Test Report"));
        assert!(md.contains("write_sequential"));
        assert!(md.contains("Results Overview"));
    }
}
