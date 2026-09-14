use std::time::{Duration, Instant};

use serde::Serialize;

/// Per-operation latency sample collector with percentile reporting.
#[derive(Debug, Clone, Default)]
pub struct LatencyStats {
    samples: Vec<Duration>,
}

impl LatencyStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, d: Duration) {
        self.samples.push(d);
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    fn percentile(&self, p: f64) -> Duration {
        if self.samples.is_empty() {
            return Duration::ZERO;
        }
        let mut sorted = self.samples.clone();
        sorted.sort();
        let idx = ((sorted.len() as f64 - 1.0) * p / 100.0).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    pub fn min(&self) -> Duration {
        self.samples.iter().copied().min().unwrap_or(Duration::ZERO)
    }

    pub fn max(&self) -> Duration {
        self.samples.iter().copied().max().unwrap_or(Duration::ZERO)
    }

    pub fn mean(&self) -> Duration {
        if self.samples.is_empty() {
            return Duration::ZERO;
        }
        let total: Duration = self.samples.iter().sum();
        total / self.samples.len() as u32
    }

    pub fn p50(&self) -> Duration {
        self.percentile(50.0)
    }

    pub fn p95(&self) -> Duration {
        self.percentile(95.0)
    }

    pub fn p99(&self) -> Duration {
        self.percentile(99.0)
    }

    pub(crate) fn samples(&self) -> &[Duration] {
        &self.samples
    }
}

/// Result of a single benchmark scenario run.
#[derive(Debug, Clone, Serialize)]
pub struct BenchResult {
    pub scenario: String,
    pub operations: u64,
    pub errors: u64,
    pub wall_time: Duration,
    pub ops_per_sec: f64,
    pub bytes_processed: u64,
    pub throughput_mib_s: f64,
    pub latency_min_us: u64,
    pub latency_mean_us: u64,
    pub latency_p50_us: u64,
    pub latency_p95_us: u64,
    pub latency_p99_us: u64,
    pub latency_max_us: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl BenchResult {
    pub fn from_stats(
        scenario: impl Into<String>,
        operations: u64,
        errors: u64,
        wall: Duration,
        stats: &LatencyStats,
        bytes_processed: u64,
        notes: Option<String>,
    ) -> Self {
        let secs = wall.as_secs_f64().max(1e-9);
        let ops_per_sec = operations as f64 / secs;
        let throughput_mib_s = (bytes_processed as f64 / (1024.0 * 1024.0)) / secs;
        Self {
            scenario: scenario.into(),
            operations,
            errors,
            wall_time: wall,
            ops_per_sec,
            bytes_processed,
            throughput_mib_s,
            latency_min_us: stats.min().as_micros() as u64,
            latency_mean_us: stats.mean().as_micros() as u64,
            latency_p50_us: stats.p50().as_micros() as u64,
            latency_p95_us: stats.p95().as_micros() as u64,
            latency_p99_us: stats.p99().as_micros() as u64,
            latency_max_us: stats.max().as_micros() as u64,
            notes,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScenarioReport {
    pub result: BenchResult,
}

#[derive(Debug, Clone, Serialize)]
pub struct StressReport {
    pub config: StressConfigSummary,
    pub scenarios: Vec<BenchResult>,
    pub total_wall_time: Duration,
}

#[derive(Debug, Clone, Serialize)]
pub struct StressConfigSummary {
    pub ops: u64,
    pub concurrency: usize,
    pub payload_bytes: usize,
    pub quick: bool,
}

/// Timer helper for measuring wall-clock duration of a block.
pub struct Timer {
    start: Instant,
}

impl Timer {
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

pub fn dur_us(d: Duration) -> u64 {
    d.as_micros() as u64
}

pub fn format_duration(d: Duration) -> String {
    if d.as_secs() >= 1 {
        format!("{:.2}s", d.as_secs_f64())
    } else if d.as_millis() >= 1 {
        format!("{:.1}ms", d.as_micros() as f64 / 1000.0)
    } else {
        format!("{}µs", d.as_micros())
    }
}

pub fn print_result(r: &BenchResult) {
    eprintln!(
        "  ops:        {} ({:.1} ops/s)",
        r.operations, r.ops_per_sec
    );
    if r.errors > 0 {
        eprintln!("  errors:     {}", r.errors);
    }
    if r.bytes_processed > 0 {
        eprintln!(
            "  throughput: {:.2} MiB/s ({} bytes total)",
            r.throughput_mib_s, r.bytes_processed
        );
    }
    eprintln!(
        "  latency:    min={} mean={} p50={} p95={} p99={} max={}",
        format_duration(Duration::from_micros(r.latency_min_us)),
        format_duration(Duration::from_micros(r.latency_mean_us)),
        format_duration(Duration::from_micros(r.latency_p50_us)),
        format_duration(Duration::from_micros(r.latency_p95_us)),
        format_duration(Duration::from_micros(r.latency_p99_us)),
        format_duration(Duration::from_micros(r.latency_max_us)),
    );
    eprintln!("  wall time:  {}", format_duration(r.wall_time));
    if let Some(notes) = &r.notes {
        eprintln!("  notes:      {notes}");
    }
}
