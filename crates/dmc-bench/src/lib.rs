//! Benchmark harness and stress-test scenarios for DataModelCore (Avrora).

pub mod harness;
pub mod metrics;
pub mod report;
pub mod scenarios;

pub use harness::{BenchConfig, BenchEnv, ConsumerEnv};
pub use metrics::{BenchResult, LatencyStats, ScenarioReport, StressReport};
pub use report::{
    build_report, make_report_id, render_markdown, ReportVerdict, StressReportDocument,
    WrittenReport,
};
pub use scenarios::{all_scenario_names, run_scenario, ScenarioKind};
