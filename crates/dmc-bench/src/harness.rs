use std::path::{Path, PathBuf};

use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{RetryPolicy, SessionId, StreamId, SubscriptionId};
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};

/// Shared configuration for all stress scenarios.
#[derive(Debug, Clone)]
pub struct BenchConfig {
    pub ops: u64,
    pub concurrency: usize,
    pub payload_bytes: usize,
    pub quick: bool,
}

impl BenchConfig {
    pub fn effective_ops(&self) -> u64 {
        if self.quick {
            self.ops.min(100).max(20)
        } else {
            self.ops
        }
    }

    pub fn effective_concurrency(&self) -> usize {
        if self.quick {
            self.concurrency.min(2).max(1)
        } else {
            self.concurrency.max(1)
        }
    }

    pub fn payload(&self) -> Vec<u8> {
        let n = if self.quick {
            self.payload_bytes.min(64).max(16)
        } else {
            self.payload_bytes
        };
        (0..n).map(|i| (i % 256) as u8).collect()
    }
}

/// Isolated runtime instance in a temp directory.
pub struct BenchEnv {
    pub _dir: tempfile::TempDir,
    pub path: PathBuf,
    pub master_hex: String,
    pub rt: Runtime,
    pub admin: SessionId,
}

impl BenchEnv {
    pub async fn create() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("store.dbs.json");
        let rt = Runtime::at_path(&path);
        let (master_hex, _) = rt.create_dev(false).await.expect("create");
        let admin = rt.admin_session().await.expect("admin session");
        Self {
            _dir: dir,
            path,
            master_hex,
            rt,
            admin,
        }
    }

    pub fn data_path(&self, suffix: &str) -> PathBuf {
        self._dir.path().join(suffix)
    }
}

/// Runtime with consumer stream/subscription wired for delivery benchmarks.
pub struct ConsumerEnv {
    pub base: BenchEnv,
    pub alice: SessionId,
    pub stream: StreamId,
    pub subscription: SubscriptionId,
}

impl ConsumerEnv {
    pub async fn create() -> Self {
        let base = BenchEnv::create().await;
        let admin = base.admin.clone();
        let rt = &base.rt;

        rt.create_role(
            &admin,
            "finance".into(),
            "Finance".into(),
            KeyPath::parse("company/finance").unwrap(),
            PermissionSet::empty().with(Permission::Read),
        )
        .await
        .expect("create role");

        rt.create_user(&admin, "alice".into(), vec!["finance".into()])
            .await
            .expect("create user");

        rt.configure_channel(ChannelSpec::internal("bus"))
            .await
            .expect("configure channel");

        let stream = rt
            .create_stream(StreamSpec {
                id: StreamId::from("finance-read"),
                direction: StreamDirection::Outbound,
                channel_id: "bus".into(),
                path_scope: KeyPath::parse("company/finance").unwrap(),
                required_perms: PermissionSet::empty().with(Permission::Read),
            })
            .await
            .expect("create stream");

        let alice = rt
            .open_user_session("alice", Some("bench"))
            .await
            .expect("open alice");

        let sub = rt
            .create_subscription(&alice, &stream, Some("bench-consumer"))
            .await
            .expect("create subscription");

        rt.set_retry_policy(&alice, &sub.id, RetryPolicy::immediate())
            .await
            .expect("retry policy");

        Self {
            base,
            alice,
            stream,
            subscription: sub.id,
        }
    }
}

pub fn bench_path(prefix: &str, idx: u64) -> String {
    format!("{prefix}/item-{idx}")
}

pub fn finance_path(idx: u64) -> String {
    bench_path("company/finance", idx)
}

pub async fn reopen_runtime(path: &Path, master_hex: &str) -> Runtime {
    let rt = Runtime::at_path(path);
    rt.unlock(master_hex).await.expect("unlock");
    rt
}
