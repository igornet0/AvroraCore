use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{CompactionPolicy, RetryPolicy, StreamId};
use dmc_journal::set_test_segment_max_bytes;
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};

struct SmallJournalSegments;

impl SmallJournalSegments {
    fn enable() -> Self {
        set_test_segment_max_bytes(Some(900));
        Self
    }
}

impl Drop for SmallJournalSegments {
    fn drop(&mut self) {
        set_test_segment_max_bytes(None);
    }
}

async fn setup_finance_read(rt: &Runtime) -> (dmc_core::SessionId, dmc_core::SessionId, StreamId) {
    let admin = rt.admin_session().await.unwrap();
    rt.create_role(
        &admin,
        "finance".into(),
        "Finance".into(),
        KeyPath::parse("company/finance").unwrap(),
        PermissionSet::empty().with(Permission::Read),
    )
    .await
    .unwrap();
    rt.create_user(&admin, "alice".into(), vec!["finance".into()])
        .await
        .unwrap();
    rt.configure_channel(ChannelSpec::internal("bus"))
        .await
        .unwrap();
    let stream = rt
        .create_stream(StreamSpec {
            id: StreamId::from("finance-read"),
            direction: StreamDirection::Outbound,
            channel_id: "bus".into(),
            path_scope: KeyPath::parse("company/finance").unwrap(),
            required_perms: PermissionSet::empty().with(Permission::Read),
        })
        .await
        .unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    (admin, alice, stream)
}

async fn put_n(rt: &Runtime, admin: &dmc_core::SessionId, n: u64) {
    for i in 0..n {
        rt.put_data(
            admin,
            &format!("company/finance/item/{i}"),
            vec![0u8; 200].as_slice(),
        )
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn compaction_candidate_independent_of_retention_pins() {
    let _seg = SmallJournalSegments::enable();
    let rt = Runtime::at_path(tempfile::tempdir().unwrap().path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    put_n(&rt, &admin, 25).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, RetryPolicy::immediate())
        .await
        .unwrap();
    for _ in 0..3 {
        let batch = rt.consume(&sub.id, 1).await.unwrap();
        rt.ack(&alice, &sub.id, &batch[0].delivery.delivery_id)
            .await
            .unwrap();
    }
    rt.force_snapshot().await.unwrap();
    rt.set_retention_policy(
        &admin,
        dmc_core::RetentionPolicy {
            max_age_ms: Some(1),
            max_bytes: Some(1),
        },
    )
    .await
    .unwrap();
    let wm = rt.retention_watermark().await.unwrap().trim_through.unwrap();
    rt.set_compaction_policy(
        &admin,
        CompactionPolicy {
            enabled: true,
            min_segments: 2,
            min_total_bytes: 0,
            max_input_bytes: 10 * 1024 * 1024,
        },
    )
    .await
    .unwrap();
    let candidate = rt.select_compaction_candidate().await.unwrap();
    assert!(candidate.is_some());
    let c = candidate.unwrap();
    assert!(c.end_sequence <= wm || c.start_sequence < wm);
}

#[tokio::test]
async fn compact_journal_builds_orphan_artifact() {
    let _seg = SmallJournalSegments::enable();
    let rt = Runtime::at_path(tempfile::tempdir().unwrap().path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, _alice, _stream) = setup_finance_read(&rt).await;
    put_n(&rt, &admin, 25).await;
    rt.set_compaction_policy(
        &admin,
        CompactionPolicy {
            enabled: true,
            min_segments: 2,
            min_total_bytes: 0,
            max_input_bytes: 10 * 1024 * 1024,
        },
    )
    .await
    .unwrap();
    let artifact = rt.compact_journal().await.unwrap();
    assert!(artifact.path.is_file());
    assert!(artifact.record_count > 0);
    assert!(artifact.end_sequence >= artifact.start_sequence);
}

#[tokio::test]
async fn compaction_policy_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (master, _) = rt.create_dev(false).await.unwrap();
    let (admin, _alice, _stream) = setup_finance_read(&rt).await;
    let policy = CompactionPolicy {
        enabled: true,
        min_segments: 3,
        min_total_bytes: 1024,
        max_input_bytes: 50_000_000,
    };
    rt.set_compaction_policy(&admin, policy.clone()).await.unwrap();
    rt.lock().await.unwrap();
    let rt2 = Runtime::at_path(dir.path().join("store.dbs.json"));
    rt2.unlock(&master).await.unwrap();
    assert_eq!(rt2.compaction_policy().await.unwrap(), policy);
}

#[tokio::test]
async fn set_compaction_policy_is_audited() {
    let rt = Runtime::at_path(tempfile::tempdir().unwrap().path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, _alice, _stream) = setup_finance_read(&rt).await;
    rt.set_compaction_policy(
        &admin,
        CompactionPolicy {
            enabled: true,
            min_segments: 2,
            min_total_bytes: 0,
            max_input_bytes: 1_000_000,
        },
    )
    .await
    .unwrap();
    assert!(
        rt.audit_log()
            .await
            .iter()
            .any(|r| r.op == "COMPACTION_POLICY_SET")
    );
}

#[tokio::test]
async fn disabled_policy_yields_no_candidate() {
    let _seg = SmallJournalSegments::enable();
    let rt = Runtime::at_path(tempfile::tempdir().unwrap().path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, _alice, _stream) = setup_finance_read(&rt).await;
    put_n(&rt, &admin, 25).await;
    assert!(rt.select_compaction_candidate().await.unwrap().is_none());
    rt.set_compaction_policy(
        &admin,
        CompactionPolicy {
            enabled: true,
            min_segments: 2,
            min_total_bytes: 0,
            max_input_bytes: 10 * 1024 * 1024,
        },
    )
    .await
    .unwrap();
    assert!(rt.select_compaction_candidate().await.unwrap().is_some());
}
