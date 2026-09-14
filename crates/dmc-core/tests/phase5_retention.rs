use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{RetentionPolicy, RetryPolicy, StreamId};
use dmc_journal::{SegmentState, set_test_segment_max_bytes, set_test_timestamp_ms};
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};

const DAY_MS: u64 = 86_400_000;
const BASE_NOW: u64 = 1_900_000_000_000;
const SETUP_TS: u64 = BASE_NOW - 30 * DAY_MS;

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
    set_test_timestamp_ms(Some(SETUP_TS));
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
    set_test_timestamp_ms(None);
    (admin, alice, stream)
}

async fn put_at(
    rt: &Runtime,
    admin: &dmc_core::SessionId,
    path: &str,
    timestamp_ms: u64,
) -> u64 {
    set_test_timestamp_ms(Some(timestamp_ms));
    let r = rt
        .put_data_with(admin, path, b"x", None)
        .await
        .unwrap();
    set_test_timestamp_ms(None);
    r.sequence
}

#[tokio::test]
async fn ttl_pins_last_sequence_before_cutoff() {
    let rt = Runtime::at_path(tempfile::tempdir().unwrap().path().join("store.dbs.json"));
    set_test_timestamp_ms(Some(SETUP_TS));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, _alice, _stream) = setup_finance_read(&rt).await;
    rt.set_now_ms(Some(BASE_NOW)).await;
    let _s1 = put_at(&rt, &admin, "company/finance/a", BASE_NOW - 10 * DAY_MS).await;
    let s2 = put_at(&rt, &admin, "company/finance/b", BASE_NOW - 8 * DAY_MS).await;
    let _s3 = put_at(&rt, &admin, "company/finance/c", BASE_NOW - 3 * DAY_MS).await;
    rt.set_retention_policy(
        &admin,
        RetentionPolicy {
            max_age_ms: Some(7 * DAY_MS),
            max_bytes: None,
        },
    )
    .await
    .unwrap();
    let pin = rt.retention_policy_trim_through().await.unwrap();
    assert_eq!(pin, Some(s2));
}

#[tokio::test]
async fn future_events_not_under_retention_pin() {
    let rt = Runtime::at_path(tempfile::tempdir().unwrap().path().join("store.dbs.json"));
    set_test_timestamp_ms(Some(SETUP_TS));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, _alice, _stream) = setup_finance_read(&rt).await;
    rt.set_now_ms(Some(BASE_NOW)).await;
    put_at(&rt, &admin, "company/finance/old", BASE_NOW - 30 * DAY_MS).await;
    let current = put_at(&rt, &admin, "company/finance/now", BASE_NOW).await;
    rt.set_retention_policy(
        &admin,
        RetentionPolicy {
            max_age_ms: Some(7 * DAY_MS),
            max_bytes: None,
        },
    )
    .await
    .unwrap();
    let pin = rt.retention_policy_trim_through().await.unwrap();
    assert!(pin.unwrap() < current);
}

#[tokio::test]
async fn max_bytes_respects_whole_segments() {
    let _seg = SmallJournalSegments::enable();
    let rt = Runtime::at_path(tempfile::tempdir().unwrap().path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, _alice, _stream) = setup_finance_read(&rt).await;
    for i in 0..25 {
        rt.put_data(
            &admin,
            &format!("company/finance/item/{i}"),
            vec![0u8; 200].as_slice(),
        )
        .await
        .unwrap();
    }
    let infos = rt.journal_segment_infos().await.unwrap();
    let sealed: Vec<_> = infos
        .iter()
        .filter(|s| s.byte_size > 0 && matches!(s.state, SegmentState::Sealed))
        .collect();
    assert!(
        sealed.len() >= 2,
        "expected multiple sealed segments, got {sealed:?}"
    );
    let total: u64 = sealed.iter().map(|s| s.byte_size).sum();
    let max_bytes = total.saturating_sub(sealed[0].byte_size);
    assert!(total > max_bytes);
    rt.set_retention_policy(
        &admin,
        RetentionPolicy {
            max_age_ms: None,
            max_bytes: Some(max_bytes),
        },
    )
    .await
    .unwrap();
    let pin = rt.retention_policy_trim_through().await.unwrap();
    assert_eq!(pin, Some(sealed[0].end_sequence));
}

#[tokio::test]
async fn combined_policy_takes_minimum() {
    let rt = Runtime::at_path(tempfile::tempdir().unwrap().path().join("store.dbs.json"));
    set_test_timestamp_ms(Some(SETUP_TS));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, _alice, _stream) = setup_finance_read(&rt).await;
    rt.set_now_ms(Some(BASE_NOW)).await;
    let mut last_old_seq = 0;
    for i in 0..10 {
        let ts = if i < 5 {
            BASE_NOW - 30 * DAY_MS
        } else {
            BASE_NOW
        };
        let seq = put_at(
            &rt,
            &admin,
            &format!("company/finance/item/{i}"),
            ts,
        )
        .await;
        if i == 4 {
            last_old_seq = seq;
        }
    }
    rt.set_retention_policy(
        &admin,
        RetentionPolicy {
            max_age_ms: Some(7 * DAY_MS),
            max_bytes: Some(1),
        },
    )
    .await
    .unwrap();
    let pin = rt.retention_policy_trim_through().await.unwrap().unwrap();
    assert_eq!(pin, last_old_seq);
}

#[tokio::test]
async fn consumer_pin_limits_retention() {
    let rt = Runtime::at_path(tempfile::tempdir().unwrap().path().join("store.dbs.json"));
    set_test_timestamp_ms(Some(SETUP_TS));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    rt.set_now_ms(Some(BASE_NOW)).await;
    for i in 0..10 {
        put_at(
            &rt,
            &admin,
            &format!("company/finance/item/{i}"),
            BASE_NOW - 30 * DAY_MS,
        )
        .await;
    }
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, RetryPolicy::immediate())
        .await
        .unwrap();
    let mut acked_seq = 0;
    for _ in 0..5 {
        let batch = rt.consume(&sub.id, 1).await.unwrap();
        rt.ack(&alice, &sub.id, &batch[0].delivery.delivery_id)
            .await
            .unwrap();
        acked_seq = batch[0].sequence;
    }
    rt.force_snapshot().await.unwrap();
    rt.set_retention_policy(
        &admin,
        RetentionPolicy {
            max_age_ms: Some(DAY_MS),
            max_bytes: None,
        },
    )
    .await
    .unwrap();
    let retention = rt.retention_policy_trim_through().await.unwrap().unwrap();
    assert!(retention >= acked_seq);
    let wm = rt.retention_watermark().await.unwrap();
    assert_eq!(wm.trim_through, Some(acked_seq));
}

#[tokio::test]
async fn replay_pin_limits_retention() {
    let rt = Runtime::at_path(tempfile::tempdir().unwrap().path().join("store.dbs.json"));
    set_test_timestamp_ms(Some(SETUP_TS));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    rt.set_now_ms(Some(BASE_NOW)).await;
    for i in 0..10 {
        put_at(
            &rt,
            &admin,
            &format!("company/finance/item/{i}"),
            BASE_NOW - 30 * DAY_MS,
        )
        .await;
    }
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.force_snapshot().await.unwrap();
    rt.set_retention_policy(
        &admin,
        RetentionPolicy {
            max_age_ms: Some(DAY_MS),
            max_bytes: None,
        },
    )
    .await
    .unwrap();
    for _ in 0..7 {
        let batch = rt.consume(&sub.id, 1).await.unwrap();
        rt.ack(&alice, &sub.id, &batch[0].delivery.delivery_id)
            .await
            .unwrap();
    }
    let _lease = rt.begin_replay_lease(&sub.id, 8, 60_000).await.unwrap();
    let wm = rt.retention_watermark().await.unwrap();
    assert_eq!(wm.trim_through, Some(7));
}

#[tokio::test]
async fn snapshot_pin_limits_retention() {
    let rt = Runtime::at_path(tempfile::tempdir().unwrap().path().join("store.dbs.json"));
    set_test_timestamp_ms(Some(SETUP_TS));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, _alice, _stream) = setup_finance_read(&rt).await;
    rt.set_now_ms(Some(BASE_NOW)).await;
    for i in 0..10 {
        put_at(
            &rt,
            &admin,
            &format!("company/finance/item/{i}"),
            BASE_NOW - 30 * DAY_MS,
        )
        .await;
    }
    let snap = rt.force_snapshot().await.unwrap();
    rt.set_retention_policy(
        &admin,
        RetentionPolicy {
            max_age_ms: Some(DAY_MS),
            max_bytes: None,
        },
    )
    .await
    .unwrap();
    let wm = rt.retention_watermark().await.unwrap();
    assert_eq!(wm.trim_through, Some(snap));
}

#[tokio::test]
async fn policy_removal_unlimits_retention() {
    let rt = Runtime::at_path(tempfile::tempdir().unwrap().path().join("store.dbs.json"));
    set_test_timestamp_ms(Some(SETUP_TS));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, _alice, _stream) = setup_finance_read(&rt).await;
    rt.set_now_ms(Some(BASE_NOW)).await;
    put_at(&rt, &admin, "company/finance/a", BASE_NOW - 30 * DAY_MS).await;
    rt.set_retention_policy(
        &admin,
        RetentionPolicy {
            max_age_ms: Some(DAY_MS),
            max_bytes: None,
        },
    )
    .await
    .unwrap();
    assert!(rt.retention_policy_trim_through().await.unwrap().is_some());
    rt.set_retention_policy(
        &admin,
        RetentionPolicy {
            max_age_ms: None,
            max_bytes: None,
        },
    )
    .await
    .unwrap();
    assert!(rt.retention_policy().await.unwrap().is_unbounded());
    assert!(rt.retention_policy_trim_through().await.unwrap().is_none());
}

#[tokio::test]
async fn policy_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (master, _) = rt.create_dev(false).await.unwrap();
    let (admin, _alice, _stream) = setup_finance_read(&rt).await;
    let policy = RetentionPolicy {
        max_age_ms: Some(7 * DAY_MS),
        max_bytes: Some(1_000_000),
    };
    rt.set_retention_policy(&admin, policy.clone()).await.unwrap();
    rt.lock().await.unwrap();
    let rt2 = Runtime::at_path(dir.path().join("store.dbs.json"));
    rt2.unlock(&master).await.unwrap();
    assert_eq!(rt2.retention_policy().await.unwrap(), policy);
}

#[tokio::test]
async fn set_retention_policy_is_audited() {
    let rt = Runtime::at_path(tempfile::tempdir().unwrap().path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, _alice, _stream) = setup_finance_read(&rt).await;
    rt.set_retention_policy(
        &admin,
        RetentionPolicy {
            max_age_ms: Some(DAY_MS),
            max_bytes: None,
        },
    )
    .await
    .unwrap();
    assert!(
        rt.audit_log()
            .await
            .iter()
            .any(|r| r.op == "RETENTION_POLICY_SET")
    );
}

#[tokio::test]
async fn retention_flows_to_trim_via_existing_gc() {
    let _seg = SmallJournalSegments::enable();
    let rt = Runtime::at_path(tempfile::tempdir().unwrap().path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, _alice, _stream) = setup_finance_read(&rt).await;
    rt.set_now_ms(Some(BASE_NOW)).await;
    for i in 0..25 {
        put_at(
            &rt,
            &admin,
            &format!("company/finance/item/{i}"),
            BASE_NOW - 30 * DAY_MS,
        )
        .await;
    }
    rt.force_snapshot().await.unwrap();
    let infos = rt.journal_segment_infos().await.unwrap();
    let sealed_before = infos
        .iter()
        .filter(|s| matches!(s.state, SegmentState::Sealed))
        .count();
    assert!(sealed_before >= 2);
    let total: u64 = infos
        .iter()
        .filter(|s| matches!(s.state, SegmentState::Sealed))
        .map(|s| s.byte_size)
        .sum();
    rt.set_retention_policy(
        &admin,
        RetentionPolicy {
            max_age_ms: None,
            max_bytes: Some(total / 2),
        },
    )
    .await
    .unwrap();
    let result = rt.trim_journal().await.unwrap();
    assert!(!result.deleted_segments.is_empty());
}
