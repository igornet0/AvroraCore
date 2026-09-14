use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{RetryPolicy, SessionId, StreamId, DLQ_PREFIX};
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};

async fn setup_finance_read(rt: &Runtime) -> (SessionId, SessionId, StreamId) {
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

fn tight() -> RetryPolicy {
    RetryPolicy {
        max_attempts: 2,
        initial_backoff_ms: 0,
        max_backoff_ms: 0,
        multiplier: 2,
    }
}

#[tokio::test]
async fn exhausted_attempts_write_dlq_and_drop_pending() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, tight()).await.unwrap();
    rt.put_data(&admin, "company/finance/a", b"1").await.unwrap();
    rt.put_data(&admin, "company/finance/b", b"2").await.unwrap();

    let d1 = rt.consume(&sub.id, 1).await.unwrap();
    let d2 = rt.consume(&sub.id, 1).await.unwrap();
    assert_eq!(d2[0].sequence, d1[0].sequence);
    assert_eq!(d2[0].delivery.attempt, 2);
    let next = rt.consume(&sub.id, 1).await.unwrap();
    assert_eq!(next[0].payload, b"2");
    assert_ne!(next[0].sequence, d1[0].sequence);
    assert!(rt.pending_delivery(&sub.id).await.unwrap().unwrap().sequence != d1[0].sequence);

    let entries = rt.list_dlq(&admin, &sub.id).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].original_event_id, d1[0].event_id);
    assert_eq!(entries[0].original_sequence, d1[0].sequence);
    assert_eq!(entries[0].attempts, 2);
    assert_eq!(entries[0].last_delivery_id, d2[0].delivery.delivery_id);
    assert_eq!(entries[0].payload, b"1");
    assert!(entries[0].original_path.contains("company/finance"));
    assert_eq!(rt.get_subscription(&sub.id).await.unwrap().position.sequence, 0);
}

#[tokio::test]
async fn dlq_restart_does_not_duplicate_and_skips_dead_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, sub_id, original_seq) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (admin, alice, stream) = setup_finance_read(&rt).await;
        let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
        rt.set_retry_policy(&alice, &sub.id, tight()).await.unwrap();
        rt.put_data(&admin, "company/finance/a", b"1").await.unwrap();
        rt.put_data(&admin, "company/finance/b", b"2").await.unwrap();
        let d1 = rt.consume(&sub.id, 1).await.unwrap();
        let _ = rt.consume(&sub.id, 1).await.unwrap();
        let next = rt.consume(&sub.id, 1).await.unwrap();
        assert_eq!(next[0].payload, b"2");
        assert_eq!(rt.list_dlq(&admin, &sub.id).await.unwrap().len(), 1);
        (master, sub.id, d1[0].sequence)
    };

    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    assert_eq!(rt.list_dlq(&admin, &sub_id).await.unwrap().len(), 1);
    assert!(rt.pending_delivery(&sub_id).await.unwrap().is_some());
    let again = rt.consume(&sub_id, 1).await.unwrap();
    assert_ne!(again[0].sequence, original_seq);
    assert_eq!(rt.list_dlq(&admin, &sub_id).await.unwrap().len(), 1);
}

#[tokio::test]
async fn crash_before_dlq_keeps_pending() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, sub_id) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (admin, alice, stream) = setup_finance_read(&rt).await;
        let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
        rt.set_retry_policy(&alice, &sub.id, tight()).await.unwrap();
        rt.put_data(&admin, "company/finance/a", b"1").await.unwrap();
        let _ = rt.consume(&sub.id, 1).await.unwrap();
        let _ = rt.consume(&sub.id, 1).await.unwrap();
        assert_eq!(rt.pending_delivery(&sub.id).await.unwrap().unwrap().attempt, 2);
        (master, sub.id)
    };

    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    assert!(rt.list_dlq(&admin, &sub_id).await.unwrap().is_empty());
    let pending = rt.pending_delivery(&sub_id).await.unwrap().unwrap();
    assert_eq!(pending.attempt, 2);
    let _ = rt.consume(&sub_id, 1).await.unwrap();
    assert_eq!(rt.list_dlq(&admin, &sub_id).await.unwrap().len(), 1);
    assert!(rt.pending_delivery(&sub_id).await.unwrap().is_none());
}

#[tokio::test]
async fn dlq_is_separate_encrypted_path_with_independent_acl() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, tight()).await.unwrap();
    rt.put_data(&admin, "company/finance/a", b"1").await.unwrap();
    let _ = rt.consume(&sub.id, 1).await.unwrap();
    let _ = rt.consume(&sub.id, 1).await.unwrap();
    let _ = rt.consume(&sub.id, 1).await.unwrap();

    let entries = rt.list_dlq(&admin, &sub.id).await.unwrap();
    assert_eq!(entries.len(), 1);
    let path = format!("{DLQ_PREFIX}/{}/{}", sub.id, entries[0].id);
    assert!(rt.get_data(&admin, &path).await.is_ok());
    assert!(rt.list_dlq(&alice, &sub.id).await.is_err());
    assert!(rt.get_data(&alice, &path).await.is_err());
}

#[tokio::test]
async fn revoked_capability_does_not_dlq() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, tight()).await.unwrap();
    rt.put_data(&admin, "company/finance/a", b"1").await.unwrap();
    let d1 = rt.consume(&sub.id, 1).await.unwrap();
    assert_eq!(d1[0].delivery.attempt, 1);
    let cap = rt
        .list_capabilities()
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.subject.as_str() == "alice")
        .unwrap();
    rt.revoke_capability(&admin, cap.id.as_str()).await.unwrap();
    let err = rt.consume(&sub.id, 1).await.unwrap_err();
    assert!(
        err.to_string().to_ascii_lowercase().contains("denied")
            || err.to_string().to_ascii_lowercase().contains("revoked"),
        "expected AUTHORIZATION_DENIED, got {err}"
    );
    let pending = rt.pending_delivery(&sub.id).await.unwrap().unwrap();
    assert_eq!(pending.attempt, 1);
    assert_eq!(pending.sequence, d1[0].sequence);
    assert!(rt.list_dlq(&admin, &sub.id).await.unwrap().is_empty());
}

#[tokio::test]
async fn retry_dlq_issues_new_delivery_id_without_rewriting_offset() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, tight()).await.unwrap();
    rt.put_data(&admin, "company/finance/a", b"1").await.unwrap();
    rt.put_data(&admin, "company/finance/b", b"2").await.unwrap();
    let first = rt.consume(&sub.id, 1).await.unwrap();
    let _ = rt.consume(&sub.id, 1).await.unwrap();
    let second = rt.consume(&sub.id, 1).await.unwrap();
    assert_eq!(second[0].payload, b"2");
    rt.ack(&alice, &sub.id, &second[0].delivery.delivery_id)
        .await
        .unwrap();
    let offset = rt.get_subscription(&sub.id).await.unwrap().position.sequence;
    assert_eq!(offset, second[0].sequence);

    let dlq = rt.list_dlq(&admin, &sub.id).await.unwrap();
    let retried = rt.retry_dlq(&admin, &dlq[0].id).await.unwrap();
    assert_eq!(retried.event_id, first[0].event_id);
    assert_eq!(retried.sequence, first[0].sequence);
    assert_ne!(retried.delivery.delivery_id, first[0].delivery.delivery_id);
    assert_ne!(retried.delivery.delivery_id, second[0].delivery.delivery_id);
    rt.ack(&admin, &sub.id, &retried.delivery.delivery_id)
        .await
        .unwrap();
    assert_eq!(
        rt.get_subscription(&sub.id).await.unwrap().position.sequence,
        offset
    );
}

#[tokio::test]
async fn replay_does_not_see_dlq_or_retry_state() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, tight()).await.unwrap();
    rt.put_data(&admin, "company/finance/a", b"1").await.unwrap();
    rt.put_data(&admin, "company/finance/b", b"2").await.unwrap();
    let first = rt.consume(&sub.id, 1).await.unwrap();
    let _ = rt.consume(&sub.id, 1).await.unwrap();
    let _ = rt.consume(&sub.id, 1).await.unwrap();

    let replayed = rt.replay(&sub.id, first[0].sequence, 10).await.unwrap();
    assert!(replayed.iter().all(|e| e.sequence == first[0].sequence || e.payload == b"2"));
    assert!(replayed.iter().all(|e| !e.path.starts_with(DLQ_PREFIX)));
    assert_eq!(replayed[0].event_id, first[0].event_id);
    assert_eq!(replayed[0].sequence, first[0].sequence);
}

#[tokio::test]
async fn delete_dlq_removes_entry() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(
        &alice,
        &sub.id,
        RetryPolicy {
            max_attempts: 1,
            initial_backoff_ms: 0,
            max_backoff_ms: 0,
            multiplier: 2,
        },
    )
    .await
    .unwrap();
    rt.put_data(&admin, "company/finance/a", b"1").await.unwrap();
    let _ = rt.consume(&sub.id, 1).await.unwrap();
    let _ = rt.consume(&sub.id, 1).await.unwrap();
    let id = rt.list_dlq(&admin, &sub.id).await.unwrap()[0].id.clone();
    rt.delete_dlq(&admin, &id).await.unwrap();
    assert!(rt.list_dlq(&admin, &sub.id).await.unwrap().is_empty());
    assert!(rt.read_dlq_entry(&admin, &id).await.is_err());
}
