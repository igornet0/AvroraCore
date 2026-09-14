use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{
    ConsumerId, DeliveredEvent, RetryPolicy, SessionId, StreamId, Subscription, SubscriptionId,
};
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

async fn subscribe(
    rt: &Runtime,
    session: &SessionId,
    stream: &StreamId,
    consumer_id: Option<&str>,
) -> Subscription {
    let sub = rt
        .create_subscription(session, stream, consumer_id)
        .await
        .unwrap();
    rt.set_retry_policy(session, &sub.id, RetryPolicy::immediate())
        .await
        .unwrap();
    sub
}

async fn consume_ack_n(
    rt: &Runtime,
    session: &SessionId,
    sub: &SubscriptionId,
    n: usize,
) -> Vec<DeliveredEvent> {
    let mut out = Vec::new();
    for _ in 0..n {
        let mut batch = rt.consume(sub, 1).await.unwrap();
        assert_eq!(batch.len(), 1);
        let ev = batch.remove(0);
        rt.ack(session, sub, &ev.delivery.delivery_id)
            .await
            .unwrap();
        out.push(ev);
    }
    out
}

#[tokio::test]
async fn subscribe_denied_when_capability_narrower_than_stream() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    rt.create_role(
        &admin,
        "invoices".into(),
        "Invoices".into(),
        KeyPath::parse("company/finance/invoices").unwrap(),
        PermissionSet::empty().with(Permission::Read),
    )
    .await
    .unwrap();
    rt.create_user(&admin, "alice".into(), vec!["invoices".into()])
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
    assert!(rt.create_subscription(&alice, &stream, None).await.is_err());
}

#[tokio::test]
async fn ack_survives_kill_and_revoke_stops_delivery() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, sub_id, first40, all_before) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (admin, alice, stream) = setup_finance_read(&rt).await;
        let sub = subscribe(&rt, &alice, &stream, Some("finance-consumer")).await;
        assert_eq!(sub.consumer_id, ConsumerId::from("finance-consumer"));
        assert_eq!(sub.position.sequence, 0);

        for i in 0..100 {
            rt.put_data(
                &admin,
                &format!("company/finance/inv/{i}"),
                format!("{i}").as_bytes(),
            )
            .await
            .unwrap();
        }
        let batch = consume_ack_n(&rt, &alice, &sub.id, 40).await;
        assert_eq!(batch.len(), 40);
        assert_eq!(batch[0].payload, b"0");
        assert_eq!(batch[39].payload, b"39");
        let ack_seq = batch[39].sequence;
        let stored = rt.get_subscription(&sub.id).await.unwrap();
        assert_eq!(stored.position.sequence, ack_seq);
        let offset = rt.get_offset(sub.id.as_str()).await.unwrap();
        assert_eq!(offset.sequence, ack_seq);
        (
            master,
            sub.id,
            ack_seq,
            batch.into_iter().map(|e| e.sequence).collect::<Vec<_>>(),
        )
    };

    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    let resumed = consume_ack_n(&rt, &alice, &sub_id, 60).await;
    assert!(!resumed.is_empty());
    assert!(resumed[0].sequence > first40);
    assert_eq!(resumed[0].payload, b"40");
    assert_eq!(resumed.last().unwrap().payload, b"99");
    assert_eq!(resumed.len(), 60);
    let seen: Vec<u64> = all_before
        .into_iter()
        .chain(resumed.iter().map(|e| e.sequence))
        .collect();
    let mut ordered = seen.clone();
    ordered.sort();
    ordered.dedup();
    assert_eq!(seen, ordered, "no gaps or duplicates in delivered sequences");

    let admin = rt.admin_session().await.unwrap();
    let caps = rt.list_capabilities().await.unwrap();
    let alice_cap = caps
        .iter()
        .find(|c| c.subject.as_str() == "alice")
        .unwrap();
    rt.revoke_capability(&admin, alice_cap.id.as_str())
        .await
        .unwrap();
    rt.put_data(&admin, "company/finance/inv/100", b"100")
        .await
        .unwrap();
    let err = rt.consume(&sub_id, 10).await.unwrap_err();
    assert!(
        err.to_string().to_ascii_lowercase().contains("denied")
            || err.to_string().to_ascii_lowercase().contains("revoked"),
        "expected AUTHORIZATION_DENIED, got {err}"
    );
}

#[tokio::test]
async fn replay_does_not_move_persistent_offset() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = subscribe(&rt, &alice, &stream, Some("replay-consumer")).await;
    for i in 0..20 {
        rt.put_data(
            &admin,
            &format!("company/finance/inv/{i}"),
            format!("{i}").as_bytes(),
        )
        .await
        .unwrap();
    }
    let first = consume_ack_n(&rt, &alice, &sub.id, 10).await;
    assert_eq!(first.len(), 10);
    let ack_seq = first[9].sequence;
    let from = first[0].sequence;

    let replayed = rt.replay(&sub.id, from, 5).await.unwrap();
    assert_eq!(replayed.len(), 5);
    assert_eq!(replayed[0].sequence, from);
    assert_eq!(replayed[0].payload, b"0");
    let after = rt.get_subscription(&sub.id).await.unwrap();
    assert_eq!(after.position.sequence, ack_seq);
    assert!(rt.pending_delivery(&sub.id).await.unwrap().is_none());

    let resumed = rt.consume(&sub.id, 1).await.unwrap();
    assert_eq!(resumed[0].payload, b"10");
}

#[tokio::test]
async fn replay_denied_after_capability_revoke() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = subscribe(&rt, &alice, &stream, None).await;
    rt.put_data(&admin, "company/finance/inv/1", b"one")
        .await
        .unwrap();
    let batch = rt.consume(&sub.id, 1).await.unwrap();
    let from = batch[0].sequence;
    let cap = rt
        .list_capabilities()
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.subject.as_str() == "alice")
        .unwrap();
    rt.revoke_capability(&admin, cap.id.as_str()).await.unwrap();
    let err = rt.replay(&sub.id, from, 10).await.unwrap_err();
    assert!(
        err.to_string().to_ascii_lowercase().contains("denied")
            || err.to_string().to_ascii_lowercase().contains("revoked"),
        "expected AUTHORIZATION_DENIED, got {err}"
    );
}

#[tokio::test]
async fn subscribe_and_replay_denied_when_capability_narrower_than_stream() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    rt.create_role(
        &admin,
        "invoices".into(),
        "Invoices".into(),
        KeyPath::parse("company/finance/invoices").unwrap(),
        PermissionSet::empty().with(Permission::Read),
    )
    .await
    .unwrap();

    rt.create_user(&admin, "carol".into(), vec!["invoices".into()])
        .await
        .unwrap();
    let carol = rt.open_user_session("carol", Some("dev-c")).await.unwrap();
    assert!(rt.create_subscription(&carol, &stream, None).await.is_err());

    let sub = subscribe(&rt, &alice, &stream, None).await;
    rt.put_data(&admin, "company/finance/inv/1", b"one")
        .await
        .unwrap();
    rt.assign_roles(&admin, "alice", vec!["invoices".into()])
        .await
        .unwrap();
    let err = rt.replay(&sub.id, 1, 10).await.unwrap_err();
    assert!(
        err.to_string().to_ascii_lowercase().contains("denied")
            || err.to_string().contains("Access denied")
            || err.to_string().to_ascii_lowercase().contains("access"),
        "expected replay denied for invoices vs finance stream, got {err}"
    );
}

#[tokio::test]
async fn crash_after_delivery_retries_same_sequence_with_new_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, sub_id, seq, event_id) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (admin, alice, stream) = setup_finance_read(&rt).await;
        let sub = subscribe(&rt, &alice, &stream, None).await;
        rt.put_data(&admin, "company/finance/inv/1", b"one")
            .await
            .unwrap();
        let d1 = rt.consume(&sub.id, 1).await.unwrap();
        assert_eq!(d1[0].delivery.attempt, 1);
        let pending = rt.pending_delivery(&sub.id).await.unwrap().unwrap();
        assert_eq!(pending.attempt, 1);
        assert_eq!(pending.sequence, d1[0].sequence);
        (
            master,
            sub.id,
            d1[0].sequence,
            d1[0].event_id.clone(),
        )
    };

    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let d2 = rt.consume(&sub_id, 1).await.unwrap();
    assert_eq!(d2[0].sequence, seq);
    assert_eq!(d2[0].event_id, event_id);
    assert_eq!(d2[0].delivery.attempt, 2);
    assert!(d2[0].delivery.delivery_id.as_str().starts_with("del_"));
}

#[tokio::test]
async fn ack_persists_and_duplicate_ack_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, sub_id, d1_id, seq) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (admin, alice, stream) = setup_finance_read(&rt).await;
        let sub = subscribe(&rt, &alice, &stream, None).await;
        rt.put_data(&admin, "company/finance/a", b"1").await.unwrap();
        rt.put_data(&admin, "company/finance/b", b"2").await.unwrap();
        let d1 = rt.consume(&sub.id, 1).await.unwrap();
        rt.ack(&alice, &sub.id, &d1[0].delivery.delivery_id)
            .await
            .unwrap();
        rt.ack(&alice, &sub.id, &d1[0].delivery.delivery_id)
            .await
            .unwrap();
        assert_eq!(
            rt.get_subscription(&sub.id).await.unwrap().position.sequence,
            d1[0].sequence
        );
        (
            master,
            sub.id,
            d1[0].delivery.delivery_id.clone(),
            d1[0].sequence,
        )
    };

    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    rt.ack(&alice, &sub_id, &d1_id).await.unwrap();
    let next = rt.consume(&sub_id, 1).await.unwrap();
    assert_eq!(next[0].payload, b"2");
    assert!(next[0].sequence > seq);
}

#[tokio::test]
async fn old_delivery_ack_must_not_ack_newer_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = subscribe(&rt, &alice, &stream, None).await;
    rt.put_data(&admin, "company/finance/inv/1", b"one")
        .await
        .unwrap();
    let d1 = rt.consume(&sub.id, 1).await.unwrap();
    let d2 = rt.consume(&sub.id, 1).await.unwrap();
    assert_eq!(d1[0].sequence, d2[0].sequence);
    assert_eq!(d2[0].delivery.attempt, 2);
    let err = rt
        .ack(&alice, &sub.id, &d1[0].delivery.delivery_id)
        .await
        .unwrap_err();
    assert!(err.to_string().to_ascii_lowercase().contains("stale"));
    rt.ack(&alice, &sub.id, &d2[0].delivery.delivery_id)
        .await
        .unwrap();
}

#[tokio::test]
async fn delivery_attempts_are_isolated_per_subscription() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    rt.create_user(&admin, "bob".into(), vec!["finance".into()])
        .await
        .unwrap();
    let bob = rt.open_user_session("bob", Some("dev-b")).await.unwrap();
    let sub_a = subscribe(&rt, &alice, &stream, None).await;
    let sub_b = subscribe(&rt, &bob, &stream, None).await;
    rt.put_data(&admin, "company/finance/inv/1", b"one")
        .await
        .unwrap();
    let _ = rt.consume(&sub_a.id, 1).await.unwrap();
    let _ = rt.consume(&sub_a.id, 1).await.unwrap();
    let a3 = rt.consume(&sub_a.id, 1).await.unwrap();
    let b1 = rt.consume(&sub_b.id, 1).await.unwrap();
    assert_eq!(a3[0].sequence, b1[0].sequence);
    assert_eq!(a3[0].delivery.attempt, 3);
    assert_eq!(b1[0].delivery.attempt, 1);
}

#[tokio::test]
async fn redelivery_gets_new_delivery_id() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = subscribe(&rt, &alice, &stream, None).await;
    rt.put_data(&admin, "company/finance/inv/1", b"one")
        .await
        .unwrap();
    let first = rt.consume(&sub.id, 1).await.unwrap();
    let second = rt.consume(&sub.id, 1).await.unwrap();
    assert_eq!(first[0].sequence, second[0].sequence);
    assert_eq!(first[0].event_id, second[0].event_id);
    assert_ne!(first[0].delivery.delivery_id, second[0].delivery.delivery_id);
    assert_eq!(first[0].delivery.attempt, 1);
    assert_eq!(second[0].delivery.attempt, 2);
    assert!(first[0].delivery.delivery_id.as_str().starts_with("del_"));
}

#[tokio::test]
async fn pending_delivery_is_encrypted_outside_journal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let rt = Runtime::at_path(&path);
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_read(&rt).await;
    let sub = subscribe(&rt, &alice, &stream, None).await;
    rt.put_data(&admin, "company/finance/inv/1", b"one")
        .await
        .unwrap();
    let _ = rt.consume(&sub.id, 1).await.unwrap();
    let layout = dmc_journal::StorageLayout::from_db_path(&path);
    let raw = std::fs::read_to_string(layout.consumer_meta()).unwrap();
    assert!(
        !raw.contains(sub.id.as_str()),
        "consumer metadata must not store subscription id in plaintext"
    );
    assert!(
        !raw.contains("\"attempt\""),
        "consumer metadata must be encrypted"
    );
}
