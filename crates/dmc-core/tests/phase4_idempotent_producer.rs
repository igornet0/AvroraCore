use dmc_core::runtime::Runtime;
use dmc_core::PutOptions;

#[tokio::test]
async fn duplicate_put_returns_same_event() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    let opts = PutOptions {
        producer_id: "local".into(),
        idempotency_key: "put-1".into(),
    };
    let first = rt
        .put_data_with(&admin, "company/a", b"one", Some(opts.clone()))
        .await
        .unwrap();
    assert!(!first.replay);
    let seq = rt.last_sequence().await;
    let second = rt
        .put_data_with(&admin, "company/a", b"one", Some(opts))
        .await
        .unwrap();
    assert!(second.replay);
    assert_eq!(second.event_id, first.event_id);
    assert_eq!(second.sequence, first.sequence);
    assert_eq!(rt.last_sequence().await, seq);
    assert_eq!(rt.get_data(&admin, "company/a").await.unwrap(), b"one");
}

#[tokio::test]
async fn different_keys_create_two_events() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    let a = rt
        .put_data_with(
            &admin,
            "company/a",
            b"1",
            Some(PutOptions {
                producer_id: String::new(),
                idempotency_key: "k1".into(),
            }),
        )
        .await
        .unwrap();
    let b = rt
        .put_data_with(
            &admin,
            "company/a",
            b"2",
            Some(PutOptions {
                producer_id: String::new(),
                idempotency_key: "k2".into(),
            }),
        )
        .await
        .unwrap();
    assert_ne!(a.event_id, b.event_id);
    assert_ne!(a.sequence, b.sequence);
    assert_eq!(rt.get_data(&admin, "company/a").await.unwrap(), b"2");
}

#[tokio::test]
async fn dedup_survives_restart_and_is_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let opts = PutOptions {
        producer_id: "dev-1".into(),
        idempotency_key: "stable".into(),
    };
    let (master, first) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let admin = rt.admin_session().await.unwrap();
        let first = rt
            .put_data_with(&admin, "company/secret", b"payload", Some(opts.clone()))
            .await
            .unwrap();
        let raw = std::fs::read(dir.path().join("runtime/producer.meta.json")).unwrap();
        let text = String::from_utf8_lossy(&raw);
        assert!(
            !text.contains("company/secret"),
            "producer metadata must not store path in plaintext"
        );
        assert!(!text.contains("stable"));
        (master, first)
    };
    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let admin = rt.admin_session().await.unwrap();
    let replay = rt
        .put_data_with(&admin, "company/secret", b"payload", Some(opts))
        .await
        .unwrap();
    assert!(replay.replay);
    assert_eq!(replay.event_id, first.event_id);
    assert_eq!(replay.sequence, first.sequence);
}

#[tokio::test]
async fn producer_dedup_is_independent_of_consumer_offset() {
    use dmc_core::channel::ChannelSpec;
    use dmc_core::stream::{StreamDirection, StreamSpec};
    use dmc_core::{RetryPolicy, StreamId};
    use dmc_vault::key::KeyPath;
    use dmc_vault::{Permission, PermissionSet};

    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
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
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, RetryPolicy::immediate())
        .await
        .unwrap();

    let opts = PutOptions {
        producer_id: "local".into(),
        idempotency_key: "inv-1".into(),
    };
    let put = rt
        .put_data_with(&admin, "company/finance/inv/1", b"1", Some(opts.clone()))
        .await
        .unwrap();
    let ev = rt.consume(&sub.id, 1).await.unwrap();
    assert_eq!(ev[0].sequence, put.sequence);
    rt.ack(&alice, &sub.id, &ev[0].delivery.delivery_id)
        .await
        .unwrap();
    let offset = rt.get_subscription(&sub.id).await.unwrap().position.sequence;
    let replay = rt
        .put_data_with(&admin, "company/finance/inv/1", b"1", Some(opts))
        .await
        .unwrap();
    assert!(replay.replay);
    assert_eq!(replay.sequence, put.sequence);
    assert_eq!(
        rt.get_subscription(&sub.id).await.unwrap().position.sequence,
        offset
    );
    assert!(rt.consume(&sub.id, 1).await.unwrap().is_empty());
}
