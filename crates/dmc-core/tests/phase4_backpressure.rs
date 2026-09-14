use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{BatchLimits, ConsumerPolicy, Error, RetryPolicy, SessionId, StreamId};
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};

async fn setup(rt: &Runtime) -> (SessionId, SessionId, StreamId) {
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

#[tokio::test]
async fn consume_batch_backpressure_when_pending_and_want_exceeds_in_flight() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup(&rt).await;
    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    rt.set_retry_policy(&alice, &sub.id, RetryPolicy::immediate())
        .await
        .unwrap();
    rt.set_consumer_policy(
        &alice,
        &sub.id,
        ConsumerPolicy {
            max_in_flight: 1,
            max_batch_events: 8,
            max_batch_bytes: 1_048_576,
        },
    )
    .await
    .unwrap();
    rt.put_data(&admin, "company/finance/a", b"1").await.unwrap();

    let first = rt
        .consume_batch(&sub.id, BatchLimits::one())
        .await
        .unwrap();
    assert_eq!(first.len(), 1);

    let err = rt
        .consume_batch(
            &sub.id,
            BatchLimits {
                max_events: 2,
                max_bytes: 1_048_576,
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::Backpressure {
                in_flight: 1,
                max_in_flight: 1,
                ..
            }
        ),
        "{err:?}"
    );

    let again = rt.consume(&sub.id, 1).await.unwrap();
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].sequence, first[0].sequence);
    assert_eq!(again[0].delivery.attempt, 2);
}

#[tokio::test]
async fn consumer_policy_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, sub_id) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (_admin, alice, stream) = setup(&rt).await;
        let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
        let policy = ConsumerPolicy {
            max_in_flight: 1,
            max_batch_events: 4,
            max_batch_bytes: 4096,
        };
        rt.set_consumer_policy(&alice, &sub.id, policy)
            .await
            .unwrap();
        (master, sub.id)
    };
    let rt = Runtime::at_path(&path);
    rt.unlock(&master).await.unwrap();
    let stored = rt.consumer_policy(&sub_id).await.unwrap();
    assert_eq!(stored.max_batch_events, 4);
    assert_eq!(stored.max_batch_bytes, 4096);
    assert_eq!(stored.max_in_flight, 1);
}
