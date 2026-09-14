//! Phase 5.8.4 — partition assignment + GroupOffset foundation.

use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{
    assign_partitions, Error, GroupId, GroupPolicy, GroupStartPosition, GroupState, MemberId,
    SessionId, StreamId, DEFAULT_MEMBER_LEASE_MS,
};
use dmc_journal::set_test_partition_count;
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};

struct PartitionGuard;
impl Drop for PartitionGuard {
    fn drop(&mut self) {
        set_test_partition_count(None);
    }
}

fn with_partitions(n: u32) -> PartitionGuard {
    set_test_partition_count(Some(n));
    PartitionGuard
}

async fn setup_finance_stream(rt: &Runtime) -> (SessionId, SessionId, StreamId) {
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

async fn setup_hr_user(rt: &Runtime, admin: &SessionId) -> SessionId {
    rt.create_role(
        admin,
        "hr".into(),
        "HR".into(),
        KeyPath::parse("company/hr").unwrap(),
        PermissionSet::empty().with(Permission::Read),
    )
    .await
    .unwrap();
    rt.create_user(admin, "bob".into(), vec!["hr".into()])
        .await
        .unwrap();
    rt.open_user_session("bob", Some("dev-b")).await.unwrap()
}

fn owners(desc: &dmc_core::GroupDescription) -> Vec<(u32, String)> {
    desc.assignments
        .iter()
        .map(|a| (a.partition_id, a.member_id.as_str().to_string()))
        .collect()
}

fn offset_pairs(desc: &dmc_core::GroupDescription) -> Vec<(u32, u64)> {
    desc.offsets
        .iter()
        .map(|o| (o.partition_id, o.sequence))
        .collect()
}

#[test]
fn assign_one_partition_one_member() {
    let a = assign_partitions(&[0], &[MemberId::from("A")]);
    assert_eq!(a.get(&0).unwrap().as_str(), "A");
}

#[test]
fn assign_one_partition_two_members() {
    let a = assign_partitions(&[0], &[MemberId::from("B"), MemberId::from("A")]);
    assert_eq!(a.len(), 1);
    assert_eq!(a.get(&0).unwrap().as_str(), "A");
}

#[test]
fn assign_three_partitions_two_members() {
    let a = assign_partitions(&[0, 1, 2], &[MemberId::from("A"), MemberId::from("B")]);
    assert_eq!(a.get(&0).unwrap().as_str(), "A");
    assert_eq!(a.get(&1).unwrap().as_str(), "B");
    assert_eq!(a.get(&2).unwrap().as_str(), "A");
}

#[test]
fn assign_five_partitions_three_members() {
    let a = assign_partitions(
        &[0, 1, 2, 3, 4],
        &[MemberId::from("A"), MemberId::from("B"), MemberId::from("C")],
    );
    assert_eq!(
        a.values().map(|m| m.as_str()).collect::<Vec<_>>(),
        vec!["A", "B", "C", "A", "B"]
    );
}

#[test]
fn assign_more_members_than_partitions() {
    let a = assign_partitions(
        &[0, 1],
        &[MemberId::from("A"), MemberId::from("B"), MemberId::from("C")],
    );
    assert_eq!(a.len(), 2);
    assert_eq!(a.get(&0).unwrap().as_str(), "A");
    assert_eq!(a.get(&1).unwrap().as_str(), "B");
}

#[test]
fn assign_zero_members() {
    assert!(assign_partitions(&[0, 1, 2], &[]).is_empty());
}

#[test]
fn assign_is_order_independent() {
    let a = assign_partitions(
        &[3, 1, 0, 2],
        &[MemberId::from("C"), MemberId::from("A"), MemberId::from("B")],
    );
    let b = assign_partitions(
        &[0, 1, 2, 3],
        &[MemberId::from("A"), MemberId::from("B"), MemberId::from("C")],
    );
    assert_eq!(a, b);
    assert_eq!(a.get(&0).unwrap().as_str(), "A");
    assert_eq!(a.get(&1).unwrap().as_str(), "B");
    assert_eq!(a.get(&2).unwrap().as_str(), "C");
    assert_eq!(a.get(&3).unwrap().as_str(), "A");
}

#[tokio::test]
async fn join_assigns_partitions_and_sets_stable() {
    let _g = with_partitions(3);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_admin, alice, stream) = setup_finance_stream(&rt).await;
    let gid = GroupId::from("workers");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.generation, 2);
    assert_eq!(desc.state, GroupState::Stable);
    assert_eq!(desc.partition_count, 3);
    assert_eq!(
        owners(&desc),
        vec![(0, "A".into()), (1, "A".into()), (2, "A".into())]
    );
}

#[tokio::test]
async fn second_join_rebalances_round_robin() {
    let _g = with_partitions(3);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_admin, alice, stream) = setup_finance_stream(&rt).await;
    let gid = GroupId::from("workers");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.generation, 3);
    assert_eq!(desc.state, GroupState::Stable);
    assert_eq!(
        owners(&desc),
        vec![(0, "A".into()), (1, "B".into()), (2, "A".into())]
    );
}

#[tokio::test]
async fn heartbeat_does_not_change_generation_or_assignment() {
    let _g = with_partitions(2);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    rt.set_now_ms(Some(10_000)).await;
    let (_admin, alice, stream) = setup_finance_stream(&rt).await;
    let gid = GroupId::from("workers");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    let before = rt.describe_group(&alice, &gid).await.unwrap();
    rt.set_now_ms(Some(15_000)).await;
    rt.heartbeat_group_member(&alice, &gid, &MemberId::from("A"))
        .await
        .unwrap();
    let after = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(after.generation, before.generation);
    assert_eq!(owners(&after), owners(&before));
}

#[tokio::test]
async fn leave_reassigns_and_preserves_offsets() {
    let _g = with_partitions(3);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_admin, alice, stream) = setup_finance_stream(&rt).await;
    let gid = GroupId::from("workers");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    let offsets_before = offset_pairs(&rt.describe_group(&alice, &gid).await.unwrap());
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    assert_eq!(
        offset_pairs(&rt.describe_group(&alice, &gid).await.unwrap()),
        offsets_before
    );
    rt.leave_group(&alice, &gid, &MemberId::from("A"))
        .await
        .unwrap();
    let after = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(after.generation, 4);
    assert_eq!(
        owners(&after),
        vec![(0, "B".into()), (1, "B".into()), (2, "B".into())]
    );
    assert_eq!(offset_pairs(&after), offsets_before);
}

#[tokio::test]
async fn expiry_reassigns_like_leave() {
    let _g = with_partitions(2);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    rt.set_now_ms(Some(1_000)).await;
    let (_admin, alice, stream) = setup_finance_stream(&rt).await;
    let gid = GroupId::from("workers");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    rt.set_now_ms(Some(2_000)).await;
    rt.join_group(&alice, &gid, MemberId::from("B"), None)
        .await
        .unwrap();
    let offsets_before = offset_pairs(&rt.describe_group(&alice, &gid).await.unwrap());
    rt.set_now_ms(Some(1_000 + DEFAULT_MEMBER_LEASE_MS)).await;
    rt.reconcile_group_leases().await.unwrap();
    let after = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(after.members.len(), 1);
    assert_eq!(after.members[0].member_id.as_str(), "B");
    assert_eq!(owners(&after), vec![(0, "B".into()), (1, "B".into())]);
    assert_eq!(offset_pairs(&after), offsets_before);
}

#[tokio::test]
async fn latest_and_earliest_bootstrap() {
    let _g = with_partitions(2);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_admin, alice, stream) = setup_finance_stream(&rt).await;
    let admin = rt.admin_session().await.unwrap();
    for i in 0..4 {
        rt.put_data(&admin, &format!("company/finance/n/{i}"), br#"{"n":1}"#)
            .await
            .unwrap();
    }
    let latest = rt
        .create_group(&alice, GroupId::from("latest-g"), &stream)
        .await
        .unwrap();
    let earliest = rt
        .create_group_with_policy(
            &alice,
            GroupId::from("earliest-g"),
            &stream,
            GroupPolicy {
                start_position: GroupStartPosition::Earliest,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let latest_seq = *latest.offsets.values().next().unwrap();
    let earliest_seq = *earliest.offsets.values().next().unwrap();
    assert!(
        latest_seq >= earliest_seq,
        "Latest={latest_seq} should be >= Earliest={earliest_seq}"
    );
    assert_eq!(latest.offsets.len(), 2);
    assert_eq!(earliest.offsets.len(), 2);
}

#[tokio::test]
async fn assignment_and_offsets_persist_across_restart() {
    let _g = with_partitions(3);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (master, gid, owners_before, offsets_before, generation) = {
        let rt = Runtime::at_path(&path);
        let (master, _) = rt.create_dev(false).await.unwrap();
        let (_admin, alice, stream) = setup_finance_stream(&rt).await;
        let gid = GroupId::from("persist-assign");
        rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
        rt.join_group(&alice, &gid, MemberId::from("A"), None)
            .await
            .unwrap();
        rt.join_group(&alice, &gid, MemberId::from("B"), None)
            .await
            .unwrap();
        let desc = rt.describe_group(&alice, &gid).await.unwrap();
        (
            master,
            gid,
            owners(&desc),
            offset_pairs(&desc),
            desc.generation,
        )
    };
    let rt = Runtime::at_path(&path);
    // Keep same partition topology after restart.
    set_test_partition_count(Some(3));
    rt.unlock(&master).await.unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a2")).await.unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.generation, generation);
    assert_eq!(owners(&desc), owners_before);
    assert_eq!(offset_pairs(&desc), offsets_before);
    assert_eq!(desc.state, GroupState::Stable);
}

#[tokio::test]
async fn capability_required_for_join() {
    let _g = with_partitions(2);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (admin, alice, stream) = setup_finance_stream(&rt).await;
    let bob = setup_hr_user(&rt, &admin).await;
    let gid = GroupId::from("finance-workers");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    let err = rt
        .join_group(&bob, &gid, MemberId::from("B"), None)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::AuthorizationDenied(_)));
}

#[tokio::test]
async fn leave_last_member_clears_assignment_keeps_offsets() {
    let _g = with_partitions(2);
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::at_path(dir.path().join("store.dbs.json"));
    let (_master, _) = rt.create_dev(false).await.unwrap();
    let (_admin, alice, stream) = setup_finance_stream(&rt).await;
    let gid = GroupId::from("solo");
    rt.create_group(&alice, gid.clone(), &stream).await.unwrap();
    let offsets0 = offset_pairs(&rt.describe_group(&alice, &gid).await.unwrap());
    rt.join_group(&alice, &gid, MemberId::from("A"), None)
        .await
        .unwrap();
    rt.leave_group(&alice, &gid, &MemberId::from("A"))
        .await
        .unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.state, GroupState::Empty);
    assert!(desc.assignments.is_empty());
    assert_eq!(offset_pairs(&desc), offsets0);
}
