//! Phase 5.8.12 — Consumer Groups Final DoD / Production Contract (ADR-015 §5.8.12).
//!
//! Single acceptance sequence: no new semantics — proves all group mechanisms together.

mod partition_contract;

use std::collections::{BTreeMap, HashSet};

use dmc_core::channel::ChannelSpec;
use dmc_core::runtime::Runtime;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::subscription::JournalPosition;
use dmc_core::{
    CompactionPolicy, Error, GroupId, GroupPolicy, GroupRetryPolicy, GroupRetryResponse,
    MemberId, SessionId, StreamId,
};
use dmc_journal::journal_manifest::read_manifest;
use dmc_journal::partition::resolve_partition;
use dmc_journal::{set_test_partition_count, set_test_segment_max_bytes, StorageLayout};
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};

use partition_contract::{
    assert_aad_excludes_partition_id, assert_crypto_fingerprints_equal,
    assert_event_views_equivalent, assert_global_sequence_ordering_contract,
    assert_history_unavailable, assert_journal_position_global_only,
    assert_manifest_partition_topology, assert_no_duplicate_sequences,
    crypto_fingerprints_for_sequences, EventView,
};

const PARTS: u32 = 3;
const EVENT_ROUNDS: u32 = 4000;
const TOTAL_EVENTS: u64 = (EVENT_ROUNDS as u64) * (PARTS as u64);
const MAX_IN_FLIGHT: u32 = 8;
const BASE_NOW: u64 = 2_000_000;
const COMPACTION_SAMPLE: usize = 200;
const GROUP_ID: &str = "production-dod";
const STREAM_ID: &str = "test-stream";

const MEMBER_A: &str = "member-a";
const MEMBER_B: &str = "member-b";
const MEMBER_C: &str = "member-c";

struct EnvGuard;
impl Drop for EnvGuard {
    fn drop(&mut self) {
        set_test_partition_count(None);
        set_test_segment_max_bytes(None);
    }
}

fn enable_env() -> EnvGuard {
    set_test_partition_count(Some(PARTS));
    set_test_segment_max_bytes(Some(900));
    EnvGuard
}

fn dod_policy() -> GroupPolicy {
    GroupPolicy {
        max_in_flight: MAX_IN_FLIGHT,
        retry: GroupRetryPolicy {
            max_attempts: 3,
            backoff_ms: vec![0, 100, 500],
        },
        ..Default::default()
    }
}

fn manifest_path(store: &std::path::Path) -> std::path::PathBuf {
    StorageLayout::from_db_path(store).journal_manifest()
}

fn journal_dir(store: &std::path::Path) -> std::path::PathBuf {
    StorageLayout::from_db_path(store).journal_dir()
}

fn path_for_partition(prefix: &str, target: u32, parts: u32) -> String {
    for i in 0..20_000 {
        let path = format!("{prefix}/route-{i}");
        let kp = KeyPath::parse(&path).unwrap();
        if resolve_partition(&kp, None, parts).unwrap().as_u32() == target {
            return path;
        }
    }
    panic!("no path for partition {target} under {prefix}");
}

async fn setup_company(
    rt: &Runtime,
) -> (
    SessionId,
    SessionId,
    SessionId,
    SessionId,
    StreamId,
) {
    let admin = rt.admin_session().await.unwrap();
    rt.create_role(
        &admin,
        "company-reader".into(),
        "Company".into(),
        KeyPath::parse("company").unwrap(),
        PermissionSet::empty().with(Permission::Read),
    )
    .await
    .unwrap();
    for user in ["alice", "bob", "carol"] {
        rt.create_user(&admin, user.into(), vec!["company-reader".into()])
            .await
            .unwrap();
    }
    rt.configure_channel(ChannelSpec::internal("bus"))
        .await
        .unwrap();
    let stream = rt
        .create_stream(StreamSpec {
            id: StreamId::from(STREAM_ID),
            direction: StreamDirection::Outbound,
            channel_id: "bus".into(),
            path_scope: KeyPath::parse("company").unwrap(),
            required_perms: PermissionSet::empty().with(Permission::Read),
        })
        .await
        .unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a")).await.unwrap();
    let bob = rt.open_user_session("bob", Some("dev-b")).await.unwrap();
    let carol = rt.open_user_session("carol", Some("dev-c")).await.unwrap();
    (admin, alice, bob, carol, stream)
}

async fn offset_of(rt: &Runtime, session: &SessionId, gid: &GroupId, pid: u32) -> u64 {
    rt.describe_group(session, gid)
        .await
        .unwrap()
        .offsets
        .iter()
        .find(|o| o.partition_id == pid)
        .map(|o| o.sequence)
        .unwrap_or(0)
}

fn owner_of(desc: &dmc_core::GroupDescription, pid: u32) -> MemberId {
    desc.assignments
        .iter()
        .find(|a| a.partition_id == pid)
        .map(|a| a.member_id.clone())
        .unwrap_or_else(|| panic!("no owner for partition {pid}"))
}

async fn put_dod_events(rt: &Runtime, admin: &SessionId) -> u64 {
    let prefixes = ["company/finance", "company/hr", "company/audit"];
    let mut idx = 0u64;
    for _round in 0..EVENT_ROUNDS {
        for p in 0..PARTS {
            let path = path_for_partition(prefixes[p as usize], p, PARTS);
            rt.put_data(admin, &path, format!("evt-{idx}").as_bytes())
                .await
                .unwrap();
            idx += 1;
        }
    }
    idx
}

async fn replay_evt_view(
    rt: &Runtime,
    sub: &dmc_core::SubscriptionId,
    limit: usize,
) -> Vec<EventView> {
    let from = rt.oldest_available_sequence().await.unwrap();
    rt.replay(sub, from, limit)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.payload.starts_with(b"evt-"))
        .map(|e| EventView {
            sequence: e.sequence,
            event_id: e.event_id,
            path: e.path,
            payload: e.payload,
        })
        .collect()
}

async fn compact_all_partitions(rt: &Runtime, admin: &SessionId) {
    rt.set_compaction_policy(
        admin,
        CompactionPolicy {
            enabled: true,
            min_segments: 2,
            min_total_bytes: 0,
            max_input_bytes: 50 * 1024 * 1024,
        },
    )
    .await
    .unwrap();
    for pid in 0..PARTS {
        while rt
            .select_compaction_candidate_for_partition(pid)
            .await
            .unwrap()
            .is_some()
        {
            let artifact = rt.compact_journal_partition(pid).await.unwrap();
            rt.publish_compaction(artifact).await.unwrap();
        }
    }
}

fn expected_contiguous_offset(resolved: &BTreeMap<u64, ()>, base: u64, high: u64) -> u64 {
    let mut off = base;
    while off < high {
        let next = off + 1;
        if resolved.contains_key(&next) {
            off = next;
        } else {
            break;
        }
    }
    off
}

async fn append_on_partition(
    rt: &Runtime,
    admin: &SessionId,
    partition: u32,
    prefix: &str,
    payload: &str,
) -> dmc_core::PutResult {
    let path = path_for_partition(prefix, partition, PARTS);
    rt.put_data_with(admin, &path, payload.as_bytes(), None)
        .await
        .unwrap()
}

async fn append_p0_sequential(
    rt: &Runtime,
    admin: &SessionId,
    count: usize,
) -> Vec<u64> {
    let path = path_for_partition("company/finance", 0, PARTS);
    let mut sequences = Vec::new();
    for i in 0..count {
        let put = rt
            .put_data_with(admin, &path, format!("gap-{i}").as_bytes(), None)
            .await
            .unwrap();
        sequences.push(put.sequence);
    }
    sequences
}

#[derive(Clone, Debug)]
struct FinalSnapshot {
    generation: u64,
    offsets: Vec<(u32, u64)>,
    assignments: Vec<(u32, String)>,
    members: Vec<String>,
    dlq_sequences: Vec<u64>,
}

async fn capture_snapshot(rt: &Runtime, alice: &SessionId, gid: &GroupId) -> FinalSnapshot {
    let desc = rt.describe_group(alice, gid).await.unwrap();
    let dlq = rt.list_group_dlq(alice, gid).await.unwrap();
    FinalSnapshot {
        generation: desc.generation,
        offsets: desc
            .offsets
            .iter()
            .map(|o| (o.partition_id, o.sequence))
            .collect(),
        assignments: desc
            .assignments
            .iter()
            .map(|a| (a.partition_id, a.member_id.as_str().to_string()))
            .collect(),
        members: desc
            .members
            .iter()
            .map(|m| m.member_id.as_str().to_string())
            .collect(),
        dlq_sequences: dlq.iter().map(|e| e.sequence).collect(),
    }
}

fn assert_snapshot_eq(a: &FinalSnapshot, b: &FinalSnapshot) {
    assert_eq!(a.generation, b.generation);
    assert_eq!(a.offsets, b.offsets);
    assert_eq!(a.assignments, b.assignments);
    assert_eq!(a.members, b.members);
    assert_eq!(a.dlq_sequences, b.dlq_sequences);
}

#[tokio::test]
#[ignore = "slow acceptance (~10 min debug); run: make test-slow"]
async fn group_final_dod_acceptance() {
    let _env = enable_env();
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store.dbs.json");
    let journal = journal_dir(&store);
    let manifest = manifest_path(&store);

    let rt = Runtime::at_path(store.clone());
    let (master, _) = rt.create_dev(false).await.unwrap();
    rt.set_now_ms(Some(BASE_NOW)).await;
    let (admin, alice, bob, carol, stream) = setup_company(&rt).await;

    let gid = GroupId::from(GROUP_ID);
    rt.create_group_with_policy(&alice, gid.clone(), &stream, dod_policy())
        .await
        .unwrap();
    rt.join_group(&alice, &gid, MemberId::from(MEMBER_A), None)
        .await
        .unwrap();
    rt.join_group(&bob, &gid, MemberId::from(MEMBER_B), None)
        .await
        .unwrap();
    rt.join_group(&carol, &gid, MemberId::from(MEMBER_C), None)
        .await
        .unwrap();

    let generation = rt.describe_group(&alice, &gid).await.unwrap().generation;
    assert_eq!(owner_of(&rt.describe_group(&alice, &gid).await.unwrap(), 0), MemberId::from(MEMBER_A));
    assert_eq!(owner_of(&rt.describe_group(&alice, &gid).await.unwrap(), 1), MemberId::from(MEMBER_B));
    assert_eq!(owner_of(&rt.describe_group(&alice, &gid).await.unwrap(), 2), MemberId::from(MEMBER_C));

    // --- 4. Gapped ACK (contiguous P0 sequences, before bulk load) ---
    let gap_sequences = append_p0_sequential(&rt, &admin, 5).await;
    assert!(
        gap_sequences.windows(2).all(|w| w[1] == w[0] + 1),
        "P0 gap batch must be contiguous: {gap_sequences:?}"
    );
    let gap_base = offset_of(&rt, &alice, &gid, 0).await;
    let mut gap_pending = Vec::new();
    for _ in 0..5 {
        gap_pending.push(
            rt.group_consume(&alice, &gid, &MemberId::from(MEMBER_A), generation)
                .await
                .unwrap()
                .expect("gap consume"),
        );
    }
    gap_pending.sort_by_key(|d| d.sequence);
    for (i, d) in gap_pending.iter().enumerate() {
        assert_eq!(d.sequence, gap_sequences[i]);
    }
    let mut resolved = BTreeMap::new();
    let ack_order = [0usize, 2, 4, 1, 3];
    let expected_steps = [
        gap_base + 1,
        gap_base + 1,
        gap_base + 1,
        gap_base + 3,
        gap_base + 5,
    ];
    for (step, &idx) in ack_order.iter().enumerate() {
        let d = &gap_pending[idx];
        rt.group_ack(
            &alice,
            &gid,
            &MemberId::from(MEMBER_A),
            generation,
            &d.delivery.delivery_id,
        )
        .await
        .unwrap();
        resolved.insert(d.sequence, ());
        let high = gap_pending.last().unwrap().sequence;
        let expected = expected_contiguous_offset(&resolved, gap_base, high);
        assert_eq!(expected, expected_steps[step], "step {step}");
        assert_eq!(offset_of(&rt, &alice, &gid, 0).await, expected);
    }

    // --- 5. DLQ contiguous semantics (fresh P0 batch before bulk load) ---
    let dlq_sequences = append_p0_sequential(&rt, &admin, 4).await;
    let mut dlq_batch = Vec::new();
    for _ in 0..4 {
        dlq_batch.push(
            rt.group_consume(&alice, &gid, &MemberId::from(MEMBER_A), generation)
                .await
                .unwrap()
                .expect("dlq batch"),
        );
    }
    dlq_batch.sort_by_key(|d| d.sequence);
    for (i, d) in dlq_batch.iter().enumerate() {
        assert_eq!(d.sequence, dlq_sequences[i]);
        assert_eq!(d.delivery.attempt, 1);
    }
    rt.group_ack(
        &alice,
        &gid,
        &MemberId::from(MEMBER_A),
        generation,
        &dlq_batch[0].delivery.delivery_id,
    )
    .await
    .unwrap();
    let mut fill_pending = Vec::new();
    for _ in 0..(MAX_IN_FLIGHT as usize - 3) {
        append_p0_sequential(&rt, &admin, 1).await;
        fill_pending.push(
            rt.group_consume(&alice, &gid, &MemberId::from(MEMBER_A), generation)
                .await
                .unwrap()
                .expect("fill P0 in-flight for retry redelivery"),
        );
    }
    let mut dlq_seq = dlq_batch[1].sequence;
    for _ in 0..2 {
        match rt
            .group_retry(
                &alice,
                &gid,
                &MemberId::from(MEMBER_A),
                generation,
                &dlq_batch[1].delivery.delivery_id,
            )
            .await
            .unwrap()
        {
            GroupRetryResponse::Retry(r) => {
                let now_ms = r.retry_at_ms;
                rt.set_now_ms(Some(now_ms)).await;
                let d = rt
                    .group_consume(&alice, &gid, &MemberId::from(MEMBER_A), generation)
                    .await
                    .unwrap()
                    .expect("redelivery for dlq");
                dlq_batch[1] = d;
            }
            GroupRetryResponse::Dlq(r) => {
                dlq_seq = r.sequence;
                break;
            }
        }
    }
    match rt
        .group_retry(
            &alice,
            &gid,
            &MemberId::from(MEMBER_A),
            generation,
            &dlq_batch[1].delivery.delivery_id,
        )
        .await
        .unwrap()
    {
        GroupRetryResponse::Dlq(_) => {}
        other => panic!("expected final Dlq, got {other:?}"),
    }
    rt.group_ack(
        &alice,
        &gid,
        &MemberId::from(MEMBER_A),
        generation,
        &dlq_batch[2].delivery.delivery_id,
    )
    .await
    .unwrap();
    rt.group_ack(
        &alice,
        &gid,
        &MemberId::from(MEMBER_A),
        generation,
        &dlq_batch[3].delivery.delivery_id,
    )
    .await
    .unwrap();
    assert!(
        rt.get_group_dlq_entry(&alice, &gid, 0, dlq_seq)
            .await
            .is_ok()
    );
    assert!(offset_of(&rt, &alice, &gid, 0).await >= dlq_batch[3].sequence);
    for d in fill_pending {
        rt.group_ack(
            &alice,
            &gid,
            &MemberId::from(MEMBER_A),
            generation,
            &d.delivery.delivery_id,
        )
        .await
        .unwrap();
    }

    // --- 6. Retry (P2 in-flight pressure + explicit retry/backoff) ---
    let mut retry_deliveries = Vec::new();
    for i in 0..MAX_IN_FLIGHT {
        append_on_partition(
            &rt,
            &admin,
            2,
            "company/audit",
            &format!("retry-{i}"),
        )
        .await;
        retry_deliveries.push(
            rt.group_consume(&carol, &gid, &MemberId::from(MEMBER_C), generation)
                .await
                .unwrap()
                .expect("retry batch consume"),
        );
    }
    let offset_retry_before = offset_of(&rt, &carol, &gid, 2).await;
    let retry_ev = &retry_deliveries[0];
    assert_eq!(retry_ev.partition_id, 2);
    assert_eq!(retry_ev.delivery.attempt, 1);
    let retry_id = retry_ev.delivery.delivery_id.clone();
    let retry = match rt
        .group_retry(
            &carol,
            &gid,
            &MemberId::from(MEMBER_C),
            generation,
            &retry_id,
        )
        .await
        .unwrap()
    {
        GroupRetryResponse::Retry(r) => r,
        other => panic!("expected Retry, got {other:?}"),
    };
    assert_eq!(retry.attempt, 1);
    assert_eq!(retry.sequence, retry_ev.sequence);
    assert_eq!(offset_of(&rt, &carol, &gid, 2).await, offset_retry_before);
    rt.set_now_ms(Some(retry.retry_at_ms.saturating_sub(1)))
        .await;
    let err = rt
        .group_consume(&carol, &gid, &MemberId::from(MEMBER_C), generation)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::GroupRetryBackoff { .. }), "got {err}");
    rt.set_now_ms(Some(retry.retry_at_ms)).await;
    let retry_redelivered = rt
        .group_consume(&carol, &gid, &MemberId::from(MEMBER_C), generation)
        .await
        .unwrap()
        .expect("retry redelivery");
    assert_eq!(retry_redelivered.sequence, retry_ev.sequence);
    assert_eq!(retry_redelivered.delivery.attempt, 2);
    assert_ne!(retry_redelivered.delivery.delivery_id, retry_id);
    rt.group_ack(
        &carol,
        &gid,
        &MemberId::from(MEMBER_C),
        generation,
        &retry_redelivered.delivery.delivery_id,
    )
    .await
    .unwrap();
    for d in retry_deliveries.iter().skip(1) {
        rt.group_ack(
            &carol,
            &gid,
            &MemberId::from(MEMBER_C),
            generation,
            &d.delivery.delivery_id,
        )
        .await
        .unwrap();
    }

    // --- 2. Bulk produce 12k+ events ---
    let produced = put_dod_events(&rt, &admin).await;
    assert_eq!(produced, TOTAL_EVENTS);

    let sub = rt.create_subscription(&alice, &stream, None).await.unwrap();
    let replayed = replay_evt_view(&rt, &sub.id, (TOTAL_EVENTS as usize) + 500).await;
    assert_eq!(replayed.len(), TOTAL_EVENTS as usize);
    let sequences: Vec<u64> = replayed.iter().map(|e| e.sequence).collect();
    assert_global_sequence_ordering_contract(&sequences);
    assert_no_duplicate_sequences(&sequences);
    let event_ids: HashSet<_> = replayed.iter().map(|e| e.event_id.as_str()).collect();
    assert_eq!(event_ids.len(), TOTAL_EVENTS as usize);
    for (i, ev) in replayed.iter().enumerate() {
        assert_eq!(ev.payload, format!("evt-{i}").as_bytes());
    }
    assert_aad_excludes_partition_id(
        "company/finance/route-0",
        sequences[0],
        1,
        dmc_journal::JournalEventKind::OverlayApply,
    );

    let sample_seqs: Vec<u64> = sequences.iter().take(5).copied().collect();
    let crypto_before = crypto_fingerprints_for_sequences(&journal, PARTS, &sample_seqs);

    // --- 3. Multi-pending consume (P0 / member-a) ---
    let offset_before_consume = offset_of(&rt, &alice, &gid, 0).await;
    let mut p0_pending = Vec::new();
    for _ in 0..MAX_IN_FLIGHT {
        p0_pending.push(
            rt.group_consume(&alice, &gid, &MemberId::from(MEMBER_A), generation)
                .await
                .unwrap()
                .expect("P0 event"),
        );
    }
    assert_eq!(
        offset_of(&rt, &alice, &gid, 0).await,
        offset_before_consume,
        "consume must not move GroupOffset"
    );
    for d in &p0_pending {
        rt.group_ack(
            &alice,
            &gid,
            &MemberId::from(MEMBER_A),
            generation,
            &d.delivery.delivery_id,
        )
        .await
        .unwrap();
    }

    // --- 5. Crash recovery (3 pending on P0) ---
    let mut crash_pending = Vec::new();
    for _ in 0..3 {
        crash_pending.push(
            rt.group_consume(&alice, &gid, &MemberId::from(MEMBER_A), generation)
                .await
                .unwrap()
                .expect("crash pending"),
        );
    }
    let crash_meta: Vec<_> = crash_pending
        .iter()
        .map(|d| {
            (
                d.sequence,
                d.event_id.clone(),
                d.delivery.delivery_id.clone(),
                d.delivery.attempt,
            )
        })
        .collect();
    rt.lock().await.unwrap();
    set_test_partition_count(Some(PARTS));
    set_test_segment_max_bytes(Some(900));
    let rt = Runtime::at_path(store.clone());
    rt.set_now_ms(Some(BASE_NOW)).await;
    rt.unlock(&master).await.unwrap();
    let alice = rt.open_user_session("alice", Some("dev-a2")).await.unwrap();
    let bob = rt.open_user_session("bob", Some("dev-b2")).await.unwrap();
    let carol = rt.open_user_session("carol", Some("dev-c2")).await.unwrap();
    let gen_after_crash = rt.describe_group(&alice, &gid).await.unwrap().generation;
    let mut crash_redelivered = Vec::new();
    for (seq, event_id, old_id, old_attempt) in crash_meta {
        let d = rt
            .group_consume(&alice, &gid, &MemberId::from(MEMBER_A), gen_after_crash)
            .await
            .unwrap()
            .expect("redelivery");
        assert_eq!(d.sequence, seq);
        assert_eq!(d.event_id, event_id);
        assert!(d.delivery.attempt > old_attempt);
        assert_ne!(d.delivery.delivery_id, old_id);
        let err = rt
            .group_ack(
                &alice,
                &gid,
                &MemberId::from(MEMBER_A),
                gen_after_crash,
                &old_id,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::StaleDelivery(_)), "got {err}");
        crash_redelivered.push(d);
    }
    for d in crash_redelivered {
        rt.group_ack(
            &alice,
            &gid,
            &MemberId::from(MEMBER_A),
            gen_after_crash,
            &d.delivery.delivery_id,
        )
        .await
        .unwrap();
    }

    // --- 6–7. Rebalance: B leaves, redelivery on P1 ---
    let gen_before_rebalance = rt.describe_group(&alice, &gid).await.unwrap().generation;
    let p1_before = offset_of(&rt, &alice, &gid, 1).await;
    let d_p1 = rt
        .group_consume(&bob, &gid, &MemberId::from(MEMBER_B), gen_before_rebalance)
        .await
        .unwrap()
        .expect("P1 pending before leave");
    assert_eq!(d_p1.partition_id, 1);
    let old_p1_delivery = d_p1.delivery.delivery_id.clone();
    let old_p1_gen = d_p1.delivery.generation;
    rt.leave_group(&bob, &gid, &MemberId::from(MEMBER_B))
        .await
        .unwrap();
    let desc = rt.describe_group(&alice, &gid).await.unwrap();
    assert_eq!(desc.generation, gen_before_rebalance + 1);
    assert!(!desc.members.iter().any(|m| m.member_id.as_str() == MEMBER_B));
    let p1_owner = owner_of(&desc, 1);
    assert!(
        p1_owner.as_str() == MEMBER_A || p1_owner.as_str() == MEMBER_C,
        "P1 owner {p1_owner:?}"
    );
    assert_eq!(offset_of(&rt, &alice, &gid, 1).await, p1_before);
    let err = rt
        .group_ack(
            &bob,
            &gid,
            &MemberId::from(MEMBER_B),
            old_p1_gen,
            &old_p1_delivery,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::StaleGeneration { .. }
                | Error::StaleDelivery(_)
                | Error::UnknownMember(_)
        ),
        "got {err}"
    );
    let gen_reb = desc.generation;
    let session_reb = if p1_owner.as_str() == MEMBER_A {
        &alice
    } else {
        &carol
    };
    let redelivered = rt
        .group_consume(session_reb, &gid, &p1_owner, gen_reb)
        .await
        .unwrap()
        .expect("P1 redelivery");
    assert_eq!(redelivered.sequence, d_p1.sequence);
    assert_eq!(redelivered.event_id, d_p1.event_id);
    assert_ne!(redelivered.delivery.delivery_id, old_p1_delivery);
    assert_eq!(redelivered.delivery.generation, gen_reb);
    assert!(redelivered.delivery.attempt >= d_p1.delivery.attempt + 1);
    rt.group_ack(
        session_reb,
        &gid,
        &p1_owner,
        gen_reb,
        &redelivered.delivery.delivery_id,
    )
    .await
    .unwrap();

    // --- 10. Compaction ---
    let admin = rt.admin_session().await.unwrap();
    let before_compaction = replay_evt_view(&rt, &sub.id, COMPACTION_SAMPLE).await;
    compact_all_partitions(&rt, &admin).await;
    let after_compaction = replay_evt_view(&rt, &sub.id, COMPACTION_SAMPLE).await;
    assert_event_views_equivalent(&before_compaction, &after_compaction);
    let crypto_after = crypto_fingerprints_for_sequences(&journal, PARTS, &sample_seqs);
    for seq in &sample_seqs {
        assert_crypto_fingerprints_equal(
            crypto_before.get(seq).expect("before"),
            crypto_after.get(seq).expect("after"),
        );
    }

    // --- 11. GC (journal trim; group metadata survives) ---
    rt.set_now_ms(Some(u64::MAX / 2)).await;
    while let Some(pending) = rt.pending_delivery(&sub.id).await.unwrap() {
        rt.ack(&alice, &sub.id, &pending.last_delivery_id)
            .await
            .unwrap();
    }
    let _snap_pin = rt.force_snapshot().await.unwrap();
    for _ in 0..20 {
        let batch = rt.consume(&sub.id, 1).await.unwrap();
        if batch.is_empty() {
            break;
        }
        rt.ack(&alice, &sub.id, &batch[0].delivery.delivery_id)
            .await
            .unwrap();
    }
    let consumer_ack = rt.get_subscription(&sub.id).await.unwrap().position.sequence;
    let replay_from = consumer_ack.saturating_sub(5);
    let lease = rt
        .begin_replay_lease(&sub.id, replay_from, 60_000)
        .await
        .unwrap();
    assert!(
        rt.retention_watermark()
            .await
            .unwrap()
            .trim_through
            .is_some()
    );
    rt.end_replay_lease(&lease).await.unwrap();
    rt.set_now_ms(None).await;

    let head_before = rt.last_sequence().await;
    let trim = rt.trim_journal().await.unwrap();
    assert!(!trim.deleted_segments.is_empty());
    let oldest = rt.oldest_available_sequence().await.unwrap();
    let dlq_before_gc = rt.list_group_dlq(&alice, &gid).await.unwrap().len();
    let offsets_before_gc = rt.describe_group(&alice, &gid).await.unwrap().offsets.clone();
    assert!(dlq_before_gc > 0);
    assert!(manifest.is_file());

    // --- 12. HistoryUnavailable + group ops still work ---
    rt.set_now_ms(Some(BASE_NOW + 10_000)).await;
    let desc_after_gc = rt.describe_group(&alice, &gid).await.unwrap();
    if !desc_after_gc
        .members
        .iter()
        .any(|m| m.member_id.as_str() == MEMBER_A)
    {
        rt.join_group(&alice, &gid, MemberId::from(MEMBER_A), None)
            .await
            .unwrap();
    }
    if !desc_after_gc
        .members
        .iter()
        .any(|m| m.member_id.as_str() == MEMBER_C)
    {
        rt.join_group(&carol, &gid, MemberId::from(MEMBER_C), None)
            .await
            .unwrap();
    }
    if oldest > 1 {
        let bad_from = oldest - 1;
        let err = rt.replay(&sub.id, bad_from, 10).await.unwrap_err();
        assert_history_unavailable(err, bad_from, oldest);
    }
    let gen_live = rt.describe_group(&alice, &gid).await.unwrap().generation;
    assert!(
        rt.group_consume(&alice, &gid, &MemberId::from(MEMBER_A), gen_live)
            .await
            .unwrap()
            .is_some()
            || rt
                .group_consume(&carol, &gid, &MemberId::from(MEMBER_C), gen_live)
                .await
                .unwrap()
                .is_some()
    );
    assert_eq!(
        rt.list_group_dlq(&alice, &gid).await.unwrap().len(),
        dlq_before_gc
    );
    assert_eq!(
        rt.describe_group(&alice, &gid).await.unwrap().offsets,
        offsets_before_gc
    );

    // --- 13. Final kill -9 snapshot ---
    let snapshot_before = capture_snapshot(&rt, &alice, &gid).await;
    rt.lock().await.unwrap();
    set_test_partition_count(Some(PARTS));
    set_test_segment_max_bytes(Some(900));
    let rt2 = Runtime::at_path(store.clone());
    rt2.set_now_ms(Some(BASE_NOW + 10_000)).await;
    rt2.unlock(&master).await.unwrap();
    let alice2 = rt2.open_user_session("alice", Some("dev-a-final")).await.unwrap();
    let snapshot_after = capture_snapshot(&rt2, &alice2, &gid).await;
    assert_snapshot_eq(&snapshot_before, &snapshot_after);
    assert_eq!(rt2.last_sequence().await, head_before);
    assert_eq!(rt2.oldest_available_sequence().await.unwrap(), oldest);

    // --- 14. Merge replay ---
    let merged: Vec<u64> = rt2
        .replay(&sub.id, oldest, 5000)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.payload.starts_with(b"evt-"))
        .map(|e| e.sequence)
        .collect();
    assert!(!merged.is_empty());
    assert_global_sequence_ordering_contract(&merged);

    let stored = read_manifest(&manifest).unwrap().expect("manifest");
    assert!(stored.generation >= 1);
    assert_manifest_partition_topology(&manifest, PARTS);

    // --- 15. Final contract assertions ---
    assert_journal_position_global_only(JournalPosition {
        sequence: offset_of(&rt2, &alice2, &gid, 0).await,
    });
    for off in &snapshot_after.offsets {
        assert_journal_position_global_only(JournalPosition {
            sequence: off.1,
        });
    }
    assert!(TOTAL_EVENTS >= 12_000);
    assert_eq!(MAX_IN_FLIGHT, 8);
    assert_eq!(PARTS, 3);
}
