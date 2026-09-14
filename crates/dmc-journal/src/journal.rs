use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;

thread_local! {
    static SEGMENT_MAX_OVERRIDE: Cell<Option<u64>> = const { Cell::new(None) };
    static PARTITION_COUNT_OVERRIDE: Cell<Option<u32>> = const { Cell::new(None) };
}

/// Test hook: override journal segment size for the current thread.
pub fn set_test_segment_max_bytes(max: Option<u64>) {
    SEGMENT_MAX_OVERRIDE.with(|c| c.set(max));
}

/// Test hook: override journal partition count for the current thread.
pub fn set_test_partition_count(count: Option<u32>) {
    PARTITION_COUNT_OVERRIDE.with(|c| c.set(count));
}

fn configured_segment_max(default: u64) -> u64 {
    if let Some(n) = SEGMENT_MAX_OVERRIDE.with(|c| c.get()) {
        return n;
    }
    if let Ok(raw) = std::env::var("DMC_JOURNAL_SEGMENT_MAX_BYTES") {
        if let Ok(n) = raw.parse::<u64>() {
            return n;
        }
    }
    default
}

fn configured_partition_count(default: u32) -> u32 {
    if let Some(n) = PARTITION_COUNT_OVERRIDE.with(|c| c.get()) {
        return n.max(1);
    }
    if let Ok(raw) = std::env::var("DMC_JOURNAL_PARTITION_COUNT") {
        if let Ok(n) = raw.parse::<u32>() {
            return n.max(1);
        }
    }
    default.max(1)
}

use dmc_vault::crypto::derive_journal_kek;
use dmc_vault::key::{KeyMaterial, KeyTree};

use crate::authoritative::authoritative_segment_ids;
use crate::codec::{
    decode_segment_footer, decode_segment_header, encode_entry, encode_footer,
    encode_segment_header, now_unix_ms, scan_segment, validate_sealed_segment,
    SegmentHeader,
};
use crate::compaction::{
    CompactionArtifact, CompactionCandidate, CompactionPolicy,
    select_compaction_candidate, select_compaction_candidate_for_partition,
};
use crate::compaction_publish::publish_compaction_artifact;
use crate::compaction_write::write_compaction_artifact;
use crate::crash_injection::{maybe_crash, maybe_crash_gc_after_deleted, CrashPoint};
use crate::error::{Error, Result};
use crate::journal_manifest::JournalManifest;
use crate::journal_manifest_v2::{
    authoritative_journal_head_from_manifest, discover_segment_partitions,
    manifest_active_segment_legacy, manifest_active_segments, manifest_v2_from_segment_infos,
    publish_stored_manifest, read_stored_manifest, segment_manifest_path,
    validate_stored_manifest, v2_to_stored, JournalManifestV2, StoredJournalManifest,
};
use crate::reconciliation::{
    inspect_reconciliation, reconcile, JournalReconciliation, JournalReconciliationResult,
};
use crate::layout::{
    discover_partition_active_segments, ensure_partition_dir, is_partitioned_layout,
    list_segment_ids, partition_data_dir, resolve_segment_path, segment_path_for_partition,
    StorageLayout,
};
use crate::meta::JournalMeta;
use crate::partition::{resolve_partition, PartitionId};
use crate::retention::{age_trim_through, bytes_trim_through, combine_trim_through};
use crate::lifecycle::{is_gc_eligible, SegmentDisposition};
use crate::segment::{
    JournalSegmentInfo, PartitionTrimCandidate, SegmentState, TrimResult,
};
use crate::topology::{JournalTopology, JournalTopologyGuard};
use crate::types::{
    journal_key_id, FsyncPolicy, JournalConfig, JournalEntry, JournalEntryDraft, JournalEntryRef,
    RecoveryReport, SEGMENT_FOOTER_LEN, SEGMENT_HEADER_LEN,
};

struct PartitionRuntime {
    segment_bytes: u64,
    entries_in_segment: u64,
    segment_last_sequence: u64,
}

pub struct Journal {
    layout: StorageLayout,
    config: JournalConfig,
    meta: JournalMeta,
    journal_key_id: [u8; 16],
    writer: Option<BufWriter<File>>,
    active_path: PathBuf,
    open_partition: Option<u32>,
    partition_runtime: HashMap<u32, PartitionRuntime>,
    last_sequence: u64,
    entries_in_segment: u64,
    segment_bytes: u64,
    segment_last_sequence: u64,
    topology: JournalTopology,
}

impl Journal {
    pub fn open(config: JournalConfig, journal_kek: &KeyMaterial) -> Result<Self> {
        let layout = StorageLayout {
            data_dir: config
                .dir
                .parent()
                .map(|p| {
                    if p.ends_with("journal") {
                        p.parent().unwrap_or(p).to_path_buf()
                    } else {
                        config.dir.parent().unwrap_or(p).to_path_buf()
                    }
                })
                .unwrap_or_else(|| config.dir.clone()),
            legacy_name: "store.dbs.json".into(),
        };
        // config.dir is the journal directory itself
        fs::create_dir_all(&config.dir).map_err(Error::io)?;
        let mut journal = Self {
            layout: StorageLayout {
                data_dir: config
                    .dir
                    .parent()
                    .unwrap_or(std::path::Path::new("."))
                    .to_path_buf(),
                legacy_name: "store.dbs.json".into(),
            },
            config,
            meta: JournalMeta::default(),
            journal_key_id: journal_key_id(journal_kek),
            writer: None,
            active_path: PathBuf::new(),
            open_partition: None,
            partition_runtime: HashMap::new(),
            last_sequence: 0,
            entries_in_segment: 0,
            segment_bytes: 0,
            segment_last_sequence: 0,
            topology: JournalTopology::new(),
        };
        journal.layout = StorageLayout {
            data_dir: journal
                .config
                .dir
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .to_path_buf(),
            legacy_name: "store.dbs.json".into(),
        };
        let _ = layout;
        journal.recover()?;
        if journal.partition_count() <= 1 {
            journal.open_writer_for(PartitionId(0))?;
        }
        Ok(journal)
    }

    pub fn partition_count(&self) -> u32 {
        self.config.partition_count.max(1)
    }

    fn active_segments(&self) -> Vec<u64> {
        self.meta.all_active_segments()
    }

    fn save_open_partition_state(&mut self) {
        if let Some(pid) = self.open_partition {
            self.partition_runtime.insert(
                pid,
                PartitionRuntime {
                    segment_bytes: self.segment_bytes,
                    entries_in_segment: self.entries_in_segment,
                    segment_last_sequence: self.segment_last_sequence,
                },
            );
        }
    }

    fn restore_partition_state(&mut self, partition_id: PartitionId) {
        if let Some(state) = self.partition_runtime.get(&partition_id.as_u32()) {
            self.segment_bytes = state.segment_bytes;
            self.entries_in_segment = state.entries_in_segment;
            self.segment_last_sequence = state.segment_last_sequence;
        } else {
            self.segment_bytes = 0;
            self.entries_in_segment = 0;
            self.segment_last_sequence = 0;
        }
    }

    fn close_writer(&mut self) {
        self.save_open_partition_state();
        self.writer.take();
        self.open_partition = None;
        self.active_path = PathBuf::new();
    }

    pub fn open_in_layout(layout: &StorageLayout, journal_kek: &KeyMaterial) -> Result<Self> {
        Self::open(JournalConfig::new(layout.journal_dir()), journal_kek)
    }

    pub fn from_master(layout: &StorageLayout, master: &KeyMaterial, salt: &[u8]) -> Result<Self> {
        let kek = derive_journal_kek(master, salt);
        let mut config = JournalConfig::new(layout.journal_dir());
        let max_bytes = configured_segment_max(config.segment_max_bytes);
        let partition_count = configured_partition_count(config.partition_count);
        config = config
            .with_segment_max_bytes(max_bytes)
            .with_partition_count(partition_count);
        Self::open(config, &kek)
    }

    pub fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    /// Aggregate retention pins. Does not delete data (Phase 5.1).
    pub fn retention_watermark(&self, pins: &[&dyn crate::watermark::JournalPin]) -> crate::watermark::RetentionWatermark {
        crate::watermark::calculate_watermark(pins.iter().copied())
    }

    /// Phase 5.5: dynamic retention pin from policy limits (does not delete segments).
    pub fn retention_policy_trim_through(
        &self,
        max_age_ms: Option<u64>,
        max_bytes: Option<u64>,
        now_ms: u64,
    ) -> Result<Option<u64>> {
        if max_age_ms.is_none() && max_bytes.is_none() {
            return Ok(None);
        }
        let segments = self.segment_infos()?;
        let read = |id: u64| {
            let path = resolve_segment_path(&self.config.dir, id);
            std::fs::read(&path).map_err(Error::io)
        };
        let age = match max_age_ms {
            Some(age) => {
                let cutoff = now_ms.saturating_sub(age);
                age_trim_through(&segments, read, cutoff)?
            }
            None => None,
        };
        let bytes = max_bytes.and_then(|max| bytes_trim_through(&segments, max));
        Ok(combine_trim_through(age, bytes))
    }

    /// Phase 5.6.1 / 5.7.8: select sealed segment chain for compaction (ignores retention pins).
    pub fn select_compaction_candidate(
        &self,
        policy: &CompactionPolicy,
    ) -> Result<Option<CompactionCandidate>> {
        let infos = self.segment_infos()?;
        let segment_partitions =
            discover_segment_partitions(&self.config.dir, self.partition_count())?;
        Ok(select_compaction_candidate(
            &infos,
            &segment_partitions,
            self.partition_count(),
            policy,
        ))
    }

    /// Phase 5.7.8: select compaction candidate within one partition.
    pub fn select_compaction_candidate_for_partition(
        &self,
        partition_id: PartitionId,
        policy: &CompactionPolicy,
    ) -> Result<Option<CompactionCandidate>> {
        let infos = self.segment_infos()?;
        let segment_partitions =
            discover_segment_partitions(&self.config.dir, self.partition_count())?;
        Ok(select_compaction_candidate_for_partition(
            &infos,
            &segment_partitions,
            partition_id,
            policy,
        ))
    }

    /// Phase 5.6.2 / 5.7.8: write physical compaction artifact (orphan until manifest publication).
    pub fn compact_candidate(&self, candidate: &CompactionCandidate) -> Result<CompactionArtifact> {
        let infos = self.segment_infos()?;
        write_compaction_artifact(
            &self.config.dir,
            self.journal_key_id,
            self.partition_count(),
            candidate,
            &infos,
        )
    }

    fn journal_runtime_dir(&self) -> PathBuf {
        self.config
            .dir
            .parent()
            .unwrap_or(self.config.dir.as_path())
            .join("runtime")
            .join("journal")
    }

    fn journal_manifest_path(&self) -> PathBuf {
        self.journal_runtime_dir().join("manifest.json")
    }

    /// Read the published journal manifest, if any (`manifest.tmp` ignored).
    pub fn read_journal_manifest(&self) -> Result<Option<JournalManifest>> {
        Ok(read_stored_manifest(&self.journal_manifest_path())?.map(|m| m.as_v1_flat()))
    }

    /// Read V2 or V1 stored manifest.
    pub fn read_stored_journal_manifest(&self) -> Result<Option<StoredJournalManifest>> {
        read_stored_manifest(&self.journal_manifest_path())
    }

    /// Bootstrap generation-1 V2 manifest from current authoritative topology (excludes orphans).
    pub fn bootstrap_journal_manifest(&self, generation: u64) -> Result<JournalManifestV2> {
        let infos = self.segment_infos()?;
        let segment_partitions =
            discover_segment_partitions(&self.config.dir, self.partition_count())?;
        let manifest = manifest_v2_from_segment_infos(
            generation,
            self.partition_count(),
            &segment_partitions,
            &infos,
        );
        let stored = v2_to_stored(manifest.clone());
        validate_stored_manifest(&stored, &self.config.dir, self.partition_count())?;
        fs::create_dir_all(self.journal_runtime_dir()).map_err(Error::io)?;
        publish_stored_manifest(&self.journal_runtime_dir(), &stored)?;
        Ok(manifest)
    }

    /// Phase 5.6.3: publish compaction artifact into authoritative manifest topology.
    pub fn publish_compaction(&mut self, artifact: &CompactionArtifact) -> Result<JournalManifest> {
        let _guard = self.begin_topology_mutation()?;
        let infos = self.segment_infos()?;
        publish_compaction_artifact(
            &self.config.dir,
            &self.journal_runtime_dir(),
            &self.journal_manifest_path(),
            artifact,
            &infos,
            self.partition_count(),
        )
    }

    /// Phase 5.6.4: classify authoritative vs non-authoritative on-disk files.
    pub fn inspect_reconciliation(&self) -> Result<JournalReconciliation> {
        inspect_reconciliation(
            &self.config.dir,
            &self.journal_manifest_path(),
            &self.journal_runtime_dir(),
            &self.active_segments(),
            self.partition_count(),
        )
    }

    /// Phase 5.6.4: remove temporary files only (no segment deletion).
    pub fn reconcile(&self) -> Result<JournalReconciliationResult> {
        reconcile(
            &self.config.dir,
            &self.journal_manifest_path(),
            &self.journal_runtime_dir(),
            &self.active_segments(),
            self.partition_count(),
        )
    }

    fn authoritative_segment_ids(&self) -> Result<Vec<u64>> {
        authoritative_segment_ids(
            &self.config.dir,
            &self.journal_manifest_path(),
            &self.active_segments(),
            self.partition_count(),
        )
    }

    /// Serialize topology mutations (trim / rotate / compaction).
    pub fn begin_topology_mutation(&self) -> Result<JournalTopologyGuard> {
        self.topology.begin_mutation()
    }

    pub fn topology(&self) -> &JournalTopology {
        &self.topology
    }

    /// Sealed authoritative and obsolete segments with `end_sequence <= trim_through`.
    /// Orphans and active segments are never eligible. Manifest-driven when published.
    pub fn eligible_segments(&self, trim_through: u64) -> Result<Vec<PartitionTrimCandidate>> {
        let manifest_path = self.journal_manifest_path();
        if manifest_path.is_file() {
            self.eligible_segments_from_manifest(trim_through)
        } else {
            self.eligible_segments_from_legacy(trim_through)
        }
    }

    fn eligible_segments_from_manifest(
        &self,
        trim_through: u64,
    ) -> Result<Vec<PartitionTrimCandidate>> {
        let journal_dir = &self.config.dir;
        let stored = read_stored_manifest(&self.journal_manifest_path())?
            .ok_or_else(|| Error::JournalManifestInconsistent("empty manifest".into()))?;
        validate_stored_manifest(&stored, journal_dir, self.partition_count())?;

        let active_by_partition: HashMap<PartitionId, u64> =
            manifest_active_segments(&stored)?.into_iter().collect();

        let mut candidates = Vec::new();
        for (pid, entry) in stored.all_segments() {
            if active_by_partition.get(&pid) == Some(&entry.segment_id) {
                continue;
            }
            if entry.state != SegmentState::Sealed {
                continue;
            }
            if is_gc_eligible(
                SegmentDisposition::Authoritative,
                true,
                entry.end_sequence,
                trim_through,
            ) {
                candidates.push(PartitionTrimCandidate {
                    partition_id: pid,
                    segment_id: entry.segment_id,
                    start_sequence: entry.start_sequence,
                    end_sequence: entry.end_sequence,
                    disposition: SegmentDisposition::Authoritative,
                });
            }
        }

        let segment_partitions =
            discover_segment_partitions(journal_dir, self.partition_count())?;
        for &id in stored.superseded_segment_ids() {
            let Some(path) = crate::layout::find_segment_path(journal_dir, id) else {
                continue;
            };
            let bytes = fs::read(&path).map_err(Error::io)?;
            if decode_segment_footer(&bytes).is_none() {
                continue;
            }
            let Ok((start, end, _, _)) = validate_sealed_segment(&bytes, id) else {
                continue;
            };
            if !is_gc_eligible(SegmentDisposition::Obsolete, true, end, trim_through) {
                continue;
            }
            let pid = segment_partitions.get(&id).copied().unwrap_or(PartitionId(0));
            candidates.push(PartitionTrimCandidate {
                partition_id: pid,
                segment_id: id,
                start_sequence: start,
                end_sequence: end,
                disposition: SegmentDisposition::Obsolete,
            });
        }

        candidates.sort_by_key(|c| (c.partition_id.as_u32(), c.segment_id));
        Ok(candidates)
    }

    fn eligible_segments_from_legacy(
        &self,
        trim_through: u64,
    ) -> Result<Vec<PartitionTrimCandidate>> {
        let journal_dir = &self.config.dir;
        let segment_partitions =
            discover_segment_partitions(journal_dir, self.partition_count())?;
        let active_set: HashSet<_> = self.active_segments().into_iter().collect();
        let mut candidates = Vec::new();

        for info in self.segment_infos()? {
            if active_set.contains(&info.id) {
                continue;
            }
            if is_gc_eligible(
                SegmentDisposition::Authoritative,
                info.state == SegmentState::Sealed,
                info.end_sequence,
                trim_through,
            ) {
                let pid = segment_partitions
                    .get(&info.id)
                    .copied()
                    .unwrap_or(PartitionId(0));
                candidates.push(PartitionTrimCandidate {
                    partition_id: pid,
                    segment_id: info.id,
                    start_sequence: info.start_sequence,
                    end_sequence: info.end_sequence,
                    disposition: SegmentDisposition::Authoritative,
                });
            }
        }

        candidates.sort_by_key(|c| (c.partition_id.as_u32(), c.segment_id));
        Ok(candidates)
    }

    /// First journal sequence still readable after GC (minimum start across authoritative segments).
    pub fn oldest_available_sequence(&self) -> Result<u64> {
        let infos = self.segment_infos()?;
        Ok(infos
            .iter()
            .map(|s| s.start_sequence)
            .min()
            .unwrap_or_else(|| self.meta.next_sequence.max(1)))
    }

    /// Delete whole sealed segments with `end_sequence <= through`. Idempotent.
    ///
    /// Removes authoritative sealed segments (retention GC) and obsolete superseded segments
    /// when allowed by `through`. Does not modify `superseded_segment_ids` in the manifest.
    pub fn trim_through(&mut self, through: u64) -> Result<TrimResult> {
        let _guard = self.topology.begin_mutation()?;
        let eligible = self.eligible_segments(through)?;
        maybe_crash(CrashPoint::BeforeGc)?;
        let journal_dir = self.config.dir.clone();
        let partition_count = self.partition_count();
        let mut deleted = Vec::new();
        let mut touched_partitions = HashSet::new();

        for seg in eligible {
            let path = if is_partitioned_layout(partition_count) {
                segment_path_for_partition(
                    &journal_dir,
                    seg.partition_id,
                    seg.segment_id,
                    partition_count,
                )
            } else {
                resolve_segment_path(&journal_dir, seg.segment_id)
            };
            if path.is_file() {
                fs::remove_file(&path).map_err(Error::io)?;
                deleted.push(seg.segment_id);
                touched_partitions.insert(seg.partition_id);
                maybe_crash_gc_after_deleted(seg.segment_id)?;
            }
        }

        sync_trim_dirs(&journal_dir, partition_count, &touched_partitions)?;
        maybe_crash(CrashPoint::AfterGc)?;

        let retained: Vec<u64> = self.segment_infos()?.into_iter().map(|s| s.id).collect();
        Ok(TrimResult {
            trim_through: through,
            deleted_segments: deleted,
            retained_segments: retained,
        })
    }

    pub fn segment_infos(&self) -> Result<Vec<JournalSegmentInfo>> {
        let journal_dir = &self.config.dir;
        let manifest_path = self.journal_manifest_path();
        if manifest_path.is_file() {
            let stored = read_stored_manifest(&manifest_path)?
                .ok_or_else(|| Error::JournalManifestInconsistent("empty manifest".into()))?;
            validate_stored_manifest(&stored, journal_dir, self.partition_count())?;
            let active_set: std::collections::HashSet<_> = manifest_active_segments(&stored)?
                .into_iter()
                .map(|(_, id)| id)
                .collect();
            let mut infos = Vec::new();
            for (pid, entry) in stored.all_segments() {
                let path = segment_manifest_path(
                    journal_dir,
                    self.partition_count(),
                    pid,
                    entry.segment_id,
                );
                let bytes = fs::read(&path).map_err(Error::io)?;
                if bytes.len() < SEGMENT_HEADER_LEN {
                    continue;
                }
                let header = decode_segment_header(&bytes[..SEGMENT_HEADER_LEN])?;
                let footer = decode_segment_footer(&bytes);
                let state = if footer.is_some() {
                    SegmentState::Sealed
                } else if active_set.contains(&entry.segment_id) {
                    SegmentState::Active
                } else {
                    entry.state
                };
                let (last_good, entries, last_seq) = scan_segment(&bytes)?;
                let end_sequence = footer.map(|(last, _)| last).unwrap_or(last_seq);
                infos.push(JournalSegmentInfo {
                    id: entry.segment_id,
                    start_sequence: header.first_sequence,
                    end_sequence,
                    state,
                    first_timestamp_unix_ms: entries
                        .first()
                        .map(|e| e.timestamp_unix_ms)
                        .or(Some(header.created_unix_ms)),
                    last_timestamp_unix_ms: entries
                        .last()
                        .map(|e| e.timestamp_unix_ms)
                        .or_else(|| entries.first().map(|e| e.timestamp_unix_ms)),
                    byte_size: last_good as u64,
                });
            }
            infos.sort_by_key(|s| s.id);
            return Ok(infos);
        }

        let ids = self.authoritative_segment_ids()?;
        let active_set: std::collections::HashSet<_> =
            self.active_segments().into_iter().collect();
        let mut infos = Vec::with_capacity(ids.len());
        for id in ids {
            let path = resolve_segment_path(journal_dir, id);
            let bytes = fs::read(&path).map_err(Error::io)?;
            if bytes.len() < SEGMENT_HEADER_LEN {
                continue;
            }
            let header = decode_segment_header(&bytes[..SEGMENT_HEADER_LEN])?;
            let footer = decode_segment_footer(&bytes);
            let state = if footer.is_some() {
                SegmentState::Sealed
            } else if active_set.contains(&id) {
                SegmentState::Active
            } else {
                SegmentState::Active
            };
            let (last_good, entries, last_seq) = scan_segment(&bytes)?;
            let end_sequence = if let Some((last, _)) = footer {
                last
            } else {
                last_seq
            };
            let first_timestamp_unix_ms = entries
                .first()
                .map(|e| e.timestamp_unix_ms)
                .or(Some(header.created_unix_ms));
            let last_timestamp_unix_ms = entries
                .last()
                .map(|e| e.timestamp_unix_ms)
                .or(first_timestamp_unix_ms);
            infos.push(JournalSegmentInfo {
                id,
                start_sequence: header.first_sequence,
                end_sequence,
                state,
                first_timestamp_unix_ms,
                last_timestamp_unix_ms,
                byte_size: last_good as u64,
            });
        }
        infos.sort_by_key(|s| s.id);
        Ok(infos)
    }

    pub fn next_sequence(&self) -> u64 {
        self.meta.next_sequence
    }

    fn maybe_bootstrap_manifest(&mut self) -> Result<bool> {
        let manifest_path = self.journal_manifest_path();
        if manifest_path.is_file() {
            return Ok(false);
        }
        let journal_dir = &self.config.dir;
        let all_ids = list_segment_ids(journal_dir)?;
        if all_ids.is_empty() {
            return Ok(false);
        }
        if self.partition_count() > 1 {
            let discovered =
                discover_partition_active_segments(journal_dir, self.partition_count())?;
            for (pid, seg_id) in discovered.iter().enumerate() {
                if *seg_id > 0 {
                    self.meta
                        .set_active_segment_for(PartitionId(pid as u32), *seg_id);
                }
            }
        } else if self.meta.active_segment == 0 {
            self.meta.active_segment = all_ids.iter().max().copied().unwrap_or(1);
            self.meta.set_active_segment_for(PartitionId(0), self.meta.active_segment);
        }
        let active = self.active_segments();
        let auth_ids = crate::authoritative::legacy_authoritative_segment_ids(journal_dir, &active)?;
        if auth_ids.is_empty() {
            return Ok(false);
        }
        let segment_partitions =
            discover_segment_partitions(journal_dir, self.partition_count())?;
        let infos = self.segment_infos_from_ids(&auth_ids, &segment_partitions)?;
        let manifest = manifest_v2_from_segment_infos(
            1,
            self.partition_count(),
            &segment_partitions,
            &infos,
        );
        let stored = v2_to_stored(manifest);
        validate_stored_manifest(&stored, journal_dir, self.partition_count())?;
        fs::create_dir_all(self.journal_runtime_dir()).map_err(Error::io)?;
        publish_stored_manifest(&self.journal_runtime_dir(), &stored)?;
        Ok(true)
    }

    fn segment_infos_from_ids(
        &self,
        ids: &[u64],
        segment_partitions: &std::collections::HashMap<u64, PartitionId>,
    ) -> Result<Vec<JournalSegmentInfo>> {
        let journal_dir = &self.config.dir;
        let active_set: std::collections::HashSet<_> =
            self.active_segments().into_iter().collect();
        let mut infos = Vec::with_capacity(ids.len());
        for &id in ids {
            let pid = segment_partitions.get(&id).copied().unwrap_or(PartitionId(0));
            let path = segment_manifest_path(journal_dir, self.partition_count(), pid, id);
            let bytes = fs::read(&path).map_err(Error::io)?;
            if bytes.len() < SEGMENT_HEADER_LEN {
                continue;
            }
            let header = decode_segment_header(&bytes[..SEGMENT_HEADER_LEN])?;
            let footer = decode_segment_footer(&bytes);
            let state = if footer.is_some() {
                SegmentState::Sealed
            } else if active_set.contains(&id) {
                SegmentState::Active
            } else {
                SegmentState::Active
            };
            let (last_good, entries, last_seq) = scan_segment(&bytes)?;
            let end_sequence = footer.map(|(last, _)| last).unwrap_or(last_seq);
            infos.push(JournalSegmentInfo {
                id,
                start_sequence: header.first_sequence,
                end_sequence,
                state,
                first_timestamp_unix_ms: entries
                    .first()
                    .map(|e| e.timestamp_unix_ms)
                    .or(Some(header.created_unix_ms)),
                last_timestamp_unix_ms: entries
                    .last()
                    .map(|e| e.timestamp_unix_ms)
                    .or_else(|| entries.first().map(|e| e.timestamp_unix_ms)),
                byte_size: last_good as u64,
            });
        }
        infos.sort_by_key(|s| s.id);
        Ok(infos)
    }

    pub fn recover(&mut self) -> Result<RecoveryReport> {
        self.close_writer();
        let journal_dir = self.config.dir.clone();
        fs::create_dir_all(&journal_dir).map_err(Error::io)?;
        let meta_path = journal_dir.join("journal.meta");
        if let Ok(meta) = JournalMeta::load(&meta_path) {
            self.meta = meta;
        }
        self.meta
            .sync_partition_count(self.partition_count());

        let _bootstrapped = self.maybe_bootstrap_manifest()?;

        let manifest_path = self.journal_manifest_path();
        let has_manifest = manifest_path.is_file();

        if has_manifest {
            let stored = read_stored_manifest(&manifest_path)?
                .ok_or_else(|| Error::JournalManifestInconsistent("empty manifest".into()))?;
            validate_stored_manifest(&stored, &journal_dir, self.partition_count())?;
            for (pid, seg_id) in manifest_active_segments(&stored)? {
                self.meta.set_active_segment_for(pid, seg_id);
            }
            if self.partition_count() <= 1 {
                self.meta.active_segment = manifest_active_segment_legacy(&stored)?;
            }
        }

        let active_segments = self.active_segments();
        let auth_ids = if has_manifest {
            authoritative_segment_ids(
                &journal_dir,
                &manifest_path,
                &active_segments,
                self.partition_count(),
            )?
        } else {
            Vec::new()
        };
        let auth_set: std::collections::HashSet<_> = auth_ids.iter().copied().collect();

        let all_ids = list_segment_ids(&journal_dir)?;
        let max_segment_id = all_ids.iter().copied().max().unwrap_or(0);
        self.meta.next_segment_id = self
            .meta
            .next_segment_id
            .max(max_segment_id.saturating_add(1))
            .max(1);

        let mut report = RecoveryReport::default();
        let stored_manifest = if has_manifest {
            read_stored_manifest(&manifest_path)?
        } else {
            None
        };

        for id in &all_ids {
            report.segments_scanned += 1;
            if has_manifest && !auth_set.contains(id) {
                continue;
            }
            let path = if let Some(ref stored) = stored_manifest {
                stored
                    .segment_partition(*id)
                    .map(|pid| {
                        segment_manifest_path(
                            &journal_dir,
                            self.partition_count(),
                            pid,
                            *id,
                        )
                    })
                    .unwrap_or_else(|| resolve_segment_path(&journal_dir, *id))
            } else {
                resolve_segment_path(&journal_dir, *id)
            };
            let bytes = fs::read(&path).map_err(Error::io)?;
            if bytes.len() < SEGMENT_HEADER_LEN {
                continue;
            }
            if decode_segment_header(&bytes[..SEGMENT_HEADER_LEN]).is_err() {
                continue;
            }

            if has_manifest {
                if let Some(ref stored) = stored_manifest {
                    let entry = stored
                        .all_segments()
                        .into_iter()
                        .find(|(_, s)| s.segment_id == *id)
                        .ok_or_else(|| {
                            Error::JournalManifestInconsistent(format!(
                                "authoritative segment {id} missing from manifest"
                            ))
                        })?
                        .1;
                    if entry.state == SegmentState::Sealed {
                        validate_sealed_segment(&bytes, *id).map_err(|e| {
                            Error::JournalSegmentCorrupt(format!("segment {id}: {e}"))
                        })?;
                        continue;
                    }
                }
            }

            let (last_good, entries, _last_seq) = scan_segment(&bytes)?;
            let truncate_to = if decode_segment_footer(&bytes).is_some() {
                let footer_start = bytes.len().saturating_sub(SEGMENT_FOOTER_LEN);
                if last_good <= footer_start {
                    bytes.len()
                } else {
                    last_good
                }
            } else if last_good < bytes.len() {
                last_good
            } else {
                bytes.len()
            };
            if truncate_to < bytes.len() {
                let truncated = (bytes.len() - truncate_to) as u64;
                report.truncated_bytes += truncated;
                let file = OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .map_err(Error::io)?;
                file.set_len(truncate_to as u64).map_err(Error::io)?;
                file.sync_all().map_err(Error::io)?;
            }
            if active_segments.contains(id) {
                self.entries_in_segment = entries.len() as u64;
                self.segment_bytes = truncate_to as u64;
            }
        }

        let max_seq = if has_manifest {
            let stored = read_stored_manifest(&manifest_path)?.unwrap();
            authoritative_journal_head_from_manifest(&stored, &journal_dir)?
        } else {
            let auth_ids = authoritative_segment_ids(
                &journal_dir,
                &manifest_path,
                &self.active_segments(),
                self.partition_count(),
            )?;
            let mut max_seq = 0u64;
            for id in &auth_ids {
                let path = resolve_segment_path(&journal_dir, *id);
                let bytes = fs::read(&path).map_err(Error::io)?;
                if bytes.len() < SEGMENT_HEADER_LEN {
                    continue;
                }
                let (_last_good, _entries, last_seq) = scan_segment(&bytes)?;
                max_seq = max_seq.max(last_seq);
            }
            max_seq
        };

        report.last_valid_sequence = max_seq;
        self.last_sequence = max_seq;
        self.meta.next_sequence = max_seq.saturating_add(1).max(1);
        if self.meta.active_segment == 0 && self.partition_count() <= 1 {
            self.meta.active_segment = auth_ids.iter().max().copied().unwrap_or(1);
        } else if has_manifest
            && self.partition_count() <= 1
            && !auth_ids.contains(&self.meta.active_segment)
        {
            return Err(Error::JournalManifestInconsistent(
                "manifest active segment not in authoritative set".into(),
            ));
        }
        self.meta.last_fsync_seq = max_seq;
        self.meta.save(&meta_path)?;
        Ok(report)
    }

    fn open_writer_for(&mut self, partition_id: PartitionId) -> Result<()> {
        if self.open_partition == Some(partition_id.as_u32()) && self.writer.is_some() {
            return Ok(());
        }
        if self.writer.is_some() {
            self.close_writer();
        }
        self.restore_partition_state(partition_id);

        let journal_dir = &self.config.dir;
        ensure_partition_dir(journal_dir, partition_id, self.partition_count())?;
        let mut segment_id = self.meta.active_segment_for(partition_id);
        if segment_id == 0 {
            segment_id = self.meta.allocate_segment_id(
                list_segment_ids(journal_dir)?
                    .into_iter()
                    .max()
                    .unwrap_or(0),
            );
            self.meta.set_active_segment_for(partition_id, segment_id);
        }
        let path = segment_path_for_partition(
            journal_dir,
            partition_id,
            segment_id,
            self.partition_count(),
        );
        let exists = path.is_file();
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .append(true)
            .open(&path)
            .map_err(Error::io)?;
        if !exists || fs::metadata(&path).map(|m| m.len()).unwrap_or(0) < SEGMENT_HEADER_LEN as u64
        {
            let header = encode_segment_header(&SegmentHeader {
                segment_id,
                first_sequence: self.meta.next_sequence.max(1),
                created_unix_ms: now_unix_ms(),
                journal_key_id: self.journal_key_id,
            });
            let mut w = BufWriter::new(file);
            w.write_all(&header).map_err(Error::io)?;
            w.flush().map_err(Error::io)?;
            w.get_ref().sync_all().map_err(Error::io)?;
            self.segment_bytes = SEGMENT_HEADER_LEN as u64;
            self.entries_in_segment = 0;
            self.segment_last_sequence = 0;
            self.writer = Some(w);
        } else {
            let len = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            self.segment_bytes = len;
            let bytes = fs::read(&path).map_err(Error::io)?;
            let (_last_good, _entries, last_seq) = scan_segment(&bytes)?;
            self.segment_last_sequence = last_seq;
            self.writer = Some(BufWriter::new(file));
        }
        self.active_path = path;
        self.open_partition = Some(partition_id.as_u32());
        Ok(())
    }

    pub fn append(
        &mut self,
        draft: JournalEntryDraft,
        path_dek: &KeyMaterial,
    ) -> Result<JournalEntryRef> {
        let partition = resolve_partition(
            &draft.path,
            draft.partition_key.as_ref(),
            self.partition_count(),
        )?;
        if self.writer.is_none() || self.open_partition != Some(partition.as_u32()) {
            self.open_writer_for(partition)?;
        }
        if self.segment_bytes >= self.config.segment_max_bytes && self.entries_in_segment > 0 {
            self.rotate_segment()?;
        }
        let sequence = self.meta.next_sequence;
        let (bytes, event_id) = encode_entry(&draft, sequence, path_dek)?;
        {
            let w = self.writer.as_mut().ok_or_else(|| Error::format("no writer"))?;
            w.write_all(&bytes).map_err(Error::io)?;
        }
        self.segment_bytes += bytes.len() as u64;
        self.entries_in_segment += 1;
        self.last_sequence = sequence;
        self.segment_last_sequence = sequence;
        self.meta.next_sequence = sequence + 1;
        Ok(JournalEntryRef { sequence, event_id })
    }

    pub fn sync(&mut self) -> Result<()> {
        if let Some(w) = self.writer.as_mut() {
            w.flush().map_err(Error::io)?;
            w.get_ref().sync_all().map_err(Error::io)?;
        }
        self.save_open_partition_state();
        self.meta.last_fsync_seq = self.last_sequence;
        let meta_path = self.config.dir.join("journal.meta");
        self.meta.save(&meta_path)?;
        if matches!(self.config.fsync_policy, FsyncPolicy::Always) {
            sync_dir(&self.config.dir)?;
            if self.partition_count() > 1 {
                for ent in fs::read_dir(&self.config.dir).map_err(Error::io)? {
                    let ent = ent.map_err(Error::io)?;
                    let name = ent.file_name().to_string_lossy().to_string();
                    if name.starts_with("p-") && ent.path().is_dir() {
                        sync_dir(&ent.path())?;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn rotate_segment(&mut self) -> Result<()> {
        let _guard = self.topology.begin_mutation()?;
        let partition_id = PartitionId(
            self.open_partition
                .ok_or_else(|| Error::format("no open partition for rotate"))?,
        );
        if let Some(mut w) = self.writer.take() {
            let footer = encode_footer(self.segment_last_sequence, self.entries_in_segment);
            w.write_all(&footer).map_err(Error::io)?;
            w.flush().map_err(Error::io)?;
            w.get_ref().sync_all().map_err(Error::io)?;
        }
        self.save_open_partition_state();
        let new_id = self.meta.allocate_segment_id(
            list_segment_ids(&self.config.dir)?
                .into_iter()
                .max()
                .unwrap_or(0),
        );
        self.meta.set_active_segment_for(partition_id, new_id);
        self.entries_in_segment = 0;
        self.segment_bytes = 0;
        self.segment_last_sequence = 0;
        self.open_partition = None;
        self.open_writer_for(partition_id)?;
        self.sync()
    }

    /// Phase 5.7.5/5.7.6: k-way merge over authoritative manifest segments.
    ///
    /// Uses published manifest when present; otherwise builds ephemeral topology from
    /// legacy authoritative selection (live session before first manifest publish/reopen).
    pub fn merge_reader(&self, from_exclusive: u64) -> Result<crate::merge_reader::JournalMergeReader> {
        let manifest_path = self.journal_manifest_path();
        if manifest_path.is_file() {
            return crate::merge_reader::JournalMergeReader::new(
                &self.config.dir,
                &manifest_path,
                self.partition_count(),
                from_exclusive,
            );
        }
        if list_segment_ids(&self.config.dir)?.is_empty() {
            return crate::merge_reader::JournalMergeReader::from_manifest(
                &self.config.dir,
                self.partition_count(),
                from_exclusive,
                &v2_to_stored(JournalManifestV2 {
                    format_version: crate::journal_manifest::JOURNAL_MANIFEST_FORMAT_VERSION_V2,
                    generation: 0,
                    partition_count: self.partition_count(),
                    partitions: Vec::new(),
                    superseded_segment_ids: Vec::new(),
                }),
            );
        }
        let auth_ids = crate::authoritative::legacy_authoritative_segment_ids(
            &self.config.dir,
            &self.active_segments(),
        )?;
        let segment_partitions =
            discover_segment_partitions(&self.config.dir, self.partition_count())?;
        let infos = self.segment_infos_from_ids(&auth_ids, &segment_partitions)?;
        let manifest = manifest_v2_from_segment_infos(
            0,
            self.partition_count(),
            &segment_partitions,
            &infos,
        );
        crate::merge_reader::JournalMergeReader::from_manifest(
            &self.config.dir,
            self.partition_count(),
            from_exclusive,
            &v2_to_stored(manifest),
        )
    }

    /// Read decrypted entries with `sequence > from_exclusive` in global order.
    ///
    /// Uses k-way merge over authoritative manifest segments (Phase 5.7.6).
    pub fn replay(&self, from_exclusive: u64, tree: &mut KeyTree) -> Result<Vec<JournalEntry>> {
        self.replay_limited(from_exclusive, None, tree)
    }

    /// Bounded replay for Runtime pull paths (`limit = None` reads all).
    pub fn replay_limited(
        &self,
        from_exclusive: u64,
        limit: Option<usize>,
        tree: &mut KeyTree,
    ) -> Result<Vec<JournalEntry>> {
        let mut reader = self.merge_reader(from_exclusive)?;
        match limit {
            Some(n) if n > 0 => reader.next_batch(tree, n),
            _ => reader.collect_all(tree),
        }
    }
}

fn sync_dir(dir: &std::path::Path) -> Result<()> {
    let f = File::open(dir).map_err(Error::io)?;
    f.sync_all().map_err(Error::io)?;
    Ok(())
}

fn sync_trim_dirs(
    journal_dir: &std::path::Path,
    partition_count: u32,
    touched_partitions: &HashSet<PartitionId>,
) -> Result<()> {
    if touched_partitions.is_empty() {
        return Ok(());
    }
    if is_partitioned_layout(partition_count) {
        for pid in touched_partitions {
            sync_dir(&partition_data_dir(journal_dir, *pid, partition_count))?;
        }
    }
    sync_dir(journal_dir)?;
    Ok(())
}
