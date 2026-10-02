use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use dmc_journal::{resolve_partition, 
    calculate_watermark, event_id_hex, session_bytes, CompactionArtifact, CompactionCandidate,
    CompactionPolicy, Journal, JournalEntry, JournalEntryDraft, JournalEventKind, JournalManifest,
    JournalSegmentCompactor, Operation, RetentionWatermark, SegmentCompactor, SnapshotStore,
    StorageLayout, TrimResult,
};
use dmc_storage::StorageEngine;
use dmc_vault::access::{Permission, PermissionSet, Role, authorize_tree_write};
use dmc_vault::key::{KeyNodeMeta, KeyPath, KeyTree};
use dmc_vault::keypass;
use dmc_vault::persist::{DbSnapshot, default_db_path};
use dmc_vault::store::EncryptedKv;
use dmc_vault::{KeyMaterial, seed_auth_service, seed_demo};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, broadcast};

use crate::audit::{AuditLog, AuditRecord};
use crate::channel::{ChannelInfo, ChannelSpec};
use crate::error::{Error, Result};
use crate::event::{CoreEvent, EventKind};
use crate::compaction_meta::{load_compaction_policy, save_compaction_policy};
use crate::consumer_meta::{load_consumer_meta, save_consumer_meta};
use crate::group::{ConsumerGroup, GroupDeliveredEvent, GroupDescription, GroupMember, GroupMetadata, LeaseReconcileResult};
use crate::group_meta::{load_group_meta, save_group_meta};
use crate::dispatch::{fan_out, MaterializerSink};
use crate::dlq::{self, DlqEntry};
use crate::producer_meta::{load_producer_meta, save_producer_meta, ProducerMetadata};
use crate::retention_meta::{load_retention_policy, save_retention_policy, RetentionPolicy};
use crate::ids::{
    ChannelId, ConsumerId, DlqEntryId, GroupId, MemberId, SessionId, StreamId, SubsystemId,
    SubscriptionId, TriggerId,
};
use crate::journal_pins::{consumer_pins_from_meta, ReplayPin, RetentionPolicyPin, SnapshotPin};
use crate::materializer::{
    core_event_from_journal, decode_cbor, encode_cbor, node_bundle, overlay_from_records,
    overlay_records, ApplyMode, ConsumerOffset, Materializer, OverlayDeleteBody, OverlayPutBody,
    RoleConfigBody, RuntimeConfigBody, SealBaseBody,
};
use crate::overlay::{OverlayPatch, OverlayStore, ResolvedView};
use crate::stream::{StreamMessage, StreamSpec};
use crate::subscription::{
    AckBatchResult, BatchLimits, ConsumerMetadata, ConsumerPolicy, DeliveredEvent, Delivery,
    DeliveryId, JournalPosition, RetryPolicy, Subscription, SubscriptionManager, SubscriptionStatus,
};
use dmc_vault::crypto::derive_metadata_kek;
use crate::subsystem::{
    SubsystemInfo, SubsystemRegistry, SubsystemSpec, interval, render_template,
};
use crate::trigger::{TriggerAction, TriggerDef};
use dmc_runtime::RuntimeHub;
use dmc_security::AccessControl;

const PRODUCT_NAME: &str = "Avrora";
const LOCAL_PRODUCER_ID: &str = "local";
const REPLAY_LEASE_TTL_MS: u64 = 15 * 60 * 1000;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PutOptions {
    pub producer_id: String,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutResult {
    pub event_id: String,
    pub sequence: u64,
    pub replay: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingSummary {
    pub sequence: u64,
    pub attempt: u32,
    pub event_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumerLag {
    pub subscription_id: String,
    pub journal_head: u64,
    pub offset: u64,
    pub lag_events: u64,
    pub pending: Option<PendingSummary>,
    pub dlq_count: u64,
    pub retry_backoff_until: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumerMetrics {
    pub subscriptions: Vec<ConsumerLag>,
    pub journal_head: u64,
    pub total_dlq: u64,
}

struct JournalRef {
    sequence: u64,
    event_id: String,
}

struct RuntimeInner {
    db_path: PathBuf,
    status: DbStatus,
    snapshot: Option<DbSnapshot>,
    kv: Option<EncryptedKv>,
    access: AccessControl,
    hub: RuntimeHub,
    audit: AuditLog,
    overlay: OverlayStore,
    subsystems: SubsystemRegistry,
    journal: Option<Journal>,
    offsets: HashMap<String, ConsumerOffset>,
    subscriptions: SubscriptionManager,
    seen_event_ids: HashSet<[u8; 16]>,
    last_applied_sequence: u64,
    consumer_meta: ConsumerMetadata,
    group_meta: GroupMetadata,
    producer_meta: ProducerMetadata,
    retention_policy: RetentionPolicy,
    compaction_policy: CompactionPolicy,
    metadata_kek: Option<KeyMaterial>,
    now_ms_override: Option<u64>,
    /// Published snapshot floor loaded from manifest (Phase 5.2). None → no snapshot pin.
    published_snapshot_sequence: Option<u64>,
    replay_leases: Vec<ReplayPin>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DbStatus {
    Empty,
    Locked,
    Unlocked,
}

/// Avrora core runtime: vault lifecycle, streams, channels, roles, triggers, overlay, subsystems.
#[derive(Clone)]
pub struct Runtime {
    /// Shared channel/stream/trigger/event domain (clone = same Arc as DMC adapter).
    hub: RuntimeHub,
    inner: Arc<Mutex<RuntimeInner>>,
    events: broadcast::Sender<CoreEvent>,
    capability_rotation_dir: Arc<std::sync::Mutex<Option<PathBuf>>>,
}

impl Runtime {
    pub fn product_name() -> &'static str {
        PRODUCT_NAME
    }

    /// Clone of the process-local [`RuntimeHub`] (same Arc as HTTP / DMC adapters).
    pub fn hub(&self) -> RuntimeHub {
        self.hub.clone()
    }

    pub fn at_path(path: impl AsRef<Path>) -> Self {
        Self::at_path_with_hub(path, RuntimeHub::new())
    }

    /// Build runtime that shares an existing hub (one hub per process for all transports).
    pub fn at_path_with_hub(path: impl AsRef<Path>, hub: RuntimeHub) -> Self {
        let db_path = path.as_ref().to_path_buf();
        let (status, snapshot) = detect_status(&db_path);
        let (events, _) = broadcast::channel(1024);
        // Empty/Locked: no in-memory root until unlock or devo-init persists identity.
        let access = AccessControl::new_bare(dmc_vault::RoleRegistry::empty());
        Self {
            hub: hub.clone(),
            capability_rotation_dir: Arc::new(std::sync::Mutex::new(None)),
            inner: Arc::new(Mutex::new(RuntimeInner {
                db_path,
                status,
                snapshot,
                kv: None,
                access,
                hub,
                audit: AuditLog::new(),
                overlay: OverlayStore::new(),
                subsystems: SubsystemRegistry::default(),
                journal: None,
                offsets: HashMap::new(),
                subscriptions: SubscriptionManager::new(),
                seen_event_ids: HashSet::new(),
                last_applied_sequence: 0,
                consumer_meta: ConsumerMetadata::default(),
                group_meta: GroupMetadata::default(),
                producer_meta: ProducerMetadata::default(),
                retention_policy: RetentionPolicy::default(),
                compaction_policy: CompactionPolicy::default(),
                metadata_kek: None,
                now_ms_override: None,
                published_snapshot_sequence: None,
                replay_leases: Vec::new(),
            })),
            events,
        }
    }

    pub fn open_default() -> Self {
        Self::at_path(default_db_path())
    }

    pub async fn start(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self::at_path(path))
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<CoreEvent> {
        self.events.subscribe()
    }

    pub async fn status(&self) -> DbStatus {
        self.inner.lock().await.status
    }

    pub async fn db_path(&self) -> PathBuf {
        self.inner.lock().await.db_path.clone()
    }

    pub async fn db_id(&self) -> Option<String> {
        let inner = self.inner.lock().await;
        inner
            .snapshot
            .as_ref()
            .and_then(|s| s.salt().ok())
            .map(|salt| keypass::db_id_from_salt(&salt))
            .or_else(|| {
                inner
                    .kv
                    .as_ref()
                    .map(|kv| keypass::db_id_from_salt(kv.tree().salt()))
            })
    }

    /// Create an empty vault: crypto key tree + journal only (no roles/users).
    /// Use [`Self::devo_init`] or [`Self::create_dev`] to provision root identity.
    pub async fn create(&self) -> Result<(String, String)> {
        self.create_with_master(None).await
    }

    /// Like [`Self::create`], optionally with a fixed master hex (docker / env.dev fixtures).
    pub async fn create_with_master(&self, master_hex: Option<&str>) -> Result<(String, String)> {
        let mut inner = self.inner.lock().await;
        let layout = StorageLayout::from_db_path(&inner.db_path);
        if inner.status != DbStatus::Empty || layout.vault_exists() {
            return Err(Error::from_vault(dmc_vault::Error::AlreadyExists));
        }
        let (tree, master) = match master_hex.map(str::trim).filter(|s| !s.is_empty()) {
            Some(hex) => {
                let master = KeyMaterial::from_hex(hex)?;
                KeyTree::create_with_master(master)?
            }
            None => KeyTree::create_new()?,
        };
        let db_id = keypass::db_id_from_salt(tree.salt());
        let master_hex = master.to_hex();
        let kv = EncryptedKv::new(tree);
        let roles = dmc_vault::RoleRegistry::empty();
        layout.ensure_dirs().map_err(|e| Error::Invalid(e.to_string()))?;
        let journal = Journal::from_master(&layout, &master, kv.tree().salt())
            .map_err(|e| Error::Invalid(e.to_string()))?;
        inner.kv = Some(kv);
        inner.access = AccessControl::new_bare(roles);
        inner.journal = Some(journal);
        inner.status = DbStatus::Unlocked;
        inner.metadata_kek = Some(derive_metadata_kek(&master, inner.kv.as_ref().unwrap().tree().salt()));
        persist_checkpoint(&mut inner)?;
        Ok((master_hex, db_id))
    }

    /// Dev/test helper: empty vault + root identity (+ optional demo seed).
    pub async fn create_dev(&self, with_demo: bool) -> Result<(String, String)> {
        let (master_hex, db_id) = self.create().await?;
        self.devo_init(with_demo).await?;
        Ok((master_hex, db_id))
    }

    /// Provision root role/user/capabilities (and optional demo data). Vault must be unlocked.
    pub async fn devo_init(&self, with_demo: bool) -> Result<()> {
        let mut inner = self.inner.lock().await;
        if inner.status != DbStatus::Unlocked {
            return Err(Error::Locked);
        }
        inner.access.provision_dev_root()?;
        if with_demo {
            let mut roles = inner.access.roles().clone();
            let kv = inner.kv.as_mut().ok_or(Error::Locked)?;
            seed_demo(kv, &mut roles);
            inner.access.replace_roles(roles);
        }
        inner.access.open_session("root")?;
        persist_checkpoint(&mut inner)?;
        Ok(())
    }

    /// Root identity + standard `auth/*` tree and embeddable service roles.
    pub async fn auth_service_init(&self) -> Result<()> {
        self.devo_init(false).await?;
        let mut inner = self.inner.lock().await;
        if inner.status != DbStatus::Unlocked {
            return Err(Error::Locked);
        }
        let mut roles = inner.access.roles().clone();
        let kv = inner.kv.as_mut().ok_or(Error::Locked)?;
        seed_auth_service(kv, &mut roles);
        inner.access.replace_roles(roles);
        persist_checkpoint(&mut inner)?;
        Ok(())
    }

    pub async fn is_dev_provisioned(&self) -> Result<bool> {
        let inner = self.inner.lock().await;
        if inner.status == DbStatus::Empty {
            return Ok(false);
        }
        Ok(inner.access.is_dev_provisioned())
    }

    /// Unlock with Master Key bytes from Phase 7 UnlockBlob (never stored).
    pub async fn unlock_material(&self, material: &[u8; 32]) -> Result<()> {
        let master = KeyMaterial::from_bytes(*material);
        let hex = master.to_hex();
        self.unlock(&hex).await?;
        Ok(())
    }

    /// Unlock with raw master hex received over the control plane (never stored).
    pub async fn unlock(&self, master_hex: &str) -> Result<SessionId> {
        let master = KeyMaterial::from_hex(master_hex)?;
        let mut inner = self.inner.lock().await;
        if inner.status == DbStatus::Unlocked {
            return Err(Error::from_vault(dmc_vault::Error::AlreadyUnlocked));
        }
        let layout = StorageLayout::from_db_path(&inner.db_path);
        let _ = dmc_journal::migrate_v1_to_v2(&layout);
        let snap = if layout.base_snapshot().is_file() {
            DbSnapshot::load(&layout.base_snapshot()).map_err(Error::from_vault)?
        } else {
            inner
                .snapshot
                .clone()
                .or_else(|| DbSnapshot::load(&inner.db_path).ok())
                .ok_or_else(|| Error::from_vault(dmc_vault::Error::NotInitialized))?
        };
        let session = apply_unlock(&mut inner, snap, &master)?;
        drop(inner);
        self.catch_up_capability_rotation().await;
        Ok(session)
    }

    pub fn set_capability_rotation_dir(&self, dir: PathBuf) {
        if let Ok(mut g) = self.capability_rotation_dir.lock() {
            *g = Some(dir);
        }
    }

    async fn catch_up_capability_rotation(&self) {
        let dir = self
            .capability_rotation_dir
            .lock()
            .ok()
            .and_then(|g| g.clone());
        let Some(dir) = dir else {
            return;
        };
        crate::control::capability_rotation_config::run_pending_after_unlock(&dir, self).await;
    }

    pub async fn lock(&self) -> Result<()> {
        let mut inner = self.inner.lock().await;
        if inner.status != DbStatus::Unlocked {
            return Err(Error::Locked);
        }
        let ids: Vec<_> = inner
            .subsystems
            .list()
            .into_iter()
            .map(|s| s.spec.id)
            .collect();
        for id in ids {
            let _ = inner.subsystems.stop(&id);
        }
        persist_checkpoint(&mut inner)?;
        let _ = persist_consumer_state(&mut inner);
        let _ = persist_group_state(&mut inner);
        let _ = persist_producer_state(&mut inner);
        let _ = persist_retention_state(&mut inner);
        let _ = persist_compaction_state(&mut inner);
        if let Some(mut kv) = inner.kv.take() {
            kv.tree_mut().wipe_secrets();
        }
        if let Some(ref mut journal) = inner.journal {
            let _ = journal.sync();
        }
        inner.journal = None;
        inner.access.wipe_sessions();
        inner.overlay.clear();
        inner.offsets.clear();
        inner.subscriptions.clear();
        inner.consumer_meta = ConsumerMetadata::default();
        inner.group_meta = GroupMetadata::default();
        inner.producer_meta = ProducerMetadata::default();
        inner.metadata_kek = None;
        inner.now_ms_override = None;
        inner.seen_event_ids.clear();
        inner.published_snapshot_sequence = None;
        inner.replay_leases.clear();
        inner.status = DbStatus::Locked;
        Ok(())
    }

    pub async fn persist(&self) -> Result<()> {
        let mut inner = self.inner.lock().await;
        persist_checkpoint(&mut inner)
    }

    pub async fn force_snapshot(&self) -> Result<u64> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        publish_materialized_snapshot(&mut inner)
    }

    pub async fn last_sequence(&self) -> u64 {
        let inner = self.inner.lock().await;
        inner
            .journal
            .as_ref()
            .map(|j| j.last_sequence())
            .unwrap_or(inner.last_applied_sequence)
    }

    pub async fn commit_offset(
        &self,
        session: &SessionId,
        consumer_id: &str,
        path_scope: &str,
        sequence: u64,
    ) -> Result<()> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let key_path = parse_path(path_scope)?;
        inner
            .access
            .authorize(session, &key_path, Permission::Read)?;
        let body = ConsumerOffset {
            consumer_id: consumer_id.to_string(),
            path_scope: key_path.to_string(),
            sequence,
        };
        journal_mutation(
            &mut inner,
            session,
            &key_path,
            JournalEventKind::ConsumerOffset,
            Operation::ConsumerOffset,
            encode_cbor(&body)?,
            "OFFSET",
            EventKind::OverlayApply,
            Vec::new(),
            None,
        )?;
        Ok(())
    }

    pub async fn get_offset(&self, consumer_id: &str) -> Option<ConsumerOffset> {
        let inner = self.inner.lock().await;
        if let Some(p) = inner.consumer_meta.progress.get(consumer_id) {
            return Some(ConsumerOffset {
                consumer_id: consumer_id.to_string(),
                path_scope: String::new(),
                sequence: p.offset,
            });
        }
        inner.offsets.get(consumer_id).cloned()
    }

    pub async fn open_session(&self, role_id: &str) -> Result<SessionId> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        Ok(inner.access.open_session(role_id)?)
    }

    pub async fn open_user_session(
        &self,
        user_id: &str,
        device_id: Option<&str>,
    ) -> Result<SessionId> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let id = inner.access.open_user_session(user_id, device_id)?;
        inner.audit.record_security(
            Some(&id),
            Some(user_id),
            device_id,
            None,
            "SESSION_OPEN",
            "ok",
            "",
        );
        Ok(id)
    }

    pub async fn create_user(
        &self,
        session: &SessionId,
        id: String,
        roles: Vec<String>,
    ) -> Result<dmc_security::User> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let actor = inner.access.capability(session)?;
        if !actor.permissions.contains(dmc_vault::Permission::Grant) {
            return Err(Error::from_vault(dmc_vault::Error::CannotDelegate(
                actor.scope.to_string(),
            )));
        }
        let user = inner.access.create_user(id, roles)?;
        persist_checkpoint(&mut inner)?;
        inner.audit.record_security(
            Some(session),
            Some(user.id.as_str()),
            None,
            None,
            "USER_CREATED",
            "ok",
            "",
        );
        Ok(user)
    }

    pub async fn assign_roles(
        &self,
        session: &SessionId,
        user_id: &str,
        roles: Vec<String>,
    ) -> Result<dmc_security::User> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let actor = inner.access.capability(session)?;
        if !actor.permissions.contains(dmc_vault::Permission::Grant) {
            return Err(Error::from_vault(dmc_vault::Error::CannotDelegate(
                actor.scope.to_string(),
            )));
        }
        let user = inner.access.assign_roles(user_id, roles)?;
        persist_checkpoint(&mut inner)?;
        inner.audit.record_security(
            Some(session),
            Some(user.id.as_str()),
            None,
            None,
            "ROLE_ASSIGNED",
            "ok",
            "",
        );
        Ok(user)
    }

    pub async fn disable_user(&self, session: &SessionId, user_id: &str) -> Result<dmc_security::User> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let actor = inner.access.capability(session)?;
        if !actor.permissions.contains(dmc_vault::Permission::Grant) {
            return Err(Error::from_vault(dmc_vault::Error::CannotDelegate(
                actor.scope.to_string(),
            )));
        }
        let user = inner.access.disable_user(user_id)?;
        persist_checkpoint(&mut inner)?;
        inner.audit.record_security(
            Some(session),
            Some(user.id.as_str()),
            None,
            None,
            "USER_DISABLED",
            "ok",
            "",
        );
        Ok(user)
    }

    pub async fn list_users(&self) -> Result<Vec<dmc_security::User>> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        Ok(inner.access.users().list())
    }

    pub async fn grant_capability(
        &self,
        session: &SessionId,
        subject: &str,
        scope: KeyPath,
        permissions: PermissionSet,
        ttl_ms: Option<u64>,
    ) -> Result<dmc_security::IssuedCapability> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let issued = inner
            .access
            .grant(session, subject, scope, permissions, ttl_ms)?;
        persist_checkpoint(&mut inner)?;
        inner.audit.record_security(
            Some(session),
            Some(issued.subject.as_str()),
            None,
            Some(issued.id.as_str()),
            "CAPABILITY_GRANTED",
            "ok",
            &issued.scope,
        );
        Ok(issued)
    }

    pub async fn revoke_capability(
        &self,
        session: &SessionId,
        capability_id: &str,
    ) -> Result<dmc_security::IssuedCapability> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        inner
            .access
            .authorize(session, &KeyPath::root(), Permission::Grant)
            .or_else(|_| {
                inner
                    .access
                    .capability(session)
                    .and_then(|cap| {
                        if cap.permissions.contains(Permission::Grant) {
                            Ok(())
                        } else {
                            Err(dmc_security::Error::DelegationDenied(
                                "GRANT required to revoke".into(),
                            ))
                        }
                    })
            })?;
        let issued = inner
            .access
            .revoke_capability(&dmc_security::CapabilityId::from(capability_id))?;
        persist_checkpoint(&mut inner)?;
        inner.audit.record_security(
            Some(session),
            Some(issued.subject.as_str()),
            None,
            Some(issued.id.as_str()),
            "CAPABILITY_REVOKED",
            "ok",
            &issued.scope,
        );
        Ok(issued)
    }

    pub async fn revoke_user_session(&self, session: &SessionId, target: &SessionId) -> Result<()> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        inner
            .access
            .capability(session)
            .and_then(|cap| {
                if cap.permissions.contains(Permission::Grant) {
                    Ok(())
                } else {
                    Err(dmc_security::Error::DelegationDenied(
                        "GRANT required to revoke session".into(),
                    ))
                }
            })?;
        inner.access.revoke_session(target);
        inner.audit.record_security(
            Some(session),
            None,
            None,
            None,
            "SESSION_REVOKED",
            "ok",
            "",
        );
        Ok(())
    }

    pub async fn list_capabilities(&self) -> Result<Vec<dmc_security::IssuedCapability>> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        Ok(inner.access.list_issued())
    }

    pub async fn rotate_all_user_capabilities(&self) -> Result<dmc_security::RotationReport> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let _ = inner.access.admin_session_id()?;
        let report = inner.access.rotate_all_user_capabilities()?;
        persist_checkpoint(&mut inner)?;
        inner.audit.record_security(
            None,
            None,
            None,
            None,
            "CAPABILITY_ROTATED",
            "ok",
            "",
        );
        Ok(report)
    }

    pub async fn bind_role(&self, session: SessionId, role: &str) -> Result<()> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        Ok(inner.access.bind_role(&session, role)?)
    }

    pub async fn admin_session(&self) -> Result<SessionId> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        Ok(inner.access.admin_session_id()?)
    }

    pub async fn configure_channel(&self, spec: ChannelSpec) -> Result<ChannelId> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        if inner.hub.channel(&spec.id).is_ok() {
            return Err(Error::ChannelExists(spec.id.to_string()));
        }
        let session = inner.access.admin_session_id()?;
        let path = parse_path(&format!("system/runtime/channels/{}", spec.id))?;
        let body = RuntimeConfigBody {
            kind: "channel".into(),
            spec: serde_json::to_value(&spec).map_err(|e| Error::Invalid(e.to_string()))?,
        };
        let id = spec.id.clone();
        journal_mutation(
            &mut inner,
            &session,
            &path,
            JournalEventKind::RuntimeConfig,
            Operation::RuntimeConfig,
            encode_cbor(&body)?,
            "CHANNEL",
            EventKind::OverlayApply,
            Vec::new(),
            None,
        )?;
        Ok(id)
    }

    pub async fn start_channel(&self, id: &ChannelId) -> Result<()> {
        self.inner.lock().await.hub.start_channel(id).map_err(Error::from)
    }

    pub async fn stop_channel(&self, id: &ChannelId) -> Result<()> {
        self.inner.lock().await.hub.stop_channel(id).map_err(Error::from)
    }

    pub async fn list_channels(&self) -> Vec<ChannelInfo> {
        self.inner.lock().await.hub.list_channels()
    }

    pub async fn create_stream(&self, spec: StreamSpec) -> Result<StreamId> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        inner.hub.channel(&spec.channel_id)?;
        if inner.hub.stream(&spec.id).is_ok() {
            return Err(Error::StreamExists(spec.id.to_string()));
        }
        let session = inner.access.admin_session_id()?;
        let path = parse_path(&format!("system/runtime/streams/{}", spec.id))?;
        let body = RuntimeConfigBody {
            kind: "stream".into(),
            spec: serde_json::to_value(&spec).map_err(|e| Error::Invalid(e.to_string()))?,
        };
        let id = spec.id.clone();
        journal_mutation(
            &mut inner,
            &session,
            &path,
            JournalEventKind::RuntimeConfig,
            Operation::RuntimeConfig,
            encode_cbor(&body)?,
            "STREAM",
            EventKind::OverlayApply,
            Vec::new(),
            None,
        )?;
        Ok(id)
    }

    pub async fn list_streams(&self) -> Vec<StreamSpec> {
        self.inner.lock().await.hub.list_streams()
    }

    pub async fn create_subscription(
        &self,
        session: &SessionId,
        stream_id: &StreamId,
        consumer_id: Option<&str>,
    ) -> Result<Subscription> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let spec = inner.hub.stream(stream_id)?;
        let actor = inner.access.session(session)?;
        let subject = actor
            .user_id
            .clone()
            .ok_or_else(|| Error::Invalid("subscription requires a user session".into()))?;
        let issued = inner
            .access
            .covering_for_scope(session, &spec.path_scope, spec.required_perms)?;
        let id = SubscriptionId::new();
        let consumer = ConsumerId::from(
            consumer_id
                .map(str::to_string)
                .unwrap_or_else(|| id.0.clone()),
        );
        let sub = Subscription {
            id: id.clone(),
            stream_id: stream_id.clone(),
            consumer_id: consumer,
            subject,
            capability_id: issued.id,
            capability_generation: issued.generation,
            position: JournalPosition { sequence: 0 },
            status: SubscriptionStatus::Active,
        };
        let path = parse_path(&format!("system/runtime/subscriptions/{}", sub.id))?;
        let body = RuntimeConfigBody {
            kind: "subscription".into(),
            spec: serde_json::to_value(&sub).map_err(|e| Error::Invalid(e.to_string()))?,
        };
        journal_mutation(
            &mut inner,
            session,
            &path,
            JournalEventKind::RuntimeConfig,
            Operation::RuntimeConfig,
            encode_cbor(&body)?,
            "SUBSCRIBE",
            EventKind::OverlayApply,
            Vec::new(),
            None,
        )?;
        inner.consumer_meta.ensure(&id);
        persist_consumer_state(&mut inner)?;
        inner.subscriptions.get(&id).cloned()
    }

    pub async fn list_subscriptions(&self) -> Vec<Subscription> {
        self.inner.lock().await.subscriptions.list()
    }

    pub async fn get_subscription(&self, id: &SubscriptionId) -> Result<Subscription> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let mut sub = inner.subscriptions.get(id)?.clone();
        if let Some(p) = inner.consumer_meta.get(id) {
            sub.position.sequence = p.offset;
        }
        Ok(sub)
    }

    /// Phase 5.8.2/5.8.4: create a consumer group on a stream (metadata only; no subscription).
    /// Bootstraps GroupOffset for every partition; does not create a subscription.
    pub async fn create_group(
        &self,
        session: &SessionId,
        group_id: GroupId,
        stream_id: &StreamId,
    ) -> Result<ConsumerGroup> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let spec = inner.hub.stream(stream_id)?;
        require_group_stream_access(&inner, session, &spec)?;
        let journal = inner.journal.as_ref().ok_or(Error::Locked)?;
        let partition_count = journal.partition_count();
        let journal_head = journal.last_sequence();
        let oldest_available = journal.oldest_available_sequence().unwrap_or(1);
        let now = consumer_now_ms(&inner);
        let gid = group_id.clone();
        inner.group_meta.create_group(
            group_id,
            stream_id.clone(),
            now,
            partition_count,
            journal_head,
            oldest_available,
            crate::group::GroupPolicy::default(),
        )?;
        persist_group_state(&mut inner)?;
        Ok(inner.group_meta.get(&gid)?.clone())
    }

    /// Phase 5.8.4: create group with explicit start-position policy.
    pub async fn create_group_with_policy(
        &self,
        session: &SessionId,
        group_id: GroupId,
        stream_id: &StreamId,
        policy: crate::group::GroupPolicy,
    ) -> Result<ConsumerGroup> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let spec = inner.hub.stream(stream_id)?;
        require_group_stream_access(&inner, session, &spec)?;
        let journal = inner.journal.as_ref().ok_or(Error::Locked)?;
        let partition_count = journal.partition_count();
        let journal_head = journal.last_sequence();
        let oldest_available = journal.oldest_available_sequence().unwrap_or(1);
        let now = consumer_now_ms(&inner);
        let gid = group_id.clone();
        inner.group_meta.create_group(
            group_id,
            stream_id.clone(),
            now,
            partition_count,
            journal_head,
            oldest_available,
            policy,
        )?;
        persist_group_state(&mut inner)?;
        Ok(inner.group_meta.get(&gid)?.clone())
    }

    /// Phase 5.8.2: add a member; bumps group generation.
    pub async fn join_group(
        &self,
        session: &SessionId,
        group_id: &GroupId,
        member_id: MemberId,
        device_id: Option<&str>,
    ) -> Result<GroupMember> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let stream_id = inner.group_meta.get(group_id)?.stream_id.clone();
        let spec = inner.hub.stream(&stream_id)?;
        require_group_stream_access(&inner, session, &spec)?;
        let now = consumer_now_ms(&inner);
        let member = inner.group_meta.join_group(
            group_id,
            member_id,
            session.clone(),
            device_id.map(str::to_string),
            now,
        )?;
        persist_group_state(&mut inner)?;
        Ok(member)
    }

    /// Phase 5.8.2: remove a member; bumps group generation.
    pub async fn leave_group(
        &self,
        session: &SessionId,
        group_id: &GroupId,
        member_id: &MemberId,
    ) -> Result<()> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let stream_id = inner.group_meta.get(group_id)?.stream_id.clone();
        let spec = inner.hub.stream(&stream_id)?;
        require_group_stream_access(&inner, session, &spec)?;
        inner.group_meta.leave_group(group_id, member_id)?;
        persist_group_state(&mut inner)?;
        Ok(())
    }

    /// Phase 5.8.2: read-only group snapshot (requires live stream capability).
    pub async fn describe_group(
        &self,
        session: &SessionId,
        group_id: &GroupId,
    ) -> Result<GroupDescription> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let group = inner.group_meta.get(group_id)?;
        let spec = inner.hub.stream(&group.stream_id)?;
        require_group_stream_access(&inner, session, &spec)?;
        Ok(group.describe())
    }

    /// Phase 5.8.2: delete an empty group.
    pub async fn delete_group(&self, session: &SessionId, group_id: &GroupId) -> Result<()> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let stream_id = inner.group_meta.get(group_id)?.stream_id.clone();
        let spec = inner.hub.stream(&stream_id)?;
        require_group_stream_access(&inner, session, &spec)?;
        inner.group_meta.delete_group(group_id)?;
        persist_group_state(&mut inner)?;
        Ok(())
    }

    /// Phase 5.8.3: refresh member lease; does not bump generation.
    pub async fn heartbeat_group_member(
        &self,
        session: &SessionId,
        group_id: &GroupId,
        member_id: &MemberId,
    ) -> Result<GroupMember> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let stream_id = inner.group_meta.get(group_id)?.stream_id.clone();
        let spec = inner.hub.stream(&stream_id)?;
        require_group_stream_access(&inner, session, &spec)?;
        let member_session = inner
            .group_meta
            .get(group_id)?
            .members
            .get(member_id)
            .ok_or_else(|| Error::UnknownMember(member_id.to_string()))?
            .session_id
            .clone();
        require_group_member_session(&member_session, session)?;
        let now = consumer_now_ms(&inner);
        let member = inner
            .group_meta
            .heartbeat_member(group_id, member_id, now)?;
        persist_group_state(&mut inner)?;
        Ok(member)
    }

    /// Phase 5.8.3: remove lease-expired members (`lease_expires_at_ms <= now`).
    pub async fn reconcile_group_leases(&self) -> Result<LeaseReconcileResult> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        reconcile_group_leases_inner(&mut inner)
    }

    /// Phase 5.8.5: deliver the next event for a group member without advancing GroupOffset.
    ///
    /// Pending deliveries are persisted before return (at-least-once). Pass the current
    /// group generation for fencing (`StaleGeneration` if outdated).
    pub async fn group_consume(
        &self,
        session: &SessionId,
        group_id: &GroupId,
        member_id: &MemberId,
        generation: u64,
    ) -> Result<Option<GroupDeliveredEvent>> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        group_consume_inner(&mut inner, session, group_id, member_id, generation)
    }

    /// Phase 5.8.6: acknowledge a group delivery and advance contiguous GroupOffset.
    pub async fn group_ack(
        &self,
        session: &SessionId,
        group_id: &GroupId,
        member_id: &MemberId,
        generation: u64,
        delivery_id: &crate::subscription::DeliveryId,
    ) -> Result<crate::group::GroupAckResult> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        group_ack_inner(&mut inner, session, group_id, member_id, generation, delivery_id)
    }

    /// Phase 5.8.9: schedule explicit retry for a failed delivery (does not advance GroupOffset).
    /// When attempts are exhausted, atomically moves pending to DLQ and advances contiguous offset.
    pub async fn group_retry(
        &self,
        session: &SessionId,
        group_id: &GroupId,
        member_id: &MemberId,
        generation: u64,
        delivery_id: &crate::subscription::DeliveryId,
    ) -> Result<crate::group::GroupRetryResponse> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        group_retry_inner(&mut inner, session, group_id, member_id, generation, delivery_id)
    }

    /// Phase 5.8.10: list durable DLQ entries for a group (newest partition/sequence order).
    pub async fn list_group_dlq(
        &self,
        session: &SessionId,
        group_id: &GroupId,
    ) -> Result<Vec<crate::group::GroupDlqEntry>> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let group = inner.group_meta.get(group_id)?;
        let spec = inner.hub.stream(&group.stream_id)?;
        require_group_stream_access(&inner, session, &spec)?;
        Ok(group.list_dlq_entries())
    }

    /// Phase 5.8.10: fetch one DLQ entry by `(partition_id, sequence)`.
    pub async fn get_group_dlq_entry(
        &self,
        session: &SessionId,
        group_id: &GroupId,
        partition_id: u32,
        sequence: u64,
    ) -> Result<crate::group::GroupDlqEntry> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let group = inner.group_meta.get(group_id)?;
        let spec = inner.hub.stream(&group.stream_id)?;
        require_group_stream_access(&inner, session, &spec)?;
        group
            .get_dlq_entry(partition_id, sequence)
            .cloned()
            .ok_or_else(|| Error::UnknownGroupDlqEntry {
                group_id: group_id.to_string(),
                partition_id,
                sequence,
            })
    }


    /// Pull the next in-flight or following event. At most one pending delivery per subscription.
    /// Pending state is persisted before the event is returned.
    pub async fn consume(
        &self,
        subscription_id: &SubscriptionId,
        _limit: usize,
    ) -> Result<Vec<DeliveredEvent>> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let sub = inner.subscriptions.get(subscription_id)?.clone();
        match consume_next(&mut inner, &sub)? {
            Some(ev) => Ok(vec![ev]),
            None => Ok(Vec::new()),
        }
    }

    pub async fn consume_batch(
        &self,
        subscription_id: &SubscriptionId,
        limits: BatchLimits,
    ) -> Result<Vec<DeliveredEvent>> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let sub = inner.subscriptions.get(subscription_id)?.clone();
        let policy = inner
            .consumer_meta
            .get(subscription_id)
            .map(|p| p.policy)
            .unwrap_or_default();
        let in_flight = inner
            .consumer_meta
            .get(subscription_id)
            .map(|p| p.in_flight())
            .unwrap_or(0);
        let want = limits.max_events.max(1).min(policy.max_batch_events.max(1) as usize);
        if want > policy.max_in_flight.max(1) as usize && in_flight >= policy.max_in_flight.max(1)
        {
            return Err(Error::Backpressure {
                subscription_id: subscription_id.to_string(),
                in_flight,
                max_in_flight: policy.max_in_flight,
            });
        }
        let max_bytes = if limits.max_bytes == 0 {
            policy.max_batch_bytes
        } else {
            limits.max_bytes.min(policy.max_batch_bytes)
        };
        match consume_next(&mut inner, &sub)? {
            Some(ev) => {
                if ev.payload.len() as u64 > max_bytes {
                    return Err(Error::Invalid("delivery exceeds max_batch_bytes".into()));
                }
                Ok(vec![ev])
            }
            None => Ok(Vec::new()),
        }
    }

    pub async fn pending_delivery(&self, subscription_id: &SubscriptionId) -> Result<Option<crate::subscription::PendingDelivery>> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        Ok(inner
            .consumer_meta
            .get(subscription_id)
            .and_then(|p| p.pending.clone()))
    }

    /// Test clock. `None` restores wall clock. Not persisted.
    pub async fn set_now_ms(&self, now_ms: Option<u64>) {
        self.inner.lock().await.now_ms_override = now_ms;
    }

    pub async fn retry_policy(&self, subscription_id: &SubscriptionId) -> Result<RetryPolicy> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let _ = inner.subscriptions.get(subscription_id)?;
        Ok(inner
            .consumer_meta
            .get(subscription_id)
            .map(|p| p.retry)
            .unwrap_or_default())
    }

    pub async fn set_retry_policy(
        &self,
        session: &SessionId,
        subscription_id: &SubscriptionId,
        policy: RetryPolicy,
    ) -> Result<()> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let sub = inner.subscriptions.get(subscription_id)?.clone();
        require_subscription_control(&inner, session, &sub)?;
        let policy = policy.validate()?;
        inner.consumer_meta.ensure(subscription_id).retry = policy;
        persist_consumer_state(&mut inner)
    }

    pub async fn consumer_policy(&self, subscription_id: &SubscriptionId) -> Result<ConsumerPolicy> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let _ = inner.subscriptions.get(subscription_id)?;
        Ok(inner
            .consumer_meta
            .get(subscription_id)
            .map(|p| p.policy)
            .unwrap_or_default())
    }

    pub async fn set_consumer_policy(
        &self,
        session: &SessionId,
        subscription_id: &SubscriptionId,
        policy: ConsumerPolicy,
    ) -> Result<()> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let sub = inner.subscriptions.get(subscription_id)?.clone();
        require_subscription_control(&inner, session, &sub)?;
        let policy = policy.validate()?;
        inner.consumer_meta.ensure(subscription_id).policy = policy;
        persist_consumer_state(&mut inner)
    }

    /// Read-only history from an inclusive journal sequence. Does not touch pending/offset.
    /// Registers a short replay retention lease so trim cannot advance past `from_sequence`.
    pub async fn replay(
        &self,
        subscription_id: &SubscriptionId,
        from_sequence: u64,
        limit: usize,
    ) -> Result<Vec<DeliveredEvent>> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let sub = inner.subscriptions.get(subscription_id)?.clone();
        validate_subscription_capability(&inner, &sub, None)?;
        require_replay_history(&inner, from_sequence)?;
        let now = consumer_now_ms(&inner);
        prune_replay_leases(&mut inner, now);
        inner.replay_leases.push(ReplayPin {
            lease_id: format!("replay_{}", uuid::Uuid::new_v4()),
            subscription_id: subscription_id.clone(),
            from_sequence,
            expires_at_ms: now.saturating_add(REPLAY_LEASE_TTL_MS),
        });
        let from_exclusive = from_sequence.saturating_sub(1);
        pull_events(&mut inner, &sub, from_exclusive, limit)
    }

    /// Phase 5.1: compute safe trim floor from pins. Does not delete journal data.
    pub async fn retention_watermark(&self) -> Result<RetentionWatermark> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        Ok(compute_retention_watermark(&inner))
    }

    /// Phase 5.5: retention policy component only (dynamic pin). Does not delete data.
    pub async fn retention_policy_trim_through(&self) -> Result<Option<u64>> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        compute_retention_policy_trim(&inner)
    }

    pub async fn retention_policy(&self) -> Result<RetentionPolicy> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        Ok(inner.retention_policy.clone())
    }

    pub async fn journal_segment_infos(&self) -> Result<Vec<dmc_journal::JournalSegmentInfo>> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        inner
            .journal
            .as_ref()
            .ok_or(Error::Locked)?
            .segment_infos()
            .map_err(|e| Error::Invalid(e.to_string()))
    }

    pub async fn set_retention_policy(
        &self,
        session: &SessionId,
        policy: RetentionPolicy,
    ) -> Result<()> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let actor = inner.access.capability(session)?;
        if !actor.permissions.contains(Permission::Grant) {
            return Err(Error::AuthorizationDenied(
                "set_retention_policy requires GRANT".into(),
            ));
        }
        inner.retention_policy = policy;
        persist_retention_state(&mut inner)?;
        let user_id = inner
            .access
            .session(session)
            .ok()
            .and_then(|s| s.user_id.as_ref().map(|u| u.as_str().to_string()));
        inner.audit.record_security(
            Some(session),
            user_id.as_deref(),
            None,
            None,
            "RETENTION_POLICY_SET",
            "ok",
            "",
        );
        Ok(())
    }

    /// Sequence of the last published snapshot manifest, if any.
    pub async fn published_snapshot_sequence(&self) -> Result<Option<u64>> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        Ok(inner.published_snapshot_sequence)
    }

    /// Explicit replay lease (same semantics as auto-lease in `replay`).
    pub async fn begin_replay_lease(
        &self,
        subscription_id: &SubscriptionId,
        from_sequence: u64,
        ttl_ms: u64,
    ) -> Result<String> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let _ = inner.subscriptions.get(subscription_id)?;
        let now = consumer_now_ms(&inner);
        prune_replay_leases(&mut inner, now);
        let lease_id = format!("replay_{}", uuid::Uuid::new_v4());
        inner.replay_leases.push(ReplayPin {
            lease_id: lease_id.clone(),
            subscription_id: subscription_id.clone(),
            from_sequence,
            expires_at_ms: now.saturating_add(ttl_ms.max(1)),
        });
        Ok(lease_id)
    }

    pub async fn end_replay_lease(&self, lease_id: &str) -> Result<()> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        inner.replay_leases.retain(|l| l.lease_id != lease_id);
        Ok(())
    }

    pub async fn compaction_policy(&self) -> Result<CompactionPolicy> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        Ok(inner.compaction_policy.clone())
    }

    pub async fn set_compaction_policy(
        &self,
        session: &SessionId,
        policy: CompactionPolicy,
    ) -> Result<()> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let actor = inner.access.capability(session)?;
        if !actor.permissions.contains(Permission::Grant) {
            return Err(Error::AuthorizationDenied(
                "set_compaction_policy requires GRANT".into(),
            ));
        }
        inner.compaction_policy = policy;
        persist_compaction_state(&mut inner)?;
        let user_id = inner
            .access
            .session(session)
            .ok()
            .and_then(|s| s.user_id.as_ref().map(|u| u.as_str().to_string()));
        inner.audit.record_security(
            Some(session),
            user_id.as_deref(),
            None,
            None,
            "COMPACTION_POLICY_SET",
            "ok",
            "",
        );
        Ok(())
    }

    pub async fn select_compaction_candidate(&self) -> Result<Option<CompactionCandidate>> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let journal = inner.journal.as_ref().ok_or(Error::Locked)?;
        journal
            .select_compaction_candidate(&inner.compaction_policy)
            .map_err(Error::from)
    }

    /// Phase 5.7.8: select compaction candidate within one partition.
    pub async fn select_compaction_candidate_for_partition(
        &self,
        partition_id: u32,
    ) -> Result<Option<CompactionCandidate>> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let journal = inner.journal.as_ref().ok_or(Error::Locked)?;
        journal
            .select_compaction_candidate_for_partition(
                dmc_journal::PartitionId(partition_id),
                &inner.compaction_policy,
            )
            .map_err(Error::from)
    }

    /// Phase 5.6.2 / 5.7.8: build physical compaction artifact without changing authoritative topology.
    pub async fn compact_journal(&self) -> Result<CompactionArtifact> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let policy = inner.compaction_policy.clone();
        let journal = inner.journal.as_mut().ok_or(Error::Locked)?;
        let candidate = journal
            .select_compaction_candidate(&policy)?
            .ok_or_else(|| Error::Invalid("no compaction candidate".into()))?;
        let mut compactor = JournalSegmentCompactor::new(journal);
        compactor.compact(&candidate).map_err(Error::from)
    }

    /// Phase 5.7.8: compact one partition (one topology job).
    pub async fn compact_journal_partition(&self, partition_id: u32) -> Result<CompactionArtifact> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let policy = inner.compaction_policy.clone();
        let journal = inner.journal.as_mut().ok_or(Error::Locked)?;
        let candidate = journal
            .select_compaction_candidate_for_partition(
                dmc_journal::PartitionId(partition_id),
                &policy,
            )?
            .ok_or_else(|| {
                Error::Invalid(format!("no compaction candidate for partition {partition_id}"))
            })?;
        let mut compactor = JournalSegmentCompactor::new(journal);
        compactor.compact(&candidate).map_err(Error::from)
    }

    /// Phase 5.6.3: publish compaction artifact into authoritative journal manifest.
    pub async fn publish_compaction(&self, artifact: CompactionArtifact) -> Result<JournalManifest> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let journal = inner.journal.as_mut().ok_or(Error::Locked)?;
        let mut compactor = JournalSegmentCompactor::new(journal);
        compactor.publish(&artifact).map_err(Error::from)
    }

    /// Phase 5.3: trim sealed journal segments through the current retention watermark.
    pub async fn trim_journal(&self) -> Result<TrimResult> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let through = compute_retention_watermark(&inner)
            .trim_through
            .ok_or(Error::TrimUnsafe)?;
        trim_journal_inner(&mut inner, through)
    }

    /// Trim through `through` if it does not exceed the computed retention watermark.
    pub async fn trim_journal_through(&self, through: u64) -> Result<TrimResult> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        trim_journal_inner(&mut inner, through)
    }

    /// First journal sequence still available for replay after segment GC.
    pub async fn oldest_available_sequence(&self) -> Result<u64> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        inner
            .journal
            .as_ref()
            .ok_or(Error::Locked)?
            .oldest_available_sequence()
            .map_err(Error::from)
    }

    /// ACK a specific delivery. Duplicate ACK of the last acked delivery is a no-op success.
    /// An older delivery_id must not acknowledge a newer in-flight attempt.
    pub async fn ack(
        &self,
        session: &SessionId,
        subscription_id: &SubscriptionId,
        delivery_id: &DeliveryId,
    ) -> Result<()> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let sub = inner.subscriptions.get(subscription_id)?.clone();
        require_subscription_control(&inner, session, &sub)?;
        let sequence = inner.consumer_meta.ack_delivery(subscription_id, delivery_id)?;
        inner.subscriptions.apply_offset(subscription_id.as_str(), sequence);
        inner.offsets.insert(
            subscription_id.0.clone(),
            ConsumerOffset {
                consumer_id: subscription_id.0.clone(),
                path_scope: String::new(),
                sequence,
            },
        );
        persist_consumer_state(&mut inner)
    }

    pub async fn ack_batch(
        &self,
        session: &SessionId,
        subscription_id: &SubscriptionId,
        delivery_ids: &[DeliveryId],
    ) -> Result<AckBatchResult> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let sub = inner.subscriptions.get(subscription_id)?.clone();
        require_subscription_control(&inner, session, &sub)?;
        let result = inner.consumer_meta.ack_batch(subscription_id, delivery_ids)?;
        inner
            .subscriptions
            .apply_offset(subscription_id.as_str(), result.offset);
        inner.offsets.insert(
            subscription_id.0.clone(),
            ConsumerOffset {
                consumer_id: subscription_id.0.clone(),
                path_scope: String::new(),
                sequence: result.offset,
            },
        );
        persist_consumer_state(&mut inner)?;
        Ok(result)
    }

    pub async fn consumer_lag(&self, subscription_id: &SubscriptionId) -> Result<ConsumerLag> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let _ = inner.subscriptions.get(subscription_id)?;
        Ok(compute_lag(&inner, subscription_id))
    }

    pub async fn consumer_metrics(&self) -> Result<ConsumerMetrics> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let journal_head = journal_head(&inner);
        let subscriptions: Vec<_> = inner
            .subscriptions
            .list()
            .into_iter()
            .map(|sub| compute_lag(&inner, &sub.id))
            .collect();
        let total_dlq = subscriptions.iter().map(|s| s.dlq_count).sum();
        Ok(ConsumerMetrics {
            subscriptions,
            journal_head,
            total_dlq,
        })
    }

    pub async fn list_dlq(
        &self,
        session: &SessionId,
        subscription_id: &SubscriptionId,
    ) -> Result<Vec<DlqEntry>> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let _ = inner.subscriptions.get(subscription_id)?;
        require_dlq_perm(&inner, session, subscription_id, Permission::Read)?;
        Ok(dlq::list_overlay_entries(&inner.overlay, subscription_id))
    }

    pub async fn read_dlq_entry(&self, session: &SessionId, entry_id: &DlqEntryId) -> Result<DlqEntry> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let entry = dlq::find_overlay_entry(&inner.overlay, entry_id)
            .ok_or_else(|| Error::UnknownDlq(entry_id.to_string()))?;
        require_dlq_perm(&inner, session, &entry.subscription_id, Permission::Read)?;
        Ok(entry)
    }

    pub async fn retry_dlq(
        &self,
        session: &SessionId,
        entry_id: &DlqEntryId,
    ) -> Result<DeliveredEvent> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let envelope = dlq::find_overlay_entry(&inner.overlay, entry_id)
            .ok_or_else(|| Error::UnknownDlq(entry_id.to_string()))?;
        require_dlq_perm(&inner, session, &envelope.subscription_id, Permission::Read)?;
        let sub = inner.subscriptions.get(&envelope.subscription_id)?.clone();
        let original = journal_entry_at(&mut inner, envelope.original_sequence)?;
        let now = consumer_now_ms(&inner);
        let delivery = inner.consumer_meta.begin_dlq_retry(
            &sub.id,
            envelope.original_sequence,
            envelope.original_event_id.clone(),
            now,
        );
        persist_consumer_state(&mut inner)?;
        delivered_from(&original, delivery)
    }

    pub async fn delete_dlq(&self, session: &SessionId, entry_id: &DlqEntryId) -> Result<()> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let envelope = dlq::find_overlay_entry(&inner.overlay, entry_id)
            .ok_or_else(|| Error::UnknownDlq(entry_id.to_string()))?;
        let path = parse_path(&dlq::dlq_entry_path(
            &envelope.subscription_id,
            &envelope.id,
        ))?;
        inner
            .access
            .authorize(session, &path, Permission::Delete)?;
        let body = OverlayDeleteBody {
            source: dlq::DLQ_SOURCE.into(),
        };
        journal_mutation(
            &mut inner,
            session,
            &path,
            JournalEventKind::DataDelete,
            Operation::OverlayDelete,
            encode_cbor(&body)?,
            "DLQ_DELETE",
            EventKind::OverlayApply,
            Vec::new(),
            None,
        )?;
        Ok(())
    }

    pub async fn subscribe_stream(
        &self,
        id: &StreamId,
    ) -> Result<broadcast::Receiver<StreamMessage>> {
        Ok(self.inner.lock().await.hub.subscribe_stream(id)?)
    }

    pub async fn register_trigger(&self, trigger: TriggerDef) -> Result<TriggerId> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        if inner.hub.trigger(&trigger.id).is_ok() {
            return Err(Error::Invalid(format!("trigger exists: {}", trigger.id)));
        }
        let session = inner.access.admin_session_id()?;
        let path = parse_path(&format!("system/runtime/triggers/{}", trigger.id))?;
        let body = RuntimeConfigBody {
            kind: "trigger".into(),
            spec: serde_json::to_value(&trigger).map_err(|e| Error::Invalid(e.to_string()))?,
        };
        let id = trigger.id.clone();
        journal_mutation(
            &mut inner,
            &session,
            &path,
            JournalEventKind::RuntimeConfig,
            Operation::RuntimeConfig,
            encode_cbor(&body)?,
            "TRIGGER",
            EventKind::OverlayApply,
            Vec::new(),
            None,
        )?;
        Ok(id)
    }

    pub async fn list_triggers(&self) -> Vec<TriggerDef> {
        self.inner.lock().await.hub.list_triggers()
    }

    pub async fn recent_events(&self, limit: usize) -> Vec<CoreEvent> {
        self.inner.lock().await.hub.recent_events(limit)
    }

    /// Seal static base data (immutable reference). Prefer this for catalogs/seeds.
    pub async fn seal_base(&self, session: &SessionId, path: &str, payload: &[u8]) -> Result<()> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        write_base(&mut inner, &self.events, session, path, payload)
    }

    /// Inbound processing: authorize → overlay layer (base untouched) → events/triggers.
    pub async fn ingest(
        &self,
        session: SessionId,
        stream: StreamId,
        path: &str,
        payload: &[u8],
    ) -> Result<()> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let entry = inner.hub.stream_entry(&stream)?;
        if entry.spec.direction != crate::stream::StreamDirection::Inbound {
            return Err(Error::NotInbound(stream.to_string()));
        }
        let key_path = parse_path(path)?;
        if !entry.spec.path_scope.is_prefix_of(&key_path) {
            return Err(Error::OutsideScope(path.to_string()));
        }
        let stream_perms = inner
            .access
            .capability_set(&session)?
            .permissions_covering(&entry.spec.path_scope);
        if !entry.spec.required_perms.is_subset_of(stream_perms) {
            return Err(Error::from_vault(dmc_vault::Error::AccessDenied(
                "STREAM".into(),
                path.to_string(),
            )));
        }
        apply_overlay(
            &mut inner,
            &self.events,
            &session,
            path,
            payload,
            &format!("stream:{}", stream),
            Some(stream),
        )?;
        Ok(())
    }

    pub async fn put_overlay(
        &self,
        session: &SessionId,
        path: &str,
        payload: &[u8],
        source: &str,
    ) -> Result<OverlayPatch> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        apply_overlay(
            &mut inner,
            &self.events,
            session,
            path,
            payload,
            source,
            None,
        )?;
        Ok(inner
            .overlay
            .get(path)
            .cloned()
            .ok_or_else(|| Error::Invalid("overlay missing after apply".into()))?)
    }

    pub async fn list_overlays(&self, prefix: &str) -> Vec<OverlayPatch> {
        self.inner.lock().await.overlay.list_under(prefix)
    }

    pub async fn resolve(&self, session: &SessionId, path: &str) -> Result<ResolvedView> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let key_path = parse_path(path)?;
        inner
            .access
            .authorize(session, &key_path, Permission::Read)?;
        let cap = inner.access.capability_for(session, &key_path, Permission::Read)?;
        let base = match inner.kv.as_mut().ok_or(Error::Locked)?.get(path, &cap) {
            Ok(v) => Some(v),
            Err(dmc_vault::Error::NotFound(_)) => None,
            Err(e) => return Err(Error::from_vault(e)),
        };
        let overlay = inner.overlay.get(path).cloned();
        Ok(merge_view(path, base, overlay))
    }

    /// Resolved value: overlay wins; deleted overlay hides base.
    pub async fn get_data(&self, session: &SessionId, path: &str) -> Result<Vec<u8>> {
        let view = self.resolve(session, path).await?;
        if view.deleted {
            return Err(Error::from_vault(dmc_vault::Error::NotFound(path.into())));
        }
        view.payload
            .ok_or_else(|| Error::from_vault(dmc_vault::Error::NotFound(path.into())))
    }

    pub async fn put_data(&self, session: &SessionId, path: &str, payload: &[u8]) -> Result<()> {
        self.put_data_with(session, path, payload, None).await?;
        Ok(())
    }

    pub async fn put_data_with(
        &self,
        session: &SessionId,
        path: &str,
        payload: &[u8],
        options: Option<PutOptions>,
    ) -> Result<PutResult> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        if let Some(opts) = options.as_ref() {
            if !opts.idempotency_key.is_empty() {
                let producer_id = producer_id_of(opts);
                if let Some(rec) = inner.producer_meta.lookup(producer_id, &opts.idempotency_key) {
                    return Ok(PutResult {
                        event_id: rec.event_id.clone(),
                        sequence: rec.sequence,
                        replay: true,
                    });
                }
            }
        }
        let applied = apply_overlay(
            &mut inner,
            &self.events,
            session,
            path,
            payload,
            "api",
            None,
        )?;
        if let Some(opts) = options.as_ref() {
            if !opts.idempotency_key.is_empty() {
                let producer_id = producer_id_of(opts);
                let now = consumer_now_ms(&inner);
                inner.producer_meta.remember(
                    producer_id,
                    &opts.idempotency_key,
                    applied.event_id.clone(),
                    applied.sequence,
                    path.to_string(),
                    now,
                );
                persist_producer_state(&mut inner)?;
            }
        }
        Ok(PutResult {
            event_id: applied.event_id,
            sequence: applied.sequence,
            replay: false,
        })
    }

    pub async fn delete_data(&self, session: &SessionId, path: &str) -> Result<()> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let key_path = parse_path(path)?;
        inner
            .access
            .authorize(session, &key_path, Permission::Delete)?;
        let body = OverlayDeleteBody {
            source: "api".into(),
        };
        journal_mutation(
            &mut inner,
            session,
            &key_path,
            JournalEventKind::DataDelete,
            Operation::OverlayDelete,
            encode_cbor(&body)?,
            "OVERLAY_DELETE",
            EventKind::OverlayApply,
            Vec::new(),
            None,
        )?;
        Ok(())
    }

    pub async fn list_keys(&self, session: &SessionId, prefix: &str) -> Result<Vec<String>> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let cap = inner.access.capability(session)?;
        let mut keys = inner
            .kv
            .as_mut()
            .ok_or(Error::Locked)?
            .list_keys(prefix, &cap)
            .map_err(Error::from_vault)?;
        for p in inner.overlay.list_under(prefix) {
            if !p.deleted && !keys.iter().any(|k| k == &p.path) {
                keys.push(p.path);
            }
        }
        keys.sort();
        keys.dedup();
        // drop deleted
        keys.retain(|k| inner.overlay.get(k).map(|p| !p.deleted).unwrap_or(true));
        Ok(keys)
    }

    /// Live schema: key-tree nodes + overlay annotations.
    pub async fn schema_snapshot(&self) -> Result<SchemaSnapshot> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let nodes = inner.kv.as_ref().ok_or(Error::Locked)?.tree().list_nodes();
        let overlays = inner.overlay.list();
        Ok(SchemaSnapshot {
            product: PRODUCT_NAME.into(),
            nodes,
            overlays,
            channels: inner.hub.list_channels(),
            streams: inner.hub.list_streams(),
            triggers: inner.hub.list_triggers(),
            subsystems: inner.subsystems.list(),
        })
    }

    pub async fn list_nodes(&self) -> Result<Vec<KeyNodeMeta>> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        Ok(inner.kv.as_ref().ok_or(Error::Locked)?.tree().list_nodes())
    }

    pub async fn ensure_node(&self, session: &SessionId, path: &str) -> Result<KeyNodeMeta> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let key_path = parse_path(path)?;
        let cap = inner.access.capability(session)?;
        authorize_tree_write(&cap, &key_path).map_err(Error::from_vault)?;
        let kv = inner.kv.as_mut().ok_or(Error::Locked)?;
        if key_path.is_root() {
            return kv
                .tree()
                .meta(&key_path)
                .ok_or_else(|| Error::from_vault(dmc_vault::Error::UnknownNode("/".into())));
        }
        kv.tree_mut().ensure_node(&key_path).map_err(Error::from)
    }

    pub async fn revoke_node(&self, session: &SessionId, path: &str) -> Result<()> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let key_path = parse_path(path)?;
        let cap = inner.access.capability(session)?;
        authorize_tree_write(&cap, &key_path).map_err(Error::from_vault)?;
        journal_mutation(
            &mut inner,
            session,
            &key_path,
            JournalEventKind::KeyRevoke,
            Operation::KeyRevoke,
            encode_cbor(&serde_json::json!({}))?,
            "REVOKE",
            EventKind::KeyRevoke,
            Vec::new(),
            None,
        )?;
        Ok(())
    }

    pub async fn rotate_node(&self, session: &SessionId, path: &str) -> Result<KeyNodeMeta> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let key_path = parse_path(path)?;
        let cap = inner.access.capability(session)?;
        authorize_tree_write(&cap, &key_path).map_err(Error::from_vault)?;
        let meta = inner
            .kv
            .as_mut()
            .ok_or(Error::Locked)?
            .tree_mut()
            .plan_rotate_meta(&key_path)?;
        journal_mutation(
            &mut inner,
            session,
            &key_path,
            JournalEventKind::KeyRotate,
            Operation::KeyRotate,
            encode_cbor(&meta)?,
            "ROTATE",
            EventKind::KeyRotate,
            Vec::new(),
            None,
        )?;
        Ok(meta)
    }

    pub async fn list_roles(&self) -> Result<Vec<Role>> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        Ok(inner.access.roles().list())
    }

    pub async fn create_role(
        &self,
        session: &SessionId,
        id: String,
        name: String,
        scope: KeyPath,
        permissions: PermissionSet,
    ) -> Result<Role> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let actor = inner.access.capability(session)?;
        let _ = actor
            .delegate(scope.clone(), permissions)
            .map_err(Error::from_vault)?;
        if inner.access.roles().get(&id).is_some() {
            return Err(Error::Invalid(format!("role already exists: {id}")));
        }
        let body = RoleConfigBody {
            action: "create".into(),
            id: id.clone(),
            name: Some(name.clone()),
            scope: Some(scope.to_string()),
            permissions: Some(
                permissions
                    .to_names()
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            ),
        };
        let path = parse_path(&format!("system/roles/{id}"))?;
        journal_mutation(
            &mut inner,
            session,
            &path,
            JournalEventKind::RoleConfig,
            Operation::RoleConfig,
            encode_cbor(&body)?,
            "ROLE_CREATE",
            EventKind::OverlayApply,
            Vec::new(),
            None,
        )?;
        Ok(inner
            .access
            .roles()
            .get(&id)
            .cloned()
            .ok_or_else(|| Error::Invalid("role missing after journal".into()))?)
    }

    pub async fn update_role(
        &self,
        session: &SessionId,
        id: &str,
        name: Option<String>,
        scope: Option<KeyPath>,
        permissions: Option<PermissionSet>,
    ) -> Result<Role> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let actor = inner.access.capability(session)?;
        let existing = inner
            .access
            .roles()
            .get(id)
            .cloned()
            .ok_or_else(|| Error::from_vault(dmc_vault::Error::NotFound(format!("role:{id}"))))?;
        let new_scope = scope.unwrap_or(existing.scope.clone());
        let new_perms = permissions.unwrap_or(existing.permissions);
        let _ = actor
            .delegate(new_scope.clone(), new_perms)
            .map_err(Error::from_vault)?;
        let new_name = name.unwrap_or(existing.name);
        let body = RoleConfigBody {
            action: "update".into(),
            id: id.to_string(),
            name: Some(new_name),
            scope: Some(new_scope.to_string()),
            permissions: Some(
                new_perms
                    .to_names()
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            ),
        };
        let path = parse_path(&format!("system/roles/{id}"))?;
        journal_mutation(
            &mut inner,
            session,
            &path,
            JournalEventKind::RoleConfig,
            Operation::RoleConfig,
            encode_cbor(&body)?,
            "ROLE_UPDATE",
            EventKind::OverlayApply,
            Vec::new(),
            None,
        )?;
        Ok(inner
            .access
            .roles()
            .get(id)
            .cloned()
            .ok_or_else(|| Error::Invalid("role missing after journal".into()))?)
    }

    pub async fn delete_role(&self, session: &SessionId, id: &str) -> Result<()> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        let active = inner.access.admin_session()?.role_id.clone();
        if active == id {
            return Err(Error::Invalid(
                "cannot delete the active role; switch session first".into(),
            ));
        }
        let body = RoleConfigBody {
            action: "delete".into(),
            id: id.to_string(),
            name: None,
            scope: None,
            permissions: None,
        };
        let path = parse_path(&format!("system/roles/{id}"))?;
        journal_mutation(
            &mut inner,
            session,
            &path,
            JournalEventKind::RoleConfig,
            Operation::RoleConfig,
            encode_cbor(&body)?,
            "ROLE_DELETE",
            EventKind::OverlayApply,
            Vec::new(),
            None,
        )?;
        Ok(())
    }

    pub async fn active_role(&self) -> Result<Role> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        Ok(inner.access.active_role()?)
    }

    pub async fn audit_log(&self) -> Vec<AuditRecord> {
        self.inner.lock().await.audit.list().to_vec()
    }

    pub async fn apply_session_to_storage(
        &self,
        session: &SessionId,
        storage: &mut StorageEngine,
    ) -> Result<()> {
        let inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        storage.set_capability(inner.access.capability(session)?);
        Ok(())
    }

    pub async fn register_subsystem(&self, spec: SubsystemSpec) -> Result<SubsystemId> {
        let mut inner = self.inner.lock().await;
        require_unlocked(&inner)?;
        inner.hub.stream(&spec.stream_id)?;
        inner.subsystems.register(spec).map_err(Error::Invalid)
    }

    pub async fn list_subsystems(&self) -> Vec<SubsystemInfo> {
        self.inner.lock().await.subsystems.list()
    }

    pub async fn start_subsystem(&self, id: &SubsystemId) -> Result<()> {
        let (spec, flag, session) = {
            let mut inner = self.inner.lock().await;
            require_unlocked(&inner)?;
            let session = inner.access.admin_session_id()?;
            let (spec, flag) = inner
                .subsystems
                .take_for_start(id)
                .map_err(Error::Invalid)?;
            (spec, flag, session)
        };
        let rt = self.clone();
        let sid = id.clone();
        let handle = tokio::spawn(async move {
            let mut n = 0u64;
            while flag.load(Ordering::SeqCst) {
                n += 1;
                let path = render_template(&spec.path_template, n);
                let payload = render_template(&spec.payload_template, n).into_bytes();
                let _ = rt
                    .ingest(session.clone(), spec.stream_id.clone(), &path, &payload)
                    .await;
                {
                    let mut inner = rt.inner.lock().await;
                    inner.subsystems.bump_tick(&sid);
                    let role = inner
                        .access
                        .session(&session)
                        .map(|s| s.role_id.clone())
                        .unwrap_or_else(|_| "root".into());
                    let ev = CoreEvent::new(
                        EventKind::SubsystemTick,
                        &path,
                        payload,
                        &session,
                        role,
                        Some(&spec.stream_id),
                    );
                    inner.hub.push_event(ev.clone());
                    let _ = rt.events.send(ev);
                }
                tokio::time::sleep(interval(&spec)).await;
            }
        });
        self.inner.lock().await.subsystems.attach_handle(id, handle);
        Ok(())
    }

    pub async fn stop_subsystem(&self, id: &SubsystemId) -> Result<()> {
        self.inner
            .lock()
            .await
            .subsystems
            .stop(id)
            .map_err(Error::Invalid)
    }

    pub async fn remove_subsystem(&self, id: &SubsystemId) -> Result<()> {
        self.inner
            .lock()
            .await
            .subsystems
            .remove(id)
            .map_err(Error::Invalid)
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct SchemaSnapshot {
    pub product: String,
    pub nodes: Vec<KeyNodeMeta>,
    pub overlays: Vec<OverlayPatch>,
    pub channels: Vec<ChannelInfo>,
    pub streams: Vec<StreamSpec>,
    pub triggers: Vec<TriggerDef>,
    pub subsystems: Vec<SubsystemInfo>,
}

fn require_unlocked(inner: &RuntimeInner) -> Result<()> {
    if inner.status != DbStatus::Unlocked || inner.kv.is_none() {
        Err(Error::Locked)
    } else {
        Ok(())
    }
}

fn detect_status(db_path: &Path) -> (DbStatus, Option<DbSnapshot>) {
    let layout = StorageLayout::from_db_path(db_path);
    if layout.base_snapshot().is_file() {
        return match DbSnapshot::load(&layout.base_snapshot()) {
            Ok(snap) => (DbStatus::Locked, Some(snap)),
            Err(_) => (DbStatus::Empty, None),
        };
    }
    if layout.legacy_snapshot().is_file() {
        return match DbSnapshot::load(&layout.legacy_snapshot()) {
            Ok(snap) => (DbStatus::Locked, Some(snap)),
            Err(_) => (DbStatus::Empty, None),
        };
    }
    (DbStatus::Empty, None)
}

fn apply_unlock(
    inner: &mut RuntimeInner,
    snap: DbSnapshot,
    master: &KeyMaterial,
) -> Result<SessionId> {
    let layout = StorageLayout::from_db_path(&inner.db_path);
    layout
        .ensure_dirs()
        .map_err(|e| Error::Invalid(e.to_string()))?;
    let salt = snap.salt().map_err(Error::from_vault)?;
    let mut journal = Journal::from_master(&layout, master, &salt)
        .map_err(|e| Error::Invalid(e.to_string()))?;
    journal
        .recover()
        .map_err(|e| Error::Invalid(e.to_string()))?;
    let journal_head = journal.last_sequence();
    inner.published_snapshot_sequence = None;
    let unlock_snap = match SnapshotStore::new(&layout).recover(journal_head) {
        Ok(Some(recovered)) => {
            inner.published_snapshot_sequence = Some(recovered.manifest.sequence);
            let manifest_snap: DbSnapshot = serde_json::from_slice(&recovered.payload)
                .map_err(|e| Error::Journal(dmc_journal::Error::SnapshotCorrupt(e.to_string())))?;
            if manifest_snap.last_applied_sequence != recovered.manifest.sequence {
                return Err(Error::Journal(dmc_journal::Error::SnapshotCorrupt(format!(
                    "snapshot last_applied_sequence {} != manifest sequence {}",
                    manifest_snap.last_applied_sequence,
                    recovered.manifest.sequence
                ))));
            }
            manifest_snap
        }
        Ok(None) => snap,
        Err(e) => return Err(Error::Journal(e)),
    };
    let last_applied = unlock_snap.last_applied_sequence;
    let (mut kv, roles) = unlock_snap.unlock(master)?;
    let overlay = unlock_snap.unseal_overlay(&mut kv).unwrap_or_default();
    inner.overlay = overlay_from_records(overlay);
    inner.last_applied_sequence = last_applied;
    inner.access = AccessControl::new_bare(roles);
    if let Ok(Some(raw)) = unlock_snap.unseal_users(&mut kv) {
        if let Ok(users) = serde_json::from_slice::<Vec<dmc_security::User>>(&raw) {
            let mut dir = dmc_security::UserDirectory::default();
            dir.replace(users);
            inner.access.replace_users(dir);
        }
    }
    if let Ok(Some(raw)) = unlock_snap.unseal_capabilities(&mut kv) {
        if let Ok(caps) = serde_json::from_slice::<Vec<dmc_security::IssuedCapability>>(&raw) {
            inner.access.replace_capabilities(caps);
        }
    } else if inner.access.is_dev_provisioned() {
        inner.access.ensure_policy_capabilities();
    }
    let session = if inner.access.is_dev_provisioned() {
        inner.access.open_user_session("root", Some("local"))?
    } else {
        SessionId::from("unprovisioned")
    };
    // Phase 1: full replay. last_applied_sequence is recorded for
    // future compaction; registries are not in the snapshot.
    let entries = journal
        .replay(0, kv.tree_mut())
        .map_err(|e| Error::Invalid(e.to_string()))?;
    inner.kv = Some(kv);
    inner.journal = Some(journal);
    inner.snapshot = Some(unlock_snap);
    inner.status = DbStatus::Unlocked;
    inner.offsets.clear();
    inner.subscriptions.clear();
    inner.seen_event_ids.clear();
    for entry in &entries {
        apply_live(inner, entry, ApplyMode::Replay)?;
        inner.hub.push_event(core_event_from_journal(entry));
        let role = entry.actor_role.clone();
        let session = SessionId::from(hex::encode(entry.actor_session));
        inner.audit.record_full(
            &session,
            &role,
            entry.path.to_string().trim_start_matches('/'),
            &format!("{:?}", entry.operation),
            "ok",
            &event_id_hex(&entry.event_id),
            entry.sequence,
            entry.key_version,
        );
    }
    let salt = inner.kv.as_ref().ok_or(Error::Locked)?.tree().salt().to_vec();
    let kek = derive_metadata_kek(master, &salt);
    inner.metadata_kek = Some(kek.clone());
    let has_file = layout.consumer_meta().is_file();
    inner.consumer_meta = load_consumer_meta(&layout, &kek)?;
    inner.group_meta = load_group_meta(&layout, &kek)?;
    inner.group_meta.mark_all_pending_for_redelivery();
    reconcile_group_leases_inner(inner)?;
    inner.producer_meta = load_producer_meta(&layout, &kek)?;
    inner.retention_policy = load_retention_policy(&layout, &kek)?;
    inner.compaction_policy = load_compaction_policy(&layout, &kek)?;
    if has_file {
        for (id, progress) in &inner.consumer_meta.progress {
            inner.subscriptions.apply_offset(id, progress.offset);
            inner.offsets.insert(
                id.clone(),
                ConsumerOffset {
                    consumer_id: id.clone(),
                    path_scope: String::new(),
                    sequence: progress.offset,
                },
            );
        }
    } else {
        for sub in inner.subscriptions.list() {
            inner.consumer_meta.ensure(&sub.id).offset = sub.position.sequence;
        }
    }
    reconcile_dlq_metadata(inner)?;
    Ok(session)
}

fn persist_consumer_state(inner: &mut RuntimeInner) -> Result<()> {
    let kek = inner.metadata_kek.as_ref().ok_or(Error::Locked)?;
    let layout = StorageLayout::from_db_path(&inner.db_path);
    save_consumer_meta(&layout, kek, &inner.consumer_meta)
}

fn persist_group_state(inner: &mut RuntimeInner) -> Result<()> {
    crate::group_crash_injection::maybe_group_crash(
        crate::group_crash_injection::GroupCrashPoint::G2_AfterStateMutation,
    )?;
    let kek = inner.metadata_kek.as_ref().ok_or(Error::Locked)?;
    let layout = StorageLayout::from_db_path(&inner.db_path);
    save_group_meta(&layout, kek, &inner.group_meta)
}

fn reconcile_group_leases_inner(inner: &mut RuntimeInner) -> Result<LeaseReconcileResult> {
    let now = consumer_now_ms(inner);
    let result = inner.group_meta.reconcile_group_leases(now);
    for (group_id, member_id) in &result.expired_members {
        let stream_path = inner
            .group_meta
            .get(group_id)
            .map(|g| g.stream_id.to_string())
            .unwrap_or_default();
        inner.audit.record_security(
            None,
            None,
            None,
            None,
            "GROUP_MEMBER_EXPIRED",
            "ok",
            &format!("{stream_path}/{group_id}/{member_id}"),
        );
    }
    if !result.expired_members.is_empty() {
        persist_group_state(inner)?;
    }
    Ok(result)
}

fn persist_producer_state(inner: &mut RuntimeInner) -> Result<()> {
    let kek = inner.metadata_kek.as_ref().ok_or(Error::Locked)?;
    let layout = StorageLayout::from_db_path(&inner.db_path);
    save_producer_meta(&layout, kek, &inner.producer_meta)
}

fn persist_retention_state(inner: &mut RuntimeInner) -> Result<()> {
    let kek = inner.metadata_kek.as_ref().ok_or(Error::Locked)?;
    let layout = StorageLayout::from_db_path(&inner.db_path);
    save_retention_policy(&layout, kek, &inner.retention_policy)
}

fn persist_compaction_state(inner: &mut RuntimeInner) -> Result<()> {
    let kek = inner.metadata_kek.as_ref().ok_or(Error::Locked)?;
    let layout = StorageLayout::from_db_path(&inner.db_path);
    save_compaction_policy(&layout, kek, &inner.compaction_policy)
}

fn compute_retention_policy_trim(inner: &RuntimeInner) -> Result<Option<u64>> {
    if inner.retention_policy.is_unbounded() {
        return Ok(None);
    }
    let journal = inner.journal.as_ref().ok_or(Error::Locked)?;
    let now = consumer_now_ms(inner);
    journal
        .retention_policy_trim_through(
            inner.retention_policy.max_age_ms,
            inner.retention_policy.max_bytes,
            now,
        )
        .map_err(|e| Error::Invalid(e.to_string()))
}

fn trim_journal_inner(inner: &mut RuntimeInner, through: u64) -> Result<TrimResult> {
    let wm = compute_retention_watermark(inner);
    match wm.trim_through {
        None => return Err(Error::TrimUnsafe),
        Some(max) if through > max => {
            return Err(Error::TrimBeyondWatermark {
                requested: through,
                watermark: max,
            });
        }
        Some(_) => {}
    }
    let journal = inner.journal.as_mut().ok_or(Error::Locked)?;
    journal.trim_through(through).map_err(Error::from)
}

fn compute_retention_watermark(inner: &RuntimeInner) -> RetentionWatermark {
    let now = consumer_now_ms(inner);
    let consumers = consumer_pins_from_meta(&inner.consumer_meta);
    let mut refs: Vec<&dyn dmc_journal::JournalPin> =
        consumers.iter().map(|p| p as &dyn dmc_journal::JournalPin).collect();
    let snapshot_pin;
    if let Some(seq) = inner.published_snapshot_sequence {
        snapshot_pin = SnapshotPin { sequence: seq };
        refs.push(&snapshot_pin);
    }
    let active_replay: Vec<ReplayPin> = inner
        .replay_leases
        .iter()
        .filter(|l| l.active_at(now))
        .cloned()
        .collect();
    for lease in &active_replay {
        refs.push(lease);
    }
    let retention_pin;
    if let Ok(Some(seq)) = compute_retention_policy_trim(inner) {
        retention_pin = RetentionPolicyPin { trim_through: seq };
        refs.push(&retention_pin);
    }
    if let Some(journal) = inner.journal.as_ref() {
        journal.retention_watermark(&refs)
    } else {
        calculate_watermark(refs.iter().copied())
    }
}

fn prune_replay_leases(inner: &mut RuntimeInner, now_ms: u64) {
    inner
        .replay_leases
        .retain(|l| l.active_at(now_ms));
}

fn producer_id_of(opts: &PutOptions) -> &str {
    if opts.producer_id.is_empty() {
        LOCAL_PRODUCER_ID
    } else {
        opts.producer_id.as_str()
    }
}

fn journal_head(inner: &RuntimeInner) -> u64 {
    inner
        .journal
        .as_ref()
        .map(|j| j.last_sequence())
        .unwrap_or(inner.last_applied_sequence)
}

fn compute_lag(inner: &RuntimeInner, subscription_id: &SubscriptionId) -> ConsumerLag {
    let journal_head = journal_head(inner);
    let progress = inner.consumer_meta.get(subscription_id);
    let offset = progress.map(|p| p.offset).unwrap_or(0);
    let pending = progress.and_then(|p| p.pending.as_ref()).map(|p| PendingSummary {
        sequence: p.sequence,
        attempt: p.attempt,
        event_id: p.event_id.clone(),
    });
    let retry_backoff_until = progress.and_then(|p| {
        let pending = p.pending.as_ref()?;
        let until = p.retry.retry_at_ms(pending.updated_at, pending.attempt);
        (until > consumer_now_ms(inner)).then_some(until)
    });
    let dlq_count = dlq::list_overlay_entries(&inner.overlay, subscription_id).len() as u64;
    ConsumerLag {
        subscription_id: subscription_id.to_string(),
        journal_head,
        offset,
        lag_events: journal_head.saturating_sub(offset),
        pending,
        dlq_count,
        retry_backoff_until,
    }
}

fn consumer_now_ms(inner: &RuntimeInner) -> u64 {
    crate::clock::runtime_now_ms(inner.now_ms_override)
}

fn require_subscription_control(
    inner: &RuntimeInner,
    session: &SessionId,
    sub: &Subscription,
) -> Result<()> {
    let actor = inner.access.session(session)?;
    let same_subject = actor
        .user_id
        .as_ref()
        .map(|u| u.as_str() == sub.subject.as_str())
        .unwrap_or(false);
    if same_subject {
        return Ok(());
    }
    let cap = inner.access.capability(session)?;
    if !cap.permissions.contains(Permission::Grant) {
        return Err(Error::AuthorizationDenied(
            "requires subscription subject or GRANT".into(),
        ));
    }
    Ok(())
}

fn require_dlq_perm(
    inner: &RuntimeInner,
    session: &SessionId,
    subscription_id: &SubscriptionId,
    perm: Permission,
) -> Result<()> {
    let path = parse_path(&dlq::dlq_subscription_path(subscription_id))?;
    inner.access.authorize(session, &path, perm)?;
    Ok(())
}

fn reconcile_dlq_metadata(inner: &mut RuntimeInner) -> Result<()> {
    let ids: Vec<SubscriptionId> = inner
        .consumer_meta
        .progress
        .keys()
        .cloned()
        .map(SubscriptionId::from)
        .collect();
    let mut dirty = false;
    for id in ids {
        let dead = dlq::dead_sequences(&inner.overlay, &id);
        if let Some(pending) = inner.consumer_meta.get(&id).and_then(|p| p.pending.clone()) {
            if dead.contains(&pending.sequence) {
                inner.consumer_meta.complete_dlq(&id, pending.sequence);
                dirty = true;
            }
        }
    }
    if dirty {
        persist_consumer_state(inner)?;
    }
    Ok(())
}


fn group_consume_inner(
    inner: &mut RuntimeInner,
    session: &SessionId,
    group_id: &GroupId,
    member_id: &MemberId,
    generation: u64,
) -> Result<Option<GroupDeliveredEvent>> {
    let _ = reconcile_group_leases_inner(inner)?;

    let stream_id = inner.group_meta.get(group_id)?.stream_id.clone();
    let spec = inner.hub.stream(&stream_id)?;
    // AuthZ before history / pending recovery.
    require_group_stream_access(inner, session, &spec)?;

    let group = inner.group_meta.get(group_id)?;
    let member = group
        .members
        .get(member_id)
        .ok_or_else(|| Error::UnknownMember(member_id.to_string()))?;
    if member.state != crate::group::MemberState::Active {
        return Err(Error::MemberNotActive(member_id.to_string()));
    }
    if generation != group.generation {
        return Err(Error::StaleGeneration {
            got: generation,
            current: group.generation,
        });
    }

    let assigned = group.assigned_partitions_sorted(member_id);
    if assigned.is_empty() {
        return Ok(None);
    }

    let partition_count = group.partition_count.max(1);
    let max_in_flight = group.policy.effective_max_in_flight() as usize;
    let now = consumer_now_ms(inner);

    // 1) Crash/orphan recovery first — sequence ASC across assigned partitions.
    //    Bypasses redelivery backoff; bumps attempt + new delivery_id.
    if let Some(pending) = group.next_recovery_pending(member_id).cloned() {
        let pid = pending.partition_id;
        let entry = load_journal_entry_at(inner, pending.sequence)?.ok_or_else(|| {
            Error::Invalid(format!(
                "group pending sequence {} missing from journal",
                pending.sequence
            ))
        })?;
        if !spec.path_scope.is_prefix_of(&entry.path) {
            return Err(Error::AuthorizationDenied(
                "pending event path outside stream scope".into(),
            ));
        }
        let delivery = inner.group_meta.get_mut(group_id)?.begin_group_delivery(
            member_id,
            pid,
            pending.sequence,
            pending.event_id.clone(),
            now,
        )?;
        persist_group_state(inner)?;
        return Ok(Some(group_delivered_from(&entry, delivery, pid)?));
    }

    // 2) Under max_in_flight: deliver new events. At limit: redeliver only if retry/recovery due.
    for &pid in &assigned {
        let group = inner.group_meta.get(group_id)?;
        let pending_count = group.pending_count_for_partition(pid);
        if pending_count >= max_in_flight {
            let Some(pending) = group.lowest_pending(pid).cloned() else {
                continue;
            };
            if group.pending_retry_scheduled(&pending) || pending.await_redelivery {
                if !group.pending_ready_for_redelivery(&pending, now) {
                    return Err(Error::GroupRetryBackoff {
                        group_id: group_id.to_string(),
                        member_id: member_id.to_string(),
                        partition_id: pid,
                        sequence: pending.sequence,
                        attempt: pending.attempt,
                        retry_at_ms: pending.retry_at_ms,
                    });
                }
                let entry = load_journal_entry_at(inner, pending.sequence)?.ok_or_else(|| {
                    Error::Invalid(format!(
                        "group pending sequence {} missing from journal",
                        pending.sequence
                    ))
                })?;
                if !spec.path_scope.is_prefix_of(&entry.path) {
                    return Err(Error::AuthorizationDenied(
                        "pending event path outside stream scope".into(),
                    ));
                }
                let delivery = inner.group_meta.get_mut(group_id)?.begin_group_delivery(
                    member_id,
                    pid,
                    pending.sequence,
                    pending.event_id.clone(),
                    now,
                )?;
                persist_group_state(inner)?;
                return Ok(Some(group_delivered_from(&entry, delivery, pid)?));
            }
            continue;
        }

        let from = group.consume_from_exclusive(pid);
        let Some(entry) =
            next_group_partition_entry(inner, &spec, pid, partition_count, from)?
        else {
            continue;
        };
        let event_id = event_id_hex(&entry.event_id);
        let delivery = inner.group_meta.get_mut(group_id)?.begin_group_delivery(
            member_id,
            pid,
            entry.sequence,
            event_id,
            now,
        )?;
        persist_group_state(inner)?;
        return Ok(Some(group_delivered_from(&entry, delivery, pid)?));
    }

    Ok(None)
}

fn group_ack_inner(
    inner: &mut RuntimeInner,
    session: &SessionId,
    group_id: &GroupId,
    member_id: &MemberId,
    generation: u64,
    delivery_id: &crate::subscription::DeliveryId,
) -> Result<crate::group::GroupAckResult> {
    let _ = reconcile_group_leases_inner(inner)?;

    let stream_id = inner.group_meta.get(group_id)?.stream_id.clone();
    let spec = inner.hub.stream(&stream_id)?;
    require_group_stream_access(inner, session, &spec)?;

    let group = inner.group_meta.get(group_id)?;
    let member = group
        .members
        .get(member_id)
        .ok_or_else(|| Error::UnknownMember(member_id.to_string()))?;
    if member.state != crate::group::MemberState::Active {
        return Err(Error::MemberNotActive(member_id.to_string()));
    }

    let result = inner.group_meta.get_mut(group_id)?.ack_group_delivery(
        member_id,
        generation,
        delivery_id,
    )?;
    persist_group_state(inner)?;
    Ok(result)
}

fn group_retry_inner(
    inner: &mut RuntimeInner,
    session: &SessionId,
    group_id: &GroupId,
    member_id: &MemberId,
    generation: u64,
    delivery_id: &crate::subscription::DeliveryId,
) -> Result<crate::group::GroupRetryResponse> {
    let _ = reconcile_group_leases_inner(inner)?;

    let stream_id = inner.group_meta.get(group_id)?.stream_id.clone();
    let spec = inner.hub.stream(&stream_id)?;
    require_group_stream_access(inner, session, &spec)?;

    let group = inner.group_meta.get(group_id)?;
    let member = group
        .members
        .get(member_id)
        .ok_or_else(|| Error::UnknownMember(member_id.to_string()))?;
    if member.state != crate::group::MemberState::Active {
        return Err(Error::MemberNotActive(member_id.to_string()));
    }

    let now = consumer_now_ms(inner);
    let result = inner.group_meta.get_mut(group_id)?.retry_group_delivery(
        member_id,
        generation,
        delivery_id,
        now,
    )?;
    persist_group_state(inner)?;
    Ok(result)
}

fn next_group_partition_entry(
    inner: &mut RuntimeInner,
    spec: &StreamSpec,
    partition_id: u32,
    partition_count: u32,
    from_exclusive: u64,
) -> Result<Option<JournalEntry>> {
    let journal = inner.journal.as_ref().ok_or(Error::Locked)?;
    let mut reader = journal
        .merge_reader(from_exclusive)
        .map_err(|e| Error::Invalid(e.to_string()))?;
    let tree = inner
        .kv
        .as_mut()
        .ok_or(Error::Locked)?
        .tree_mut();
    loop {
        let batch = reader
            .next_batch(tree, 64)
            .map_err(|e| Error::Invalid(e.to_string()))?;
        if batch.is_empty() {
            return Ok(None);
        }
        for entry in batch {
            if !is_consumer_event(&entry) {
                continue;
            }
            if dlq::is_dlq_path(&entry.path) {
                continue;
            }
            if !spec.path_scope.is_prefix_of(&entry.path) {
                continue;
            }
            let pid = resolve_partition(&entry.path, None, partition_count)
                .map_err(|e| Error::Invalid(e.to_string()))?
                .as_u32();
            if pid != partition_id {
                continue;
            }
            if entry.sequence <= from_exclusive {
                continue;
            }
            return Ok(Some(entry));
        }
    }
}

fn load_journal_entry_at(
    inner: &mut RuntimeInner,
    sequence: u64,
) -> Result<Option<JournalEntry>> {
    let journal = inner.journal.as_ref().ok_or(Error::Locked)?;
    let from = sequence.saturating_sub(1);
    let mut reader = journal
        .merge_reader(from)
        .map_err(|e| Error::Invalid(e.to_string()))?;
    let tree = inner
        .kv
        .as_mut()
        .ok_or(Error::Locked)?
        .tree_mut();
    loop {
        let batch = reader
            .next_batch(tree, 64)
            .map_err(|e| Error::Invalid(e.to_string()))?;
        if batch.is_empty() {
            return Ok(None);
        }
        for entry in batch {
            if entry.sequence == sequence {
                return Ok(Some(entry));
            }
            if entry.sequence > sequence {
                return Ok(None);
            }
        }
    }
}

fn group_delivered_from(
    entry: &JournalEntry,
    delivery: crate::group::GroupDelivery,
    partition_id: u32,
) -> Result<GroupDeliveredEvent> {
    let payload = match entry.operation {
        Operation::OverlayPut => decode_cbor::<OverlayPutBody>(&entry.payload)
            .map(|b| b.payload)
            .unwrap_or_default(),
        Operation::SealBase => decode_cbor::<SealBaseBody>(&entry.payload)
            .map(|b| b.payload)
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    Ok(GroupDeliveredEvent {
        sequence: entry.sequence,
        event_id: delivery.event_id.clone(),
        path: entry.path.to_string().trim_start_matches('/').to_string(),
        payload,
        operation: format!("{:?}", entry.operation),
        partition_id,
        delivery,
    })
}


fn consume_next(inner: &mut RuntimeInner, sub: &Subscription) -> Result<Option<DeliveredEvent>> {
    loop {
        if let Err(e) = validate_subscription_capability(inner, sub, None) {
            return Err(Error::AuthorizationDenied(e.to_string()));
        }
        let now = consumer_now_ms(inner);
        let policy = inner
            .consumer_meta
            .get(&sub.id)
            .map(|p| p.retry)
            .unwrap_or_default();
        let pending = inner
            .consumer_meta
            .get(&sub.id)
            .and_then(|p| p.pending.clone());
        if let Some(pending) = pending {
            let entry = matching_entries(inner, sub, pending.sequence.saturating_sub(1), None)?
                .into_iter()
                .find(|e| e.sequence == pending.sequence)
                .ok_or_else(|| {
                    Error::Invalid(format!(
                        "pending sequence {} missing from journal",
                        pending.sequence
                    ))
                })?;
            if let Err(e) = validate_subscription_capability(inner, sub, Some(&entry.path)) {
                return Err(Error::AuthorizationDenied(e.to_string()));
            }
            let max_attempts = policy.max_attempts.max(1);
            if pending.attempt >= max_attempts {
                move_to_dlq(inner, sub, &pending, &entry)?;
                continue;
            }
            let retry_at_ms = policy.retry_at_ms(pending.updated_at, pending.attempt);
            if now < retry_at_ms {
                return Err(Error::RetryBackoff {
                    subscription_id: sub.id.to_string(),
                    sequence: pending.sequence,
                    attempt: pending.attempt,
                    retry_at_ms,
                });
            }
            let event_id = event_id_hex(&entry.event_id);
            let delivery = inner.consumer_meta.begin_delivery(
                &sub.id,
                entry.sequence,
                event_id,
                now,
            );
            persist_consumer_state(inner)?;
            return Ok(Some(delivered_from(&entry, delivery)?));
        }
        let offset = inner
            .consumer_meta
            .get(&sub.id)
            .map(|p| p.offset)
            .unwrap_or(sub.position.sequence);
        let dead = dlq::dead_sequences(&inner.overlay, &sub.id);
        let mut found = matching_entries(inner, sub, offset, None)?;
        found.retain(|e| !dead.contains(&e.sequence));
        if found.is_empty() {
            return Ok(None);
        }
        let entry = found.remove(0);
        if let Err(e) = validate_subscription_capability(inner, sub, Some(&entry.path)) {
            return Err(Error::AuthorizationDenied(e.to_string()));
        }
        let event_id = event_id_hex(&entry.event_id);
        let delivery = inner.consumer_meta.begin_delivery(
            &sub.id,
            entry.sequence,
            event_id,
            now,
        );
        persist_consumer_state(inner)?;
        return Ok(Some(delivered_from(&entry, delivery)?));
    }
}

fn move_to_dlq(
    inner: &mut RuntimeInner,
    sub: &Subscription,
    pending: &crate::subscription::PendingDelivery,
    entry: &JournalEntry,
) -> Result<()> {
    let already = dlq::list_overlay_entries(&inner.overlay, &sub.id)
        .iter()
        .any(|e| e.original_sequence == pending.sequence);
    if !already {
        let id = DlqEntryId::new();
        let path = parse_path(&dlq::dlq_entry_path(&sub.id, &id))?;
        let envelope = dlq::from_pending(
            id,
            pending,
            entry.path.to_string().trim_start_matches('/').to_string(),
            payload_bytes(entry),
            );
        let admin = inner.access.admin_session_id()?;
        let body = OverlayPutBody {
            payload: serde_json::to_vec(&envelope).map_err(|e| Error::Invalid(e.to_string()))?,
            source: dlq::DLQ_SOURCE.into(),
        };
        journal_mutation(
            inner,
            &admin,
            &path,
            JournalEventKind::OverlayApply,
            Operation::OverlayPut,
            encode_cbor(&body)?,
            "DLQ",
            EventKind::OverlayApply,
            Vec::new(),
            None,
        )?;
    }
    inner.consumer_meta.complete_dlq(&sub.id, pending.sequence);
    persist_consumer_state(inner)
}

fn payload_bytes(entry: &JournalEntry) -> Vec<u8> {
    match entry.operation {
        Operation::OverlayPut => decode_cbor::<OverlayPutBody>(&entry.payload)
            .map(|b| b.payload)
            .unwrap_or_default(),
        Operation::SealBase => decode_cbor::<SealBaseBody>(&entry.payload)
            .map(|b| b.payload)
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn journal_entry_at(inner: &mut RuntimeInner, sequence: u64) -> Result<JournalEntry> {
    let journal = inner.journal.take().ok_or(Error::Locked)?;
    let replayed = match inner.kv.as_mut() {
        Some(kv) => journal.replay(sequence.saturating_sub(1), kv.tree_mut()),
        None => {
            inner.journal = Some(journal);
            return Err(Error::Locked);
        }
    };
    inner.journal = Some(journal);
    let entries = replayed.map_err(|e| Error::Invalid(e.to_string()))?;
    entries
        .into_iter()
        .find(|e| e.sequence == sequence)
        .ok_or_else(|| Error::Invalid(format!("journal sequence {sequence} missing")))
}

fn materialize_checkpoint(inner: &RuntimeInner) -> Result<(DbSnapshot, u64)> {
    let kv = inner.kv.as_ref().ok_or(Error::Locked)?;
    let seq = inner
        .journal
        .as_ref()
        .map(|j| j.last_sequence())
        .unwrap_or(inner.last_applied_sequence);
    let overlay = overlay_records(&inner.overlay);
    let mut snap = DbSnapshot::from_kv_checkpoint(
        kv,
        inner.access.roles(),
        seq,
        Some(overlay.as_slice()),
    )?;
    if let Ok(json) = serde_json::to_vec(&inner.access.users().list()) {
        if let Ok(blob) = kv.seal_users_blob(&json) {
            snap.sealed_users = Some(blob);
        }
    }
    if let Ok(json) = serde_json::to_vec(&inner.access.list_issued()) {
        if let Ok(blob) = kv.seal_capabilities_blob(&json) {
            snap.sealed_capabilities = Some(blob);
        }
    }
    Ok((snap, seq))
}

fn publish_materialized_snapshot(inner: &mut RuntimeInner) -> Result<u64> {
    let (snap, seq) = materialize_checkpoint(inner)?;
    let payload = serde_json::to_vec(&snap).map_err(|e| Error::Invalid(e.to_string()))?;
    let layout = StorageLayout::from_db_path(&inner.db_path);
    layout
        .ensure_dirs()
        .map_err(|e| Error::Invalid(e.to_string()))?;
    let store = SnapshotStore::new(&layout);
    let manifest = store
        .publish(seq, &payload, consumer_now_ms(inner))
        .map_err(Error::from)?;
    snap.save(&layout.base_snapshot())?;
    inner.last_applied_sequence = seq;
    inner.snapshot = Some(snap);
    inner.published_snapshot_sequence = Some(manifest.sequence);
    if let Ok(meta) = serde_json::to_string_pretty(&serde_json::json!({
        "last_applied_sequence": seq,
        "overlay_count": inner.overlay.list().len(),
        "published_snapshot_sequence": manifest.sequence,
    })) {
        let _ = std::fs::write(layout.checkpoint(), meta);
    }
    Ok(manifest.sequence)
}

fn persist_checkpoint(inner: &mut RuntimeInner) -> Result<()> {
    let (snap, seq) = materialize_checkpoint(inner)?;
    let layout = StorageLayout::from_db_path(&inner.db_path);
    layout
        .ensure_dirs()
        .map_err(|e| Error::Invalid(e.to_string()))?;
    snap.save(&layout.base_snapshot())?;
    inner.last_applied_sequence = seq;
    inner.snapshot = Some(snap);
    if let Ok(meta) = serde_json::to_string_pretty(&serde_json::json!({
        "last_applied_sequence": seq,
        "overlay_count": inner.overlay.list().len(),
    })) {
        let _ = std::fs::write(layout.checkpoint(), meta);
    }
    Ok(())
}

fn journal_mutation(
    inner: &mut RuntimeInner,
    session: &SessionId,
    key_path: &KeyPath,
    event_kind: JournalEventKind,
    operation: Operation,
    payload: Vec<u8>,
    op: &str,
    kind: EventKind,
    event_payload: Vec<u8>,
    source_stream: Option<StreamId>,
) -> Result<JournalRef> {
    let role = inner.access.session(session)?.role_id.clone();
    let kv = inner.kv.as_mut().ok_or(Error::Locked)?;
    if !key_path.is_root() {
        kv.tree_mut().ensure_node(key_path)?;
    }
    let dek = kv.tree_mut().dek(key_path)?.clone();
    let key_version = kv
        .tree()
        .meta(key_path)
        .map(|m| m.generation)
        .unwrap_or(1);
    let bundle = node_bundle(kv, key_path);
    let draft = JournalEntryDraft {
        path: key_path.clone(),
        event_kind,
        operation,
        key_version,
        actor_session: session_bytes(session.as_str()),
        actor_role: role.clone(),
        node_bundle: bundle,
        payload: payload.clone(),
        partition_key: None,
    };
    let journal = inner.journal.as_mut().ok_or(Error::Locked)?;
    let r = journal
        .append(draft, &dek)
        .map_err(|e| Error::Invalid(e.to_string()))?;
    journal.sync().map_err(|e| Error::Invalid(e.to_string()))?;
    let entry = JournalEntry {
        sequence: r.sequence,
        event_id: r.event_id,
        timestamp_unix_ms: 0,
        path: key_path.clone(),
        event_kind,
        operation,
        key_version,
        actor_session: session_bytes(session.as_str()),
        actor_role: role.clone(),
        node_bundle: Vec::new(),
        payload,
    };
    apply_live(inner, &entry, ApplyMode::Live)?;
    finish_event(
        inner,
        session,
        &role,
        &key_path.to_string().trim_start_matches('/').to_string(),
        op,
        kind,
        event_payload,
        source_stream,
        &event_id_hex(&r.event_id),
        r.sequence,
        key_version,
    )?;
    Ok(JournalRef {
        sequence: r.sequence,
        event_id: event_id_hex(&r.event_id),
    })
}

fn apply_live(inner: &mut RuntimeInner, entry: &JournalEntry, mode: ApplyMode) -> Result<()> {
    let kv = inner.kv.as_mut().ok_or(Error::Locked)?;
    let mut sink = MaterializerSink {
        materializer: Materializer {
            kv,
            access: &mut inner.access,
            overlay: &mut inner.overlay,
            hub: &inner.hub,
            subscriptions: &mut inner.subscriptions,
            offsets: &mut inner.offsets,
            seen: &mut inner.seen_event_ids,
        },
        mode,
    };
    fan_out(&mut [&mut sink], entry)
}

fn is_consumer_event(entry: &JournalEntry) -> bool {
    matches!(
        entry.operation,
        Operation::OverlayPut | Operation::OverlayDelete | Operation::SealBase
    )
}

fn matching_entries(
    inner: &mut RuntimeInner,
    sub: &Subscription,
    from_exclusive: u64,
    limit: Option<usize>,
) -> Result<Vec<JournalEntry>> {
    let spec = inner.hub.stream(&sub.stream_id)?;
    let journal = inner.journal.as_ref().ok_or(Error::Locked)?;
    let mut reader = journal
        .merge_reader(from_exclusive)
        .map_err(|e| Error::Invalid(e.to_string()))?;
    let tree = inner
        .kv
        .as_mut()
        .ok_or(Error::Locked)?
        .tree_mut();
    let mut out = Vec::new();
    let chunk = limit.map(|n| n.max(1).min(256)).unwrap_or(256);
    loop {
        if limit.is_some_and(|n| out.len() >= n.max(1)) {
            break;
        }
        let fetch = limit
            .map(|n| n.max(1).saturating_sub(out.len()).min(chunk))
            .unwrap_or(chunk);
        let batch = reader
            .next_batch(tree, fetch)
            .map_err(|e| Error::Invalid(e.to_string()))?;
        if batch.is_empty() {
            break;
        }
        for entry in batch {
            if !is_consumer_event(&entry) {
                continue;
            }
            if dlq::is_dlq_path(&entry.path) {
                continue;
            }
            if !spec.path_scope.is_prefix_of(&entry.path) {
                continue;
            }
            out.push(entry);
            if limit.is_some_and(|n| out.len() >= n.max(1)) {
                break;
            }
        }
    }
    Ok(out)
}

fn require_replay_history(inner: &RuntimeInner, from_sequence: u64) -> Result<()> {
    let journal = inner.journal.as_ref().ok_or(Error::Locked)?;
    let oldest = journal
        .oldest_available_sequence()
        .map_err(Error::from)?;
    if from_sequence < oldest {
        return Err(Error::HistoryUnavailable {
            requested_from: from_sequence,
            oldest_available: oldest,
        });
    }
    Ok(())
}

fn pull_events(
    inner: &mut RuntimeInner,
    sub: &Subscription,
    from_exclusive: u64,
    limit: usize,
) -> Result<Vec<DeliveredEvent>> {
    if let Err(e) = validate_subscription_capability(inner, sub, None) {
        return Err(Error::AuthorizationDenied(e.to_string()));
    }
    let entries = matching_entries(inner, sub, from_exclusive, Some(limit.max(1)))?;
    let mut out = Vec::new();
    for entry in entries {
        if let Err(e) = validate_subscription_capability(inner, sub, Some(&entry.path)) {
            return Err(Error::AuthorizationDenied(e.to_string()));
        }
        let event_id = event_id_hex(&entry.event_id);
        let delivery = Delivery {
            delivery_id: DeliveryId::new(),
            subscription_id: sub.id.clone(),
            event_id,
            sequence: entry.sequence,
            attempt: 1,
        };
        out.push(delivered_from(&entry, delivery)?);
    }
    Ok(out)
}

fn require_group_stream_access(
    inner: &RuntimeInner,
    session: &SessionId,
    spec: &StreamSpec,
) -> Result<()> {
    let actor = inner.access.session(session)?;
    if actor.user_id.is_none() {
        return Err(Error::Invalid(
            "consumer group operations require a user session".into(),
        ));
    }
    inner
        .access
        .covering_for_scope(session, &spec.path_scope, spec.required_perms)
        .map_err(|e| Error::AuthorizationDenied(e.to_string()))?;
    Ok(())
}

fn require_group_member_session(member_session: &SessionId, session: &SessionId) -> Result<()> {
    if member_session != session {
        return Err(Error::AuthorizationDenied(
            "group member belongs to another session".into(),
        ));
    }
    Ok(())
}

fn validate_subscription_capability(
    inner: &RuntimeInner,
    sub: &Subscription,
    path: Option<&KeyPath>,
) -> Result<()> {
    let spec = inner.hub.stream(&sub.stream_id)?;
    let issued = inner
        .access
        .covering_for_subject(
            sub.subject.as_str(),
            &spec.path_scope,
            spec.required_perms,
        )
        .map_err(|e| Error::AuthorizationDenied(e.to_string()))?;
    let cap = issued.to_vault()?;
    if let Some(path) = path {
        if !cap.scope.is_prefix_of(path) {
            return Err(Error::AuthorizationDenied(format!(
                "path {path} outside capability {}",
                issued.id
            )));
        }
        if !spec.path_scope.is_prefix_of(path) {
            return Err(Error::OutsideScope(path.to_string()));
        }
    }
    Ok(())
}

fn delivered_from(entry: &JournalEntry, delivery: Delivery) -> Result<DeliveredEvent> {
    let payload = match entry.operation {
        Operation::OverlayPut => decode_cbor::<OverlayPutBody>(&entry.payload)
            .map(|b| b.payload)
            .unwrap_or_default(),
        Operation::SealBase => decode_cbor::<SealBaseBody>(&entry.payload)
            .map(|b| b.payload)
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    Ok(DeliveredEvent {
        sequence: entry.sequence,
        event_id: delivery.event_id.clone(),
        path: entry.path.to_string().trim_start_matches('/').to_string(),
        payload,
        operation: format!("{:?}", entry.operation),
        delivery,
    })
}

fn parse_path(raw: &str) -> Result<KeyPath> {
    let t = raw.trim().trim_matches('/');
    if t.is_empty() {
        Ok(KeyPath::root())
    } else {
        KeyPath::parse(t).map_err(Error::from_vault)
    }
}

fn merge_view(path: &str, base: Option<Vec<u8>>, overlay: Option<OverlayPatch>) -> ResolvedView {
    match overlay {
        Some(o) if o.deleted => ResolvedView {
            path: path.into(),
            base_present: base.is_some(),
            overlay_present: true,
            deleted: true,
            payload: None,
            layer_seq: Some(o.seq),
        },
        Some(o) => ResolvedView {
            path: path.into(),
            base_present: base.is_some(),
            overlay_present: true,
            deleted: false,
            payload: Some(o.payload),
            layer_seq: Some(o.seq),
        },
        None => ResolvedView {
            path: path.into(),
            base_present: base.is_some(),
            overlay_present: false,
            deleted: false,
            payload: base,
            layer_seq: None,
        },
    }
}

fn write_base(
    inner: &mut RuntimeInner,
    _events: &broadcast::Sender<CoreEvent>,
    session: &SessionId,
    path: &str,
    payload: &[u8],
) -> Result<()> {
    let key_path = parse_path(path)?;
    inner
        .access
        .authorize(session, &key_path, Permission::Write)?;
    let body = SealBaseBody {
        payload: payload.to_vec(),
    };
    journal_mutation(
        inner,
        session,
        &key_path,
        JournalEventKind::DataPut,
        Operation::SealBase,
        encode_cbor(&body)?,
        "SEAL_BASE",
        EventKind::DataPut,
        payload.to_vec(),
        None,
    )?;
    Ok(())
}

fn apply_overlay(
    inner: &mut RuntimeInner,
    _events: &broadcast::Sender<CoreEvent>,
    session: &SessionId,
    path: &str,
    payload: &[u8],
    source: &str,
    source_stream: Option<StreamId>,
) -> Result<JournalRef> {
    let key_path = parse_path(path)?;
    inner
        .access
        .authorize(session, &key_path, Permission::Write)?;
    let body = OverlayPutBody {
        payload: payload.to_vec(),
        source: source.to_string(),
    };
    journal_mutation(
        inner,
        session,
        &key_path,
        JournalEventKind::OverlayApply,
        Operation::OverlayPut,
        encode_cbor(&body)?,
        "OVERLAY",
        EventKind::OverlayApply,
        payload.to_vec(),
        source_stream,
    )
}

fn finish_event(
    inner: &mut RuntimeInner,
    session: &SessionId,
    role: &str,
    path: &str,
    op: &str,
    kind: EventKind,
    payload: Vec<u8>,
    source_stream: Option<StreamId>,
    event_id: &str,
    sequence: u64,
    key_version: u64,
) -> Result<()> {
    inner.audit.record_full(
        session, role, path, op, "ok", event_id, sequence, key_version,
    );
    let (user_id, device_id) = inner
        .access
        .session(session)
        .ok()
        .map(|s| {
            (
                s.user_id.as_ref().map(|u| u.to_string()),
                s.device_id.as_ref().map(|d| d.to_string()),
            )
        })
        .unwrap_or((None, None));
    let capability_id = parse_path(path).ok().and_then(|kp| {
        inner
            .access
            .authorize_with(session, &kp, Permission::Write)
            .or_else(|_| inner.access.authorize_with(session, &kp, Permission::Read))
            .or_else(|_| inner.access.authorize_with(session, &kp, Permission::Delete))
            .ok()
            .map(|c| c.id.to_string())
    });
    inner
        .audit
        .attach_identity(user_id, device_id, capability_id);
    let event = CoreEvent::new(kind, path, payload, session, role, source_stream.as_ref());
    inner.hub.push_event(event.clone());
    dispatch_triggers(inner, &inner_events_unused(), &event)
}

fn inner_events_unused() -> broadcast::Sender<CoreEvent> {
    let (tx, _) = broadcast::channel(16);
    tx
}

fn dispatch_triggers(
    inner: &mut RuntimeInner,
    events: &broadcast::Sender<CoreEvent>,
    event: &CoreEvent,
) -> Result<()> {
    let matched = inner.hub.matching_triggers(event);
    for def in matched {
        match def.action {
            TriggerAction::ForwardToStream { stream_id: dest } => {
                let entry = inner.hub.stream_entry(&dest)?;
                if entry.spec.direction != crate::stream::StreamDirection::Outbound {
                    return Err(Error::NotOutbound(dest.to_string()));
                }
                let key_path = parse_path(&event.path)?;
                if !entry.spec.path_scope.is_prefix_of(&key_path) {
                    return Err(Error::OutsideScope(event.path.clone()));
                }
                let session = SessionId::from(event.session.as_str());
                inner
                    .access
                    .authorize(&session, &key_path, Permission::Write)?;
                inner.hub.publish_stream(
                    &dest,
                    StreamMessage {
                        stream_id: dest.clone(),
                        path: event.path.clone(),
                        payload: event.payload.clone(),
                        event: EventKind::StreamMessage,
                    },
                )?;
                let fwd = CoreEvent::new(
                    EventKind::StreamMessage,
                    &event.path,
                    event.payload.clone(),
                    &session,
                    &event.role_id,
                    Some(&dest),
                );
                inner.hub.push_event(fwd.clone());
                let _ = events.send(fwd);
            }
        }
    }
    Ok(())
}
