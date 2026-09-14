use std::collections::{HashMap, HashSet};

use dmc_journal::{JournalEntry, JournalEventKind, Operation};
use dmc_vault::access::PermissionSet;
use dmc_vault::key::KeyPath;
use dmc_vault::persist::OverlayRecord;
use serde::{Deserialize, Serialize};

use crate::channel::{ChannelRegistry, ChannelSpec};
use crate::error::{Error, Result};
use crate::event::{CoreEvent, EventKind};
use crate::ids::{SessionId, StreamId};
use crate::overlay::{OverlayPatch, OverlayStore};
use crate::stream::{StreamManager, StreamSpec};
use crate::subscription::{Subscription, SubscriptionManager};
use crate::trigger::{TriggerDef, TriggerEngine};
use dmc_security::AccessControl;
use dmc_vault::store::EncryptedKv;
use dmc_vault::Capability;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OverlayPutBody {
    pub payload: Vec<u8>,
    pub source: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OverlayDeleteBody {
    pub source: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealBaseBody {
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoleConfigBody {
    pub action: String,
    pub id: String,
    pub name: Option<String>,
    pub scope: Option<String>,
    pub permissions: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeConfigBody {
    pub kind: String,
    pub spec: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsumerOffset {
    pub consumer_id: String,
    pub path_scope: String,
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyMode {
    Live,
    Replay,
}

pub fn encode_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| Error::Invalid(e.to_string()))?;
    Ok(buf)
}

pub fn decode_cbor<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    ciborium::from_reader(bytes).map_err(|e| Error::Invalid(e.to_string()))
}

pub fn overlay_records(store: &OverlayStore) -> Vec<OverlayRecord> {
    store
        .list()
        .into_iter()
        .map(|p| OverlayRecord {
            path: p.path,
            deleted: p.deleted,
            payload: p.payload,
            source: p.source,
            seq: p.seq,
        })
        .collect()
}

pub fn overlay_from_records(records: Vec<OverlayRecord>) -> OverlayStore {
    let mut store = OverlayStore::new();
    store.restore(
        records
            .into_iter()
            .map(|r| OverlayPatch {
                path: r.path,
                deleted: r.deleted,
                payload: r.payload,
                source: r.source,
                seq: r.seq,
            })
            .collect(),
    );
    store
}

pub fn node_bundle(kv: &EncryptedKv, path: &KeyPath) -> Vec<dmc_vault::KeyNodeMeta> {
    kv.tree()
        .list_nodes()
        .into_iter()
        .filter(|n| {
            n.key_path()
                .map(|p| p.is_prefix_of(path))
                .unwrap_or(false)
        })
        .collect()
}

pub struct Materializer<'a> {
    pub kv: &'a mut EncryptedKv,
    pub access: &'a mut AccessControl,
    pub overlay: &'a mut OverlayStore,
    pub channels: &'a mut ChannelRegistry,
    pub streams: &'a mut StreamManager,
    pub triggers: &'a mut TriggerEngine,
    pub subscriptions: &'a mut SubscriptionManager,
    pub offsets: &'a mut HashMap<String, ConsumerOffset>,
    pub seen: &'a mut HashSet<[u8; 16]>,
}

impl Materializer<'_> {
    pub fn apply(&mut self, entry: &JournalEntry, mode: ApplyMode) -> Result<()> {
        if !self.seen.insert(entry.event_id) {
            return Ok(());
        }
        if mode == ApplyMode::Replay {
            for meta in &entry.node_bundle {
                let _ = self.kv.tree_mut().install_meta(meta.clone());
            }
        }
        match entry.operation {
            Operation::OverlayPut => {
                let body: OverlayPutBody = decode_cbor(&entry.payload)?;
                self.overlay
                    .apply_at(&entry.path.to_string().trim_start_matches('/').to_string(), body.payload, &body.source, entry.sequence);
            }
            Operation::OverlayDelete => {
                let body: OverlayDeleteBody = decode_cbor(&entry.payload)?;
                self.overlay.mark_deleted_at(
                    entry.path.to_string().trim_start_matches('/'),
                    &body.source,
                    entry.sequence,
                );
            }
            Operation::SealBase => {
                let body: SealBaseBody = decode_cbor(&entry.payload)?;
                let cap = Capability::root_admin();
                let p = entry.path.to_string();
                let path = p.trim_start_matches('/');
                self.kv.put(path, &body.payload, &cap).map_err(Error::from_vault)?;
            }
            Operation::KeyRevoke => {
                self.kv.tree_mut().revoke(&entry.path)?;
            }
            Operation::KeyRotate => {
                let meta: dmc_vault::KeyNodeMeta = decode_cbor(&entry.payload)?;
                self.kv.tree_mut().install_meta(meta)?;
            }
            Operation::RoleConfig => {
                let body: RoleConfigBody = decode_cbor(&entry.payload)?;
                apply_role(self.access, &body)?;
            }
            Operation::RuntimeConfig => {
                let body: RuntimeConfigBody = decode_cbor(&entry.payload)?;
                apply_runtime(
                    self.channels,
                    self.streams,
                    self.triggers,
                    self.subscriptions,
                    &body,
                )?;
            }
            Operation::ConsumerOffset => {
                let body: ConsumerOffset = decode_cbor(&entry.payload)?;
                self.subscriptions
                    .apply_offset(&body.consumer_id, body.sequence);
                self.offsets.insert(body.consumer_id.clone(), body);
            }
        }
        Ok(())
    }
}

fn apply_role(access: &mut AccessControl, body: &RoleConfigBody) -> Result<()> {
    match body.action.as_str() {
        "create" | "update" => {
            let scope = match body.scope.as_deref() {
                None | Some("") | Some("/") => KeyPath::root(),
                Some(s) => KeyPath::parse(s.trim_start_matches('/'))?,
            };
            let perms = match &body.permissions {
                Some(n) => PermissionSet::from_names(n).map_err(Error::from_vault)?,
                None => PermissionSet::empty(),
            };
            let name = body.name.clone().unwrap_or_else(|| body.id.clone());
            access
                .roles_mut()
                .seed_role(&body.id, &name, scope, perms);
        }
        "delete" => {
            let _ = access.roles_mut().delete(&body.id);
        }
        _ => return Err(Error::Invalid(format!("unknown role action {}", body.action))),
    }
    Ok(())
}

fn apply_runtime(
    channels: &mut ChannelRegistry,
    streams: &mut StreamManager,
    triggers: &mut TriggerEngine,
    subscriptions: &mut SubscriptionManager,
    body: &RuntimeConfigBody,
) -> Result<()> {
    match body.kind.as_str() {
        "channel" => {
            let spec: ChannelSpec = serde_json::from_value(body.spec.clone())
                .map_err(|e| Error::Invalid(e.to_string()))?;
            if channels.get(&spec.id).is_err() {
                channels.configure(spec)?;
            }
        }
        "stream" => {
            let spec: StreamSpec = serde_json::from_value(body.spec.clone())
                .map_err(|e| Error::Invalid(e.to_string()))?;
            if streams.get(&spec.id).is_err() {
                streams.create(spec)?;
            }
        }
        "trigger" => {
            let def: TriggerDef = serde_json::from_value(body.spec.clone())
                .map_err(|e| Error::Invalid(e.to_string()))?;
            if !triggers.list().iter().any(|t| t.id == def.id) {
                triggers.register(def)?;
            }
        }
        "subscription" => {
            let sub: Subscription = serde_json::from_value(body.spec.clone())
                .map_err(|e| Error::Invalid(e.to_string()))?;
            if subscriptions.get(&sub.id).is_err() {
                subscriptions.insert(sub)?;
            }
        }
        _ => return Err(Error::Invalid(format!("unknown runtime kind {}", body.kind))),
    }
    Ok(())
}

pub fn core_event_from_journal(entry: &JournalEntry) -> CoreEvent {
    let kind = match entry.event_kind {
        JournalEventKind::DataPut => EventKind::DataPut,
        JournalEventKind::DataDelete => EventKind::DataDelete,
        JournalEventKind::KeyRevoke => EventKind::KeyRevoke,
        JournalEventKind::KeyRotate => EventKind::KeyRotate,
        JournalEventKind::StreamMessage => EventKind::StreamMessage,
        JournalEventKind::OverlayApply => EventKind::OverlayApply,
        JournalEventKind::SubsystemTick => EventKind::SubsystemTick,
        JournalEventKind::RuntimeConfig | JournalEventKind::RoleConfig => EventKind::OverlayApply,
        JournalEventKind::ConsumerOffset => EventKind::OverlayApply,
    };
    let session = SessionId::from(hex::encode(entry.actor_session));
    let payload = match entry.operation {
        Operation::OverlayPut => decode_cbor::<OverlayPutBody>(&entry.payload)
            .map(|b| b.payload)
            .unwrap_or_default(),
        Operation::SealBase => decode_cbor::<SealBaseBody>(&entry.payload)
            .map(|b| b.payload)
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    CoreEvent::new(
        kind,
        entry.path.to_string().trim_start_matches('/'),
        payload,
        &session,
        &entry.actor_role,
        None::<&StreamId>,
    )
}
