//! User → roles → issued capabilities → session refs. Local, no network.

use std::collections::{HashMap, HashSet};

use dmc_vault::access::{Capability, Permission, PermissionSet, Role, RoleRegistry};
use dmc_vault::key::KeyPath;

use crate::audit::{AuditOperation, AuditResult, AuditTrail};
use crate::capabilities::{
    CapabilityId, CapabilityRef, CapabilityRegistry, CapabilitySet, CapabilityStatus,
    IssuedCapability,
};
use crate::identity::user::{User, UserDirectory, UserStatus};
use crate::identity::{
    now_unix_ms, DeviceId, SessionId, UserId, DEFAULT_SESSION_TTL_MS, LOCAL_DEVICE, ROOT_USER,
};
use crate::{AuthorizationService, Error, Result};

const ROOT_CAPABILITY: &str = "cap_root";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RotationReport {
    pub rotated_users: u32,
    pub rotated_capabilities: u32,
}

#[derive(Clone, Debug)]
pub struct Session {
    pub id: SessionId,
    pub user_id: Option<UserId>,
    pub device_id: Option<DeviceId>,
    pub role_ids: Vec<String>,
    /// Primary role id (first in snapshot). Legacy field for callers.
    pub role_id: String,
    pub capabilities: CapabilitySet,
    /// Primary capability (first in snapshot) for EncryptedKv callers.
    pub capability: Capability,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl Session {
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at
    }
}

/// Product-level identity + authorization.
#[derive(Clone)]
pub struct AccessControl {
    roles: RoleRegistry,
    users: UserDirectory,
    capabilities: CapabilityRegistry,
    sessions: HashMap<String, Session>,
    admin_session: Option<SessionId>,
    session_ttl_ms: u64,
    clock_ms: Option<u64>,
    audit: AuditTrail,
}

impl AccessControl {
    /// Vault checkpoint load: roles from snapshot; users/caps restored separately.
    pub fn new(roles: RoleRegistry) -> Self {
        Self::new_bare(roles)
    }

    pub fn new_bare(roles: RoleRegistry) -> Self {
        Self {
            roles,
            users: UserDirectory::default(),
            capabilities: CapabilityRegistry::new(),
            sessions: HashMap::new(),
            admin_session: None,
            session_ttl_ms: DEFAULT_SESSION_TTL_MS,
            clock_ms: None,
            audit: AuditTrail::new(),
        }
    }

    pub fn empty() -> Self {
        let mut ac = Self::new_bare(RoleRegistry::with_root());
        ac.provision_dev_root().expect("empty access control");
        ac
    }

    pub fn is_dev_provisioned(&self) -> bool {
        self.users.get(ROOT_USER).is_some() && self.roles.get("root").is_some()
    }

    /// Install root role, root user, and cap_root (dev / first-run provisioning).
    pub fn provision_dev_root(&mut self) -> Result<()> {
        if self.is_dev_provisioned() {
            return Err(Error::Conflict(
                "dev identity already provisioned (root user and role present)".into(),
            ));
        }
        self.roles.ensure_root();
        self.users = UserDirectory::with_root();
        self.capabilities = CapabilityRegistry::seed_root();
        self.sessions.clear();
        self.admin_session = None;
        Ok(())
    }

    pub fn now(&self) -> u64 {
        self.clock_ms.unwrap_or_else(now_unix_ms)
    }

    /// Test / replay clock. `None` restores wall clock.
    pub fn set_clock_ms(&mut self, now: Option<u64>) {
        self.clock_ms = now;
    }

    pub fn roles(&self) -> &RoleRegistry {
        &self.roles
    }

    pub fn roles_mut(&mut self) -> &mut RoleRegistry {
        &mut self.roles
    }

    pub fn users(&self) -> &UserDirectory {
        &self.users
    }

    pub fn users_mut(&mut self) -> &mut UserDirectory {
        &mut self.users
    }

    pub fn capabilities(&self) -> &CapabilityRegistry {
        &self.capabilities
    }

    pub fn audit(&self) -> &AuditTrail {
        &self.audit
    }

    pub fn replace_roles(&mut self, roles: RoleRegistry) {
        self.roles = roles;
        self.sessions.clear();
        self.admin_session = None;
    }

    pub fn replace_users(&mut self, users: UserDirectory) {
        self.users = users;
    }

    pub fn replace_capabilities(&mut self, caps: Vec<IssuedCapability>) {
        self.capabilities.replace(caps);
    }

    /// Issue missing role-derived caps after loading an older snapshot.
    pub fn ensure_policy_capabilities(&mut self) {
        let issuer = UserId::root();
        let users = self.users.list();
        for user in users {
            if !user.is_active() {
                continue;
            }
            for rid in &user.roles {
                if let Some(role) = self.roles.get(rid).cloned() {
                    let _ = self.ensure_role_issued(&issuer, &user.id, &role);
                }
            }
        }
    }

    /// Canonical: User → live issued capabilities → Session refs.
    pub fn open_user_session(
        &mut self,
        user_id: &str,
        device_id: Option<&str>,
    ) -> Result<SessionId> {
        let user = self
            .users
            .get(user_id)
            .cloned()
            .ok_or_else(|| Error::UnknownUser(user_id.to_string()))?;
        if !user.is_active() {
            return Err(Error::UserDisabled(user_id.to_string()));
        }
        if !user.roles.is_empty() {
            let roles = self.resolve_roles(&user.roles)?;
            let issuer = UserId::root();
            for role in &roles {
                let _ = self.ensure_role_issued(&issuer, &user.id, role);
            }
        }
        let capabilities = self.snapshot_live(user.id.as_str());
        if capabilities.refs().is_empty() {
            return Err(Error::UnknownRole(format!(
                "user {user_id} has no live capabilities"
            )));
        }
        let primary = capabilities
            .primary()
            .unwrap_or_else(Capability::root_admin);
        let now = self.now();
        let id = SessionId::new();
        let device = DeviceId::new(device_id.unwrap_or(LOCAL_DEVICE));
        let session = Session {
            id: id.clone(),
            user_id: Some(user.id.clone()),
            device_id: Some(device.clone()),
            role_ids: user.roles.clone(),
            role_id: user.roles.first().cloned().unwrap_or_else(|| "root".into()),
            capabilities,
            capability: primary,
            issued_at: now,
            expires_at: now.saturating_add(self.session_ttl_ms),
        };
        self.sessions.insert(id.0.clone(), session);
        if self.admin_session.is_none() {
            self.admin_session = Some(id.clone());
        }
        self.audit.emit(
            AuditOperation::SessionOpen,
            AuditResult::Allow,
            Some(user.id),
            Some(device),
            Some(id.clone()),
            None,
            None,
            None,
        );
        Ok(id)
    }

    /// Legacy Phase 1: treat `role_id` as user id if a user exists, otherwise
    /// snapshot that single role with `user_id = None`.
    pub fn open_session(&mut self, role_id: &str) -> Result<SessionId> {
        if self.users.get(role_id).is_some() {
            return self.open_user_session(role_id, Some(LOCAL_DEVICE));
        }
        let role = self
            .roles
            .get(role_id)
            .cloned()
            .ok_or_else(|| Error::UnknownRole(role_id.to_string()))?;
        let subject = legacy_subject(role_id);
        let issued = self.ensure_role_issued(&UserId::root(), &subject, &role)?;
        let capabilities = CapabilitySet::from_refs(vec![CapabilityRef::from_issued(&issued)]);
        let now = self.now();
        let id = SessionId::new();
        let session = Session {
            id: id.clone(),
            user_id: None,
            device_id: Some(DeviceId::local()),
            role_ids: vec![role.id.clone()],
            role_id: role.id.clone(),
            capability: role.to_capability(),
            capabilities,
            issued_at: now,
            expires_at: now.saturating_add(self.session_ttl_ms),
        };
        self.sessions.insert(id.0.clone(), session);
        if self.admin_session.is_none() {
            self.admin_session = Some(id.clone());
        }
        self.audit.emit(
            AuditOperation::SessionOpen,
            AuditResult::Allow,
            None,
            Some(DeviceId::local()),
            Some(id.clone()),
            Some(issued.id),
            None,
            None,
        );
        Ok(id)
    }

    pub fn bind_role(&mut self, session: &SessionId, role_id: &str) -> Result<()> {
        self.ensure_fresh(session)?;
        let role = self
            .roles
            .get(role_id)
            .cloned()
            .ok_or_else(|| Error::UnknownRole(role_id.to_string()))?;
        let subject = {
            let s = self.session(session)?;
            s.user_id
                .clone()
                .unwrap_or_else(|| legacy_subject(role_id))
        };
        let issued = self.ensure_role_issued(&UserId::root(), &subject, &role)?;
        let slot = self
            .sessions
            .get_mut(session.as_str())
            .ok_or_else(|| Error::UnknownSession(session.to_string()))?;
        slot.role_id = role.id.clone();
        slot.role_ids = vec![role.id.clone()];
        slot.capability = role.to_capability();
        slot.capabilities = CapabilitySet::from_refs(vec![CapabilityRef::from_issued(&issued)]);
        Ok(())
    }

    pub fn session(&self, id: &SessionId) -> Result<&Session> {
        let s = self
            .sessions
            .get(id.as_str())
            .ok_or_else(|| Error::UnknownSession(id.to_string()))?;
        if s.is_expired(self.now()) {
            return Err(Error::SessionExpired(id.to_string()));
        }
        Ok(s)
    }

    pub fn admin_session(&self) -> Result<&Session> {
        let id = self.admin_session.as_ref().ok_or(Error::Locked)?;
        self.session(id)
    }

    pub fn admin_session_id(&self) -> Result<SessionId> {
        let id = self.admin_session.clone().ok_or(Error::Locked)?;
        self.ensure_fresh(&id)?;
        Ok(id)
    }

    /// Security gate: user → session → capability live/generation → perm → path.
    pub fn authorize(&self, session: &SessionId, path: &KeyPath, perm: Permission) -> Result<()> {
        self.authorize_with(session, path, perm).map(|_| ())
    }

    pub fn authorize_with(
        &self,
        session: &SessionId,
        path: &KeyPath,
        perm: Permission,
    ) -> Result<IssuedCapability> {
        let s = self.session(session)?;
        if let Some(uid) = &s.user_id {
            let user = self
                .users
                .get(uid.as_str())
                .ok_or_else(|| Error::UnknownUser(uid.to_string()))?;
            if !user.is_active() {
                return Err(Error::UserDisabled(uid.to_string()));
            }
        }
        let now = self.now();
        let mut last = None;
        for r in s.capabilities.refs() {
            match self.live_issued(r, now) {
                Ok(issued) => match issued.to_vault() {
                    Ok(cap) => match cap.authorize(path, perm) {
                        Ok(()) => return Ok(issued.clone()),
                        Err(e) => last = Some(Error::from_vault(e)),
                    },
                    Err(e) => last = Some(e),
                },
                Err(e) => {
                    if ref_might_cover(r, path) {
                        last = Some(e);
                    }
                }
            }
        }
        Err(last.unwrap_or_else(|| {
            Error::from_vault(dmc_vault::Error::AccessDenied(
                perm.to_string(),
                path.to_string(),
            ))
        }))
    }

    /// One live capability whose scope contains `scope` and whose perms contain `required`.
    /// Used for stream subscription: stream scope must not widen the capability.
    pub fn covering_for_scope(
        &self,
        session: &SessionId,
        scope: &KeyPath,
        required: PermissionSet,
    ) -> Result<IssuedCapability> {
        let s = self.session(session)?;
        if let Some(uid) = &s.user_id {
            let user = self
                .users
                .get(uid.as_str())
                .ok_or_else(|| Error::UnknownUser(uid.to_string()))?;
            if !user.is_active() {
                return Err(Error::UserDisabled(uid.to_string()));
            }
        }
        let now = self.now();
        let mut best: Option<IssuedCapability> = None;
        let mut best_len = 0usize;
        for r in s.capabilities.refs() {
            let Ok(issued) = self.live_issued(r, now) else {
                continue;
            };
            let Ok(cap) = issued.to_vault() else {
                continue;
            };
            if !cap.scope.is_prefix_of(scope) {
                continue;
            }
            if !required.is_subset_of(cap.permissions) {
                continue;
            }
            let len = cap.scope.as_str().len();
            if best.is_none() || len > best_len {
                best_len = len;
                best = Some(issued.clone());
            }
        }
        best.ok_or_else(|| {
            Error::from_vault(dmc_vault::Error::AccessDenied(
                required.to_names().join("|"),
                scope.to_string(),
            ))
        })
    }

    /// Live capability of `subject` that currently covers `scope`. Used by consume/replay
    /// (authorization is evaluated now, not at event creation time).
    pub fn covering_for_subject(
        &self,
        subject: &str,
        scope: &KeyPath,
        required: PermissionSet,
    ) -> Result<IssuedCapability> {
        if let Some(user) = self.users.get(subject) {
            if !user.is_active() {
                return Err(Error::UserDisabled(subject.to_string()));
            }
        }
        let now = self.now();
        let mut best: Option<IssuedCapability> = None;
        let mut best_len = 0usize;
        for issued in self.capabilities.for_subject(subject) {
            if !issued.is_live(now) {
                continue;
            }
            let Ok(cap) = issued.to_vault() else {
                continue;
            };
            if !cap.scope.is_prefix_of(scope) {
                continue;
            }
            if !required.is_subset_of(cap.permissions) {
                continue;
            }
            let len = cap.scope.as_str().len();
            if best.is_none() || len > best_len {
                best_len = len;
                best = Some(issued);
            }
        }
        best.ok_or_else(|| {
            Error::from_vault(dmc_vault::Error::AccessDenied(
                required.to_names().join("|"),
                scope.to_string(),
            ))
        })
    }

    /// Delivery-time check for a subscription-bound capability.
    pub fn bound_capability(
        &self,
        capability_id: &CapabilityId,
        generation: u64,
    ) -> Result<&IssuedCapability> {
        let issued = self.issued(capability_id)?;
        match issued.effective_status(self.now()) {
            CapabilityStatus::Revoked => {
                return Err(Error::CapabilityRevoked(capability_id.to_string()));
            }
            CapabilityStatus::Expired => {
                return Err(Error::CapabilityExpired(capability_id.to_string()));
            }
            CapabilityStatus::Active => {}
        }
        if issued.generation != generation {
            return Err(Error::CapabilityStale(capability_id.to_string()));
        }
        if let Some(user) = self.users.get(issued.subject.as_str()) {
            if !user.is_active() {
                return Err(Error::UserDisabled(issued.subject.to_string()));
            }
        }
        Ok(issued)
    }

    pub fn capability(&self, session: &SessionId) -> Result<Capability> {
        let now = self.now();
        let s = self.session(session)?;
        for r in s.capabilities.refs() {
            if let Ok(issued) = self.live_issued(r, now) {
                if let Ok(cap) = issued.to_vault() {
                    if cap.permissions.contains(Permission::Grant) {
                        return Ok(cap);
                    }
                }
            }
        }
        for r in s.capabilities.refs() {
            if let Ok(issued) = self.live_issued(r, now) {
                if let Ok(cap) = issued.to_vault() {
                    return Ok(cap);
                }
            }
        }
        Ok(s.capability.clone())
    }

    pub fn capability_for(
        &self,
        session: &SessionId,
        path: &KeyPath,
        perm: Permission,
    ) -> Result<Capability> {
        self.authorize_with(session, path, perm)?.to_vault()
    }

    pub fn capability_set(&self, session: &SessionId) -> Result<CapabilitySet> {
        Ok(self.session(session)?.capabilities.clone())
    }

    pub fn active_role(&self) -> Result<Role> {
        let session = self.admin_session()?;
        self.roles
            .get(&session.role_id)
            .cloned()
            .ok_or_else(|| Error::UnknownRole(session.role_id.clone()))
    }

    pub fn create_user(&mut self, id: String, roles: Vec<String>) -> Result<User> {
        for rid in &roles {
            if self.roles.get(rid).is_none() {
                return Err(Error::UnknownRole(rid.clone()));
            }
        }
        let user = self.users.create(id, roles)?;
        let issuer = UserId::root();
        for rid in &user.roles {
            if let Some(role) = self.roles.get(rid).cloned() {
                let _ = self.ensure_role_issued(&issuer, &user.id, &role);
            }
        }
        self.audit.emit(
            AuditOperation::UserCreated,
            AuditResult::Allow,
            Some(user.id.clone()),
            None,
            None,
            None,
            None,
            None,
        );
        Ok(user)
    }

    pub fn assign_roles(&mut self, user_id: &str, roles: Vec<String>) -> Result<User> {
        for rid in &roles {
            if self.roles.get(rid).is_none() {
                return Err(Error::UnknownRole(rid.clone()));
            }
        }
        let previous = self
            .users
            .get(user_id)
            .ok_or_else(|| Error::UnknownUser(user_id.to_string()))?
            .roles
            .clone();
        let user = self.users.assign_roles(user_id, roles)?;
        let issuer = UserId::root();
        let subject = user.id.clone();
        for rid in &previous {
            if !user.roles.contains(rid) {
                self.revoke_role_derived(&subject, rid);
            }
        }
        for rid in &user.roles {
            if let Some(role) = self.roles.get(rid).cloned() {
                self.reissue_role(&issuer, &subject, &role);
            }
        }
        self.audit.emit(
            AuditOperation::RoleAssigned,
            AuditResult::Allow,
            Some(user.id.clone()),
            None,
            None,
            None,
            None,
            None,
        );
        Ok(user)
    }

    pub fn disable_user(&mut self, user_id: &str) -> Result<User> {
        let user = self.users.set_status(user_id, UserStatus::Disabled)?;
        self.revoke_user_sessions(user_id);
        self.audit.emit(
            AuditOperation::UserDisabled,
            AuditResult::Allow,
            Some(user.id.clone()),
            None,
            None,
            None,
            None,
            None,
        );
        Ok(user)
    }

    pub fn grant(
        &mut self,
        issuer_session: &SessionId,
        subject: &str,
        scope: KeyPath,
        permissions: PermissionSet,
        ttl_ms: Option<u64>,
    ) -> Result<IssuedCapability> {
        let issuer_sess = self.session(issuer_session)?.clone();
        let issuer = issuer_sess
            .user_id
            .clone()
            .ok_or_else(|| Error::DelegationDenied("legacy session cannot grant".into()))?;
        let issuer_user = self
            .users
            .get(issuer.as_str())
            .ok_or_else(|| Error::UnknownUser(issuer.to_string()))?;
        if !issuer_user.is_active() {
            return Err(Error::UserDisabled(issuer.to_string()));
        }
        let subject_user = self
            .users
            .get(subject)
            .ok_or_else(|| Error::UnknownUser(subject.to_string()))?;
        if !subject_user.is_active() {
            return Err(Error::UserDisabled(subject.to_string()));
        }
        let parent = self
            .delegation_parent(&issuer_sess, &scope, permissions)?
            .clone();
        let child = parent
            .to_vault()?
            .delegate(scope.clone(), permissions)
            .map_err(|e| Error::DelegationDenied(e.to_string()))?;
        let now = self.now();
        let issued = IssuedCapability {
            id: CapabilityId::new(),
            generation: 1,
            issuer,
            subject: subject_user.id.clone(),
            scope: child.scope.to_string(),
            permissions: child
                .permissions
                .to_names()
                .into_iter()
                .map(str::to_string)
                .collect(),
            issued_at: now,
            expires_at: ttl_ms.map(|ttl| now.saturating_add(ttl)),
            status: CapabilityStatus::Active,
            parent_id: Some(parent.id.clone()),
            source_role: None,
        };
        let issued = self.capabilities.insert(issued);
        self.audit.emit(
            AuditOperation::CapabilityGranted,
            AuditResult::Allow,
            Some(subject_user.id.clone()),
            issuer_sess.device_id.clone(),
            Some(issuer_session.clone()),
            Some(issued.id.clone()),
            Some(issued.scope.clone()),
            None,
        );
        Ok(issued)
    }

    pub fn revoke_capability(&mut self, capability_id: &CapabilityId) -> Result<IssuedCapability> {
        if capability_id.as_str() == ROOT_CAPABILITY {
            return Err(Error::DelegationDenied("cannot revoke root capability".into()));
        }
        let cap = self.capabilities.revoke(capability_id)?;
        self.audit.emit(
            AuditOperation::CapabilityRevoked,
            AuditResult::Allow,
            Some(cap.subject.clone()),
            None,
            None,
            Some(cap.id.clone()),
            Some(cap.scope.clone()),
            None,
        );
        Ok(cap)
    }

    pub fn issued(&self, id: &CapabilityId) -> Result<&IssuedCapability> {
        self.capabilities
            .get(id)
            .ok_or_else(|| Error::UnknownCapability(id.to_string()))
    }

    pub fn list_issued(&self) -> Vec<IssuedCapability> {
        self.capabilities.list()
    }

    /// Reissue live capabilities for every active vault user except `root`.
    /// Role-derived caps are revoked and issued again; direct grants keep
    /// scope / permissions / expiry and get a new id. User sessions are closed.
    pub fn rotate_all_user_capabilities(&mut self) -> Result<RotationReport> {
        let now = self.now();
        let users: Vec<User> = self
            .users
            .list()
            .into_iter()
            .filter(|u| u.is_active() && u.id.as_str() != ROOT_USER)
            .collect();

        let mut report = RotationReport::default();
        for user in users {
            let live: Vec<IssuedCapability> = self
                .capabilities
                .for_subject(user.id.as_str())
                .into_iter()
                .filter(|c| c.is_live(now) && c.id.as_str() != ROOT_CAPABILITY)
                .collect();

            let mut roles: HashSet<String> = user.roles.iter().cloned().collect();
            for cap in &live {
                if let Some(role) = &cap.source_role {
                    roles.insert(role.clone());
                }
            }

            let mut rotated = 0u32;
            for rid in &roles {
                self.revoke_role_derived(&user.id, rid);
                if let Some(role) = self.roles.get(rid).cloned() {
                    let issued = self.issue_from_role(&UserId::root(), &user.id, &role, None);
                    self.audit.emit(
                        AuditOperation::CapabilityRotated,
                        AuditResult::Allow,
                        Some(user.id.clone()),
                        None,
                        None,
                        Some(issued.id.clone()),
                        Some(issued.scope.clone()),
                        None,
                    );
                    rotated += 1;
                }
            }

            for cap in live.iter().filter(|c| c.source_role.is_none()) {
                let _ = self.capabilities.revoke(&cap.id);
                let issued = IssuedCapability {
                    id: CapabilityId::new(),
                    generation: 1,
                    issuer: cap.issuer.clone(),
                    subject: cap.subject.clone(),
                    scope: cap.scope.clone(),
                    permissions: cap.permissions.clone(),
                    issued_at: now,
                    expires_at: cap.expires_at,
                    status: CapabilityStatus::Active,
                    parent_id: cap.parent_id.clone(),
                    source_role: None,
                };
                let issued = self.capabilities.insert(issued);
                self.audit.emit(
                    AuditOperation::CapabilityRotated,
                    AuditResult::Allow,
                    Some(user.id.clone()),
                    None,
                    None,
                    Some(issued.id.clone()),
                    Some(issued.scope.clone()),
                    None,
                );
                rotated += 1;
            }

            if rotated > 0 {
                self.revoke_user_sessions(user.id.as_str());
                report.rotated_users += 1;
                report.rotated_capabilities += rotated;
            }
        }
        Ok(report)
    }

    pub fn revoke_user_sessions(&mut self, user_id: &str) {
        let ids: Vec<String> = self
            .sessions
            .values()
            .filter(|s| s.user_id.as_ref().map(|u| u.as_str()) == Some(user_id))
            .map(|s| s.id.0.clone())
            .collect();
        for id in ids {
            self.revoke_session(&SessionId(id));
        }
    }

    pub fn revoke_session(&mut self, session: &SessionId) {
        let removed = self.sessions.remove(session.as_str());
        if self.admin_session.as_ref() == Some(session) {
            self.admin_session = None;
        }
        if let Some(s) = removed {
            self.audit.emit(
                AuditOperation::SessionRevoked,
                AuditResult::Allow,
                s.user_id,
                s.device_id,
                Some(session.clone()),
                None,
                None,
                None,
            );
        }
    }

    pub fn wipe_sessions(&mut self) {
        self.sessions.clear();
        self.admin_session = None;
    }

    fn resolve_roles(&self, ids: &[String]) -> Result<Vec<Role>> {
        let mut out = Vec::new();
        for id in ids {
            let role = self
                .roles
                .get(id)
                .cloned()
                .ok_or_else(|| Error::UnknownRole(id.clone()))?;
            out.push(role);
        }
        Ok(out)
    }

    fn ensure_fresh(&self, session: &SessionId) -> Result<()> {
        let s = self
            .sessions
            .get(session.as_str())
            .ok_or_else(|| Error::UnknownSession(session.to_string()))?;
        if s.is_expired(self.now()) {
            return Err(Error::SessionExpired(session.to_string()));
        }
        Ok(())
    }

    fn snapshot_live(&self, subject: &str) -> CapabilitySet {
        let now = self.now();
        let mut refs: Vec<CapabilityRef> = self
            .capabilities
            .for_subject(subject)
            .into_iter()
            .filter(|c| c.is_live(now))
            .map(|c| CapabilityRef::from_issued(&c))
            .collect();
        refs.sort_by(|a, b| a.capability_id.0.cmp(&b.capability_id.0));
        CapabilitySet::from_refs(refs)
    }

    fn live_issued(&self, r: &CapabilityRef, now: u64) -> Result<&IssuedCapability> {
        let issued = self
            .capabilities
            .get(&r.capability_id)
            .ok_or_else(|| Error::UnknownCapability(r.capability_id.to_string()))?;
        match issued.effective_status(now) {
            CapabilityStatus::Revoked => {
                return Err(Error::CapabilityRevoked(issued.id.to_string()));
            }
            CapabilityStatus::Expired => {
                return Err(Error::CapabilityExpired(issued.id.to_string()));
            }
            CapabilityStatus::Active => {}
        }
        if issued.generation != r.generation {
            return Err(Error::CapabilityStale(r.capability_id.to_string()));
        }
        Ok(issued)
    }

    fn ensure_role_issued(
        &mut self,
        issuer: &UserId,
        subject: &UserId,
        role: &Role,
    ) -> Result<IssuedCapability> {
        let now = self.now();
        let mut revoked = false;
        for c in self.capabilities.for_subject(subject.as_str()) {
            if c.source_role.as_deref() != Some(role.id.as_str()) {
                continue;
            }
            if c.is_live(now) {
                return Ok(c);
            }
            if c.status == CapabilityStatus::Revoked {
                revoked = true;
            }
        }
        if revoked {
            return Err(Error::CapabilityRevoked(format!(
                "role {} for {}",
                role.id,
                subject.as_str()
            )));
        }
        Ok(self.issue_from_role(issuer, subject, role, None))
    }

    fn reissue_role(&mut self, issuer: &UserId, subject: &UserId, role: &Role) -> IssuedCapability {
        let now = self.now();
        for c in self.capabilities.for_subject(subject.as_str()) {
            if c.source_role.as_deref() == Some(role.id.as_str()) && c.is_live(now) {
                return c;
            }
        }
        self.issue_from_role(issuer, subject, role, None)
    }

    fn issue_from_role(
        &mut self,
        issuer: &UserId,
        subject: &UserId,
        role: &Role,
        expires_at: Option<u64>,
    ) -> IssuedCapability {
        let cap = role.to_capability();
        let now = self.now();
        let issued = IssuedCapability {
            id: if subject.as_str() == "root" && role.id == "root" {
                CapabilityId::from(ROOT_CAPABILITY)
            } else {
                CapabilityId::new()
            },
            generation: 1,
            issuer: issuer.clone(),
            subject: subject.clone(),
            scope: cap.scope.to_string(),
            permissions: cap
                .permissions
                .to_names()
                .into_iter()
                .map(str::to_string)
                .collect(),
            issued_at: now,
            expires_at,
            status: CapabilityStatus::Active,
            parent_id: None,
            source_role: Some(role.id.clone()),
        };
        if self.capabilities.get(&issued.id).is_some() {
            return self.capabilities.get(&issued.id).cloned().unwrap();
        }
        self.capabilities.insert(issued)
    }

    fn revoke_role_derived(&mut self, subject: &UserId, role_id: &str) {
        let ids: Vec<CapabilityId> = self
            .capabilities
            .for_subject(subject.as_str())
            .into_iter()
            .filter(|c| c.source_role.as_deref() == Some(role_id))
            .map(|c| c.id)
            .collect();
        for id in ids {
            let _ = self.capabilities.revoke(&id);
        }
    }

    fn delegation_parent(
        &self,
        issuer_sess: &Session,
        scope: &KeyPath,
        permissions: PermissionSet,
    ) -> Result<&IssuedCapability> {
        let now = self.now();
        let mut last = None;
        for r in issuer_sess.capabilities.refs() {
            match self.live_issued(r, now) {
                Ok(issued) => match issued.to_vault() {
                    Ok(cap) => match cap.delegate(scope.clone(), permissions) {
                        Ok(_) => return Ok(issued),
                        Err(e) => last = Some(Error::DelegationDenied(e.to_string())),
                    },
                    Err(e) => last = Some(e),
                },
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| {
            Error::DelegationDenied("issuer has no GRANT capability".into())
        }))
    }
}

fn legacy_subject(role_id: &str) -> UserId {
    UserId::new(format!("legacy:{role_id}"))
}

fn ref_might_cover(r: &CapabilityRef, path: &KeyPath) -> bool {
    r.scope_path()
        .map(|scope| scope.is_prefix_of(path))
        .unwrap_or(false)
}

impl AuthorizationService for AccessControl {
    fn create_session(&mut self, role_id: &str) -> Result<SessionId> {
        self.open_session(role_id)
    }

    fn authorize(&self, session: &SessionId, resource: &KeyPath, permission: Permission) -> Result<()> {
        AccessControl::authorize(self, session, resource, permission)
    }

    fn resolve_capabilities(&self, session: &SessionId) -> Result<Capability> {
        self.capability(session)
    }

    fn revoke_session(&mut self, session: &SessionId) {
        AccessControl::revoke_session(self, session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmc_vault::access::{Permission, PermissionSet};

    #[test]
    fn root_session_can_read_and_unknown_role_fails() {
        let mut ac = AccessControl::empty();
        assert!(ac.open_session("nope").is_err());

        let id = ac.open_session("root").unwrap();
        let path = KeyPath::parse("company/finance").unwrap();
        ac.authorize(&id, &path, Permission::Read).unwrap();
        let s = ac.session(&id).unwrap();
        assert_eq!(s.user_id.as_ref().map(|u| u.as_str()), Some("root"));
        assert!(ac.capability(&id).is_ok());
    }

    #[test]
    fn user_session_snapshots_roles_and_ignores_later_assign() {
        let mut ac = AccessControl::empty();
        ac.roles_mut().seed_role(
            "finance",
            "Finance",
            KeyPath::parse("company/finance").unwrap(),
            PermissionSet::read_write(),
        );
        ac.roles_mut().seed_role(
            "hr",
            "HR",
            KeyPath::parse("company/hr").unwrap(),
            PermissionSet::empty().with(Permission::Read),
        );
        ac.create_user("alice".into(), vec!["finance".into()]).unwrap();
        let sid = ac.open_user_session("alice", Some("device-42")).unwrap();
        ac.authorize(
            &sid,
            &KeyPath::parse("company/finance/inv/1").unwrap(),
            Permission::Write,
        )
        .unwrap();
        assert!(ac
            .authorize(&sid, &KeyPath::parse("company/hr/e/1").unwrap(), Permission::Read)
            .is_err());

        ac.assign_roles("alice", vec!["finance".into(), "hr".into()])
            .unwrap();
        // Live session is a snapshot — HR not added until re-auth.
        assert!(ac
            .authorize(&sid, &KeyPath::parse("company/hr/e/1").unwrap(), Permission::Read)
            .is_err());

        let sid2 = ac.open_user_session("alice", Some("device-42")).unwrap();
        ac.authorize(&sid2, &KeyPath::parse("company/hr/e/1").unwrap(), Permission::Read)
            .unwrap();
    }

    #[test]
    fn disable_user_revokes_sessions() {
        let mut ac = AccessControl::empty();
        ac.roles_mut().seed_role(
            "finance",
            "Finance",
            KeyPath::parse("company/finance").unwrap(),
            PermissionSet::read_write(),
        );
        ac.create_user("bob".into(), vec!["finance".into()]).unwrap();
        let sid = ac.open_user_session("bob", None).unwrap();
        ac.disable_user("bob").unwrap();
        assert!(ac.session(&sid).is_err());
        assert!(ac.open_user_session("bob", None).is_err());
    }
}
