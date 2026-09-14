//! Phase 7.10.8 — Failure policy classifier (ADR-026).
//!
//! Classifies **existing** error surfaces into RejectOnly / NotReady / Fatal.
//! Does **not** invent a new error-handling pipeline or auto-`handle_error` SM.

use serde::{Deserialize, Serialize};

use dmc_protocol::ProtocolErrorCode;
use dmc_server::CoreLifecycle;

use crate::error::{ShutdownError, StartupError};
use crate::lifecycle::{LifecycleState, ProcessLifecycle, ProjectedReadiness};
use crate::startup::StartedCore;

/// Operational failure class — independent of vault / auth session axes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    /// Request/operation local — Core stays Ready; accepts new work.
    RejectOnly,
    /// Process alive; readiness NotReady; no corresponding new work.
    NotReady,
    /// Terminal process failure → [`LifecycleState::Failed`].
    Fatal,
}

impl FailureClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RejectOnly => "reject_only",
            Self::NotReady => "not_ready",
            Self::Fatal => "fatal",
        }
    }
}

/// Named rows of the ADR-026 failure matrix (stable classification keys).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    InvalidSql,
    AuthFailed,
    AuthzDenied,
    VaultLocked,
    ConstraintViolation,
    WriteConflict,
    LimitExceeded,
    ClientDisconnect,
    ClientProtocolValidation,
    SessionInvalid,
    UnlockClientError,
    BackupValidationFailure,
    UnsupportedOperation,
    TransactionRollback,
    ExecutionError,
    /// Explicit temporary operational dependency (rare — do not invent freely).
    TemporaryOperationalDependency,
    RecoveryArtifactInvalid,
    JournalOpenFailure,
    CatalogOpenFailure,
    MandatoryStorageOpenFailure,
    RecoveryOnStartupFailure,
    RequiredDurableFlushFailure,
    StartupConfigOrLayoutFailure,
    StartupVaultFailure,
    CorruptMandatorySot,
}

impl FailureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidSql => "invalid_sql",
            Self::AuthFailed => "auth_failed",
            Self::AuthzDenied => "authz_denied",
            Self::VaultLocked => "vault_locked",
            Self::ConstraintViolation => "constraint_violation",
            Self::WriteConflict => "write_conflict",
            Self::LimitExceeded => "limit_exceeded",
            Self::ClientDisconnect => "client_disconnect",
            Self::ClientProtocolValidation => "client_protocol_validation",
            Self::SessionInvalid => "session_invalid",
            Self::UnlockClientError => "unlock_client_error",
            Self::BackupValidationFailure => "backup_validation_failure",
            Self::UnsupportedOperation => "unsupported_operation",
            Self::TransactionRollback => "transaction_rollback",
            Self::ExecutionError => "execution_error",
            Self::TemporaryOperationalDependency => "temporary_operational_dependency",
            Self::RecoveryArtifactInvalid => "recovery_artifact_invalid",
            Self::JournalOpenFailure => "journal_open_failure",
            Self::CatalogOpenFailure => "catalog_open_failure",
            Self::MandatoryStorageOpenFailure => "mandatory_storage_open_failure",
            Self::RecoveryOnStartupFailure => "recovery_on_startup_failure",
            Self::RequiredDurableFlushFailure => "required_durable_flush_failure",
            Self::StartupConfigOrLayoutFailure => "startup_config_or_layout_failure",
            Self::StartupVaultFailure => "startup_vault_failure",
            Self::CorruptMandatorySot => "corrupt_mandatory_sot",
        }
    }
}

/// Deterministic ADR matrix: [`FailureKind`] → [`FailureClass`].
pub fn classify_kind(kind: FailureKind) -> FailureClass {
    match kind {
        FailureKind::InvalidSql
        | FailureKind::AuthFailed
        | FailureKind::AuthzDenied
        | FailureKind::VaultLocked
        | FailureKind::ConstraintViolation
        | FailureKind::WriteConflict
        | FailureKind::LimitExceeded
        | FailureKind::ClientDisconnect
        | FailureKind::ClientProtocolValidation
        | FailureKind::SessionInvalid
        | FailureKind::UnlockClientError
        | FailureKind::BackupValidationFailure
        | FailureKind::UnsupportedOperation
        | FailureKind::TransactionRollback
        | FailureKind::ExecutionError => FailureClass::RejectOnly,

        FailureKind::TemporaryOperationalDependency => FailureClass::NotReady,

        FailureKind::RecoveryArtifactInvalid
        | FailureKind::JournalOpenFailure
        | FailureKind::CatalogOpenFailure
        | FailureKind::MandatoryStorageOpenFailure
        | FailureKind::RecoveryOnStartupFailure
        | FailureKind::RequiredDurableFlushFailure
        | FailureKind::StartupConfigOrLayoutFailure
        | FailureKind::StartupVaultFailure
        | FailureKind::CorruptMandatorySot => FailureClass::Fatal,
    }
}

/// Wire / protocol codes from Data/Control — almost always RejectOnly.
pub fn classify_protocol(code: ProtocolErrorCode) -> FailureClass {
    match code {
        ProtocolErrorCode::AuthenticationFailed
        | ProtocolErrorCode::AuthorizationDenied
        | ProtocolErrorCode::SessionInvalid
        | ProtocolErrorCode::InvalidRequest
        | ProtocolErrorCode::InvalidFrame
        | ProtocolErrorCode::UnsupportedVersion
        | ProtocolErrorCode::ResourceNotFound
        | ProtocolErrorCode::ExecutionError
        | ProtocolErrorCode::FrameTooLarge
        | ProtocolErrorCode::ProtocolError
        | ProtocolErrorCode::TransportError
        | ProtocolErrorCode::InvalidSql
        | ProtocolErrorCode::ConstraintViolation
        | ProtocolErrorCode::TransactionConflict
        | ProtocolErrorCode::TlsHandshakeFailed
        | ProtocolErrorCode::CertificateInvalid
        | ProtocolErrorCode::CertificateExpired
        | ProtocolErrorCode::CertificateUntrusted
        | ProtocolErrorCode::HostnameMismatch
        | ProtocolErrorCode::ConnectionClosed
        | ProtocolErrorCode::VaultLocked
        | ProtocolErrorCode::UnlockFailed
        | ProtocolErrorCode::UnlockBlobInvalid
        | ProtocolErrorCode::UnlockBlobReplay
        | ProtocolErrorCode::UnlockSessionMismatch
        | ProtocolErrorCode::LegacyUnlockDisabled
        | ProtocolErrorCode::BackupInvalid
        | ProtocolErrorCode::BackupTargetNotEmpty
        | ProtocolErrorCode::RecoveryNotReady
        | ProtocolErrorCode::BackupNotFound => FailureClass::RejectOnly,
        // InternalError on wire stays reject-only for a live Core — fatal paths use Startup/Shutdown.
        ProtocolErrorCode::InternalError => FailureClass::RejectOnly,
    }
}

pub fn classify_startup(err: &StartupError) -> FailureClass {
    match err {
        StartupError::Config(_)
        | StartupError::Layout(_)
        | StartupError::Provision(_)
        | StartupError::Journal(_)
        | StartupError::Catalog(_)
        | StartupError::Storage(_)
        | StartupError::Vault(_)
        | StartupError::RecoveryMetadata(_)
        | StartupError::Recovery(_)
        | StartupError::Lifecycle(_)
        | StartupError::Io(_) => FailureClass::Fatal,
    }
}

pub fn classify_shutdown(err: &ShutdownError) -> FailureClass {
    match err {
        ShutdownError::Flush(_) | ShutdownError::Vault(_) => FailureClass::Fatal,
        // Lifecycle/rollback glitches during shutdown are operational — not request RejectOnly.
        ShutdownError::Lifecycle(_) | ShutdownError::Rollback(_) => FailureClass::Fatal,
    }
}

/// What lifecycle policy permits given a class and current process state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureDecision {
    pub class: FailureClass,
    pub accepts_new_work: bool,
    pub projected_readiness: ProjectedReadiness,
    pub terminal: bool,
    /// Whether applying this class may transition process → Failed.
    pub may_mark_failed: bool,
    /// Whether applying this class may set NotReady overlay (process stays Ready).
    pub may_note_not_ready: bool,
}

/// Pure policy: classify → decision (no mutation).
pub fn decision_for(class: FailureClass, current: LifecycleState) -> FailureDecision {
    match class {
        FailureClass::RejectOnly => FailureDecision {
            class,
            accepts_new_work: current.accepts_new_work(),
            projected_readiness: match current {
                LifecycleState::Starting => ProjectedReadiness::Initializing,
                LifecycleState::Ready => ProjectedReadiness::Ready,
                LifecycleState::Stopping | LifecycleState::Stopped => ProjectedReadiness::NotReady,
                LifecycleState::Failed => ProjectedReadiness::Failed,
            },
            terminal: false,
            may_mark_failed: false,
            may_note_not_ready: false,
        },
        FailureClass::NotReady => FailureDecision {
            class,
            accepts_new_work: false,
            projected_readiness: ProjectedReadiness::NotReady,
            terminal: false,
            may_mark_failed: false,
            may_note_not_ready: matches!(current, LifecycleState::Ready),
        },
        FailureClass::Fatal => FailureDecision {
            class,
            accepts_new_work: false,
            projected_readiness: ProjectedReadiness::Failed,
            terminal: true,
            may_mark_failed: matches!(
                current,
                LifecycleState::Starting | LifecycleState::Ready | LifecycleState::Stopping
            ),
            may_note_not_ready: false,
        },
    }
}

/// Apply classification to process lifecycle only — **not** vault/SQL/journal.
///
/// * RejectOnly → no-op  
/// * NotReady → `note_operational_not_ready` when Ready  
/// * Fatal → `mark_failed`
pub fn apply_failure_class(
    lifecycle: &mut ProcessLifecycle,
    class: FailureClass,
) -> crate::error::LifecycleResult<()> {
    match class {
        FailureClass::RejectOnly => Ok(()),
        FailureClass::NotReady => lifecycle.note_operational_not_ready(),
        FailureClass::Fatal => lifecycle.mark_failed(),
    }
}

/// Apply Fatal to a running StartedCore: Failed + wipe secrets + invalidate sessions.
/// RejectOnly / NotReady do not wipe. Observability sinks are never consulted.
pub fn apply_failure_to_started(
    started: &mut StartedCore,
    class: FailureClass,
) -> crate::error::LifecycleResult<()> {
    apply_failure_class(&mut started.lifecycle, class)?;
    match class {
        FailureClass::RejectOnly => Ok(()),
        FailureClass::NotReady => {
            // Process stays Ready; server reject gate via accepts_new_work overlay.
            // Do not lock/unlock vault.
            Ok(())
        }
        FailureClass::Fatal => {
            started.server.wipe_for_shutdown();
            started.server.set_lifecycle(CoreLifecycle::Failed);
            Ok(())
        }
    }
}

/// ADR matrix as stable (kind, class) pairs for docs/tests.
pub fn failure_matrix() -> &'static [(FailureKind, FailureClass)] {
    use FailureClass::*;
    use FailureKind::*;
    &[
        (InvalidSql, RejectOnly),
        (AuthFailed, RejectOnly),
        (AuthzDenied, RejectOnly),
        (VaultLocked, RejectOnly),
        (ConstraintViolation, RejectOnly),
        (WriteConflict, RejectOnly),
        (LimitExceeded, RejectOnly),
        (ClientDisconnect, RejectOnly),
        (BackupValidationFailure, RejectOnly),
        (TemporaryOperationalDependency, NotReady),
        (RecoveryArtifactInvalid, Fatal),
        (JournalOpenFailure, Fatal),
        (CatalogOpenFailure, Fatal),
        (MandatoryStorageOpenFailure, Fatal),
        (RecoveryOnStartupFailure, Fatal),
        (RequiredDurableFlushFailure, Fatal),
    ]
}
