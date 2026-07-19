//! Generic UniFFI boundary for MDBX vault clients.
//!
//! This crate intentionally exposes vault, project, and generic entry
//! operations only. Product-specific payloads belong in each client.

use std::path::Path;
use std::sync::{Arc, Mutex};

use mdbx_core::model::{EntryType, UnlockMethodType};
use mdbx_core::tiga::{
    AuditLevel, AuthorizationConstraint, AuthorizationDecision, AuthorizationOutcome,
    AuthorizationReason, DeviceAssurance, DeviceContext, PolicyCompliance, PolicyException,
    ResolvedTigaPolicy, TigaMode, TigaOperation, TigaPolicyOverride, TigaScope,
};
use mdbx_storage::connection::VaultConnection;
use mdbx_storage::error::{StorageError, StorageResult};
use mdbx_storage::init::{initialize_vault, VaultInitParams};
use mdbx_storage::migration::{inspect_migration_path, upgrade_path, MigrationInfo};
use mdbx_storage::repo::{
    CommitChange, CommitContext, CommitHistoryItem, CommitHistoryPage, CommitHistoryRepo,
    CommitOperation, EntryRepo, OperationExecution, ProjectRepo,
};
use mdbx_storage::tiga::TigaService;
use mdbx_storage::tiga_policy::{SecurityAuditEvent, TigaAuthorizationContext};
use mdbx_storage::unlock::{TigaUnlockAssessment, UnlockService};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MdbxFfiError {
    #[error("storage error: {message}")]
    Storage { message: String },
    #[error("serialization error: {message}")]
    Serialization { message: String },
    #[error("invalid entry type: {entry_type}")]
    InvalidEntryType { entry_type: String },
    #[error("vault lock poisoned")]
    LockPoisoned,
}

impl From<StorageError> for MdbxFfiError {
    fn from(value: StorageError) -> Self {
        MdbxFfiError::Storage {
            message: value.to_string(),
        }
    }
}

impl From<serde_json::Error> for MdbxFfiError {
    fn from(value: serde_json::Error) -> Self {
        MdbxFfiError::Serialization {
            message: value.to_string(),
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct VaultInfo {
    pub vault_id: String,
    pub device_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxMigrationInfo {
    pub initialized: bool,
    pub format_version: Option<String>,
    pub schema_version: Option<u32>,
    pub min_reader_version: Option<String>,
    pub min_writer_version: Option<String>,
    pub requires_upgrade: bool,
    pub unknown_critical_extensions: bool,
    pub target_format_version: String,
    pub target_schema_version: u32,
}

impl From<MigrationInfo> for MdbxMigrationInfo {
    fn from(value: MigrationInfo) -> Self {
        Self {
            initialized: value.initialized,
            format_version: value.format_version,
            schema_version: value.schema_version,
            min_reader_version: value.min_reader_version,
            min_writer_version: value.min_writer_version,
            requires_upgrade: value.requires_upgrade,
            unknown_critical_extensions: value.unknown_critical_extensions,
            target_format_version: value.target_format_version,
            target_schema_version: value.target_schema_version,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ProjectRecord {
    pub project_id: String,
    pub title: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct EntryRecord {
    pub entry_id: String,
    pub project_id: String,
    pub entry_type: String,
    pub title: String,
    pub payload_json: String,
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, uniffi::Enum)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum MdbxWriteCommand {
    CreateProject {
        project_id: String,
        title: String,
    },
    CreateEntry {
        entry_id: String,
        project_id: String,
        entry_type: String,
        title: String,
        payload_json: String,
    },
    UpdateEntry {
        entry_id: String,
        project_id: String,
        entry_type: String,
        title: String,
        payload_json: String,
    },
    DeleteEntry {
        entry_id: String,
        project_id: String,
    },
    RestoreEntry {
        entry_id: String,
        project_id: String,
    },
    MoveEntry {
        entry_id: String,
        project_id: String,
        target_project_id: String,
    },
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MdbxWriteOperationResult {
    pub commit_id: String,
    pub already_committed: bool,
    pub project_ids: Vec<String>,
    pub entry_ids: Vec<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MdbxCommitChange {
    pub object_type: String,
    pub object_id: String,
    pub action: String,
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MdbxCommitHistoryItem {
    pub commit_id: String,
    pub device_id: String,
    pub local_seq: u64,
    pub commit_kind: String,
    pub change_scope: String,
    pub created_at: String,
    pub operation_id: Option<String>,
    pub operation_kind: Option<String>,
    pub branch_name: Option<String>,
    pub message: Option<String>,
    pub changes: Vec<MdbxCommitChange>,
    pub parent_ids: Vec<String>,
    pub legacy: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MdbxCommitHistoryPage {
    pub items: Vec<MdbxCommitHistoryItem>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MdbxTigaMode {
    Sky,
    Multi,
    Power,
}

impl From<MdbxTigaMode> for TigaMode {
    fn from(value: MdbxTigaMode) -> Self {
        match value {
            MdbxTigaMode::Sky => TigaMode::Sky,
            MdbxTigaMode::Multi => TigaMode::Multi,
            MdbxTigaMode::Power => TigaMode::Power,
        }
    }
}

impl From<TigaMode> for MdbxTigaMode {
    fn from(value: TigaMode) -> Self {
        match value {
            TigaMode::Sky => Self::Sky,
            TigaMode::Multi => Self::Multi,
            TigaMode::Power => Self::Power,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MdbxDeviceAssurance {
    Unknown,
    Standard,
    TrustedHardware,
}

impl From<MdbxDeviceAssurance> for DeviceAssurance {
    fn from(value: MdbxDeviceAssurance) -> Self {
        match value {
            MdbxDeviceAssurance::Unknown => Self::Unknown,
            MdbxDeviceAssurance::Standard => Self::Standard,
            MdbxDeviceAssurance::TrustedHardware => Self::TrustedHardware,
        }
    }
}

impl From<DeviceAssurance> for MdbxDeviceAssurance {
    fn from(value: DeviceAssurance) -> Self {
        match value {
            DeviceAssurance::Unknown => Self::Unknown,
            DeviceAssurance::Standard => Self::Standard,
            DeviceAssurance::TrustedHardware => Self::TrustedHardware,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxDeviceContext {
    pub assurance: MdbxDeviceAssurance,
    pub secure_clipboard_available: bool,
    pub screen_capture_protection_available: bool,
    pub secure_temp_files_available: bool,
}

impl MdbxDeviceContext {
    fn into_core(self, device_id: &str) -> DeviceContext {
        DeviceContext {
            device_id: Some(device_id.to_string()),
            assurance: self.assurance.into(),
            secure_clipboard_available: self.secure_clipboard_available,
            screen_capture_protection_available: self.screen_capture_protection_available,
            secure_temp_files_available: self.secure_temp_files_available,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MdbxTigaScopeType {
    Vault,
    Project,
    Entry,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxTigaScope {
    pub scope_type: MdbxTigaScopeType,
    pub scope_id: Option<String>,
}

impl MdbxTigaScope {
    fn into_core(self) -> Result<TigaScope, MdbxFfiError> {
        match self.scope_type {
            MdbxTigaScopeType::Vault => Ok(TigaScope::Vault),
            MdbxTigaScopeType::Project => Ok(TigaScope::Project {
                project_id: required_scope_id(self.scope_id, "project")?,
            }),
            MdbxTigaScopeType::Entry => Ok(TigaScope::Entry {
                entry_id: required_scope_id(self.scope_id, "entry")?,
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MdbxTigaOperation {
    RevealSecret,
    CopySecret,
    ExportData,
    PrintData,
    DecryptAttachment,
    RestoreSnapshot,
    ChangeUnlockMethods,
    ChangeSecurityPolicy,
    ChangeRecoveryMethods,
    DeleteAuditRecords,
    BackgroundAccess,
    SyncCiphertext,
    CreatePlaintextCache,
}

impl From<MdbxTigaOperation> for TigaOperation {
    fn from(value: MdbxTigaOperation) -> Self {
        match value {
            MdbxTigaOperation::RevealSecret => Self::RevealSecret,
            MdbxTigaOperation::CopySecret => Self::CopySecret,
            MdbxTigaOperation::ExportData => Self::ExportData,
            MdbxTigaOperation::PrintData => Self::PrintData,
            MdbxTigaOperation::DecryptAttachment => Self::DecryptAttachment,
            MdbxTigaOperation::RestoreSnapshot => Self::RestoreSnapshot,
            MdbxTigaOperation::ChangeUnlockMethods => Self::ChangeUnlockMethods,
            MdbxTigaOperation::ChangeSecurityPolicy => Self::ChangeSecurityPolicy,
            MdbxTigaOperation::ChangeRecoveryMethods => Self::ChangeRecoveryMethods,
            MdbxTigaOperation::DeleteAuditRecords => Self::DeleteAuditRecords,
            MdbxTigaOperation::BackgroundAccess => Self::BackgroundAccess,
            MdbxTigaOperation::SyncCiphertext => Self::SyncCiphertext,
            MdbxTigaOperation::CreatePlaintextCache => Self::CreatePlaintextCache,
        }
    }
}

impl From<TigaOperation> for MdbxTigaOperation {
    fn from(value: TigaOperation) -> Self {
        match value {
            TigaOperation::RevealSecret => Self::RevealSecret,
            TigaOperation::CopySecret => Self::CopySecret,
            TigaOperation::ExportData => Self::ExportData,
            TigaOperation::PrintData => Self::PrintData,
            TigaOperation::DecryptAttachment => Self::DecryptAttachment,
            TigaOperation::RestoreSnapshot => Self::RestoreSnapshot,
            TigaOperation::ChangeUnlockMethods => Self::ChangeUnlockMethods,
            TigaOperation::ChangeSecurityPolicy => Self::ChangeSecurityPolicy,
            TigaOperation::ChangeRecoveryMethods => Self::ChangeRecoveryMethods,
            TigaOperation::DeleteAuditRecords => Self::DeleteAuditRecords,
            TigaOperation::BackgroundAccess => Self::BackgroundAccess,
            TigaOperation::SyncCiphertext => Self::SyncCiphertext,
            TigaOperation::CreatePlaintextCache => Self::CreatePlaintextCache,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MdbxAuthorizationOutcome {
    Allow,
    AllowWithConstraints,
    RequireFreshAuthentication,
    RequireAdditionalFactor,
    Deny,
}

impl From<AuthorizationOutcome> for MdbxAuthorizationOutcome {
    fn from(value: AuthorizationOutcome) -> Self {
        match value {
            AuthorizationOutcome::Allow => Self::Allow,
            AuthorizationOutcome::AllowWithConstraints => Self::AllowWithConstraints,
            AuthorizationOutcome::RequireFreshAuthentication => Self::RequireFreshAuthentication,
            AuthorizationOutcome::RequireAdditionalFactor => Self::RequireAdditionalFactor,
            AuthorizationOutcome::Deny => Self::Deny,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MdbxAuthorizationReason {
    SessionMissing,
    SessionExpired,
    AuthenticationStale,
    InsufficientAuthenticationFactors,
    SecurityKeyRequired,
    DeviceAssuranceInsufficient,
    SecureClipboardUnavailable,
    ScreenCaptureProtectionUnavailable,
    OperationDisabled,
    PolicyWeakeningNotAuthorized,
    PolicyExceptionInvalid,
}

impl From<AuthorizationReason> for MdbxAuthorizationReason {
    fn from(value: AuthorizationReason) -> Self {
        match value {
            AuthorizationReason::SessionMissing => Self::SessionMissing,
            AuthorizationReason::SessionExpired => Self::SessionExpired,
            AuthorizationReason::AuthenticationStale => Self::AuthenticationStale,
            AuthorizationReason::InsufficientAuthenticationFactors => {
                Self::InsufficientAuthenticationFactors
            }
            AuthorizationReason::SecurityKeyRequired => Self::SecurityKeyRequired,
            AuthorizationReason::DeviceAssuranceInsufficient => Self::DeviceAssuranceInsufficient,
            AuthorizationReason::SecureClipboardUnavailable => Self::SecureClipboardUnavailable,
            AuthorizationReason::ScreenCaptureProtectionUnavailable => {
                Self::ScreenCaptureProtectionUnavailable
            }
            AuthorizationReason::OperationDisabled => Self::OperationDisabled,
            AuthorizationReason::PolicyWeakeningNotAuthorized => Self::PolicyWeakeningNotAuthorized,
            AuthorizationReason::PolicyExceptionInvalid => Self::PolicyExceptionInvalid,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MdbxAuthorizationConstraintKind {
    ClearClipboardAfterSeconds,
    ExcludeClipboardHistory,
    PreventScreenCapture,
    NoPlaintextPersistence,
    UseSecureTemporaryFiles,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxAuthorizationConstraint {
    pub kind: MdbxAuthorizationConstraintKind,
    pub seconds: Option<u32>,
}

impl From<AuthorizationConstraint> for MdbxAuthorizationConstraint {
    fn from(value: AuthorizationConstraint) -> Self {
        match value {
            AuthorizationConstraint::ClearClipboardAfterSeconds(seconds) => Self {
                kind: MdbxAuthorizationConstraintKind::ClearClipboardAfterSeconds,
                seconds: Some(seconds),
            },
            AuthorizationConstraint::ExcludeClipboardHistory => Self {
                kind: MdbxAuthorizationConstraintKind::ExcludeClipboardHistory,
                seconds: None,
            },
            AuthorizationConstraint::PreventScreenCapture => Self {
                kind: MdbxAuthorizationConstraintKind::PreventScreenCapture,
                seconds: None,
            },
            AuthorizationConstraint::NoPlaintextPersistence => Self {
                kind: MdbxAuthorizationConstraintKind::NoPlaintextPersistence,
                seconds: None,
            },
            AuthorizationConstraint::UseSecureTemporaryFiles => Self {
                kind: MdbxAuthorizationConstraintKind::UseSecureTemporaryFiles,
                seconds: None,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxAuthorizationDecision {
    pub outcome: MdbxAuthorizationOutcome,
    pub reasons: Vec<MdbxAuthorizationReason>,
    pub constraints: Vec<MdbxAuthorizationConstraint>,
    pub audit_required: bool,
}

impl From<AuthorizationDecision> for MdbxAuthorizationDecision {
    fn from(value: AuthorizationDecision) -> Self {
        Self {
            outcome: value.outcome.into(),
            reasons: value.reasons.into_iter().map(Into::into).collect(),
            constraints: value.constraints.into_iter().map(Into::into).collect(),
            audit_required: value.audit_required,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MdbxPolicyCompliance {
    Compliant,
    Exception,
    RemediationRequired,
}

impl From<PolicyCompliance> for MdbxPolicyCompliance {
    fn from(value: PolicyCompliance) -> Self {
        match value {
            PolicyCompliance::Compliant => Self::Compliant,
            PolicyCompliance::Exception => Self::Exception,
            PolicyCompliance::RemediationRequired => Self::RemediationRequired,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MdbxAuditLevel {
    SecurityChanges,
    SensitiveOperations,
    AllDecisions,
}

impl From<AuditLevel> for MdbxAuditLevel {
    fn from(value: AuditLevel) -> Self {
        match value {
            AuditLevel::SecurityChanges => Self::SecurityChanges,
            AuditLevel::SensitiveOperations => Self::SensitiveOperations,
            AuditLevel::AllDecisions => Self::AllDecisions,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxResolvedTigaPolicy {
    pub policy_version: u32,
    pub profile: MdbxTigaMode,
    pub compliance: MdbxPolicyCompliance,
    pub exception_id: Option<String>,
    pub warnings: Vec<String>,
    pub portable_unlock_allowed: bool,
    pub minimum_auth_factors: u32,
    pub security_key_required: bool,
    pub security_key_recommended: bool,
    pub idle_timeout_secs: u32,
    pub max_lifetime_secs: u32,
    pub lock_on_background: bool,
    pub fresh_auth_window_secs: u32,
    pub reveal_requires_fresh_auth: bool,
    pub clipboard_allowed: bool,
    pub clipboard_ttl_secs: u32,
    pub copy_requires_fresh_auth: bool,
    pub secure_clipboard_required: bool,
    pub screen_capture_protection_required: bool,
    pub export_allowed: bool,
    pub print_allowed: bool,
    pub egress_requires_fresh_auth: bool,
    pub egress_minimum_auth_factors: u32,
    pub persistent_plaintext_cache_allowed: bool,
    pub attachment_temp_files_allowed: bool,
    pub locked_ciphertext_sync_allowed: bool,
    pub minimum_recovery_methods: u32,
    pub portable_recovery_required: bool,
    pub administration_requires_fresh_auth: bool,
    pub administration_minimum_auth_factors: u32,
    pub audit_deletion_allowed: bool,
    pub minimum_device_assurance: MdbxDeviceAssurance,
    pub audit_level: MdbxAuditLevel,
}

impl From<ResolvedTigaPolicy> for MdbxResolvedTigaPolicy {
    fn from(value: ResolvedTigaPolicy) -> Self {
        let policy = value.policy;
        Self {
            policy_version: policy.policy_version,
            profile: policy.profile.into(),
            compliance: value.compliance.into(),
            exception_id: value.exception_id,
            warnings: value.warnings,
            portable_unlock_allowed: policy.unlock.portable_unlock_allowed,
            minimum_auth_factors: u32::from(policy.unlock.minimum_auth_factors),
            security_key_required: policy.unlock.security_key_required,
            security_key_recommended: policy.unlock.security_key_recommended,
            idle_timeout_secs: policy.session.idle_timeout_secs,
            max_lifetime_secs: policy.session.max_lifetime_secs,
            lock_on_background: policy.session.lock_on_background,
            fresh_auth_window_secs: policy.session.fresh_auth_window_secs,
            reveal_requires_fresh_auth: policy.disclosure.reveal_requires_fresh_auth,
            clipboard_allowed: policy.disclosure.clipboard_allowed,
            clipboard_ttl_secs: policy.disclosure.clipboard_ttl_secs,
            copy_requires_fresh_auth: policy.disclosure.copy_requires_fresh_auth,
            secure_clipboard_required: policy.disclosure.secure_clipboard_required,
            screen_capture_protection_required: policy
                .disclosure
                .screen_capture_protection_required,
            export_allowed: policy.egress.export_allowed,
            print_allowed: policy.egress.print_allowed,
            egress_requires_fresh_auth: policy.egress.requires_fresh_auth,
            egress_minimum_auth_factors: u32::from(policy.egress.minimum_auth_factors),
            persistent_plaintext_cache_allowed: policy
                .data_handling
                .persistent_plaintext_cache_allowed,
            attachment_temp_files_allowed: policy.data_handling.attachment_temp_files_allowed,
            locked_ciphertext_sync_allowed: policy.data_handling.locked_ciphertext_sync_allowed,
            minimum_recovery_methods: u32::from(policy.recovery.minimum_recovery_methods),
            portable_recovery_required: policy.recovery.portable_recovery_required,
            administration_requires_fresh_auth: policy.administration.requires_fresh_auth,
            administration_minimum_auth_factors: u32::from(
                policy.administration.minimum_auth_factors,
            ),
            audit_deletion_allowed: policy.administration.audit_deletion_allowed,
            minimum_device_assurance: policy.minimum_device_assurance.into(),
            audit_level: policy.audit_level.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MdbxUnlockMethodType {
    Pin,
    Password,
    SecurityKey,
    PasswordSecurityKey,
}

impl From<UnlockMethodType> for MdbxUnlockMethodType {
    fn from(value: UnlockMethodType) -> Self {
        match value {
            UnlockMethodType::Pin => Self::Pin,
            UnlockMethodType::Password => Self::Password,
            UnlockMethodType::SecurityKey => Self::SecurityKey,
            UnlockMethodType::PasswordSecurityKey => Self::PasswordSecurityKey,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxUnlockMethod {
    pub method_id: String,
    pub method_type: MdbxUnlockMethodType,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxSessionInfo {
    pub session_id: String,
    pub unlock_method: MdbxUnlockMethodType,
    pub authenticated_at_unix_secs: i64,
    pub last_activity_at_unix_secs: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxTigaUnlockAssessment {
    pub mode: MdbxTigaMode,
    pub configured_methods: Vec<MdbxUnlockMethodType>,
    pub has_portable_unlock: bool,
    pub has_security_key_unlock: bool,
    pub has_combined_password_security_key: bool,
    pub has_required_combined_strength: bool,
    pub satisfies_policy: bool,
    pub warnings: Vec<String>,
}

impl From<TigaUnlockAssessment> for MdbxTigaUnlockAssessment {
    fn from(value: TigaUnlockAssessment) -> Self {
        Self {
            mode: value.mode.into(),
            configured_methods: value
                .configured_methods
                .into_iter()
                .map(Into::into)
                .collect(),
            has_portable_unlock: value.has_portable_unlock,
            has_security_key_unlock: value.has_security_key_unlock,
            has_combined_password_security_key: value.has_combined_password_security_key,
            has_required_combined_strength: value.has_required_combined_strength,
            satisfies_policy: value.satisfies_policy,
            warnings: value.warnings,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxSecurityAuditEvent {
    pub event_id: String,
    pub occurred_at: String,
    pub operation: MdbxTigaOperation,
    pub outcome: MdbxAuthorizationOutcome,
    pub scope: MdbxTigaScope,
    pub session_id: Option<String>,
    pub device_id: Option<String>,
    pub reasons: Vec<MdbxAuthorizationReason>,
    pub constraints: Vec<MdbxAuthorizationConstraint>,
    pub exception_id: Option<String>,
}

impl From<SecurityAuditEvent> for MdbxSecurityAuditEvent {
    fn from(value: SecurityAuditEvent) -> Self {
        Self {
            event_id: value.event_id,
            occurred_at: value.occurred_at,
            operation: value.operation.into(),
            outcome: value.outcome.into(),
            scope: scope_from_core(value.scope),
            session_id: value.session_id,
            device_id: value.device_id,
            reasons: value.reasons.into_iter().map(Into::into).collect(),
            constraints: value.constraints.into_iter().map(Into::into).collect(),
            exception_id: value.exception_id,
        }
    }
}

#[derive(uniffi::Object)]
pub struct MdbxVault {
    conn: Mutex<VaultConnection>,
    device_id: String,
    vault_id: String,
}

#[uniffi::export]
impl MdbxVault {
    pub fn info(&self) -> VaultInfo {
        VaultInfo {
            vault_id: self.vault_id.clone(),
            device_id: self.device_id.clone(),
        }
    }

    pub fn resolve_tiga_policy(
        &self,
        scope: MdbxTigaScope,
    ) -> Result<MdbxResolvedTigaPolicy, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let resolved = match scope.into_core()? {
            TigaScope::Vault => TigaService::resolve_vault_policy(&conn)?,
            TigaScope::Project { project_id } => {
                TigaService::resolve_policy_for_project(&conn, &project_id)?
            }
            TigaScope::Entry { entry_id } => {
                TigaService::resolve_policy_for_entry(&conn, &entry_id)?
            }
        };
        Ok(resolved.into())
    }

    pub fn authorize_tiga_operation(
        &self,
        scope: MdbxTigaScope,
        operation: MdbxTigaOperation,
        device: MdbxDeviceContext,
    ) -> Result<MdbxAuthorizationDecision, MdbxFfiError> {
        let mut conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let scope = scope.into_core()?;
        let device = device.into_core(&self.device_id);
        let decision = TigaService::authorize_operation_with_active_session(
            &mut conn,
            &scope,
            operation.into(),
            &device,
            unix_now(),
        )?;
        Ok(decision.into())
    }

    pub fn active_session_info(&self) -> Result<Option<MdbxSessionInfo>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(conn.active_session().map(|session| MdbxSessionInfo {
            session_id: session.session_id.clone(),
            unlock_method: session.unlock_method.into(),
            authenticated_at_unix_secs: session.assurance.authenticated_at_unix_secs,
            last_activity_at_unix_secs: session.assurance.last_activity_at_unix_secs,
        }))
    }

    pub fn list_unlock_methods(&self) -> Result<Vec<MdbxUnlockMethod>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(UnlockService::list_methods(&conn)?
            .into_iter()
            .map(|method| MdbxUnlockMethod {
                method_id: method.method_id,
                method_type: method.method_type.into(),
                created_at: method.created_at,
                updated_at: method.updated_at,
            })
            .collect())
    }

    pub fn assess_tiga_unlock_policy(&self) -> Result<MdbxTigaUnlockAssessment, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let mode = TigaService::get_global_default(&conn)?;
        Ok(UnlockService::assess_tiga_unlock_policy(&conn, mode)?.into())
    }

    pub fn list_security_audit_events(
        &self,
        limit: u32,
    ) -> Result<Vec<MdbxSecurityAuditEvent>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(
            TigaService::list_security_audit_events(&conn, limit as usize)?
                .into_iter()
                .map(Into::into)
                .collect(),
        )
    }

    pub fn set_tiga_profile(
        &self,
        mode: MdbxTigaMode,
        weakening_reason: Option<String>,
        exception_expires_at_unix_secs: Option<i64>,
        device: MdbxDeviceContext,
    ) -> Result<MdbxResolvedTigaPolicy, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let target_mode: TigaMode = mode.into();
        let current_mode = TigaService::get_global_default(&conn)?;
        let exception = if target_mode < current_mode {
            let reason = weakening_reason
                .filter(|reason| !reason.trim().is_empty())
                .ok_or_else(|| {
                    MdbxFfiError::from(StorageError::Validation(
                        "a non-empty reason is required when weakening the Tiga profile"
                            .to_string(),
                    ))
                })?;
            Some(PolicyException {
                exception_id: Uuid::new_v4().to_string(),
                target: TigaScope::Vault,
                approved_override: TigaPolicyOverride::for_vault_profile(target_mode),
                reason,
                expires_at_unix_secs: exception_expires_at_unix_secs,
            })
        } else {
            None
        };
        let session = conn.active_session().cloned();
        let device = device.into_core(&self.device_id);
        let now = unix_now();
        let ctx = CommitContext::new(self.device_id.clone());
        TigaService::set_vault_profile_authorized(
            &conn,
            &ctx,
            target_mode,
            exception.as_ref(),
            TigaAuthorizationContext {
                session: session.as_ref(),
                device: &device,
                now_unix_secs: now,
            },
        )?;
        Ok(TigaService::resolve_vault_policy(&conn)?.into())
    }

    pub fn create_project(&self, title: String) -> Result<ProjectRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let ctx = CommitContext::new(self.device_id.clone());
        let project = ProjectRepo::create(&conn, &ctx, &title, None, None)?;
        Ok(ProjectRecord {
            project_id: project.project_id,
            title: String::from_utf8_lossy(&project.title_ct).to_string(),
        })
    }

    pub fn execute_write_operation(
        &self,
        operation_id: String,
        operation_kind: String,
        commands: Vec<MdbxWriteCommand>,
    ) -> Result<MdbxWriteOperationResult, MdbxFfiError> {
        validate_write_operation(&operation_id, &operation_kind, &commands)?;
        let intent = serde_json::to_vec(&commands)?;
        let intent_hash = Sha256::digest(intent).to_vec();
        let changed_objects = write_operation_changes(&commands);
        let operation = CommitOperation::new(
            operation_id,
            operation_kind,
            "main",
            "change",
            write_operation_scope(&changed_objects),
            changed_objects,
        )
        .with_intent_hash(intent_hash);

        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let ctx = CommitContext::new(self.device_id.clone());
        let execution = ctx.run_operation(&conn, operation, |scoped| {
            execute_write_commands(&conn, scoped, &commands)
        })?;
        let (commit_id, already_committed) = match execution {
            OperationExecution::Applied { commit_id, .. } => (commit_id, false),
            OperationExecution::AlreadyCommitted { commit_id } => (commit_id, true),
        };
        Ok(write_operation_result(
            &commands,
            commit_id,
            already_committed,
        ))
    }

    pub fn list_commit_history(
        &self,
        page_size: u32,
        cursor: Option<String>,
    ) -> Result<MdbxCommitHistoryPage, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let page = CommitHistoryRepo::list(&conn, page_size as usize, cursor.as_deref())?;
        Ok(commit_history_page_from_storage(page))
    }

    pub fn get_commit_history(
        &self,
        commit_id: String,
    ) -> Result<Option<MdbxCommitHistoryItem>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(CommitHistoryRepo::get(&conn, &commit_id)?.map(commit_history_item_from_storage))
    }

    pub fn create_entry(
        &self,
        project_id: String,
        entry_type: String,
        title: String,
        payload_json: String,
    ) -> Result<EntryRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let ctx = CommitContext::new(self.device_id.clone());
        let payload = parse_payload_json(&payload_json)?;
        let entry = EntryRepo::create(
            &conn,
            &ctx,
            &project_id,
            parse_entry_type(&entry_type)?,
            Some(&title),
            &payload,
        )?;
        entry_record_from_entry(&entry)
    }

    pub fn list_entries(
        &self,
        project_id: String,
        entry_type: Option<String>,
    ) -> Result<Vec<EntryRecord>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let entry_type = parse_optional_entry_type(entry_type)?;
        let entries = match entry_type {
            Some(entry_type) => {
                EntryRepo::list_by_project_and_type(&conn, &project_id, entry_type)?
            }
            None => EntryRepo::list_by_project(&conn, &project_id)?,
        };
        entries.iter().map(entry_record_from_entry).collect()
    }

    pub fn list_deleted_entries(
        &self,
        project_id: String,
        entry_type: Option<String>,
    ) -> Result<Vec<EntryRecord>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let entry_type = parse_optional_entry_type(entry_type)?;
        let entries = match entry_type {
            Some(entry_type) => {
                EntryRepo::list_deleted_by_project_and_type(&conn, &project_id, entry_type)?
            }
            None => EntryRepo::list_deleted_by_project(&conn, &project_id)?,
        };
        entries.iter().map(entry_record_from_entry).collect()
    }

    pub fn update_entry(
        &self,
        project_id: String,
        entry_id: String,
        entry_type: String,
        title: String,
        payload_json: String,
    ) -> Result<EntryRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let expected_type = parse_entry_type(&entry_type)?;
        let mut entry = entry_for_project(&conn, &project_id, &entry_id)?;
        if entry.deleted {
            return Err(StorageError::ConstraintViolation(format!(
                "entry {} is deleted",
                entry_id
            ))
            .into());
        }
        if entry.entry_type != expected_type {
            return Err(StorageError::ConstraintViolation(format!(
                "entry {} is not a {} entry",
                entry_id, entry_type
            ))
            .into());
        }

        entry.title_ct = Some(title.into_bytes());
        entry.payload_ct = serde_json::to_vec(&parse_payload_json(&payload_json)?)?;

        let ctx = CommitContext::new(self.device_id.clone());
        let updated = EntryRepo::update(&conn, &ctx, &entry)?;
        entry_record_from_entry(&updated)
    }

    pub fn delete_entry(&self, project_id: String, entry_id: String) -> Result<(), MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let entry = entry_for_project(&conn, &project_id, &entry_id)?;
        if entry.deleted {
            return Err(StorageError::ConstraintViolation(format!(
                "entry {} is already deleted",
                entry_id
            ))
            .into());
        }

        let ctx = CommitContext::new(self.device_id.clone());
        EntryRepo::soft_delete(&conn, &ctx, &entry_id)?;
        Ok(())
    }

    pub fn restore_entry(
        &self,
        project_id: String,
        entry_id: String,
    ) -> Result<EntryRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let entry = entry_for_project(&conn, &project_id, &entry_id)?;
        if !entry.deleted {
            return Err(StorageError::ConstraintViolation(format!(
                "entry {} is not deleted",
                entry_id
            ))
            .into());
        }

        let ctx = CommitContext::new(self.device_id.clone());
        let restored = EntryRepo::restore(&conn, &ctx, &entry_id)?;
        entry_record_from_entry(&restored)
    }

    pub fn move_entry(
        &self,
        project_id: String,
        entry_id: String,
        target_project_id: String,
    ) -> Result<EntryRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let entry = entry_for_project(&conn, &project_id, &entry_id)?;
        if entry.deleted {
            return Err(StorageError::ConstraintViolation(format!(
                "entry {} is deleted",
                entry_id
            ))
            .into());
        }

        let ctx = CommitContext::new(self.device_id.clone());
        let moved = EntryRepo::move_to_project(&conn, &ctx, &entry_id, &target_project_id)?;
        entry_record_from_entry(&moved)
    }

    pub fn setup_local_security_key_unlock(
        &self,
        key_material: Vec<u8>,
    ) -> Result<(), MdbxFfiError> {
        self.setup_local_security_key_unlock_with_device_context(
            key_material,
            conservative_ffi_device_context(),
        )
    }

    pub fn setup_local_security_key_unlock_with_device_context(
        &self,
        key_material: Vec<u8>,
        device: MdbxDeviceContext,
    ) -> Result<(), MdbxFfiError> {
        let mut conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let key_material = Zeroizing::new(key_material);
        let session = conn.active_session().cloned().ok_or_else(|| {
            MdbxFfiError::from(StorageError::Validation(
                "adding a security key requires an active unlock session".to_string(),
            ))
        })?;
        let device = device.into_core(&self.device_id);
        UnlockService::setup_security_key_authorized(
            &mut conn,
            key_material.as_slice(),
            TigaAuthorizationContext {
                session: Some(&session),
                device: &device,
                now_unix_secs: unix_now(),
            },
        )?;
        Ok(())
    }

    pub fn setup_password_security_key_unlock(
        &self,
        password: String,
        key_material: Vec<u8>,
        device: MdbxDeviceContext,
    ) -> Result<(), MdbxFfiError> {
        let mut conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let password = Zeroizing::new(password);
        let key_material = Zeroizing::new(key_material);
        let session = conn.active_session().cloned().ok_or_else(|| {
            MdbxFfiError::from(StorageError::Validation(
                "adding a combined unlock method requires an active unlock session".to_string(),
            ))
        })?;
        let mode = TigaService::get_global_default(&conn)?;
        let device = device.into_core(&self.device_id);
        UnlockService::setup_password_security_key_authorized(
            &mut conn,
            password.as_str(),
            key_material.as_slice(),
            mode,
            TigaAuthorizationContext {
                session: Some(&session),
                device: &device,
                now_unix_secs: unix_now(),
            },
        )?;
        Ok(())
    }

    pub fn remove_unlock_method(
        &self,
        method_id: String,
        device: MdbxDeviceContext,
    ) -> Result<(), MdbxFfiError> {
        let mut conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let session = conn.active_session().cloned().ok_or_else(|| {
            MdbxFfiError::from(StorageError::Validation(
                "removing an unlock method requires an active unlock session".to_string(),
            ))
        })?;
        let device = device.into_core(&self.device_id);
        UnlockService::remove_method_authorized(
            &mut conn,
            &method_id,
            TigaAuthorizationContext {
                session: Some(&session),
                device: &device,
                now_unix_secs: unix_now(),
            },
        )?;
        Ok(())
    }

    pub fn reset_master_password(&self, new_password: String) -> Result<(), MdbxFfiError> {
        self.reset_master_password_with_tiga_mode(new_password, MdbxTigaMode::Multi)
    }

    pub fn reset_master_password_with_tiga_mode(
        &self,
        new_password: String,
        mode: MdbxTigaMode,
    ) -> Result<(), MdbxFfiError> {
        self.reset_master_password_with_tiga_mode_and_device_context(
            new_password,
            mode,
            conservative_ffi_device_context(),
        )
    }

    pub fn reset_master_password_with_tiga_mode_and_device_context(
        &self,
        new_password: String,
        mode: MdbxTigaMode,
        device: MdbxDeviceContext,
    ) -> Result<(), MdbxFfiError> {
        let mut conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let new_password = Zeroizing::new(new_password);
        let session = conn.active_session().cloned().ok_or_else(|| {
            MdbxFfiError::from(StorageError::Validation(
                "resetting the password requires an active unlock session".to_string(),
            ))
        })?;
        let device = device.into_core(&self.device_id);
        UnlockService::reset_password_authorized(
            &mut conn,
            new_password.as_str(),
            mode.into(),
            TigaAuthorizationContext {
                session: Some(&session),
                device: &device,
                now_unix_secs: unix_now(),
            },
        )?;
        Ok(())
    }
}

fn conservative_ffi_device_context() -> MdbxDeviceContext {
    MdbxDeviceContext {
        assurance: MdbxDeviceAssurance::Standard,
        secure_clipboard_available: false,
        screen_capture_protection_available: false,
        secure_temp_files_available: true,
    }
}

fn required_scope_id(value: Option<String>, scope_type: &str) -> Result<String, MdbxFfiError> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            MdbxFfiError::from(StorageError::Validation(format!(
                "{scope_type} Tiga scope requires a non-empty scope_id"
            )))
        })
}

fn scope_from_core(value: TigaScope) -> MdbxTigaScope {
    match value {
        TigaScope::Vault => MdbxTigaScope {
            scope_type: MdbxTigaScopeType::Vault,
            scope_id: None,
        },
        TigaScope::Project { project_id } => MdbxTigaScope {
            scope_type: MdbxTigaScopeType::Project,
            scope_id: Some(project_id),
        },
        TigaScope::Entry { entry_id } => MdbxTigaScope {
            scope_type: MdbxTigaScopeType::Entry,
            scope_id: Some(entry_id),
        },
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}

#[uniffi::export]
pub fn create_vault(
    path: String,
    password: String,
    device_id: String,
) -> Result<Arc<MdbxVault>, MdbxFfiError> {
    create_vault_with_tiga_mode(path, password, device_id, MdbxTigaMode::Multi)
}

/// Read migration metadata without opening the vault for writing.
#[uniffi::export]
pub fn inspect_vault_migration(path: String) -> Result<MdbxMigrationInfo, MdbxFfiError> {
    Ok(inspect_migration_path(Path::new(&path))?.into())
}

/// Explicitly run the storage-core migration after the client has inspected,
/// backed up, and obtained user consent. The compatibility `open_vault` path
/// remains automatic for callers that do not need this orchestration.
#[uniffi::export]
pub fn upgrade_vault(path: String) -> Result<MdbxMigrationInfo, MdbxFfiError> {
    upgrade_path(Path::new(&path))?;
    Ok(inspect_migration_path(Path::new(&path))?.into())
}

#[uniffi::export]
pub fn create_vault_with_tiga_mode(
    path: String,
    password: String,
    device_id: String,
    mode: MdbxTigaMode,
) -> Result<Arc<MdbxVault>, MdbxFfiError> {
    let mut conn = VaultConnection::create(Path::new(&path))?;
    let mode: TigaMode = mode.into();
    let init = initialize_vault(
        &conn,
        &VaultInitParams {
            default_tiga_mode: mode.to_string(),
            device_id: device_id.clone(),
            ..Default::default()
        },
    )?;
    let password = Zeroizing::new(password);
    UnlockService::setup_password_with_mode(&mut conn, password.as_str(), mode)?;
    Ok(Arc::new(MdbxVault {
        conn: Mutex::new(conn),
        device_id,
        vault_id: init.vault_id,
    }))
}

#[uniffi::export]
pub fn open_vault(
    path: String,
    password: String,
    device_id: String,
) -> Result<Arc<MdbxVault>, MdbxFfiError> {
    let mut conn = VaultConnection::open(Path::new(&path))?;
    let password = Zeroizing::new(password);
    UnlockService::unlock_with_password(&mut conn, password.as_str())?;
    let vault_id = read_vault_id(&conn)?;
    Ok(Arc::new(MdbxVault {
        conn: Mutex::new(conn),
        device_id,
        vault_id,
    }))
}

#[uniffi::export]
pub fn open_vault_with_security_key(
    path: String,
    key_material: Vec<u8>,
    device_id: String,
) -> Result<Arc<MdbxVault>, MdbxFfiError> {
    let mut conn = VaultConnection::open(Path::new(&path))?;
    let key_material = Zeroizing::new(key_material);
    UnlockService::unlock_with_security_key(&mut conn, key_material.as_slice())?;
    let vault_id = read_vault_id(&conn)?;
    Ok(Arc::new(MdbxVault {
        conn: Mutex::new(conn),
        device_id,
        vault_id,
    }))
}

#[uniffi::export]
pub fn open_vault_with_password_security_key(
    path: String,
    password: String,
    key_material: Vec<u8>,
    device_id: String,
) -> Result<Arc<MdbxVault>, MdbxFfiError> {
    let mut conn = VaultConnection::open(Path::new(&path))?;
    let password = Zeroizing::new(password);
    let key_material = Zeroizing::new(key_material);
    UnlockService::unlock_with_password_security_key(
        &mut conn,
        password.as_str(),
        key_material.as_slice(),
    )?;
    let vault_id = read_vault_id(&conn)?;
    Ok(Arc::new(MdbxVault {
        conn: Mutex::new(conn),
        device_id,
        vault_id,
    }))
}

fn read_vault_id(conn: &VaultConnection) -> Result<String, MdbxFfiError> {
    conn.inner()
        .query_row("SELECT vault_id FROM vault_meta LIMIT 1", [], |row| {
            row.get::<_, String>(0)
        })
        .map_err(StorageError::from)
        .map_err(MdbxFfiError::from)
}

fn entry_for_project(
    conn: &VaultConnection,
    project_id: &str,
    entry_id: &str,
) -> StorageResult<mdbx_core::model::Entry> {
    let entry = EntryRepo::get_by_id(conn, entry_id)?
        .ok_or_else(|| StorageError::NotFound(entry_id.to_string()))?;
    if entry.project_id != project_id {
        return Err(StorageError::ConstraintViolation(format!(
            "entry {} does not belong to project {}",
            entry_id, project_id
        )));
    }
    Ok(entry)
}

fn validate_write_operation(
    operation_id: &str,
    operation_kind: &str,
    commands: &[MdbxWriteCommand],
) -> Result<(), MdbxFfiError> {
    if operation_id.trim().is_empty() {
        return Err(StorageError::Validation("operation_id must not be empty".to_string()).into());
    }
    if operation_kind.trim().is_empty() {
        return Err(
            StorageError::Validation("operation_kind must not be empty".to_string()).into(),
        );
    }
    if commands.is_empty() {
        return Err(
            StorageError::Validation("write operation requires commands".to_string()).into(),
        );
    }
    for command in commands {
        match command {
            MdbxWriteCommand::CreateProject { project_id, .. } => {
                validate_uuid(project_id, "project_id")?
            }
            MdbxWriteCommand::CreateEntry {
                entry_id,
                entry_type,
                payload_json,
                ..
            }
            | MdbxWriteCommand::UpdateEntry {
                entry_id,
                entry_type,
                payload_json,
                ..
            } => {
                validate_uuid(entry_id, "entry_id")?;
                parse_entry_type(entry_type)?;
                parse_payload_json(payload_json)?;
            }
            MdbxWriteCommand::DeleteEntry { entry_id, .. }
            | MdbxWriteCommand::RestoreEntry { entry_id, .. }
            | MdbxWriteCommand::MoveEntry { entry_id, .. } => validate_uuid(entry_id, "entry_id")?,
        }
    }
    Ok(())
}

fn validate_uuid(value: &str, field: &str) -> Result<(), MdbxFfiError> {
    Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| StorageError::Validation(format!("{field} {value} must be a UUID")).into())
}

fn write_operation_changes(commands: &[MdbxWriteCommand]) -> Vec<CommitChange> {
    let mut changes = Vec::new();
    for command in commands {
        let (object_type, object_id) = match command {
            MdbxWriteCommand::CreateProject { project_id, .. } => ("project", project_id),
            MdbxWriteCommand::CreateEntry { entry_id, .. }
            | MdbxWriteCommand::UpdateEntry { entry_id, .. }
            | MdbxWriteCommand::DeleteEntry { entry_id, .. }
            | MdbxWriteCommand::RestoreEntry { entry_id, .. }
            | MdbxWriteCommand::MoveEntry { entry_id, .. } => ("entry", entry_id),
        };
        if !changes.iter().any(|change: &CommitChange| {
            change.object_type == object_type && change.object_id == *object_id
        }) {
            changes.push(CommitChange {
                object_type: object_type.to_string(),
                object_id: object_id.clone(),
                action: "change".to_string(),
                fields: Vec::new(),
            });
        }
    }
    changes
}

fn write_operation_scope(changes: &[CommitChange]) -> String {
    let first = &changes[0].object_type;
    if changes.iter().all(|change| change.object_type == *first) {
        first.clone()
    } else {
        "multi".to_string()
    }
}

fn execute_write_commands(
    conn: &VaultConnection,
    ctx: &CommitContext,
    commands: &[MdbxWriteCommand],
) -> StorageResult<()> {
    for command in commands {
        match command {
            MdbxWriteCommand::CreateProject { project_id, title } => {
                ProjectRepo::create_with_id(conn, ctx, project_id, title, None, None)?;
            }
            MdbxWriteCommand::CreateEntry {
                entry_id,
                project_id,
                entry_type,
                title,
                payload_json,
            } => {
                let payload = serde_json::from_str(payload_json)
                    .map_err(|error| StorageError::Validation(error.to_string()))?;
                let entry_type = entry_type.parse().map_err(|_| {
                    StorageError::Validation(format!("invalid entry type: {entry_type}"))
                })?;
                EntryRepo::create_with_id(
                    conn,
                    ctx,
                    entry_id,
                    project_id,
                    entry_type,
                    Some(title),
                    &payload,
                )?;
            }
            MdbxWriteCommand::UpdateEntry {
                entry_id,
                project_id,
                entry_type,
                title,
                payload_json,
            } => {
                let expected_type = entry_type.parse().map_err(|_| {
                    StorageError::Validation(format!("invalid entry type: {entry_type}"))
                })?;
                let mut entry = entry_for_project(conn, project_id, entry_id)?;
                if entry.deleted || entry.entry_type != expected_type {
                    return Err(StorageError::ConstraintViolation(format!(
                        "entry {entry_id} cannot be updated"
                    )));
                }
                entry.title_ct = Some(title.as_bytes().to_vec());
                entry.payload_ct = serde_json::to_vec(
                    &serde_json::from_str::<serde_json::Value>(payload_json)
                        .map_err(|error| StorageError::Validation(error.to_string()))?,
                )
                .map_err(|error| StorageError::Validation(error.to_string()))?;
                EntryRepo::update(conn, ctx, &entry)?;
            }
            MdbxWriteCommand::DeleteEntry {
                entry_id,
                project_id,
            } => {
                entry_for_project(conn, project_id, entry_id)?;
                EntryRepo::soft_delete(conn, ctx, entry_id)?;
            }
            MdbxWriteCommand::RestoreEntry {
                entry_id,
                project_id,
            } => {
                entry_for_project(conn, project_id, entry_id)?;
                EntryRepo::restore(conn, ctx, entry_id)?;
            }
            MdbxWriteCommand::MoveEntry {
                entry_id,
                project_id,
                target_project_id,
            } => {
                entry_for_project(conn, project_id, entry_id)?;
                EntryRepo::move_to_project(conn, ctx, entry_id, target_project_id)?;
            }
        }
    }
    Ok(())
}

fn write_operation_result(
    commands: &[MdbxWriteCommand],
    commit_id: String,
    already_committed: bool,
) -> MdbxWriteOperationResult {
    let changes = write_operation_changes(commands);
    let mut project_ids = Vec::new();
    let mut entry_ids = Vec::new();
    for change in changes {
        match change.object_type.as_str() {
            "project" => project_ids.push(change.object_id),
            "entry" => entry_ids.push(change.object_id),
            _ => {}
        }
    }
    MdbxWriteOperationResult {
        commit_id,
        already_committed,
        project_ids,
        entry_ids,
    }
}

fn commit_history_page_from_storage(page: CommitHistoryPage) -> MdbxCommitHistoryPage {
    MdbxCommitHistoryPage {
        items: page
            .items
            .into_iter()
            .map(commit_history_item_from_storage)
            .collect(),
        next_cursor: page.next_cursor,
    }
}

fn commit_history_item_from_storage(item: CommitHistoryItem) -> MdbxCommitHistoryItem {
    MdbxCommitHistoryItem {
        commit_id: item.commit_id,
        device_id: item.device_id,
        local_seq: item.local_seq,
        commit_kind: item.commit_kind,
        change_scope: item.change_scope,
        created_at: item.created_at,
        operation_id: item.operation_id,
        operation_kind: item.operation_kind,
        branch_name: item.branch_name,
        message: item.message,
        changes: item
            .changes
            .into_iter()
            .map(|change| MdbxCommitChange {
                object_type: change.object_type,
                object_id: change.object_id,
                action: change.action,
                fields: change.fields,
            })
            .collect(),
        parent_ids: item.parent_ids,
        legacy: item.legacy,
    }
}

fn parse_entry_type(entry_type: &str) -> Result<EntryType, MdbxFfiError> {
    entry_type
        .parse()
        .map_err(|_| MdbxFfiError::InvalidEntryType {
            entry_type: entry_type.to_string(),
        })
}

fn parse_optional_entry_type(
    entry_type: Option<String>,
) -> Result<Option<EntryType>, MdbxFfiError> {
    entry_type.as_deref().map(parse_entry_type).transpose()
}

fn parse_payload_json(payload_json: &str) -> Result<serde_json::Value, MdbxFfiError> {
    serde_json::from_str(payload_json).map_err(MdbxFfiError::from)
}

fn entry_record_from_entry(entry: &mdbx_core::model::Entry) -> Result<EntryRecord, MdbxFfiError> {
    let payload: serde_json::Value = serde_json::from_slice(&entry.payload_ct)?;
    Ok(EntryRecord {
        entry_id: entry.entry_id.clone(),
        project_id: entry.project_id.clone(),
        entry_type: entry.entry_type.to_string(),
        title: entry
            .title_ct
            .as_deref()
            .map(String::from_utf8_lossy)
            .map(|s| s.to_string())
            .unwrap_or_default(),
        payload_json: serde_json::to_string(&payload)?,
        deleted: entry.deleted,
    })
}
