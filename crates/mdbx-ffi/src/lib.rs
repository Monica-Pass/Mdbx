//! Generic UniFFI boundary for MDBX vault clients.
//!
//! This crate exposes vault, generic object, metadata, and attachment
//! operations. Product-specific payload meaning belongs in each client.

mod attachment_facade;
mod write_facade;

use attachment_facade::*;
use write_facade::*;

use std::io::Cursor;
use std::path::Path;
use std::sync::{Arc, Mutex};

use mdbx_core::model::{
    Attachment, CollectionProfile, CollectionTypeId, Conflict, ConflictObjectType,
    ConflictResolution, EntryType, ExtensionCapabilityId, ObjectSummary, ObjectTypeId,
    PayloadMigrationExecution, PayloadMigrationOutput, PayloadMigrationPlan,
    PayloadMigrationPlanItem, RelationKindId, Tombstone, UnlockMethodType,
};
use mdbx_core::tiga::{
    AuditLevel, AuthorizationConstraint, AuthorizationDecision, AuthorizationOutcome,
    AuthorizationReason, DeviceAssurance, DeviceContext, PolicyCompliance, PolicyException,
    ResolvedTigaPolicy, TigaMode, TigaOperation, TigaPolicyOverride, TigaScope,
};
use mdbx_storage::backup::{BackupService, VaultBackupInfo};
use mdbx_storage::connection::{PendingVaultCreation, VaultConnection};
use mdbx_storage::error::{StorageError, StorageResult};
use mdbx_storage::init::{initialize_vault, VaultInitParams};
use mdbx_storage::key_epoch::{KeyEpochRotationResult, KeyEpochService};
use mdbx_storage::migration::{inspect_migration_path, upgrade_path, MigrationInfo};
use mdbx_storage::recovery::{HealthCheckResult, HealthIssue, IssueSeverity, RecoveryVerifier};
use mdbx_storage::repo::{
    AttachmentPlaintextPurpose, AttachmentRepo, AttachmentWriteOptions, BranchRepo,
    CollectionProfileRepo, CollectionProfileSpec, CommitContext, CommitHistoryItem,
    CommitHistoryPage, CommitHistoryRepo, ConflictRepo, EntryRepo,
    ObjectLabelAssignmentCreateRequest, ObjectLabelAssignmentRepo, ObjectLabelCreateRequest,
    ObjectLabelRepo, ObjectRelationCreateRequest, ObjectRelationRepo, ObjectSummaryRepo,
    PayloadMigrationPlanRequest, PayloadMigrationRepo, PermanentPurgeReceipt, ProjectRepo,
    TombstonePurgeBlocker, TombstonePurgeEligibility, TombstonePurgeScheduleResult, TombstoneRepo,
};
use mdbx_storage::tiga::TigaService;
use mdbx_storage::tiga_policy::{SecurityAuditEvent, TigaAuthorizationContext};
use mdbx_storage::unlock::{TigaUnlockAssessment, UnlockService};
use mdbx_sync::{
    BlobChunkRequest, BlobChunkResponse, BlobManifestEntry, BlobManifestEntryState,
    BlobManifestPageRequest, BlobManifestPageResponse, BlobSyncPhase, BlobSyncResume, BranchHead,
    HelloRequest, HelloResponse, SyncClient, SyncMessage, SyncNegotiator, SyncWireFrame,
    SyncWireLimits, SyncWireResume, SyncWireSession,
};
use uuid::Uuid;
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

#[uniffi::export]
pub fn default_write_operation_limits() -> MdbxWriteOperationLimits {
    InternalWriteOperationLimits::default().public()
}

#[uniffi::export]
pub fn default_composite_write_operation_limits() -> MdbxCompositeWriteOperationLimits {
    MdbxCompositeWriteOperationLimits {
        write_limits: default_write_operation_limits(),
        attachment_limits: default_attachment_batch_limits(),
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MdbxFfiError {
    #[error("storage error: {message}")]
    Storage { message: String },
    #[error("serialization error: {message}")]
    Serialization { message: String },
    #[error("sync protocol error: {message}")]
    SyncProtocol { message: String },
    #[error("invalid entry type: {entry_type}")]
    InvalidEntryType { entry_type: String },
    #[error("invalid object type ID: {object_type_id}")]
    InvalidObjectTypeId { object_type_id: String },
    #[error("invalid relation kind: {relation_kind}")]
    InvalidRelationKind { relation_kind: String },
    #[error("invalid collection type ID: {collection_type_id}")]
    InvalidCollectionTypeId { collection_type_id: String },
    #[error("invalid extension capability ID: {capability_id}")]
    InvalidExtensionCapabilityId { capability_id: String },
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

impl From<mdbx_sync::SyncError> for MdbxFfiError {
    fn from(value: mdbx_sync::SyncError) -> Self {
        MdbxFfiError::SyncProtocol {
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
pub struct MdbxBackupInfo {
    pub vault_id: String,
    pub format_version: String,
    pub schema_version: u32,
    pub file_size_bytes: u64,
}

impl From<VaultBackupInfo> for MdbxBackupInfo {
    fn from(value: VaultBackupInfo) -> Self {
        Self {
            vault_id: value.vault_id,
            format_version: value.format_version,
            schema_version: value.schema_version,
            file_size_bytes: value.file_size_bytes,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MdbxHealthIssueSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl From<IssueSeverity> for MdbxHealthIssueSeverity {
    fn from(value: IssueSeverity) -> Self {
        match value {
            IssueSeverity::Info => Self::Info,
            IssueSeverity::Warning => Self::Warning,
            IssueSeverity::Error => Self::Error,
            IssueSeverity::Critical => Self::Critical,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxHealthIssue {
    pub severity: MdbxHealthIssueSeverity,
    pub category: String,
    pub description: String,
}

impl From<HealthIssue> for MdbxHealthIssue {
    fn from(value: HealthIssue) -> Self {
        Self {
            severity: value.severity.into(),
            category: value.category,
            description: value.description,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxHealthCheckResult {
    pub healthy: bool,
    pub issues: Vec<MdbxHealthIssue>,
}

impl From<HealthCheckResult> for MdbxHealthCheckResult {
    fn from(value: HealthCheckResult) -> Self {
        Self {
            healthy: value.healthy,
            issues: value.issues.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxTombstonePurgeBlocker {
    pub code: String,
    pub device_id: Option<String>,
    pub commit_id: Option<String>,
    pub timestamp: Option<String>,
    pub dependent_object_type: Option<String>,
    pub dependent_object_count: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxTombstoneRecord {
    pub tombstone_id: String,
    pub target_object_type: String,
    pub target_object_id: String,
    pub delete_clock: String,
    pub deleted_by_device_id: String,
    pub deleted_at: String,
    pub purge_eligible_at: Option<String>,
    pub delete_commit_id: Option<String>,
}

impl From<Tombstone> for MdbxTombstoneRecord {
    fn from(value: Tombstone) -> Self {
        Self {
            tombstone_id: value.tombstone_id,
            target_object_type: value.target_object_type.to_string(),
            target_object_id: value.target_object_id,
            delete_clock: value.delete_clock,
            deleted_by_device_id: value.deleted_by_device_id,
            deleted_at: value.deleted_at,
            purge_eligible_at: value.purge_eligible_at,
            delete_commit_id: value.delete_commit_id,
        }
    }
}

impl From<TombstonePurgeBlocker> for MdbxTombstonePurgeBlocker {
    fn from(value: TombstonePurgeBlocker) -> Self {
        match value {
            TombstonePurgeBlocker::RetentionNotScheduled => Self::new("retention-not-scheduled"),
            TombstonePurgeBlocker::RetentionPeriodActive { eligible_at } => Self {
                timestamp: Some(eligible_at),
                ..Self::new("retention-period-active")
            },
            TombstonePurgeBlocker::InvalidRetentionTimestamp { value } => Self {
                timestamp: Some(value),
                ..Self::new("invalid-retention-timestamp")
            },
            TombstonePurgeBlocker::MissingDeleteCommit => Self::new("missing-delete-commit"),
            TombstonePurgeBlocker::DeleteCommitMissing { commit_id } => Self {
                commit_id: Some(commit_id),
                ..Self::new("delete-commit-missing")
            },
            TombstonePurgeBlocker::TargetMissing => Self::new("target-missing"),
            TombstonePurgeBlocker::TargetNotDeleted => Self::new("target-not-deleted"),
            TombstonePurgeBlocker::UnresolvedConflict => Self::new("unresolved-conflict"),
            TombstonePurgeBlocker::DeviceHasNotAcknowledgedDelete { device_id } => Self {
                device_id: Some(device_id),
                ..Self::new("device-has-not-acknowledged-delete")
            },
            TombstonePurgeBlocker::DependentObjectsRemain { object_type, count } => Self {
                dependent_object_type: Some(object_type),
                dependent_object_count: Some(count),
                ..Self::new("dependent-objects-remain")
            },
            TombstonePurgeBlocker::UnsupportedTargetType => Self::new("unsupported-target-type"),
        }
    }
}

impl MdbxTombstonePurgeBlocker {
    fn new(code: &str) -> Self {
        Self {
            code: code.to_string(),
            device_id: None,
            commit_id: None,
            timestamp: None,
            dependent_object_type: None,
            dependent_object_count: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxTombstonePurgeEligibility {
    pub tombstone_id: String,
    pub eligible: bool,
    pub blockers: Vec<MdbxTombstonePurgeBlocker>,
}

impl From<TombstonePurgeEligibility> for MdbxTombstonePurgeEligibility {
    fn from(value: TombstonePurgeEligibility) -> Self {
        Self {
            tombstone_id: value.tombstone_id,
            eligible: value.eligible,
            blockers: value.blockers.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxTombstonePurgeScheduleResult {
    pub tombstone_id: String,
    pub purge_eligible_at: String,
    pub commit_id: String,
}

impl From<TombstonePurgeScheduleResult> for MdbxTombstonePurgeScheduleResult {
    fn from(value: TombstonePurgeScheduleResult) -> Self {
        Self {
            tombstone_id: value.tombstone_id,
            purge_eligible_at: value.purge_eligible_at,
            commit_id: value.commit_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxPermanentPurgeReceipt {
    pub purge_id: String,
    pub tombstone_id: String,
    pub target_object_type: String,
    pub target_object_id: String,
    pub delete_commit_id: String,
    pub purge_commit_id: String,
    pub delete_clock: String,
    pub retention_eligible_at: String,
    pub purged_by_device_id: String,
    pub purged_at: String,
    pub integrity_tag: Vec<u8>,
}

impl From<PermanentPurgeReceipt> for MdbxPermanentPurgeReceipt {
    fn from(value: PermanentPurgeReceipt) -> Self {
        Self {
            purge_id: value.purge_id,
            tombstone_id: value.tombstone_id,
            target_object_type: value.target_object_type,
            target_object_id: value.target_object_id,
            delete_commit_id: value.delete_commit_id,
            purge_commit_id: value.purge_commit_id,
            delete_clock: value.delete_clock,
            retention_eligible_at: value.retention_eligible_at,
            purged_by_device_id: value.purged_by_device_id,
            purged_at: value.purged_at,
            integrity_tag: value.integrity_tag,
        }
    }
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

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxCollectionProfile {
    pub collection_id: String,
    pub collection_type_id: String,
    pub payload: Vec<u8>,
    pub payload_schema_version: u32,
    pub allowed_object_type_ids: Vec<String>,
    pub required_capability_ids: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    pub created_by_device_id: String,
    pub updated_by_device_id: String,
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

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxObjectRecord {
    pub object_id: String,
    pub collection_id: String,
    pub object_type_id: String,
    pub title: String,
    pub payload_json: String,
    pub payload_schema_version: u32,
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxPayloadMigrationPlanItem {
    pub object_id: String,
    pub object_head_commit_id: String,
    pub source_payload_digest: Vec<u8>,
    pub source_payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxPayloadMigrationPlan {
    pub plan_id: String,
    pub collection_id: String,
    pub object_type_id: String,
    pub source_schema_version: u32,
    pub target_schema_version: u32,
    pub branch_id: String,
    pub branch_name: String,
    pub branch_head_commit_id: String,
    pub collection_profile_digest: Option<Vec<u8>>,
    pub items: Vec<MdbxPayloadMigrationPlanItem>,
    pub remaining_count: u64,
    pub total_source_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxPayloadMigrationOutput {
    pub object_id: String,
    pub target_payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxPayloadMigrationExecution {
    pub commit_id: String,
    pub migrated_count: u32,
    pub already_committed: bool,
}

impl From<PayloadMigrationPlanItem> for MdbxPayloadMigrationPlanItem {
    fn from(value: PayloadMigrationPlanItem) -> Self {
        Self {
            object_id: value.object_id,
            object_head_commit_id: value.object_head_commit_id,
            source_payload_digest: value.source_payload_digest,
            source_payload: value.source_payload,
        }
    }
}

impl From<PayloadMigrationPlan> for MdbxPayloadMigrationPlan {
    fn from(value: PayloadMigrationPlan) -> Self {
        Self {
            plan_id: value.plan_id,
            collection_id: value.collection_id,
            object_type_id: value.object_type_id.to_string(),
            source_schema_version: value.source_schema_version,
            target_schema_version: value.target_schema_version,
            branch_id: value.branch_id,
            branch_name: value.branch_name,
            branch_head_commit_id: value.branch_head_commit_id,
            collection_profile_digest: value.collection_profile_digest,
            items: value.items.into_iter().map(Into::into).collect(),
            remaining_count: value.remaining_count,
            total_source_bytes: value.total_source_bytes,
        }
    }
}

impl MdbxPayloadMigrationPlan {
    fn into_core(self) -> Result<PayloadMigrationPlan, MdbxFfiError> {
        Ok(PayloadMigrationPlan {
            plan_id: self.plan_id,
            collection_id: self.collection_id,
            object_type_id: parse_object_type_id(&self.object_type_id)?,
            source_schema_version: self.source_schema_version,
            target_schema_version: self.target_schema_version,
            branch_id: self.branch_id,
            branch_name: self.branch_name,
            branch_head_commit_id: self.branch_head_commit_id,
            collection_profile_digest: self.collection_profile_digest,
            items: self
                .items
                .into_iter()
                .map(|item| PayloadMigrationPlanItem {
                    object_id: item.object_id,
                    object_head_commit_id: item.object_head_commit_id,
                    source_payload_digest: item.source_payload_digest,
                    source_payload: item.source_payload,
                })
                .collect(),
            remaining_count: self.remaining_count,
            total_source_bytes: self.total_source_bytes,
        })
    }
}

impl From<PayloadMigrationExecution> for MdbxPayloadMigrationExecution {
    fn from(value: PayloadMigrationExecution) -> Self {
        Self {
            commit_id: value.commit_id,
            migrated_count: value.migrated_count,
            already_committed: value.already_committed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxObjectSummary {
    pub object_id: String,
    pub collection_id: String,
    pub object_type_id: String,
    pub title: String,
    pub payload_schema_version: u32,
    pub head_commit_id: String,
    pub deleted: bool,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxObjectSummaryPage {
    pub items: Vec<MdbxObjectSummary>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxObjectRelationRecord {
    pub relation_id: String,
    pub source_object_id: String,
    pub target_object_id: String,
    pub relation_kind: String,
    pub payload_json: String,
    pub payload_schema_version: u32,
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxObjectLabelRecord {
    pub label_id: String,
    pub collection_id: String,
    pub name: String,
    pub payload_json: String,
    pub payload_schema_version: u32,
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxObjectLabelAssignmentRecord {
    pub assignment_id: String,
    pub object_id: String,
    pub label_id: String,
    pub deleted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MdbxConflictChoice {
    LocalWins,
    IncomingWins,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxConflictRecord {
    pub conflict_id: String,
    pub object_type: String,
    pub object_id: String,
    pub base_commit_id: String,
    pub local_commit_id: String,
    pub incoming_commit_id: String,
    pub conflicting_fields: Vec<String>,
    pub resolution: String,
    pub created_at: String,
    pub resolved_at: Option<String>,
}

/// Client-editable project fields for an explicit custom conflict merge.
///
/// The conflict ID supplies the project identity. Policy, clocks, collection
/// profile, and derived counters remain storage-owned.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxProjectConflictMerge {
    pub title: String,
    pub summary: Option<String>,
    pub group_id: Option<String>,
    pub icon_ref: Option<String>,
    pub favorite: bool,
    pub archived: bool,
    pub deleted: bool,
}

/// Client-editable attachment metadata for an explicit custom conflict merge.
///
/// Content identity and chunk metadata are intentionally absent. Content must
/// be transferred and verified through the attachment/blob APIs first.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxAttachmentConflictMerge {
    pub project_id: String,
    pub entry_id: Option<String>,
    pub file_name: String,
    pub media_type: Option<String>,
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxAttachmentRecord {
    pub attachment_id: String,
    pub project_id: String,
    pub entry_id: Option<String>,
    pub file_name: String,
    pub media_type: Option<String>,
    pub storage_mode: String,
    pub content_hash: String,
    pub original_size: u64,
    pub stored_size: u64,
    pub chunk_count: u32,
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxAttachmentCreateRequest {
    pub attachment_id: String,
    pub project_id: String,
    pub entry_id: Option<String>,
    pub file_name: String,
    pub media_type: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct MdbxAttachmentContentLimits {
    pub chunk_size: u64,
    pub max_plaintext_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxAttachmentWriteResult {
    pub attachment: MdbxAttachmentRecord,
    pub commit_id: String,
    pub already_committed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum MdbxAttachmentBatchCommand {
    Create {
        attachment_id: String,
        project_id: String,
        entry_id: Option<String>,
        file_name: String,
        media_type: Option<String>,
        content: Vec<u8>,
    },
    Replace {
        attachment_id: String,
        content: Vec<u8>,
    },
    Rename {
        attachment_id: String,
        file_name: String,
        media_type: Option<String>,
    },
    Delete {
        attachment_id: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct MdbxAttachmentBatchLimits {
    pub max_commands: u64,
    pub max_plaintext_bytes_per_command: u64,
    pub max_plaintext_bytes: u64,
    pub chunk_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxAttachmentBatchResult {
    pub attachments: Vec<MdbxAttachmentRecord>,
    pub commit_id: String,
    pub already_committed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct MdbxCompositeWriteOperationLimits {
    pub write_limits: MdbxWriteOperationLimits,
    pub attachment_limits: MdbxAttachmentBatchLimits,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MdbxCompositeWriteOperationResult {
    pub operation: MdbxWriteOperationResult,
    pub attachments: Vec<MdbxAttachmentRecord>,
}

const DEFAULT_ATTACHMENT_CHUNK_SIZE: usize = 256 * 1024;
const HARD_MAX_ATTACHMENT_CHUNK_SIZE: usize = 4 * 1024 * 1024;
const DEFAULT_MAX_ATTACHMENT_PLAINTEXT_BYTES: usize = 8 * 1024 * 1024;
const HARD_MAX_ATTACHMENT_PLAINTEXT_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_MAX_ATTACHMENT_BATCH_COMMANDS: usize = 64;
const HARD_MAX_ATTACHMENT_BATCH_COMMANDS: usize = 512;
const DEFAULT_MAX_ATTACHMENT_BATCH_PLAINTEXT_BYTES: usize = 32 * 1024 * 1024;
const HARD_MAX_ATTACHMENT_BATCH_PLAINTEXT_BYTES: usize = 256 * 1024 * 1024;

#[uniffi::export]
pub fn default_attachment_content_limits() -> MdbxAttachmentContentLimits {
    MdbxAttachmentContentLimits {
        chunk_size: DEFAULT_ATTACHMENT_CHUNK_SIZE as u64,
        max_plaintext_bytes: DEFAULT_MAX_ATTACHMENT_PLAINTEXT_BYTES as u64,
    }
}

#[uniffi::export]
pub fn default_attachment_batch_limits() -> MdbxAttachmentBatchLimits {
    MdbxAttachmentBatchLimits {
        max_commands: DEFAULT_MAX_ATTACHMENT_BATCH_COMMANDS as u64,
        max_plaintext_bytes_per_command: DEFAULT_MAX_ATTACHMENT_PLAINTEXT_BYTES as u64,
        max_plaintext_bytes: DEFAULT_MAX_ATTACHMENT_BATCH_PLAINTEXT_BYTES as u64,
        chunk_size: DEFAULT_ATTACHMENT_CHUNK_SIZE as u64,
    }
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
    CreateObjectRelation {
        relation_id: String,
        source_object_id: String,
        target_object_id: String,
        relation_kind: String,
        payload_json: String,
        payload_schema_version: u32,
    },
    UpdateObjectRelation {
        relation_id: String,
        relation_kind: String,
        payload_json: String,
        payload_schema_version: u32,
    },
    DeleteObjectRelation {
        relation_id: String,
    },
    CreateObjectLabel {
        label_id: String,
        collection_id: String,
        name: String,
        payload_json: String,
        payload_schema_version: u32,
    },
    UpdateObjectLabel {
        label_id: String,
        name: String,
        payload_json: String,
        payload_schema_version: u32,
    },
    DeleteObjectLabel {
        label_id: String,
    },
    AssignObjectLabel {
        assignment_id: String,
        object_id: String,
        label_id: String,
    },
    RemoveObjectLabelAssignment {
        assignment_id: String,
    },
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MdbxWriteOperationResult {
    pub commit_id: String,
    pub already_committed: bool,
    pub project_ids: Vec<String>,
    pub entry_ids: Vec<String>,
    pub relation_ids: Vec<String>,
    pub label_ids: Vec<String>,
    pub label_assignment_ids: Vec<String>,
}

/// Resource contract for one generic user-level write operation.
///
/// The defaults are suitable for interactive clients. Explicit values are
/// accepted only within the hard ceilings so a caller cannot disable the
/// boundary by opting into a custom profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct MdbxWriteOperationLimits {
    pub max_commands: u64,
    pub max_payload_bytes_per_command: u64,
    pub max_payload_bytes: u64,
    pub max_intent_bytes: u64,
}

const DEFAULT_MAX_WRITE_COMMANDS: usize = 256;
const HARD_MAX_WRITE_COMMANDS: usize = 4_096;
const DEFAULT_MAX_WRITE_PAYLOAD_BYTES_PER_COMMAND: usize = 1024 * 1024;
const HARD_MAX_WRITE_PAYLOAD_BYTES_PER_COMMAND: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_WRITE_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
const HARD_MAX_WRITE_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_MAX_WRITE_INTENT_BYTES: usize = 16 * 1024 * 1024;
const HARD_MAX_WRITE_INTENT_BYTES: usize = 128 * 1024 * 1024;

impl Default for MdbxWriteOperationLimits {
    fn default() -> Self {
        Self {
            max_commands: DEFAULT_MAX_WRITE_COMMANDS as u64,
            max_payload_bytes_per_command: DEFAULT_MAX_WRITE_PAYLOAD_BYTES_PER_COMMAND as u64,
            max_payload_bytes: DEFAULT_MAX_WRITE_PAYLOAD_BYTES as u64,
            max_intent_bytes: DEFAULT_MAX_WRITE_INTENT_BYTES as u64,
        }
    }
}

impl MdbxWriteOperationLimits {
    fn into_internal(self) -> Result<InternalWriteOperationLimits, MdbxFfiError> {
        let limits = InternalWriteOperationLimits {
            max_commands: usize::try_from(self.max_commands)
                .map_err(|_| StorageError::Validation("max_commands is too large".to_string()))?,
            max_payload_bytes_per_command: usize::try_from(self.max_payload_bytes_per_command)
                .map_err(|_| {
                    StorageError::Validation(
                        "max_payload_bytes_per_command is too large".to_string(),
                    )
                })?,
            max_payload_bytes: usize::try_from(self.max_payload_bytes).map_err(|_| {
                StorageError::Validation("max_payload_bytes is too large".to_string())
            })?,
            max_intent_bytes: usize::try_from(self.max_intent_bytes).map_err(|_| {
                StorageError::Validation("max_intent_bytes is too large".to_string())
            })?,
        };
        limits.validate()?;
        Ok(limits)
    }
}

#[derive(Debug, Clone, Copy)]
struct InternalWriteOperationLimits {
    max_commands: usize,
    max_payload_bytes_per_command: usize,
    max_payload_bytes: usize,
    max_intent_bytes: usize,
}

impl Default for InternalWriteOperationLimits {
    fn default() -> Self {
        MdbxWriteOperationLimits::default()
            .into_internal()
            .expect("built-in write operation limits must be valid")
    }
}

impl InternalWriteOperationLimits {
    fn validate(self) -> Result<(), MdbxFfiError> {
        let checks = [
            ("max_commands", self.max_commands, HARD_MAX_WRITE_COMMANDS),
            (
                "max_payload_bytes_per_command",
                self.max_payload_bytes_per_command,
                HARD_MAX_WRITE_PAYLOAD_BYTES_PER_COMMAND,
            ),
            (
                "max_payload_bytes",
                self.max_payload_bytes,
                HARD_MAX_WRITE_PAYLOAD_BYTES,
            ),
            (
                "max_intent_bytes",
                self.max_intent_bytes,
                HARD_MAX_WRITE_INTENT_BYTES,
            ),
        ];
        for (name, value, hard_max) in checks {
            if value == 0 || value > hard_max {
                return Err(StorageError::Validation(format!(
                    "{name} must be between 1 and {hard_max}"
                ))
                .into());
            }
        }
        if self.max_payload_bytes_per_command > self.max_payload_bytes {
            return Err(StorageError::Validation(
                "per-command payload limit cannot exceed total payload limit".to_string(),
            )
            .into());
        }
        Ok(())
    }

    fn public(self) -> MdbxWriteOperationLimits {
        MdbxWriteOperationLimits {
            max_commands: self.max_commands as u64,
            max_payload_bytes_per_command: self.max_payload_bytes_per_command as u64,
            max_payload_bytes: self.max_payload_bytes as u64,
            max_intent_bytes: self.max_intent_bytes as u64,
        }
    }
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

#[derive(Debug, Clone, uniffi::Record)]
pub struct MdbxCommitHistoryItemV2 {
    pub item: MdbxCommitHistoryItem,
    pub branch_id: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MdbxCommitHistoryPageV2 {
    pub items: Vec<MdbxCommitHistoryItemV2>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MdbxBranchInfo {
    pub branch_id: String,
    pub branch_name: String,
    pub head_commit_id: String,
    pub created_at: String,
    pub updated_at: String,
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
    Attachment,
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
            MdbxTigaScopeType::Attachment => Ok(TigaScope::Attachment {
                attachment_id: required_scope_id(self.scope_id, "attachment")?,
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
    RotateKeyEpoch,
    DeleteAuditRecords,
    ManageDeletedObjectRetention,
    PurgeDeletedObject,
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
            MdbxTigaOperation::RotateKeyEpoch => Self::RotateKeyEpoch,
            MdbxTigaOperation::DeleteAuditRecords => Self::DeleteAuditRecords,
            MdbxTigaOperation::ManageDeletedObjectRetention => Self::ManageDeletedObjectRetention,
            MdbxTigaOperation::PurgeDeletedObject => Self::PurgeDeletedObject,
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
            TigaOperation::RotateKeyEpoch => Self::RotateKeyEpoch,
            TigaOperation::DeleteAuditRecords => Self::DeleteAuditRecords,
            TigaOperation::ManageDeletedObjectRetention => Self::ManageDeletedObjectRetention,
            TigaOperation::PurgeDeletedObject => Self::PurgeDeletedObject,
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
pub struct MdbxKeyEpochRotationResult {
    pub previous_epoch_id: String,
    pub active_epoch_id: String,
    pub commit_id: String,
    pub rotated_at: String,
}

impl From<KeyEpochRotationResult> for MdbxKeyEpochRotationResult {
    fn from(value: KeyEpochRotationResult) -> Self {
        Self {
            previous_epoch_id: value.previous_epoch_id,
            active_epoch_id: value.active_epoch_id,
            commit_id: value.commit_id,
            rotated_at: value.rotated_at,
        }
    }
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

/// MDBX2 audit projection. The original record and list method remain stable
/// for existing generated clients; this version adds commit correlation and
/// the exact policy evidence used for authorization.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxSecurityAuditEventV2 {
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
    pub operation_id: Option<String>,
    pub commit_id: Option<String>,
    pub policy_version: Option<u32>,
    pub policy_fingerprint: Option<Vec<u8>>,
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

impl From<SecurityAuditEvent> for MdbxSecurityAuditEventV2 {
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
            operation_id: value.operation_id,
            commit_id: value.commit_id,
            policy_version: value.policy_version,
            policy_fingerprint: value.policy_fingerprint,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxSyncBranchHead {
    pub branch_id: Option<String>,
    pub branch_name: String,
    pub head_commit_id: String,
}

impl From<BranchHead> for MdbxSyncBranchHead {
    fn from(value: BranchHead) -> Self {
        Self {
            branch_id: value.branch_id,
            branch_name: value.branch_name,
            head_commit_id: value.head_commit_id,
        }
    }
}

impl From<MdbxSyncBranchHead> for BranchHead {
    fn from(value: MdbxSyncBranchHead) -> Self {
        Self {
            branch_id: value.branch_id,
            branch_name: value.branch_name,
            head_commit_id: value.head_commit_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxSyncHello {
    pub device_id: String,
    pub protocol_version: u32,
    pub heads: Vec<MdbxSyncBranchHead>,
    pub known_commit_ids: Vec<String>,
    pub capabilities: Vec<String>,
}

impl From<HelloRequest> for MdbxSyncHello {
    fn from(value: HelloRequest) -> Self {
        Self {
            device_id: value.device_id,
            protocol_version: value.protocol_version,
            heads: value.heads.into_iter().map(Into::into).collect(),
            known_commit_ids: value.known_commit_ids,
            capabilities: value.capabilities,
        }
    }
}

impl From<HelloResponse> for MdbxSyncHello {
    fn from(value: HelloResponse) -> Self {
        Self {
            device_id: value.device_id,
            protocol_version: value.protocol_version,
            heads: value.heads.into_iter().map(Into::into).collect(),
            known_commit_ids: value.known_commit_ids,
            capabilities: value.capabilities,
        }
    }
}

impl MdbxSyncHello {
    fn into_request(self) -> HelloRequest {
        HelloRequest {
            device_id: self.device_id,
            protocol_version: self.protocol_version,
            heads: self.heads.into_iter().map(Into::into).collect(),
            known_commit_ids: self.known_commit_ids,
            capabilities: self.capabilities,
        }
    }

    fn into_response(self) -> HelloResponse {
        HelloResponse {
            device_id: self.device_id,
            protocol_version: self.protocol_version,
            heads: self.heads.into_iter().map(Into::into).collect(),
            known_commit_ids: self.known_commit_ids,
            capabilities: self.capabilities,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MdbxBlobManifestEntryState {
    Available,
    SourceMissing,
    SourceSizeInvalid,
}

impl From<BlobManifestEntryState> for MdbxBlobManifestEntryState {
    fn from(value: BlobManifestEntryState) -> Self {
        match value {
            BlobManifestEntryState::Available => Self::Available,
            BlobManifestEntryState::SourceMissing => Self::SourceMissing,
            BlobManifestEntryState::SourceSizeInvalid => Self::SourceSizeInvalid,
        }
    }
}

impl From<MdbxBlobManifestEntryState> for BlobManifestEntryState {
    fn from(value: MdbxBlobManifestEntryState) -> Self {
        match value {
            MdbxBlobManifestEntryState::Available => Self::Available,
            MdbxBlobManifestEntryState::SourceMissing => Self::SourceMissing,
            MdbxBlobManifestEntryState::SourceSizeInvalid => Self::SourceSizeInvalid,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxBlobManifestEntry {
    pub blob_id: String,
    pub total_size: Option<u64>,
    pub state: MdbxBlobManifestEntryState,
}

impl From<BlobManifestEntry> for MdbxBlobManifestEntry {
    fn from(value: BlobManifestEntry) -> Self {
        Self {
            blob_id: value.blob_id,
            total_size: value.total_size,
            state: value.state.into(),
        }
    }
}

impl From<MdbxBlobManifestEntry> for BlobManifestEntry {
    fn from(value: MdbxBlobManifestEntry) -> Self {
        Self {
            blob_id: value.blob_id,
            total_size: value.total_size,
            state: value.state.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxBlobManifestPageRequest {
    pub namespace_id: String,
    pub checkpoint: Option<String>,
    pub cursor: Option<String>,
    pub page_size: u32,
}

impl From<BlobManifestPageRequest> for MdbxBlobManifestPageRequest {
    fn from(value: BlobManifestPageRequest) -> Self {
        Self {
            namespace_id: value.namespace_id,
            checkpoint: value.checkpoint,
            cursor: value.cursor,
            page_size: u32::from(value.page_size),
        }
    }
}

impl MdbxBlobManifestPageRequest {
    fn into_core(self) -> Result<BlobManifestPageRequest, MdbxFfiError> {
        BlobManifestPageRequest::new(
            self.namespace_id,
            self.checkpoint,
            self.cursor,
            usize::try_from(self.page_size).map_err(|_| MdbxFfiError::SyncProtocol {
                message: "Blob manifest page size cannot be represented locally".to_string(),
            })?,
        )
        .map_err(Into::into)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxBlobManifestPageResponse {
    pub namespace_id: String,
    pub checkpoint: String,
    pub items: Vec<MdbxBlobManifestEntry>,
    pub next_cursor: Option<String>,
}

impl From<BlobManifestPageResponse> for MdbxBlobManifestPageResponse {
    fn from(value: BlobManifestPageResponse) -> Self {
        Self {
            namespace_id: value.namespace_id,
            checkpoint: value.checkpoint,
            items: value.items.into_iter().map(Into::into).collect(),
            next_cursor: value.next_cursor,
        }
    }
}

impl From<MdbxBlobManifestPageResponse> for BlobManifestPageResponse {
    fn from(value: MdbxBlobManifestPageResponse) -> Self {
        Self {
            namespace_id: value.namespace_id,
            checkpoint: value.checkpoint,
            items: value.items.into_iter().map(Into::into).collect(),
            next_cursor: value.next_cursor,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxBlobChunkRequest {
    pub namespace_id: String,
    pub blob_id: String,
    pub total_size: u64,
    pub offset: u64,
    pub max_bytes: u32,
}

impl From<BlobChunkRequest> for MdbxBlobChunkRequest {
    fn from(value: BlobChunkRequest) -> Self {
        Self {
            namespace_id: value.namespace_id,
            blob_id: value.blob_id,
            total_size: value.total_size,
            offset: value.offset,
            max_bytes: value.max_bytes,
        }
    }
}

impl MdbxBlobChunkRequest {
    fn into_core(self) -> Result<BlobChunkRequest, MdbxFfiError> {
        BlobChunkRequest::new(
            self.namespace_id,
            self.blob_id,
            self.total_size,
            self.offset,
            usize::try_from(self.max_bytes).map_err(|_| MdbxFfiError::SyncProtocol {
                message: "Blob chunk size cannot be represented locally".to_string(),
            })?,
        )
        .map_err(Into::into)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxBlobChunkResponse {
    pub namespace_id: String,
    pub blob_id: String,
    pub total_size: u64,
    pub offset: u64,
    pub ciphertext: Vec<u8>,
    pub is_last: bool,
}

impl From<BlobChunkResponse> for MdbxBlobChunkResponse {
    fn from(value: BlobChunkResponse) -> Self {
        Self {
            namespace_id: value.namespace_id,
            blob_id: value.blob_id,
            total_size: value.total_size,
            offset: value.offset,
            ciphertext: value.ciphertext,
            is_last: value.is_last,
        }
    }
}

impl From<MdbxBlobChunkResponse> for BlobChunkResponse {
    fn from(value: MdbxBlobChunkResponse) -> Self {
        Self {
            namespace_id: value.namespace_id,
            blob_id: value.blob_id,
            total_size: value.total_size,
            offset: value.offset,
            ciphertext: value.ciphertext,
            is_last: value.is_last,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxBlobSyncResume {
    pub namespace_id: String,
    pub manifest_checkpoint: Option<String>,
    pub manifest_cursor: Option<String>,
    pub current_blob_id: Option<String>,
    pub total_size: u64,
    pub next_durable_offset: u64,
    pub manifest_complete: bool,
}

impl From<BlobSyncResume> for MdbxBlobSyncResume {
    fn from(value: BlobSyncResume) -> Self {
        Self {
            namespace_id: value.namespace_id,
            manifest_checkpoint: value.manifest_checkpoint,
            manifest_cursor: value.manifest_cursor,
            current_blob_id: value.current_blob_id,
            total_size: value.total_size,
            next_durable_offset: value.next_durable_offset,
            manifest_complete: value.manifest_complete,
        }
    }
}

impl From<MdbxBlobSyncResume> for BlobSyncResume {
    fn from(value: MdbxBlobSyncResume) -> Self {
        Self {
            namespace_id: value.namespace_id,
            manifest_checkpoint: value.manifest_checkpoint,
            manifest_cursor: value.manifest_cursor,
            current_blob_id: value.current_blob_id,
            total_size: value.total_size,
            next_durable_offset: value.next_durable_offset,
            manifest_complete: value.manifest_complete,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MdbxBlobSyncPhase {
    Disabled,
    Idle,
    Manifest,
    AwaitingManifestAcknowledgement,
    Chunk,
    AwaitingChunkAcknowledgement,
    Complete,
}

impl From<BlobSyncPhase> for MdbxBlobSyncPhase {
    fn from(value: BlobSyncPhase) -> Self {
        match value {
            BlobSyncPhase::Disabled => Self::Disabled,
            BlobSyncPhase::Idle => Self::Idle,
            BlobSyncPhase::Manifest => Self::Manifest,
            BlobSyncPhase::AwaitingManifestAcknowledgement => Self::AwaitingManifestAcknowledgement,
            BlobSyncPhase::Chunk => Self::Chunk,
            BlobSyncPhase::AwaitingChunkAcknowledgement => Self::AwaitingChunkAcknowledgement,
            BlobSyncPhase::Complete => Self::Complete,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct MdbxSyncWireResume {
    pub session_id: String,
    pub next_outbound_sequence: u64,
    pub next_inbound_sequence: u64,
}

impl From<SyncWireResume> for MdbxSyncWireResume {
    fn from(value: SyncWireResume) -> Self {
        Self {
            session_id: value.session_id,
            next_outbound_sequence: value.next_outbound_sequence,
            next_inbound_sequence: value.next_inbound_sequence,
        }
    }
}

impl MdbxSyncWireResume {
    fn into_core(self) -> SyncWireResume {
        SyncWireResume {
            session_id: self.session_id,
            next_outbound_sequence: self.next_outbound_sequence,
            next_inbound_sequence: self.next_inbound_sequence,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxSyncWireHello {
    pub sequence: u64,
    pub in_reply_to: Option<u64>,
    pub hello: MdbxSyncHello,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxSyncWireManifestPageRequest {
    pub sequence: u64,
    pub in_reply_to: Option<u64>,
    pub request: MdbxBlobManifestPageRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxSyncWireManifestPageResponse {
    pub sequence: u64,
    pub in_reply_to: Option<u64>,
    pub response: MdbxBlobManifestPageResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxSyncWireChunkRequest {
    pub sequence: u64,
    pub in_reply_to: Option<u64>,
    pub request: MdbxBlobChunkRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxSyncWireChunkResponse {
    pub sequence: u64,
    pub in_reply_to: Option<u64>,
    pub response: MdbxBlobChunkResponse,
}

#[derive(uniffi::Object)]
pub struct MdbxSyncWireSession {
    wire: Mutex<SyncWireSession>,
    limits: SyncWireLimits,
}

#[uniffi::export]
impl MdbxSyncWireSession {
    pub fn resume(&self) -> Result<MdbxSyncWireResume, MdbxFfiError> {
        let wire = self.wire.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(wire.resume().clone().into())
    }

    pub fn restore_resume(&self, resume: MdbxSyncWireResume) -> Result<(), MdbxFfiError> {
        let mut wire = self.wire.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        *wire = SyncWireSession::restore(resume.into_core())?;
        Ok(())
    }

    pub fn pending_inbound_sequence(&self) -> Result<Option<u64>, MdbxFfiError> {
        let wire = self.wire.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(wire.pending_inbound_sequence())
    }

    pub fn acknowledge_inbound(&self, sequence: u64) -> Result<(), MdbxFfiError> {
        let mut wire = self.wire.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        wire.acknowledge_inbound(sequence)?;
        Ok(())
    }

    pub fn discard_inbound(&self, sequence: u64) -> Result<(), MdbxFfiError> {
        let mut wire = self.wire.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        wire.discard_inbound(sequence)?;
        Ok(())
    }

    pub fn encode_hello(
        &self,
        hello: MdbxSyncHello,
        in_reply_to: Option<u64>,
    ) -> Result<Vec<u8>, MdbxFfiError> {
        self.encode(SyncMessage::Hello(hello.into_request()), in_reply_to)
    }

    pub fn encode_hello_ack(
        &self,
        hello: MdbxSyncHello,
        in_reply_to: Option<u64>,
    ) -> Result<Vec<u8>, MdbxFfiError> {
        self.encode(SyncMessage::HelloAck(hello.into_response()), in_reply_to)
    }

    pub fn encode_blob_manifest_page_request(
        &self,
        request: MdbxBlobManifestPageRequest,
        in_reply_to: Option<u64>,
    ) -> Result<Vec<u8>, MdbxFfiError> {
        self.encode(
            SyncMessage::BlobManifestPageRequest(request.into_core()?),
            in_reply_to,
        )
    }

    pub fn encode_blob_manifest_page_response(
        &self,
        response: MdbxBlobManifestPageResponse,
        in_reply_to: Option<u64>,
    ) -> Result<Vec<u8>, MdbxFfiError> {
        self.encode(
            SyncMessage::BlobManifestPageResponse(response.into()),
            in_reply_to,
        )
    }

    pub fn encode_blob_chunk_request(
        &self,
        request: MdbxBlobChunkRequest,
        in_reply_to: Option<u64>,
    ) -> Result<Vec<u8>, MdbxFfiError> {
        self.encode(
            SyncMessage::BlobChunkRequest(request.into_core()?),
            in_reply_to,
        )
    }

    pub fn encode_blob_chunk_response(
        &self,
        response: MdbxBlobChunkResponse,
        in_reply_to: Option<u64>,
    ) -> Result<Vec<u8>, MdbxFfiError> {
        self.encode(SyncMessage::BlobChunkResponse(response.into()), in_reply_to)
    }

    pub fn accept_hello(&self, bytes: Vec<u8>) -> Result<MdbxSyncWireHello, MdbxFfiError> {
        let frame = self.accept(bytes)?;
        match frame.message {
            SyncMessage::Hello(hello) => Ok(MdbxSyncWireHello {
                sequence: frame.sequence,
                in_reply_to: frame.in_reply_to,
                hello: hello.into(),
            }),
            _ => self.reject_wrong_message(frame.sequence, "Hello"),
        }
    }

    pub fn accept_hello_ack(&self, bytes: Vec<u8>) -> Result<MdbxSyncWireHello, MdbxFfiError> {
        let frame = self.accept(bytes)?;
        match frame.message {
            SyncMessage::HelloAck(hello) => Ok(MdbxSyncWireHello {
                sequence: frame.sequence,
                in_reply_to: frame.in_reply_to,
                hello: hello.into(),
            }),
            _ => self.reject_wrong_message(frame.sequence, "HelloAck"),
        }
    }

    pub fn accept_blob_manifest_page_request(
        &self,
        bytes: Vec<u8>,
    ) -> Result<MdbxSyncWireManifestPageRequest, MdbxFfiError> {
        let frame = self.accept(bytes)?;
        match frame.message {
            SyncMessage::BlobManifestPageRequest(request) => Ok(MdbxSyncWireManifestPageRequest {
                sequence: frame.sequence,
                in_reply_to: frame.in_reply_to,
                request: request.into(),
            }),
            _ => self.reject_wrong_message(frame.sequence, "BlobManifestPageRequest"),
        }
    }

    pub fn accept_blob_manifest_page_response(
        &self,
        bytes: Vec<u8>,
    ) -> Result<MdbxSyncWireManifestPageResponse, MdbxFfiError> {
        let frame = self.accept(bytes)?;
        match frame.message {
            SyncMessage::BlobManifestPageResponse(response) => {
                Ok(MdbxSyncWireManifestPageResponse {
                    sequence: frame.sequence,
                    in_reply_to: frame.in_reply_to,
                    response: response.into(),
                })
            }
            _ => self.reject_wrong_message(frame.sequence, "BlobManifestPageResponse"),
        }
    }

    pub fn accept_blob_chunk_request(
        &self,
        bytes: Vec<u8>,
    ) -> Result<MdbxSyncWireChunkRequest, MdbxFfiError> {
        let frame = self.accept(bytes)?;
        match frame.message {
            SyncMessage::BlobChunkRequest(request) => Ok(MdbxSyncWireChunkRequest {
                sequence: frame.sequence,
                in_reply_to: frame.in_reply_to,
                request: request.into(),
            }),
            _ => self.reject_wrong_message(frame.sequence, "BlobChunkRequest"),
        }
    }

    pub fn accept_blob_chunk_response(
        &self,
        bytes: Vec<u8>,
    ) -> Result<MdbxSyncWireChunkResponse, MdbxFfiError> {
        let frame = self.accept(bytes)?;
        match frame.message {
            SyncMessage::BlobChunkResponse(response) => Ok(MdbxSyncWireChunkResponse {
                sequence: frame.sequence,
                in_reply_to: frame.in_reply_to,
                response: response.into(),
            }),
            _ => self.reject_wrong_message(frame.sequence, "BlobChunkResponse"),
        }
    }
}

impl MdbxSyncWireSession {
    fn encode(
        &self,
        message: SyncMessage,
        in_reply_to: Option<u64>,
    ) -> Result<Vec<u8>, MdbxFfiError> {
        let mut wire = self.wire.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(wire.encode_outbound(message, in_reply_to, self.limits)?)
    }

    fn accept(&self, bytes: Vec<u8>) -> Result<SyncWireFrame, MdbxFfiError> {
        let mut wire = self.wire.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(wire.accept_inbound_bytes(&bytes, self.limits)?)
    }

    fn reject_wrong_message<T>(&self, sequence: u64, expected: &str) -> Result<T, MdbxFfiError> {
        let mut wire = self.wire.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        wire.discard_inbound(sequence)?;
        Err(MdbxFfiError::SyncProtocol {
            message: format!("expected {expected} message in sync wire frame"),
        })
    }
}

/// Protocol-only Blob synchronization state for generated clients. The
/// application owns transport and Provider I/O, then calls acknowledgement
/// methods only after durable storage succeeds.
#[derive(uniffi::Object)]
pub struct MdbxBlobSyncSession {
    client: Mutex<SyncClient>,
}

#[uniffi::export]
impl MdbxBlobSyncSession {
    pub fn hello(&self) -> Result<MdbxSyncHello, MdbxFfiError> {
        let mut client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(client.hello()?.into())
    }

    pub fn accept_hello(&self, hello: MdbxSyncHello) -> Result<MdbxSyncHello, MdbxFfiError> {
        let mut client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(client.on_hello(&hello.into_request())?.into())
    }

    pub fn accept_hello_ack(&self, hello: MdbxSyncHello) -> Result<(), MdbxFfiError> {
        let mut client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        client.on_hello_ack(&hello.into_response())?;
        Ok(())
    }

    pub fn blob_replication_is_negotiated(&self) -> Result<bool, MdbxFfiError> {
        let client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(client.blob_replication_is_negotiated())
    }

    pub fn begin_blob_sync(&self, namespace_id: String) -> Result<(), MdbxFfiError> {
        let mut client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        client.begin_blob_sync(namespace_id)?;
        Ok(())
    }

    pub fn restore_blob_sync(&self, resume: MdbxBlobSyncResume) -> Result<(), MdbxFfiError> {
        let mut client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        client.restore_blob_sync(resume.into())?;
        Ok(())
    }

    pub fn blob_resume(&self) -> Result<Option<MdbxBlobSyncResume>, MdbxFfiError> {
        let client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(client.blob_resume().cloned().map(Into::into))
    }

    pub fn blob_sync_phase(&self) -> Result<MdbxBlobSyncPhase, MdbxFfiError> {
        let client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(client.blob_sync_phase().into())
    }

    pub fn blob_manifest_request(
        &self,
        page_size: u32,
    ) -> Result<MdbxBlobManifestPageRequest, MdbxFfiError> {
        let page_size = usize::try_from(page_size).map_err(|_| MdbxFfiError::SyncProtocol {
            message: "Blob manifest page size cannot be represented locally".to_string(),
        })?;
        let mut client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(client.blob_manifest_request(page_size)?.into())
    }

    pub fn validate_blob_manifest_response(
        &self,
        response: MdbxBlobManifestPageResponse,
    ) -> Result<(), MdbxFfiError> {
        let response: BlobManifestPageResponse = response.into();
        let mut client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        client.validate_blob_manifest_response(&response)?;
        Ok(())
    }

    pub fn acknowledge_blob_manifest_page(
        &self,
        response: MdbxBlobManifestPageResponse,
    ) -> Result<(), MdbxFfiError> {
        let response: BlobManifestPageResponse = response.into();
        let mut client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        client.acknowledge_blob_manifest_page(&response)?;
        Ok(())
    }

    pub fn blob_chunk_request(
        &self,
        blob_id: String,
        total_size: u64,
        max_bytes: u32,
    ) -> Result<MdbxBlobChunkRequest, MdbxFfiError> {
        let max_bytes = usize::try_from(max_bytes).map_err(|_| MdbxFfiError::SyncProtocol {
            message: "Blob chunk size cannot be represented locally".to_string(),
        })?;
        let mut client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(client
            .blob_chunk_request(blob_id, total_size, max_bytes)?
            .into())
    }

    pub fn validate_blob_chunk_response(
        &self,
        response: MdbxBlobChunkResponse,
    ) -> Result<(), MdbxFfiError> {
        let response: BlobChunkResponse = response.into();
        let mut client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        client.validate_blob_chunk_response(&response)?;
        Ok(())
    }

    pub fn acknowledge_blob_chunk(
        &self,
        response: MdbxBlobChunkResponse,
    ) -> Result<(), MdbxFfiError> {
        let response: BlobChunkResponse = response.into();
        let mut client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        client.acknowledge_blob_chunk(&response)?;
        Ok(())
    }

    pub fn restart_blob_transfer_after_abort(
        &self,
        blob_id: String,
        total_size: u64,
    ) -> Result<(), MdbxFfiError> {
        let mut client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        client.restart_blob_transfer_after_abort(&blob_id, total_size)?;
        Ok(())
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

    pub fn create_backup(&self, destination: String) -> Result<MdbxBackupInfo, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(BackupService::create_portable_copy(&conn, Path::new(&destination))?.into())
    }

    pub fn health_check(&self) -> Result<MdbxHealthCheckResult, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(RecoveryVerifier::full_health_check(&conn)?.into())
    }

    pub fn evaluate_tombstone_purge_eligibility(
        &self,
        tombstone_id: String,
        now: String,
    ) -> Result<MdbxTombstonePurgeEligibility, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(TombstoneRepo::evaluate_purge_eligibility(&conn, &tombstone_id, &now)?.into())
    }

    pub fn find_tombstone_by_target(
        &self,
        target_object_id: String,
    ) -> Result<Option<MdbxTombstoneRecord>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(TombstoneRepo::find_by_target(&conn, &target_object_id)?.map(Into::into))
    }

    pub fn find_permanent_purge_receipt_by_tombstone(
        &self,
        tombstone_id: String,
    ) -> Result<Option<MdbxPermanentPurgeReceipt>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(TombstoneRepo::find_purge_receipt_by_tombstone(&conn, &tombstone_id)?.map(Into::into))
    }

    pub fn find_permanent_purge_receipt_by_target(
        &self,
        target_object_type: String,
        target_object_id: String,
    ) -> Result<Option<MdbxPermanentPurgeReceipt>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(TombstoneRepo::find_purge_receipt_by_target(
            &conn,
            &target_object_type,
            &target_object_id,
        )?
        .map(Into::into))
    }

    pub fn schedule_tombstone_purge(
        &self,
        tombstone_id: String,
        purge_eligible_at: String,
        device: MdbxDeviceContext,
    ) -> Result<MdbxTombstonePurgeScheduleResult, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let session = conn.active_session().cloned();
        let device = device.into_core(&self.device_id);
        let ctx = CommitContext::new(self.device_id.clone());
        let (result, _) = TombstoneRepo::schedule_purge_authorized(
            &conn,
            &ctx,
            &tombstone_id,
            &purge_eligible_at,
            TigaAuthorizationContext {
                session: session.as_ref(),
                device: &device,
                now_unix_secs: unix_now(),
            },
        )?;
        Ok(result.into())
    }

    pub fn purge_tombstone(
        &self,
        tombstone_id: String,
        device: MdbxDeviceContext,
    ) -> Result<MdbxPermanentPurgeReceipt, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let session = conn.active_session().cloned();
        let device = device.into_core(&self.device_id);
        let ctx = CommitContext::new(self.device_id.clone());
        let (receipt, _) = TombstoneRepo::purge_authorized(
            &conn,
            &ctx,
            &tombstone_id,
            TigaAuthorizationContext {
                session: session.as_ref(),
                device: &device,
                now_unix_secs: unix_now(),
            },
        )?;
        Ok(receipt.into())
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
            TigaScope::Attachment { attachment_id } => {
                TigaService::resolve_policy_for_attachment(&conn, &attachment_id)?
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

    pub fn rotate_key_epoch(
        &self,
        device: MdbxDeviceContext,
    ) -> Result<MdbxKeyEpochRotationResult, MdbxFfiError> {
        let mut conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let session = conn.active_session().cloned();
        let device = device.into_core(&self.device_id);
        let ctx = CommitContext::new(self.device_id.clone());
        Ok(KeyEpochService::rotate_authorized(
            &mut conn,
            &ctx,
            TigaAuthorizationContext {
                session: session.as_ref(),
                device: &device,
                now_unix_secs: unix_now(),
            },
        )?
        .into())
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

    pub fn list_security_audit_events_v2(
        &self,
        limit: u32,
    ) -> Result<Vec<MdbxSecurityAuditEventV2>, MdbxFfiError> {
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

    pub fn get_attachment(
        &self,
        attachment_id: String,
    ) -> Result<Option<MdbxAttachmentRecord>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        AttachmentRepo::get_by_id(&conn, &attachment_id)?
            .as_ref()
            .map(attachment_record_from_core)
            .transpose()
    }

    pub fn list_attachments(
        &self,
        project_id: String,
        entry_id: Option<String>,
    ) -> Result<Vec<MdbxAttachmentRecord>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let attachments = match entry_id.as_deref() {
            Some(entry_id) => AttachmentRepo::list_by_entry(&conn, entry_id)?
                .into_iter()
                .filter(|attachment| attachment.project_id == project_id)
                .collect(),
            None => AttachmentRepo::list_by_project(&conn, &project_id)?,
        };
        attachments
            .iter()
            .map(attachment_record_from_core)
            .collect()
    }

    pub fn list_deleted_attachments(&self) -> Result<Vec<MdbxAttachmentRecord>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        AttachmentRepo::list_deleted(&conn)?
            .iter()
            .map(attachment_record_from_core)
            .collect()
    }

    pub fn rename_attachment(
        &self,
        attachment_id: String,
        file_name: String,
        media_type: Option<String>,
    ) -> Result<MdbxAttachmentRecord, MdbxFfiError> {
        if file_name.trim().is_empty() {
            return Err(StorageError::Validation(
                "attachment file_name must not be empty".to_string(),
            )
            .into());
        }
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let updated = AttachmentRepo::rename(
            &conn,
            &CommitContext::new(self.device_id.clone()),
            &attachment_id,
            &file_name,
            media_type.as_deref(),
        )?;
        attachment_record_from_core(&updated)
    }

    pub fn delete_attachment(&self, attachment_id: String) -> Result<(), MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        AttachmentRepo::soft_delete(
            &conn,
            &CommitContext::new(self.device_id.clone()),
            &attachment_id,
        )?;
        Ok(())
    }

    pub fn create_attachment_with_content(
        &self,
        operation_id: String,
        request: MdbxAttachmentCreateRequest,
        content: Vec<u8>,
        limits: MdbxAttachmentContentLimits,
    ) -> Result<MdbxAttachmentWriteResult, MdbxFfiError> {
        let MdbxAttachmentCreateRequest {
            attachment_id,
            project_id,
            entry_id,
            file_name,
            media_type,
        } = request;
        validate_attachment_operation_inputs(
            &operation_id,
            &attachment_id,
            &project_id,
            entry_id.as_deref(),
            &file_name,
            content.len(),
            limits,
        )?;
        let chunk_size = attachment_chunk_size(limits)?;
        let intent_hash = hash_attachment_intent(
            "create",
            &operation_id,
            &attachment_id,
            &project_id,
            entry_id.as_deref(),
            &file_name,
            media_type.as_deref(),
            chunk_size,
            &content,
        );
        let operation_id_for_closure = operation_id.clone();
        let attachment_id_for_closure = attachment_id.clone();
        let project_id_for_closure = project_id.clone();
        let file_name_for_closure = file_name.clone();
        let media_type_for_closure = media_type.clone();
        let content_for_closure = content;
        execute_attachment_content_operation(
            &self.conn,
            &self.device_id,
            AttachmentContentOperation {
                operation_id: operation_id_for_closure,
                operation_kind: "attachment-create".to_string(),
                attachment_id: attachment_id.clone(),
                fields: vec![
                    "project_id",
                    "entry_id",
                    "file_name",
                    "media_type",
                    "content",
                ],
                intent_hash,
            },
            move |conn, ctx| {
                let original_size = content_for_closure.len() as u64;
                AttachmentRepo::add_with_id(
                    conn,
                    ctx,
                    &attachment_id_for_closure,
                    mdbx_storage::repo::AttachmentCreateRequest {
                        project_id: &project_id_for_closure,
                        entry_id: entry_id.as_deref(),
                        file_name: &file_name_for_closure,
                        media_type: media_type_for_closure.as_deref(),
                        content_hash: "",
                        original_size,
                    },
                )?;
                let mut reader = Cursor::new(content_for_closure);
                AttachmentRepo::write_content_from_reader_with_options(
                    conn,
                    ctx,
                    &attachment_id_for_closure,
                    &mut reader,
                    AttachmentWriteOptions::exact(chunk_size, original_size),
                )?;
                AttachmentRepo::get_by_id(conn, &attachment_id_for_closure)?
                    .ok_or_else(|| StorageError::NotFound(attachment_id_for_closure.clone()))
            },
        )
    }

    pub fn replace_attachment_content(
        &self,
        operation_id: String,
        attachment_id: String,
        content: Vec<u8>,
        limits: MdbxAttachmentContentLimits,
    ) -> Result<MdbxAttachmentWriteResult, MdbxFfiError> {
        if operation_id.trim().is_empty() {
            return Err(
                StorageError::Validation("operation_id must not be empty".to_string()).into(),
            );
        }
        validate_uuid(&attachment_id, "attachment_id")?;
        let chunk_size = attachment_chunk_size(limits)?;
        if content.len() > attachment_max_plaintext_bytes(limits)? {
            return Err(StorageError::ResourceLimit {
                resource: "attachment plaintext bytes".to_string(),
                actual: content.len() as u64,
                limit: limits.max_plaintext_bytes,
            }
            .into());
        }
        let intent_hash = hash_attachment_intent(
            "replace",
            &operation_id,
            &attachment_id,
            "",
            None,
            "",
            None,
            chunk_size,
            &content,
        );
        let attachment_id_for_closure = attachment_id.clone();
        let content_for_closure = content;
        execute_attachment_content_operation(
            &self.conn,
            &self.device_id,
            AttachmentContentOperation {
                operation_id,
                operation_kind: "attachment-replace".to_string(),
                attachment_id: attachment_id.clone(),
                fields: vec!["content"],
                intent_hash,
            },
            move |conn, ctx| {
                let original_size = content_for_closure.len() as u64;
                let mut reader = Cursor::new(content_for_closure);
                AttachmentRepo::write_content_from_reader_with_options(
                    conn,
                    ctx,
                    &attachment_id_for_closure,
                    &mut reader,
                    AttachmentWriteOptions::exact(chunk_size, original_size),
                )?;
                AttachmentRepo::get_by_id(conn, &attachment_id_for_closure)?
                    .ok_or_else(|| StorageError::NotFound(attachment_id_for_closure.clone()))
            },
        )
    }

    pub fn execute_attachment_batch(
        &self,
        operation_id: String,
        commands: Vec<MdbxAttachmentBatchCommand>,
    ) -> Result<MdbxAttachmentBatchResult, MdbxFfiError> {
        self.execute_attachment_batch_with_limits(
            operation_id,
            commands,
            default_attachment_batch_limits(),
        )
    }

    pub fn execute_attachment_batch_with_limits(
        &self,
        operation_id: String,
        commands: Vec<MdbxAttachmentBatchCommand>,
        limits: MdbxAttachmentBatchLimits,
    ) -> Result<MdbxAttachmentBatchResult, MdbxFfiError> {
        let chunk_size =
            validate_attachment_batch_operation_inputs(&operation_id, &commands, limits)?;
        let intent_hash = hash_attachment_batch_intent(&operation_id, &commands, limits);
        let attachment_ids = attachment_batch_ids(&commands);
        execute_attachment_batch_operation(
            &self.conn,
            &self.device_id,
            operation_id,
            commands,
            chunk_size,
            intent_hash,
            attachment_ids,
        )
    }

    pub fn read_attachment_content(
        &self,
        attachment_id: String,
        max_plaintext_bytes: u64,
    ) -> Result<Vec<u8>, MdbxFfiError> {
        let max_plaintext_bytes = validate_attachment_read_limit(max_plaintext_bytes)?;
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let attachment = AttachmentRepo::get_by_id(&conn, &attachment_id)?
            .ok_or_else(|| StorageError::NotFound(attachment_id.clone()))?;
        if attachment.stored_size > max_plaintext_bytes as u64 {
            return Err(StorageError::ResourceLimit {
                resource: "attachment plaintext bytes".to_string(),
                actual: attachment.stored_size,
                limit: max_plaintext_bytes as u64,
            }
            .into());
        }
        let session = conn.active_session().cloned();
        let device = conservative_ffi_device_context().into_core(&self.device_id);
        AttachmentRepo::authorize_plaintext_access(
            &conn,
            &attachment_id,
            AttachmentPlaintextPurpose::InMemory,
            TigaAuthorizationContext {
                session: session.as_ref(),
                device: &device,
                now_unix_secs: unix_now(),
            },
        )?;
        let mut content = LimitedAttachmentContentWriter::new(max_plaintext_bytes);
        content
            .bytes
            .try_reserve_exact(attachment.stored_size as usize)
            .map_err(|error| {
                StorageError::Validation(format!("cannot allocate attachment content: {error}"))
            })?;
        let read_result =
            AttachmentRepo::read_content_to_writer(&conn, &attachment_id, &mut content);
        if let Some(actual) = content.exceeded_at {
            return Err(StorageError::ResourceLimit {
                resource: "attachment plaintext bytes".to_string(),
                actual: actual as u64,
                limit: max_plaintext_bytes as u64,
            }
            .into());
        }
        read_result?;
        Ok(content.bytes)
    }

    pub fn verify_attachment_integrity(&self, attachment_id: String) -> Result<bool, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(AttachmentRepo::verify_integrity(&conn, &attachment_id)?)
    }

    pub fn set_extension_capabilities(
        &self,
        capability_ids: Vec<String>,
    ) -> Result<(), MdbxFfiError> {
        let capabilities = capability_ids
            .iter()
            .map(|capability_id| parse_extension_capability_id(capability_id))
            .collect::<Result<Vec<_>, _>>()?;
        let mut conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        conn.set_extension_capabilities(capabilities);
        Ok(())
    }

    pub fn get_collection_profile(
        &self,
        collection_id: String,
    ) -> Result<Option<MdbxCollectionProfile>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(
            CollectionProfileRepo::get_by_collection_id(&conn, &collection_id)?
                .map(collection_profile_from_core),
        )
    }

    pub fn set_collection_profile(
        &self,
        collection_id: String,
        collection_type_id: String,
        payload: Vec<u8>,
        payload_schema_version: u32,
        allowed_object_type_ids: Vec<String>,
        required_capability_ids: Vec<String>,
    ) -> Result<MdbxCollectionProfile, MdbxFfiError> {
        let allowed_object_type_ids = allowed_object_type_ids
            .iter()
            .map(|object_type_id| parse_object_type_id(object_type_id))
            .collect::<Result<Vec<_>, _>>()?;
        let required_capability_ids = required_capability_ids
            .iter()
            .map(|capability_id| parse_extension_capability_id(capability_id))
            .collect::<Result<Vec<_>, _>>()?;
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let ctx = CommitContext::new(self.device_id.clone());
        let profile = CollectionProfileRepo::set(
            &conn,
            &ctx,
            CollectionProfileSpec {
                collection_id,
                collection_type_id: parse_collection_type_id(&collection_type_id)?,
                payload,
                payload_schema_version,
                allowed_object_type_ids,
                required_capability_ids,
            },
        )?;
        Ok(collection_profile_from_core(profile))
    }

    /// Build a bounded Adapter payload migration plan. The returned payloads
    /// are decrypted bytes; the Adapter owns their interpretation and
    /// conversion, while storage rechecks every binding during execution.
    pub fn create_payload_migration_plan(
        &self,
        collection_id: String,
        object_type_id: String,
        source_schema_version: u32,
        target_schema_version: u32,
        max_items: u32,
        branch_id: Option<String>,
    ) -> Result<MdbxPayloadMigrationPlan, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(PayloadMigrationRepo::create_plan(
            &conn,
            PayloadMigrationPlanRequest {
                collection_id,
                object_type_id: parse_object_type_id(&object_type_id)?,
                source_schema_version,
                target_schema_version,
                max_items: max_items as usize,
                branch_id,
            },
        )?
        .into())
    }

    /// Apply Adapter-produced payloads as one idempotent user operation.
    pub fn execute_payload_migration(
        &self,
        plan: MdbxPayloadMigrationPlan,
        outputs: Vec<MdbxPayloadMigrationOutput>,
    ) -> Result<MdbxPayloadMigrationExecution, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let plan = plan.into_core()?;
        let outputs = outputs
            .into_iter()
            .map(|output| PayloadMigrationOutput {
                object_id: output.object_id,
                target_payload: output.target_payload,
            })
            .collect::<Vec<_>>();
        let ctx = CommitContext::new(self.device_id.clone());
        Ok(PayloadMigrationRepo::execute(&conn, &ctx, &plan, &outputs)?.into())
    }

    pub fn execute_write_operation(
        &self,
        operation_id: String,
        operation_kind: String,
        commands: Vec<MdbxWriteCommand>,
    ) -> Result<MdbxWriteOperationResult, MdbxFfiError> {
        execute_write_operation_for_branch(
            self,
            None,
            operation_id,
            operation_kind,
            commands,
            InternalWriteOperationLimits::default(),
        )
    }

    pub fn execute_write_operation_with_limits(
        &self,
        operation_id: String,
        operation_kind: String,
        commands: Vec<MdbxWriteCommand>,
        limits: MdbxWriteOperationLimits,
    ) -> Result<MdbxWriteOperationResult, MdbxFfiError> {
        execute_write_operation_for_branch(
            self,
            None,
            operation_id,
            operation_kind,
            commands,
            limits.into_internal()?,
        )
    }

    pub fn execute_write_operation_on_branch(
        &self,
        branch_id: String,
        operation_id: String,
        operation_kind: String,
        commands: Vec<MdbxWriteCommand>,
    ) -> Result<MdbxWriteOperationResult, MdbxFfiError> {
        execute_write_operation_for_branch(
            self,
            Some(branch_id),
            operation_id,
            operation_kind,
            commands,
            InternalWriteOperationLimits::default(),
        )
    }

    pub fn execute_write_operation_on_branch_with_limits(
        &self,
        branch_id: String,
        operation_id: String,
        operation_kind: String,
        commands: Vec<MdbxWriteCommand>,
        limits: MdbxWriteOperationLimits,
    ) -> Result<MdbxWriteOperationResult, MdbxFfiError> {
        execute_write_operation_for_branch(
            self,
            Some(branch_id),
            operation_id,
            operation_kind,
            commands,
            limits.into_internal()?,
        )
    }

    pub fn execute_composite_write_operation(
        &self,
        operation_id: String,
        operation_kind: String,
        commands: Vec<MdbxWriteCommand>,
        attachment_commands: Vec<MdbxAttachmentBatchCommand>,
    ) -> Result<MdbxCompositeWriteOperationResult, MdbxFfiError> {
        execute_composite_write_operation(
            self,
            CompositeWriteOperation {
                branch_id: None,
                operation_id,
                operation_kind,
                commands,
                attachment_commands,
                write_limits: InternalWriteOperationLimits::default(),
                attachment_limits: default_attachment_batch_limits(),
            },
        )
    }

    pub fn execute_composite_write_operation_with_limits(
        &self,
        operation_id: String,
        operation_kind: String,
        commands: Vec<MdbxWriteCommand>,
        attachment_commands: Vec<MdbxAttachmentBatchCommand>,
        limits: MdbxCompositeWriteOperationLimits,
    ) -> Result<MdbxCompositeWriteOperationResult, MdbxFfiError> {
        execute_composite_write_operation(
            self,
            CompositeWriteOperation {
                branch_id: None,
                operation_id,
                operation_kind,
                commands,
                attachment_commands,
                write_limits: limits.write_limits.into_internal()?,
                attachment_limits: limits.attachment_limits,
            },
        )
    }

    pub fn execute_composite_write_operation_on_branch(
        &self,
        branch_id: String,
        operation_id: String,
        operation_kind: String,
        commands: Vec<MdbxWriteCommand>,
        attachment_commands: Vec<MdbxAttachmentBatchCommand>,
    ) -> Result<MdbxCompositeWriteOperationResult, MdbxFfiError> {
        execute_composite_write_operation(
            self,
            CompositeWriteOperation {
                branch_id: Some(branch_id),
                operation_id,
                operation_kind,
                commands,
                attachment_commands,
                write_limits: InternalWriteOperationLimits::default(),
                attachment_limits: default_attachment_batch_limits(),
            },
        )
    }

    pub fn execute_composite_write_operation_on_branch_with_limits(
        &self,
        branch_id: String,
        operation_id: String,
        operation_kind: String,
        commands: Vec<MdbxWriteCommand>,
        attachment_commands: Vec<MdbxAttachmentBatchCommand>,
        limits: MdbxCompositeWriteOperationLimits,
    ) -> Result<MdbxCompositeWriteOperationResult, MdbxFfiError> {
        execute_composite_write_operation(
            self,
            CompositeWriteOperation {
                branch_id: Some(branch_id),
                operation_id,
                operation_kind,
                commands,
                attachment_commands,
                write_limits: limits.write_limits.into_internal()?,
                attachment_limits: limits.attachment_limits,
            },
        )
    }

    pub fn list_branches(&self) -> Result<Vec<MdbxBranchInfo>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(BranchRepo::list(&conn)?
            .into_iter()
            .map(|branch| MdbxBranchInfo {
                branch_id: branch.branch_id,
                branch_name: branch.branch_name,
                head_commit_id: branch.head_commit_id,
                created_at: branch.created_at,
                updated_at: branch.updated_at,
            })
            .collect())
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

    pub fn list_commit_history_v2(
        &self,
        page_size: u32,
        cursor: Option<String>,
    ) -> Result<MdbxCommitHistoryPageV2, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let page = CommitHistoryRepo::list(&conn, page_size as usize, cursor.as_deref())?;
        Ok(commit_history_page_v2_from_storage(page))
    }

    pub fn get_commit_history_v2(
        &self,
        commit_id: String,
    ) -> Result<Option<MdbxCommitHistoryItemV2>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(CommitHistoryRepo::get(&conn, &commit_id)?.map(commit_history_item_v2_from_storage))
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

    pub fn create_object(
        &self,
        collection_id: String,
        object_type_id: String,
        title: String,
        payload_json: String,
        payload_schema_version: u32,
    ) -> Result<MdbxObjectRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let ctx = CommitContext::new(self.device_id.clone());
        let payload = parse_payload_json(&payload_json)?;
        let object = EntryRepo::create_with_payload_schema_version(
            &conn,
            &ctx,
            &collection_id,
            parse_object_type_id(&object_type_id)?,
            Some(&title),
            &payload,
            payload_schema_version,
        )?;
        object_record_from_entry(&object)
    }

    pub fn get_object(
        &self,
        collection_id: String,
        object_id: String,
    ) -> Result<Option<MdbxObjectRecord>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let Some(object) = EntryRepo::get_by_id(&conn, &object_id)? else {
            return Ok(None);
        };
        if object.project_id != collection_id {
            return Ok(None);
        }
        Ok(Some(object_record_from_entry(&object)?))
    }

    pub fn list_objects(
        &self,
        collection_id: String,
        object_type_id: Option<String>,
    ) -> Result<Vec<MdbxObjectRecord>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let object_type_id = parse_optional_object_type_id(object_type_id)?;
        let objects = match object_type_id {
            Some(object_type_id) => {
                EntryRepo::list_by_project_and_type(&conn, &collection_id, object_type_id)?
            }
            None => EntryRepo::list_by_project(&conn, &collection_id)?,
        };
        objects.iter().map(object_record_from_entry).collect()
    }

    pub fn list_object_summaries(
        &self,
        collection_id: String,
        object_type_id: Option<String>,
        page_size: u32,
        cursor: Option<String>,
    ) -> Result<MdbxObjectSummaryPage, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let object_type_id = parse_optional_object_type_id(object_type_id)?;
        let page = ObjectSummaryRepo::list(
            &conn,
            &collection_id,
            object_type_id.as_ref(),
            page_size as usize,
            cursor.as_deref(),
        )?;
        Ok(MdbxObjectSummaryPage {
            items: page
                .items
                .into_iter()
                .map(object_summary_from_core)
                .collect(),
            next_cursor: page.next_cursor,
        })
    }

    pub fn update_object(
        &self,
        collection_id: String,
        object_id: String,
        object_type_id: String,
        title: String,
        payload_json: String,
        payload_schema_version: u32,
    ) -> Result<MdbxObjectRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let expected_type = parse_object_type_id(&object_type_id)?;
        let mut object = entry_for_project(&conn, &collection_id, &object_id)?;
        if object.deleted {
            return Err(StorageError::ConstraintViolation(format!(
                "object {} is deleted",
                object_id
            ))
            .into());
        }
        if object.entry_type != expected_type {
            return Err(StorageError::ConstraintViolation(format!(
                "object {} does not have type {}",
                object_id, object_type_id
            ))
            .into());
        }

        object.title_ct = Some(title.into_bytes());
        object.payload_ct = serde_json::to_vec(&parse_payload_json(&payload_json)?)?;
        object.payload_schema_version = payload_schema_version;

        let ctx = CommitContext::new(self.device_id.clone());
        let updated = EntryRepo::update(&conn, &ctx, &object)?;
        object_record_from_entry(&updated)
    }

    pub fn create_object_relation(
        &self,
        source_object_id: String,
        target_object_id: String,
        relation_kind: String,
        payload_json: String,
        payload_schema_version: u32,
    ) -> Result<MdbxObjectRelationRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let ctx = CommitContext::new(self.device_id.clone());
        let relation = ObjectRelationRepo::create(
            &conn,
            &ctx,
            ObjectRelationCreateRequest::new(
                source_object_id,
                target_object_id,
                parse_relation_kind(&relation_kind)?,
                parse_payload_json(&payload_json)?,
            )
            .with_payload_schema_version(payload_schema_version),
        )?;
        object_relation_record(&relation)
    }

    pub fn get_object_relation(
        &self,
        relation_id: String,
    ) -> Result<Option<MdbxObjectRelationRecord>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        ObjectRelationRepo::get_by_id(&conn, &relation_id)?
            .as_ref()
            .map(object_relation_record)
            .transpose()
    }

    pub fn list_object_relations_from(
        &self,
        source_object_id: String,
        relation_kind: Option<String>,
    ) -> Result<Vec<MdbxObjectRelationRecord>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let kind = relation_kind
            .as_deref()
            .map(parse_relation_kind)
            .transpose()?;
        ObjectRelationRepo::list_from_object(&conn, &source_object_id, kind.as_ref())?
            .iter()
            .map(object_relation_record)
            .collect()
    }

    pub fn list_object_relations_to(
        &self,
        target_object_id: String,
        relation_kind: Option<String>,
    ) -> Result<Vec<MdbxObjectRelationRecord>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let kind = relation_kind
            .as_deref()
            .map(parse_relation_kind)
            .transpose()?;
        ObjectRelationRepo::list_to_object(&conn, &target_object_id, kind.as_ref())?
            .iter()
            .map(object_relation_record)
            .collect()
    }

    pub fn update_object_relation(
        &self,
        relation_id: String,
        relation_kind: String,
        payload_json: String,
        payload_schema_version: u32,
    ) -> Result<MdbxObjectRelationRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let mut relation = ObjectRelationRepo::get_by_id(&conn, &relation_id)?
            .ok_or_else(|| StorageError::NotFound(relation_id.clone()))?;
        relation.relation_kind = parse_relation_kind(&relation_kind)?;
        relation.payload_ct = serde_json::to_vec(&parse_payload_json(&payload_json)?)?;
        relation.payload_schema_version = payload_schema_version;
        let ctx = CommitContext::new(self.device_id.clone());
        object_relation_record(&ObjectRelationRepo::update(&conn, &ctx, &relation)?)
    }

    pub fn delete_object_relation(&self, relation_id: String) -> Result<(), MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        ObjectRelationRepo::soft_delete(
            &conn,
            &CommitContext::new(self.device_id.clone()),
            &relation_id,
        )?;
        Ok(())
    }

    pub fn create_object_label(
        &self,
        collection_id: String,
        name: String,
        payload_json: String,
        payload_schema_version: u32,
    ) -> Result<MdbxObjectLabelRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let label = ObjectLabelRepo::create(
            &conn,
            &CommitContext::new(self.device_id.clone()),
            ObjectLabelCreateRequest::new(collection_id, name, parse_payload_json(&payload_json)?)
                .with_payload_schema_version(payload_schema_version),
        )?;
        object_label_record(&label)
    }

    pub fn list_object_labels(
        &self,
        collection_id: String,
    ) -> Result<Vec<MdbxObjectLabelRecord>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        ObjectLabelRepo::list_by_collection(&conn, &collection_id)?
            .iter()
            .map(object_label_record)
            .collect()
    }

    pub fn update_object_label(
        &self,
        label_id: String,
        name: String,
        payload_json: String,
        payload_schema_version: u32,
    ) -> Result<MdbxObjectLabelRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let mut label = ObjectLabelRepo::get_by_id(&conn, &label_id)?
            .ok_or_else(|| StorageError::NotFound(label_id.clone()))?;
        label.name_ct = name.into_bytes();
        label.payload_ct = serde_json::to_vec(&parse_payload_json(&payload_json)?)?;
        label.payload_schema_version = payload_schema_version;
        object_label_record(&ObjectLabelRepo::update(
            &conn,
            &CommitContext::new(self.device_id.clone()),
            &label,
        )?)
    }

    pub fn delete_object_label(&self, label_id: String) -> Result<(), MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        ObjectLabelRepo::soft_delete(
            &conn,
            &CommitContext::new(self.device_id.clone()),
            &label_id,
        )?;
        Ok(())
    }

    pub fn assign_object_label(
        &self,
        object_id: String,
        label_id: String,
    ) -> Result<MdbxObjectLabelAssignmentRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(object_label_assignment_record(
            &ObjectLabelAssignmentRepo::create(
                &conn,
                &CommitContext::new(self.device_id.clone()),
                ObjectLabelAssignmentCreateRequest::new(object_id, label_id),
            )?,
        ))
    }

    pub fn list_object_label_assignments(
        &self,
        object_id: String,
    ) -> Result<Vec<MdbxObjectLabelAssignmentRecord>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(
            ObjectLabelAssignmentRepo::list_by_object(&conn, &object_id)?
                .iter()
                .map(object_label_assignment_record)
                .collect(),
        )
    }

    pub fn remove_object_label_assignment(
        &self,
        assignment_id: String,
    ) -> Result<(), MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        ObjectLabelAssignmentRepo::soft_delete(
            &conn,
            &CommitContext::new(self.device_id.clone()),
            &assignment_id,
        )?;
        Ok(())
    }

    pub fn list_unresolved_conflicts(&self) -> Result<Vec<MdbxConflictRecord>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(ConflictRepo::list_unresolved(&conn)?
            .iter()
            .map(conflict_record)
            .collect())
    }

    pub fn resolve_conflict(
        &self,
        conflict_id: String,
        choice: MdbxConflictChoice,
    ) -> Result<MdbxConflictRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let conflict = ConflictRepo::get_by_id(&conn, &conflict_id)?
            .ok_or_else(|| StorageError::NotFound(conflict_id.clone()))?;
        let ctx = CommitContext::new(self.device_id.clone());
        let resolution = conflict_resolution(choice);
        let resolved = match conflict.object_type {
            ConflictObjectType::Project => {
                ConflictRepo::resolve_project(&conn, &ctx, &conflict_id, resolution)?
            }
            ConflictObjectType::Entry => {
                ConflictRepo::resolve_entry(&conn, &ctx, &conflict_id, resolution)?
            }
            ConflictObjectType::Attachment => {
                ConflictRepo::resolve_attachment(&conn, &ctx, &conflict_id, resolution)?
            }
            ConflictObjectType::ObjectRelation => {
                ConflictRepo::resolve_object_relation(&conn, &ctx, &conflict_id, resolution)?
            }
            ConflictObjectType::ObjectLabel => {
                ConflictRepo::resolve_object_label(&conn, &ctx, &conflict_id, resolution)?
            }
            ConflictObjectType::ObjectLabelAssignment => {
                ConflictRepo::resolve_object_label_assignment(
                    &conn,
                    &ctx,
                    &conflict_id,
                    resolution,
                )?
            }
        };
        Ok(conflict_record(&resolved))
    }

    pub fn resolve_entry_conflict_custom_payload(
        &self,
        conflict_id: String,
        payload_json: String,
    ) -> Result<MdbxConflictRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let resolved = ConflictRepo::resolve_entry_custom_payload(
            &conn,
            &CommitContext::new(self.device_id.clone()),
            &conflict_id,
            &parse_payload_json(&payload_json)?,
        )?;
        Ok(conflict_record(&resolved))
    }

    pub fn resolve_project_conflict_custom(
        &self,
        conflict_id: String,
        merged: MdbxProjectConflictMerge,
    ) -> Result<MdbxConflictRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let conflict = ConflictRepo::get_by_id(&conn, &conflict_id)?
            .ok_or_else(|| StorageError::NotFound(conflict_id.clone()))?;
        if conflict.object_type != ConflictObjectType::Project {
            return Err(StorageError::ConstraintViolation(
                "project custom resolution requires a project conflict".to_string(),
            )
            .into());
        }
        let mut project = ProjectRepo::get_by_id(&conn, &conflict.object_id)?
            .ok_or_else(|| StorageError::NotFound(conflict.object_id.clone()))?;
        project.title_ct = merged.title.into_bytes();
        project.summary_ct = merged.summary.map(String::into_bytes);
        project.group_id = merged.group_id;
        project.icon_ref = merged.icon_ref;
        project.favorite = merged.favorite;
        project.archived = merged.archived;
        project.deleted = merged.deleted;
        let resolved = ConflictRepo::resolve_project_custom(
            &conn,
            &CommitContext::new(self.device_id.clone()),
            &conflict_id,
            &project,
        )?;
        Ok(conflict_record(&resolved))
    }

    pub fn resolve_attachment_conflict_custom(
        &self,
        conflict_id: String,
        merged: MdbxAttachmentConflictMerge,
    ) -> Result<MdbxConflictRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let conflict = ConflictRepo::get_by_id(&conn, &conflict_id)?
            .ok_or_else(|| StorageError::NotFound(conflict_id.clone()))?;
        if conflict.object_type != ConflictObjectType::Attachment {
            return Err(StorageError::ConstraintViolation(
                "attachment custom resolution requires an attachment conflict".to_string(),
            )
            .into());
        }
        let mut attachment: Attachment = AttachmentRepo::get_by_id(&conn, &conflict.object_id)?
            .ok_or_else(|| StorageError::NotFound(conflict.object_id.clone()))?;
        attachment.project_id = merged.project_id;
        attachment.entry_id = merged.entry_id;
        attachment.file_name_ct = merged.file_name.into_bytes();
        attachment.media_type_ct = merged.media_type.map(String::into_bytes);
        attachment.deleted = merged.deleted;
        let resolved = ConflictRepo::resolve_attachment_custom(
            &conn,
            &CommitContext::new(self.device_id.clone()),
            &conflict_id,
            &attachment,
        )?;
        Ok(conflict_record(&resolved))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn resolve_object_relation_conflict_custom(
        &self,
        conflict_id: String,
        source_object_id: String,
        target_object_id: String,
        relation_kind: String,
        payload_json: String,
        payload_schema_version: u32,
        deleted: bool,
    ) -> Result<MdbxConflictRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let conflict = ConflictRepo::get_by_id(&conn, &conflict_id)?
            .ok_or_else(|| StorageError::NotFound(conflict_id.clone()))?;
        let mut merged = ObjectRelationRepo::get_by_id(&conn, &conflict.object_id)?
            .ok_or_else(|| StorageError::NotFound(conflict.object_id.clone()))?;
        merged.source_object_id = source_object_id;
        merged.target_object_id = target_object_id;
        merged.relation_kind = parse_relation_kind(&relation_kind)?;
        merged.payload_ct = serde_json::to_vec(&parse_payload_json(&payload_json)?)?;
        merged.payload_schema_version = payload_schema_version;
        merged.deleted = deleted;
        let resolved = ConflictRepo::resolve_object_relation_custom(
            &conn,
            &CommitContext::new(self.device_id.clone()),
            &conflict_id,
            &merged,
        )?;
        Ok(conflict_record(&resolved))
    }

    pub fn resolve_object_label_conflict_custom(
        &self,
        conflict_id: String,
        name: String,
        payload_json: String,
        payload_schema_version: u32,
        deleted: bool,
    ) -> Result<MdbxConflictRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let conflict = ConflictRepo::get_by_id(&conn, &conflict_id)?
            .ok_or_else(|| StorageError::NotFound(conflict_id.clone()))?;
        let mut merged = ObjectLabelRepo::get_by_id(&conn, &conflict.object_id)?
            .ok_or_else(|| StorageError::NotFound(conflict.object_id.clone()))?;
        merged.name_ct = name.into_bytes();
        merged.payload_ct = serde_json::to_vec(&parse_payload_json(&payload_json)?)?;
        merged.payload_schema_version = payload_schema_version;
        merged.deleted = deleted;
        let resolved = ConflictRepo::resolve_object_label_custom(
            &conn,
            &CommitContext::new(self.device_id.clone()),
            &conflict_id,
            &merged,
        )?;
        Ok(conflict_record(&resolved))
    }

    pub fn resolve_object_label_assignment_conflict_custom(
        &self,
        conflict_id: String,
        deleted: bool,
    ) -> Result<MdbxConflictRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let conflict = ConflictRepo::get_by_id(&conn, &conflict_id)?
            .ok_or_else(|| StorageError::NotFound(conflict_id.clone()))?;
        let mut merged = ObjectLabelAssignmentRepo::get_by_id(&conn, &conflict.object_id)?
            .ok_or_else(|| StorageError::NotFound(conflict.object_id.clone()))?;
        merged.deleted = deleted;
        let resolved = ConflictRepo::resolve_object_label_assignment_custom(
            &conn,
            &CommitContext::new(self.device_id.clone()),
            &conflict_id,
            &merged,
        )?;
        Ok(conflict_record(&resolved))
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
        TigaScope::Attachment { attachment_id } => MdbxTigaScope {
            scope_type: MdbxTigaScopeType::Attachment,
            scope_id: Some(attachment_id),
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
pub fn create_blob_sync_session(
    device_id: String,
) -> Result<Arc<MdbxBlobSyncSession>, MdbxFfiError> {
    let mut negotiator = SyncNegotiator::new(&device_id, Vec::new(), Vec::new());
    negotiator.enable_blob_replication_capabilities()?;
    Ok(Arc::new(MdbxBlobSyncSession {
        client: Mutex::new(SyncClient::new(negotiator, None, None)),
    }))
}

#[uniffi::export]
pub fn default_sync_wire_payload_bytes() -> u64 {
    mdbx_sync::MAX_SYNC_WIRE_PAYLOAD_BYTES
}

#[uniffi::export]
pub fn create_sync_wire_session(
    session_id: String,
    max_payload_bytes: u64,
) -> Result<Arc<MdbxSyncWireSession>, MdbxFfiError> {
    let limits = SyncWireLimits::new(max_payload_bytes)?;
    Ok(Arc::new(MdbxSyncWireSession {
        wire: Mutex::new(SyncWireSession::new(session_id)?),
        limits,
    }))
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

/// Create a verified portable backup without writable open, unlock, or
/// automatic migration of the source vault.
#[uniffi::export]
pub fn create_portable_backup(
    source_path: String,
    destination: String,
) -> Result<MdbxBackupInfo, MdbxFfiError> {
    Ok(
        BackupService::create_portable_copy_path(Path::new(&source_path), Path::new(&destination))?
            .into(),
    )
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
    let mut creation = PendingVaultCreation::begin(Path::new(&path))?;
    let mode: TigaMode = mode.into();
    let init = initialize_vault(
        creation.connection(),
        &VaultInitParams {
            default_tiga_mode: mode.to_string(),
            device_id: device_id.clone(),
            ..Default::default()
        },
    )?;
    let password = Zeroizing::new(password);
    UnlockService::setup_password_with_mode(creation.connection_mut(), password.as_str(), mode)?;
    let conn = creation.commit();
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

fn validate_uuid(value: &str, field: &str) -> Result<(), MdbxFfiError> {
    Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| StorageError::Validation(format!("{field} {value} must be a UUID")).into())
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

fn commit_history_page_v2_from_storage(page: CommitHistoryPage) -> MdbxCommitHistoryPageV2 {
    MdbxCommitHistoryPageV2 {
        items: page
            .items
            .into_iter()
            .map(commit_history_item_v2_from_storage)
            .collect(),
        next_cursor: page.next_cursor,
    }
}

fn commit_history_item_v2_from_storage(item: CommitHistoryItem) -> MdbxCommitHistoryItemV2 {
    MdbxCommitHistoryItemV2 {
        branch_id: item.branch_id.clone(),
        item: commit_history_item_from_storage(item),
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
    let parsed: EntryType = entry_type
        .parse()
        .map_err(|_| MdbxFfiError::InvalidEntryType {
            entry_type: entry_type.to_string(),
        })?;
    if parsed.is_legacy() {
        Ok(parsed)
    } else {
        Err(MdbxFfiError::InvalidEntryType {
            entry_type: entry_type.to_string(),
        })
    }
}

fn parse_write_object_type(entry_type: &str) -> Result<EntryType, MdbxFfiError> {
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

fn parse_object_type_id(object_type_id: &str) -> Result<ObjectTypeId, MdbxFfiError> {
    object_type_id
        .parse()
        .map_err(|_| MdbxFfiError::InvalidObjectTypeId {
            object_type_id: object_type_id.to_string(),
        })
}

fn parse_optional_object_type_id(
    object_type_id: Option<String>,
) -> Result<Option<ObjectTypeId>, MdbxFfiError> {
    object_type_id
        .as_deref()
        .map(parse_object_type_id)
        .transpose()
}

fn parse_relation_kind(relation_kind: &str) -> Result<RelationKindId, MdbxFfiError> {
    relation_kind
        .parse()
        .map_err(|_| MdbxFfiError::InvalidRelationKind {
            relation_kind: relation_kind.to_string(),
        })
}

fn parse_collection_type_id(collection_type_id: &str) -> Result<CollectionTypeId, MdbxFfiError> {
    collection_type_id
        .parse()
        .map_err(|_| MdbxFfiError::InvalidCollectionTypeId {
            collection_type_id: collection_type_id.to_string(),
        })
}

fn parse_extension_capability_id(
    capability_id: &str,
) -> Result<ExtensionCapabilityId, MdbxFfiError> {
    capability_id
        .parse()
        .map_err(|_| MdbxFfiError::InvalidExtensionCapabilityId {
            capability_id: capability_id.to_string(),
        })
}

fn parse_payload_json(payload_json: &str) -> Result<serde_json::Value, MdbxFfiError> {
    serde_json::from_str(payload_json).map_err(MdbxFfiError::from)
}

fn collection_profile_from_core(profile: CollectionProfile) -> MdbxCollectionProfile {
    MdbxCollectionProfile {
        collection_id: profile.collection_id,
        collection_type_id: profile.collection_type_id.to_string(),
        payload: profile.payload_ct,
        payload_schema_version: profile.payload_schema_version,
        allowed_object_type_ids: profile
            .allowed_object_type_ids
            .into_iter()
            .map(|object_type| object_type.to_string())
            .collect(),
        required_capability_ids: profile
            .required_capability_ids
            .into_iter()
            .map(|capability| capability.to_string())
            .collect(),
        created_at: profile.created_at,
        updated_at: profile.updated_at,
        created_by_device_id: profile.created_by_device_id,
        updated_by_device_id: profile.updated_by_device_id,
    }
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

fn object_record_from_entry(
    entry: &mdbx_core::model::Entry,
) -> Result<MdbxObjectRecord, MdbxFfiError> {
    let payload: serde_json::Value = serde_json::from_slice(&entry.payload_ct)?;
    Ok(MdbxObjectRecord {
        object_id: entry.entry_id.clone(),
        collection_id: entry.project_id.clone(),
        object_type_id: entry.entry_type.to_string(),
        title: entry
            .title_ct
            .as_deref()
            .map(String::from_utf8_lossy)
            .map(|s| s.to_string())
            .unwrap_or_default(),
        payload_json: serde_json::to_string(&payload)?,
        payload_schema_version: entry.payload_schema_version,
        deleted: entry.deleted,
    })
}

fn object_summary_from_core(summary: ObjectSummary) -> MdbxObjectSummary {
    MdbxObjectSummary {
        object_id: summary.object_id,
        collection_id: summary.collection_id,
        object_type_id: summary.object_type_id.to_string(),
        title: summary
            .title
            .as_deref()
            .map(String::from_utf8_lossy)
            .map(|value| value.to_string())
            .unwrap_or_default(),
        payload_schema_version: summary.payload_schema_version,
        head_commit_id: summary.head_commit_id,
        deleted: summary.deleted,
        updated_at: summary.updated_at,
    }
}

fn conflict_resolution(choice: MdbxConflictChoice) -> ConflictResolution {
    match choice {
        MdbxConflictChoice::LocalWins => ConflictResolution::LocalWins,
        MdbxConflictChoice::IncomingWins => ConflictResolution::IncomingWins,
    }
}

fn conflict_record(conflict: &Conflict) -> MdbxConflictRecord {
    MdbxConflictRecord {
        conflict_id: conflict.conflict_id.clone(),
        object_type: conflict.object_type.to_string(),
        object_id: conflict.object_id.clone(),
        base_commit_id: conflict.base_commit_id.clone(),
        local_commit_id: conflict.local_commit_id.clone(),
        incoming_commit_id: conflict.incoming_commit_id.clone(),
        conflicting_fields: conflict.conflicting_fields.clone(),
        resolution: conflict.resolution.to_string(),
        created_at: conflict.created_at.clone(),
        resolved_at: conflict.resolved_at.clone(),
    }
}

fn object_relation_record(
    relation: &mdbx_core::model::ObjectRelation,
) -> Result<MdbxObjectRelationRecord, MdbxFfiError> {
    let payload: serde_json::Value = serde_json::from_slice(&relation.payload_ct)?;
    Ok(MdbxObjectRelationRecord {
        relation_id: relation.relation_id.clone(),
        source_object_id: relation.source_object_id.clone(),
        target_object_id: relation.target_object_id.clone(),
        relation_kind: relation.relation_kind.to_string(),
        payload_json: serde_json::to_string(&payload)?,
        payload_schema_version: relation.payload_schema_version,
        deleted: relation.deleted,
    })
}

fn object_label_record(
    label: &mdbx_core::model::ObjectLabel,
) -> Result<MdbxObjectLabelRecord, MdbxFfiError> {
    let name =
        String::from_utf8(label.name_ct.clone()).map_err(|error| MdbxFfiError::Serialization {
            message: error.to_string(),
        })?;
    let payload: serde_json::Value = serde_json::from_slice(&label.payload_ct)?;
    Ok(MdbxObjectLabelRecord {
        label_id: label.label_id.clone(),
        collection_id: label.collection_id.clone(),
        name,
        payload_json: serde_json::to_string(&payload)?,
        payload_schema_version: label.payload_schema_version,
        deleted: label.deleted,
    })
}

fn object_label_assignment_record(
    assignment: &mdbx_core::model::ObjectLabelAssignment,
) -> MdbxObjectLabelAssignmentRecord {
    MdbxObjectLabelAssignmentRecord {
        assignment_id: assignment.assignment_id.clone(),
        object_id: assignment.object_id.clone(),
        label_id: assignment.label_id.clone(),
        deleted: assignment.deleted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use sha2::{Digest, Sha256};

    fn ffi_test_vault() -> MdbxVault {
        let mut conn = VaultConnection::open_in_memory().unwrap();
        let init = initialize_vault(&conn, &VaultInitParams::default()).unwrap();
        UnlockService::setup_password_with_mode(&mut conn, "attachment-password", TigaMode::Multi)
            .unwrap();
        MdbxVault {
            conn: Mutex::new(conn),
            device_id: "ffi-attachment-device".to_string(),
            vault_id: init.vault_id,
        }
    }

    fn ffi_test_count(vault: &MdbxVault, table: &str) -> i64 {
        let conn = vault.conn.lock().unwrap();
        conn.inner()
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    }

    #[test]
    fn ffi_wire_session_roundtrips_blob_messages_and_sequences() {
        let limit = default_sync_wire_payload_bytes();
        let sender = create_sync_wire_session("wire-session".to_string(), limit).unwrap();
        let receiver = create_sync_wire_session("wire-session".to_string(), limit).unwrap();
        let blob_id = "a".repeat(64);
        let request = MdbxBlobChunkRequest {
            namespace_id: "source".to_string(),
            blob_id: blob_id.clone(),
            total_size: 8,
            offset: 0,
            max_bytes: 4,
        };
        let bytes = sender
            .encode_blob_chunk_request(request.clone(), None)
            .unwrap();
        let decoded = receiver.accept_blob_chunk_request(bytes.clone()).unwrap();
        assert_eq!(decoded.sequence, 1);
        assert_eq!(decoded.request, request);
        assert_eq!(receiver.pending_inbound_sequence().unwrap(), Some(1));
        receiver.acknowledge_inbound(1).unwrap();
        assert!(receiver.accept_blob_chunk_request(bytes).is_err());

        let response = MdbxBlobChunkResponse {
            namespace_id: "source".to_string(),
            blob_id,
            total_size: 8,
            offset: 0,
            ciphertext: vec![1, 2, 3, 4],
            is_last: false,
        };
        let response_bytes = sender
            .encode_blob_chunk_response(response.clone(), Some(decoded.sequence))
            .unwrap();
        let decoded_response = receiver.accept_blob_chunk_response(response_bytes).unwrap();
        assert_eq!(decoded_response.sequence, 2);
        assert_eq!(decoded_response.in_reply_to, Some(1));
        assert_eq!(decoded_response.response, response);
    }

    #[test]
    fn ffi_wire_session_restores_sequence_state_and_rejects_wrong_types() {
        let limit = default_sync_wire_payload_bytes();
        let sender = create_sync_wire_session("wire-session".to_string(), limit).unwrap();
        let receiver = create_sync_wire_session("wire-session".to_string(), limit).unwrap();
        let hello = MdbxSyncHello {
            device_id: "device-a".to_string(),
            protocol_version: 2,
            heads: Vec::new(),
            known_commit_ids: Vec::new(),
            capabilities: Vec::new(),
        };
        let hello_bytes = sender.encode_hello(hello.clone(), None).unwrap();
        let decoded = receiver.accept_hello(hello_bytes).unwrap();
        assert_eq!(decoded.hello, hello);
        receiver.acknowledge_inbound(decoded.sequence).unwrap();
        let resume = receiver.resume().unwrap();
        let encoded_resume = serde_json::to_vec(&resume).unwrap();
        let restored: MdbxSyncWireResume = serde_json::from_slice(&encoded_resume).unwrap();
        let restarted = create_sync_wire_session("wire-session".to_string(), limit).unwrap();
        restarted.restore_resume(restored).unwrap();
        assert_eq!(restarted.resume().unwrap().next_inbound_sequence, 2);

        let response = MdbxBlobChunkResponse {
            namespace_id: "source".to_string(),
            blob_id: "b".repeat(64),
            total_size: 4,
            offset: 0,
            ciphertext: vec![8, 9, 10, 11],
            is_last: true,
        };
        let response_bytes = sender
            .encode_blob_chunk_response(response, Some(decoded.sequence))
            .unwrap();
        assert!(restarted.accept_blob_chunk_request(response_bytes).is_err());
        assert_eq!(restarted.pending_inbound_sequence().unwrap(), None);
    }

    #[test]
    fn ffi_blob_sync_session_negotiates_and_advances_only_after_ack() {
        let local = create_blob_sync_session("ffi-local".to_string()).unwrap();
        let remote = create_blob_sync_session("ffi-remote".to_string()).unwrap();
        local
            .begin_blob_sync("source-namespace".to_string())
            .unwrap();
        let hello = local.hello().unwrap();
        assert_eq!(hello.capabilities.len(), 3);
        let ack = remote.accept_hello(hello).unwrap();
        local.accept_hello_ack(ack).unwrap();
        assert!(local.blob_replication_is_negotiated().unwrap());
        assert_eq!(
            local.blob_sync_phase().unwrap(),
            MdbxBlobSyncPhase::Manifest
        );

        let blob_id = "a".repeat(64);
        local.blob_manifest_request(8).unwrap();
        let manifest = MdbxBlobManifestPageResponse {
            namespace_id: "source-namespace".to_string(),
            checkpoint: "checkpoint".to_string(),
            items: vec![MdbxBlobManifestEntry {
                blob_id: blob_id.clone(),
                total_size: Some(8),
                state: MdbxBlobManifestEntryState::Available,
            }],
            next_cursor: None,
        };
        local
            .validate_blob_manifest_response(manifest.clone())
            .unwrap();
        assert!(local
            .blob_resume()
            .unwrap()
            .unwrap()
            .manifest_checkpoint
            .is_none());

        let first_request = local.blob_chunk_request(blob_id.clone(), 8, 4).unwrap();
        let first = MdbxBlobChunkResponse {
            namespace_id: "source-namespace".to_string(),
            blob_id: blob_id.clone(),
            total_size: 8,
            offset: first_request.offset,
            ciphertext: vec![1, 2, 3, 4],
            is_last: false,
        };
        local.validate_blob_chunk_response(first.clone()).unwrap();
        assert_eq!(local.blob_resume().unwrap().unwrap().next_durable_offset, 0);
        local.acknowledge_blob_chunk(first).unwrap();
        assert_eq!(local.blob_resume().unwrap().unwrap().next_durable_offset, 4);

        let second_request = local.blob_chunk_request(blob_id.clone(), 8, 4).unwrap();
        let second = MdbxBlobChunkResponse {
            namespace_id: "source-namespace".to_string(),
            blob_id,
            total_size: 8,
            offset: second_request.offset,
            ciphertext: vec![5, 6, 7, 8],
            is_last: true,
        };
        local.acknowledge_blob_chunk(second).unwrap();
        local.acknowledge_blob_manifest_page(manifest).unwrap();
        assert_eq!(
            local.blob_sync_phase().unwrap(),
            MdbxBlobSyncPhase::Complete
        );
    }

    #[test]
    fn ffi_blob_sync_session_restores_resume_and_rejects_partial_negotiation() {
        let local = create_blob_sync_session("ffi-local".to_string()).unwrap();
        let remote = create_blob_sync_session("ffi-remote".to_string()).unwrap();
        local
            .begin_blob_sync("source-namespace".to_string())
            .unwrap();
        let hello = local.hello().unwrap();
        let mut ack = remote.accept_hello(hello).unwrap();
        ack.capabilities.pop();
        local.accept_hello_ack(ack).unwrap();
        assert!(!local.blob_replication_is_negotiated().unwrap());
        assert!(matches!(
            local.blob_manifest_request(1),
            Err(MdbxFfiError::SyncProtocol { .. })
        ));

        let restored = MdbxBlobSyncResume {
            namespace_id: "source-namespace".to_string(),
            manifest_checkpoint: Some("checkpoint".to_string()),
            manifest_cursor: None,
            current_blob_id: Some("b".repeat(64)),
            total_size: 8,
            next_durable_offset: 4,
            manifest_complete: false,
        };
        let resumed = create_blob_sync_session("ffi-resumed".to_string()).unwrap();
        let peer = create_blob_sync_session("ffi-peer".to_string()).unwrap();
        resumed
            .begin_blob_sync("source-namespace".to_string())
            .unwrap();
        let hello = resumed.hello().unwrap();
        let ack = peer.accept_hello(hello).unwrap();
        resumed.accept_hello_ack(ack).unwrap();
        resumed.restore_blob_sync(restored.clone()).unwrap();
        assert_eq!(resumed.blob_resume().unwrap().unwrap(), restored);
    }

    #[test]
    fn attachment_tiga_scope_roundtrips_through_ffi_types() {
        let core = MdbxTigaScope {
            scope_type: MdbxTigaScopeType::Attachment,
            scope_id: Some("attachment-1".to_string()),
        }
        .into_core()
        .unwrap();
        assert_eq!(
            core,
            TigaScope::Attachment {
                attachment_id: "attachment-1".to_string()
            }
        );
        assert_eq!(
            scope_from_core(core),
            MdbxTigaScope {
                scope_type: MdbxTigaScopeType::Attachment,
                scope_id: Some("attachment-1".to_string())
            }
        );
    }

    #[test]
    fn attachment_facade_roundtrips_and_coalesces_content_commits() {
        let vault = ffi_test_vault();
        let project = vault.create_project("Steam".to_string()).unwrap();
        let attachment_id = Uuid::new_v4().to_string();
        let operation_id = Uuid::new_v4().to_string();
        let limits = MdbxAttachmentContentLimits {
            chunk_size: 3,
            max_plaintext_bytes: 64,
        };
        let commits_before = ffi_test_count(&vault, "commits");

        let created = vault
            .create_attachment_with_content(
                operation_id.clone(),
                MdbxAttachmentCreateRequest {
                    attachment_id: attachment_id.clone(),
                    project_id: project.project_id.clone(),
                    entry_id: None,
                    file_name: "account.maFile".to_string(),
                    media_type: Some("application/json".to_string()),
                },
                b"mafile".to_vec(),
                limits,
            )
            .unwrap();
        assert!(!created.already_committed);
        assert_eq!(created.attachment.attachment_id, attachment_id);
        assert_eq!(created.attachment.chunk_count, 2);
        assert_eq!(ffi_test_count(&vault, "commits"), commits_before + 1);
        assert_eq!(
            vault
                .read_attachment_content(attachment_id.clone(), 64)
                .unwrap(),
            b"mafile"
        );

        let retried = vault
            .create_attachment_with_content(
                operation_id.clone(),
                MdbxAttachmentCreateRequest {
                    attachment_id: attachment_id.clone(),
                    project_id: project.project_id.clone(),
                    entry_id: None,
                    file_name: "account.maFile".to_string(),
                    media_type: Some("application/json".to_string()),
                },
                b"mafile".to_vec(),
                limits,
            )
            .unwrap();
        assert!(retried.already_committed);
        assert_eq!(retried.commit_id, created.commit_id);
        assert!(vault
            .create_attachment_with_content(
                operation_id,
                MdbxAttachmentCreateRequest {
                    attachment_id: attachment_id.clone(),
                    project_id: project.project_id.clone(),
                    entry_id: None,
                    file_name: "account.maFile".to_string(),
                    media_type: Some("application/json".to_string()),
                },
                b"different".to_vec(),
                limits,
            )
            .is_err());
        assert_eq!(ffi_test_count(&vault, "commits"), commits_before + 1);

        let original_hash = created.attachment.content_hash;
        let replaced = vault
            .replace_attachment_content(
                Uuid::new_v4().to_string(),
                attachment_id.clone(),
                b"mail-body".to_vec(),
                limits,
            )
            .unwrap();
        assert_ne!(replaced.attachment.content_hash, original_hash);
        let renamed = vault
            .rename_attachment(
                attachment_id.clone(),
                "message.eml".to_string(),
                Some("message/rfc822".to_string()),
            )
            .unwrap();
        assert_eq!(renamed.content_hash, replaced.attachment.content_hash);
        assert_eq!(renamed.file_name, "message.eml");
        assert_eq!(
            vault
                .list_attachments(project.project_id, None)
                .unwrap()
                .len(),
            1
        );

        vault.delete_attachment(attachment_id.clone()).unwrap();
        assert!(
            vault
                .get_attachment(attachment_id.clone())
                .unwrap()
                .unwrap()
                .deleted
        );
        assert!(vault
            .list_deleted_attachments()
            .unwrap()
            .iter()
            .any(|attachment| attachment.attachment_id == attachment_id));
    }

    #[test]
    fn attachment_batch_is_atomic_idempotent_and_mixes_content_metadata() {
        let vault = ffi_test_vault();
        let project = vault.create_project("Mail".to_string()).unwrap();
        let first_id = Uuid::new_v4().to_string();
        let second_id = Uuid::new_v4().to_string();
        let operation_id = Uuid::new_v4().to_string();
        let limits = MdbxAttachmentBatchLimits {
            max_commands: 4,
            max_plaintext_bytes_per_command: 64,
            max_plaintext_bytes: 64,
            chunk_size: 3,
        };
        let commands = vec![
            MdbxAttachmentBatchCommand::Create {
                attachment_id: first_id.clone(),
                project_id: project.project_id.clone(),
                entry_id: None,
                file_name: "first.bin".to_string(),
                media_type: Some("application/octet-stream".to_string()),
                content: b"first-content".to_vec(),
            },
            MdbxAttachmentBatchCommand::Create {
                attachment_id: second_id.clone(),
                project_id: project.project_id,
                entry_id: None,
                file_name: "second.bin".to_string(),
                media_type: None,
                content: b"second-content".to_vec(),
            },
            MdbxAttachmentBatchCommand::Rename {
                attachment_id: first_id.clone(),
                file_name: "renamed.bin".to_string(),
                media_type: Some("application/custom".to_string()),
            },
            MdbxAttachmentBatchCommand::Replace {
                attachment_id: second_id.clone(),
                content: b"replacement".to_vec(),
            },
        ];
        let commits_before = ffi_test_count(&vault, "commits");
        let first = vault
            .execute_attachment_batch_with_limits(operation_id.clone(), commands.clone(), limits)
            .unwrap();
        assert!(!first.already_committed);
        assert_eq!(first.attachments.len(), 2);
        assert_eq!(first.attachments[0].attachment_id, first_id);
        assert_eq!(first.attachments[0].file_name, "renamed.bin");
        assert_eq!(first.attachments[1].attachment_id, second_id);
        assert_eq!(first.attachments[1].original_size, 14);
        assert_eq!(first.attachments[1].stored_size, 11);
        assert_eq!(ffi_test_count(&vault, "commits"), commits_before + 1);
        assert_eq!(
            vault
                .read_attachment_content(first.attachments[0].attachment_id.clone(), 64)
                .unwrap(),
            b"first-content"
        );
        assert_eq!(
            vault
                .read_attachment_content(first.attachments[1].attachment_id.clone(), 64)
                .unwrap(),
            b"replacement"
        );

        let retry = vault
            .execute_attachment_batch_with_limits(operation_id.clone(), commands.clone(), limits)
            .unwrap();
        assert!(retry.already_committed);
        assert_eq!(retry.commit_id, first.commit_id);
        assert_eq!(ffi_test_count(&vault, "commits"), commits_before + 1);

        let mut changed_commands = commands;
        if let MdbxAttachmentBatchCommand::Replace { content, .. } = &mut changed_commands[3] {
            *content = b"different-content".to_vec();
        }
        assert!(vault
            .execute_attachment_batch_with_limits(operation_id, changed_commands, limits,)
            .unwrap_err()
            .to_string()
            .contains("reused for a different operation"));

        let deleted = vault
            .execute_attachment_batch_with_limits(
                Uuid::new_v4().to_string(),
                vec![
                    MdbxAttachmentBatchCommand::Delete {
                        attachment_id: first.attachments[0].attachment_id.clone(),
                    },
                    MdbxAttachmentBatchCommand::Replace {
                        attachment_id: first.attachments[1].attachment_id.clone(),
                        content: b"final".to_vec(),
                    },
                ],
                limits,
            )
            .unwrap();
        assert_eq!(ffi_test_count(&vault, "commits"), commits_before + 2);
        assert!(deleted.attachments[0].deleted);
        assert_eq!(
            vault
                .read_attachment_content(first.attachments[1].attachment_id.clone(), 64)
                .unwrap(),
            b"final"
        );
        {
            let conn = vault.conn.lock().unwrap();
            conn.inner()
                .execute(
                    "UPDATE attachment_chunks SET chunk_ct = zeroblob(length(chunk_ct))
                     WHERE attachment_id = ?1 AND chunk_index = 0",
                    [&first.attachments[1].attachment_id],
                )
                .unwrap();
        }
        assert!(!vault
            .verify_attachment_integrity(first.attachments[1].attachment_id.clone())
            .unwrap());
        assert!(vault
            .read_attachment_content(first.attachments[1].attachment_id.clone(), 64)
            .is_err());
    }

    #[test]
    fn attachment_batch_rejects_partial_failures_bounds_and_missing_capability() {
        let vault = ffi_test_vault();
        let project = vault.create_project("Mail".to_string()).unwrap();
        let commits_before = ffi_test_count(&vault, "commits");
        let attachments_before = ffi_test_count(&vault, "attachments");
        assert!(vault
            .execute_attachment_batch(
                Uuid::new_v4().to_string(),
                vec![
                    MdbxAttachmentBatchCommand::Create {
                        attachment_id: Uuid::new_v4().to_string(),
                        project_id: project.project_id.clone(),
                        entry_id: None,
                        file_name: "rolled-back.bin".to_string(),
                        media_type: None,
                        content: b"content".to_vec(),
                    },
                    MdbxAttachmentBatchCommand::Delete {
                        attachment_id: Uuid::new_v4().to_string(),
                    },
                ],
            )
            .is_err());
        assert_eq!(ffi_test_count(&vault, "commits"), commits_before);
        assert_eq!(ffi_test_count(&vault, "attachments"), attachments_before);

        let small_limits = MdbxAttachmentBatchLimits {
            max_commands: 2,
            max_plaintext_bytes_per_command: 4,
            max_plaintext_bytes: 8,
            chunk_size: 2,
        };
        assert!(vault
            .execute_attachment_batch_with_limits(
                Uuid::new_v4().to_string(),
                vec![MdbxAttachmentBatchCommand::Create {
                    attachment_id: Uuid::new_v4().to_string(),
                    project_id: project.project_id.clone(),
                    entry_id: None,
                    file_name: "oversized.bin".to_string(),
                    media_type: None,
                    content: b"12345".to_vec(),
                }],
                small_limits,
            )
            .unwrap_err()
            .to_string()
            .contains("command plaintext bytes"));
        assert_eq!(ffi_test_count(&vault, "commits"), commits_before);

        vault
            .set_extension_capabilities(vec!["com.monica.mail.store".to_string()])
            .unwrap();
        vault
            .set_collection_profile(
                project.project_id.clone(),
                "com.monica.mail".to_string(),
                b"profile".to_vec(),
                1,
                vec!["com.monica.mail.message".to_string()],
                vec!["com.monica.mail.store".to_string()],
            )
            .unwrap();
        vault.set_extension_capabilities(Vec::new()).unwrap();
        let commits_before_capability_failure = ffi_test_count(&vault, "commits");
        assert!(vault
            .execute_attachment_batch(
                Uuid::new_v4().to_string(),
                vec![MdbxAttachmentBatchCommand::Create {
                    attachment_id: Uuid::new_v4().to_string(),
                    project_id: project.project_id,
                    entry_id: None,
                    file_name: "blocked.bin".to_string(),
                    media_type: None,
                    content: b"content".to_vec(),
                }],
            )
            .is_err());
        assert_eq!(
            ffi_test_count(&vault, "commits"),
            commits_before_capability_failure
        );
        assert_eq!(ffi_test_count(&vault, "attachments"), attachments_before);
    }

    #[test]
    fn attachment_facade_rejects_oversized_content_without_side_effects() {
        let vault = ffi_test_vault();
        let project = vault.create_project("Mail".to_string()).unwrap();
        let commits_before = ffi_test_count(&vault, "commits");
        let attachments_before = ffi_test_count(&vault, "attachments");
        let result = vault.create_attachment_with_content(
            Uuid::new_v4().to_string(),
            MdbxAttachmentCreateRequest {
                attachment_id: Uuid::new_v4().to_string(),
                project_id: project.project_id,
                entry_id: None,
                file_name: "large.eml".to_string(),
                media_type: Some("message/rfc822".to_string()),
            },
            vec![0; 5],
            MdbxAttachmentContentLimits {
                chunk_size: 2,
                max_plaintext_bytes: 4,
            },
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("attachment plaintext bytes"));
        assert_eq!(ffi_test_count(&vault, "commits"), commits_before);
        assert_eq!(ffi_test_count(&vault, "attachments"), attachments_before);
    }

    #[test]
    fn attachment_facade_enforces_stream_limits_and_detects_tampering() {
        let vault = ffi_test_vault();
        let project = vault.create_project("Mail".to_string()).unwrap();
        let attachment_id = Uuid::new_v4().to_string();
        vault
            .create_attachment_with_content(
                Uuid::new_v4().to_string(),
                MdbxAttachmentCreateRequest {
                    attachment_id: attachment_id.clone(),
                    project_id: project.project_id,
                    entry_id: None,
                    file_name: "message.eml".to_string(),
                    media_type: None,
                },
                b"123456".to_vec(),
                MdbxAttachmentContentLimits {
                    chunk_size: 3,
                    max_plaintext_bytes: 64,
                },
            )
            .unwrap();
        {
            let conn = vault.conn.lock().unwrap();
            conn.inner()
                .execute(
                    "UPDATE attachments SET stored_size = 1 WHERE attachment_id = ?1",
                    [&attachment_id],
                )
                .unwrap();
        }
        let limit_error = vault
            .read_attachment_content(attachment_id.clone(), 4)
            .unwrap_err();
        assert!(
            limit_error
                .to_string()
                .contains("attachment stored size mismatch"),
            "unexpected error: {limit_error}"
        );
        let mut limited = LimitedAttachmentContentWriter::new(4);
        limited.write_all(b"123").unwrap();
        assert!(limited.write_all(b"456").is_err());
        assert_eq!(limited.bytes, b"123");
        {
            let conn = vault.conn.lock().unwrap();
            conn.inner()
                .execute(
                    "UPDATE attachments SET stored_size = 6 WHERE attachment_id = ?1",
                    [&attachment_id],
                )
                .unwrap();
            conn.inner()
                .execute(
                    "UPDATE attachment_chunks SET chunk_ct = zeroblob(length(chunk_ct))
                     WHERE attachment_id = ?1 AND chunk_index = 0",
                    [&attachment_id],
                )
                .unwrap();
        }
        assert!(vault
            .read_attachment_content(attachment_id.clone(), 64)
            .is_err());
        assert!(!vault.verify_attachment_integrity(attachment_id).unwrap());
    }

    #[test]
    fn attachment_facade_honors_collection_capability_trimming() {
        let vault = ffi_test_vault();
        let project = vault.create_project("Mail".to_string()).unwrap();
        vault
            .set_extension_capabilities(vec!["com.monica.mail.store".to_string()])
            .unwrap();
        vault
            .set_collection_profile(
                project.project_id.clone(),
                "com.monica.mail".to_string(),
                b"profile".to_vec(),
                1,
                vec!["com.monica.mail.message".to_string()],
                vec!["com.monica.mail.store".to_string()],
            )
            .unwrap();
        vault.set_extension_capabilities(Vec::new()).unwrap();
        let commits_before = ffi_test_count(&vault, "commits");

        assert!(vault
            .create_attachment_with_content(
                Uuid::new_v4().to_string(),
                MdbxAttachmentCreateRequest {
                    attachment_id: Uuid::new_v4().to_string(),
                    project_id: project.project_id,
                    entry_id: None,
                    file_name: "blocked.eml".to_string(),
                    media_type: None,
                },
                b"content".to_vec(),
                default_attachment_content_limits(),
            )
            .is_err());
        assert_eq!(ffi_test_count(&vault, "commits"), commits_before);
        assert_eq!(ffi_test_count(&vault, "attachments"), 0);
    }

    #[test]
    fn collection_profile_facade_registers_capabilities_and_guards_object_types() {
        let conn = VaultConnection::open_in_memory().unwrap();
        initialize_vault(&conn, &VaultInitParams::default()).unwrap();
        let vault = MdbxVault {
            conn: Mutex::new(conn),
            device_id: "ffi-profile-device".to_string(),
            vault_id: "ffi-profile-vault".to_string(),
        };
        let collection = vault.create_project("Mail".to_string()).unwrap();
        vault
            .set_extension_capabilities(vec!["com.monica.mail.store".to_string()])
            .unwrap();
        let profile = vault
            .set_collection_profile(
                collection.project_id.clone(),
                "com.monica.mail".to_string(),
                b"opaque-profile".to_vec(),
                1,
                vec!["com.monica.mail.message".to_string()],
                vec!["com.monica.mail.store".to_string()],
            )
            .unwrap();
        assert_eq!(profile.collection_type_id, "com.monica.mail");
        assert_eq!(
            vault
                .get_collection_profile(collection.project_id.clone())
                .unwrap()
                .unwrap()
                .payload,
            b"opaque-profile"
        );

        vault
            .create_object(
                collection.project_id.clone(),
                "com.monica.mail.message".to_string(),
                "Message".to_string(),
                r#"{"body":"hello"}"#.to_string(),
                1,
            )
            .unwrap();
        assert!(vault
            .create_object(
                collection.project_id,
                "login".to_string(),
                "Login".to_string(),
                "{}".to_string(),
                1,
            )
            .is_err());
    }

    #[test]
    fn payload_migration_facade_exposes_adapter_bytes_and_one_commit_result() {
        let conn = VaultConnection::open_in_memory().unwrap();
        initialize_vault(&conn, &VaultInitParams::default()).unwrap();
        let vault = MdbxVault {
            conn: Mutex::new(conn),
            device_id: "ffi-migration-device".to_string(),
            vault_id: "ffi-migration-vault".to_string(),
        };
        let collection = vault.create_project("Mail".to_string()).unwrap();
        vault
            .set_extension_capabilities(vec!["com.monica.mail.payload-v2".to_string()])
            .unwrap();
        vault
            .set_collection_profile(
                collection.project_id.clone(),
                "com.monica.mail".to_string(),
                b"profile".to_vec(),
                1,
                vec!["com.monica.mail.message".to_string()],
                vec!["com.monica.mail.payload-v2".to_string()],
            )
            .unwrap();
        let object = vault
            .create_object(
                collection.project_id.clone(),
                "com.monica.mail.message".to_string(),
                "Message".to_string(),
                r#"{"version":1}"#.to_string(),
                1,
            )
            .unwrap();

        let plan = vault
            .create_payload_migration_plan(
                collection.project_id.clone(),
                "com.monica.mail.message".to_string(),
                1,
                2,
                16,
                None,
            )
            .unwrap();
        assert_eq!(plan.items.len(), 1);
        assert_eq!(plan.items[0].object_id, object.object_id);
        assert_eq!(plan.items[0].source_payload, br#"{"version":1}"#);

        let result = vault
            .execute_payload_migration(
                plan,
                vec![MdbxPayloadMigrationOutput {
                    object_id: object.object_id.clone(),
                    target_payload: br#"{"version":2}"#.to_vec(),
                }],
            )
            .unwrap();
        assert_eq!(result.migrated_count, 1);
        assert!(!result.already_committed);
        let migrated = vault
            .get_object(collection.project_id, object.object_id)
            .unwrap()
            .unwrap();
        assert_eq!(migrated.payload_schema_version, 2);
        assert_eq!(migrated.payload_json, r#"{"version":2}"#);
    }

    #[test]
    fn conflict_facade_lists_and_resolves_generic_metadata() {
        let conn = VaultConnection::open_in_memory().unwrap();
        initialize_vault(&conn, &VaultInitParams::default()).unwrap();
        let ctx = CommitContext::new("ffi-conflict-device".to_string());
        let project = ProjectRepo::create(&conn, &ctx, "Mail", None, None).unwrap();
        let first = EntryRepo::create(
            &conn,
            &ctx,
            &project.project_id,
            EntryType::custom("com.monica.mail.message").unwrap(),
            Some("First"),
            &serde_json::json!({"body":"first"}),
        )
        .unwrap();
        let second = EntryRepo::create(
            &conn,
            &ctx,
            &project.project_id,
            EntryType::custom("com.monica.mail.message").unwrap(),
            Some("Second"),
            &serde_json::json!({"body":"second"}),
        )
        .unwrap();
        let relation = ObjectRelationRepo::create(
            &conn,
            &ctx,
            ObjectRelationCreateRequest::new(
                &first.entry_id,
                &second.entry_id,
                RelationKindId::new("com.monica.mail.reply-to").unwrap(),
                serde_json::json!({"position":1}),
            ),
        )
        .unwrap();
        let current = mdbx_storage::repo::ObjectVersionRepo::current_object_relation_row(
            &conn,
            &relation.relation_id,
        )
        .unwrap();
        let incoming_commit = ctx
            .create_commit(
                &conn,
                "change",
                "object-relation",
                std::slice::from_ref(&relation.relation_id),
                std::slice::from_ref(&current.head_commit_id),
            )
            .unwrap();
        let mut incoming = current.clone();
        incoming.payload_ct = serde_json::to_vec(&serde_json::json!({"position":2})).unwrap();
        incoming.head_commit_id = incoming_commit.clone();
        mdbx_storage::repo::ObjectVersionRepo::record_object_relation_row(
            &conn,
            &incoming_commit,
            &incoming,
        )
        .unwrap();
        let conflict = ConflictRepo::create(
            &conn,
            &ctx,
            ConflictObjectType::ObjectRelation,
            &relation.relation_id,
            &current.head_commit_id,
            &current.head_commit_id,
            &incoming_commit,
            &["payload_ct".to_string()],
        )
        .unwrap();
        let vault = MdbxVault {
            conn: Mutex::new(conn),
            device_id: "ffi-conflict-device".to_string(),
            vault_id: "ffi-conflict-vault".to_string(),
        };

        let listed = vault.list_unresolved_conflicts().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].object_type, "object-relation");
        let resolved = vault
            .resolve_conflict(conflict.conflict_id, MdbxConflictChoice::IncomingWins)
            .unwrap();
        assert_eq!(resolved.resolution, "incoming-wins");
        assert!(vault.list_unresolved_conflicts().unwrap().is_empty());
        let conn = vault.conn.lock().unwrap();
        let stored = ObjectRelationRepo::get_by_id(&conn, &relation.relation_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&stored.payload_ct).unwrap(),
            serde_json::json!({"position":2})
        );
    }

    #[test]
    fn conflict_facade_applies_typed_project_and_attachment_custom_merges() {
        let conn = VaultConnection::open_in_memory().unwrap();
        initialize_vault(&conn, &VaultInitParams::default()).unwrap();
        let ctx = CommitContext::new("ffi-custom-conflict-device".to_string());
        let project = ProjectRepo::create(&conn, &ctx, "Local", None, None).unwrap();
        let project_row =
            mdbx_storage::repo::ObjectVersionRepo::current_project_row(&conn, &project.project_id)
                .unwrap();
        let project_incoming_commit = ctx
            .create_commit(
                &conn,
                "change",
                "project",
                std::slice::from_ref(&project.project_id),
                std::slice::from_ref(&project_row.head_commit_id),
            )
            .unwrap();
        let mut incoming_project = project_row.clone();
        incoming_project.title_ct = b"Incoming".to_vec();
        incoming_project.head_commit_id = project_incoming_commit.clone();
        mdbx_storage::repo::ObjectVersionRepo::record_project_row(
            &conn,
            &project_incoming_commit,
            &incoming_project,
        )
        .unwrap();
        let project_conflict = ConflictRepo::create(
            &conn,
            &ctx,
            ConflictObjectType::Project,
            &project.project_id,
            &project_row.head_commit_id,
            &project_row.head_commit_id,
            &project_incoming_commit,
            &["title_ct".to_string()],
        )
        .unwrap();

        let content_hash = "a".repeat(64);
        let attachment = AttachmentRepo::add(
            &conn,
            &ctx,
            &project.project_id,
            None,
            "local.mafile",
            Some("application/json"),
            &content_hash,
            256,
        )
        .unwrap();
        let attachment_row = mdbx_storage::repo::ObjectVersionRepo::current_attachment_row(
            &conn,
            &attachment.attachment_id,
        )
        .unwrap();
        let attachment_incoming_commit = ctx
            .create_commit(
                &conn,
                "change",
                "attachment",
                std::slice::from_ref(&attachment.attachment_id),
                std::slice::from_ref(&attachment_row.head_commit_id),
            )
            .unwrap();
        let mut incoming_attachment = attachment_row.clone();
        incoming_attachment.file_name_ct = b"incoming.mafile".to_vec();
        incoming_attachment.head_commit_id = attachment_incoming_commit.clone();
        mdbx_storage::repo::ObjectVersionRepo::record_attachment_row(
            &conn,
            &attachment_incoming_commit,
            &incoming_attachment,
        )
        .unwrap();
        let attachment_conflict = ConflictRepo::create(
            &conn,
            &ctx,
            ConflictObjectType::Attachment,
            &attachment.attachment_id,
            &attachment_row.head_commit_id,
            &attachment_row.head_commit_id,
            &attachment_incoming_commit,
            &["file_name_ct".to_string()],
        )
        .unwrap();
        let vault = MdbxVault {
            conn: Mutex::new(conn),
            device_id: "ffi-custom-conflict-device".to_string(),
            vault_id: "ffi-custom-conflict-vault".to_string(),
        };

        assert!(vault
            .resolve_project_conflict_custom(
                attachment_conflict.conflict_id.clone(),
                MdbxProjectConflictMerge {
                    title: "Wrong type".to_string(),
                    summary: None,
                    group_id: None,
                    icon_ref: None,
                    favorite: false,
                    archived: false,
                    deleted: false,
                },
            )
            .is_err());

        let resolved_project = vault
            .resolve_project_conflict_custom(
                project_conflict.conflict_id,
                MdbxProjectConflictMerge {
                    title: "Merged".to_string(),
                    summary: Some("Selected summary".to_string()),
                    group_id: Some("accounts".to_string()),
                    icon_ref: Some("steam".to_string()),
                    favorite: true,
                    archived: false,
                    deleted: false,
                },
            )
            .unwrap();
        let resolved_attachment = vault
            .resolve_attachment_conflict_custom(
                attachment_conflict.conflict_id,
                MdbxAttachmentConflictMerge {
                    project_id: project.project_id.clone(),
                    entry_id: None,
                    file_name: "merged.mafile".to_string(),
                    media_type: Some("application/vnd.monica.mafile+json".to_string()),
                    deleted: false,
                },
            )
            .unwrap();

        assert_eq!(resolved_project.resolution, "custom");
        assert_eq!(resolved_attachment.resolution, "custom");
        assert!(vault.list_unresolved_conflicts().unwrap().is_empty());
        let conn = vault.conn.lock().unwrap();
        let stored_project = ProjectRepo::get_by_id(&conn, &project.project_id)
            .unwrap()
            .unwrap();
        let stored_attachment = AttachmentRepo::get_by_id(&conn, &attachment.attachment_id)
            .unwrap()
            .unwrap();
        assert_eq!(stored_project.title_ct, b"Merged");
        assert_eq!(
            stored_project.summary_ct.as_deref(),
            Some(b"Selected summary".as_slice())
        );
        assert!(stored_project.favorite);
        assert_eq!(stored_attachment.file_name_ct, b"merged.mafile");
        assert_eq!(stored_attachment.content_hash, content_hash);
        assert_eq!(stored_attachment.original_size, 256);
    }

    #[test]
    fn health_check_returns_structured_tombstone_issues() {
        let conn = VaultConnection::open_in_memory().unwrap();
        initialize_vault(&conn, &VaultInitParams::default()).unwrap();
        let ctx = CommitContext::new("ffi-health-device".to_string());
        let project = ProjectRepo::create(&conn, &ctx, "Health", None, None).unwrap();
        let vault = MdbxVault {
            conn: Mutex::new(conn),
            device_id: "ffi-health-device".to_string(),
            vault_id: "ffi-health-vault".to_string(),
        };

        let clean = vault.health_check().unwrap();
        assert!(clean.healthy);

        {
            let conn = vault.conn.lock().unwrap();
            ProjectRepo::soft_delete(&conn, &ctx, &project.project_id).unwrap();
            conn.inner()
                .execute(
                    "DELETE FROM tombstones
                     WHERE target_object_type = 'project' AND target_object_id = ?1",
                    rusqlite::params![project.project_id],
                )
                .unwrap();
        }

        let unhealthy = vault.health_check().unwrap();
        assert!(!unhealthy.healthy);
        assert!(unhealthy.issues.iter().any(|issue| {
            issue.severity == MdbxHealthIssueSeverity::Error
                && issue.category == "tombstones"
                && issue.description.contains(&project.project_id)
                && issue.description.contains("deleted without")
        }));
    }

    #[test]
    fn tombstone_purge_eligibility_is_available_to_native_clients() {
        let conn = VaultConnection::open_in_memory().unwrap();
        initialize_vault(
            &conn,
            &VaultInitParams {
                device_id: "ffi-purge-device".to_string(),
                ..VaultInitParams::default()
            },
        )
        .unwrap();
        let ctx = CommitContext::new("ffi-purge-device".to_string());
        let project = ProjectRepo::create(&conn, &ctx, "Purge", None, None).unwrap();
        ProjectRepo::soft_delete(&conn, &ctx, &project.project_id).unwrap();
        let tombstone = TombstoneRepo::find_by_target(&conn, &project.project_id)
            .unwrap()
            .unwrap();
        let vault = MdbxVault {
            conn: Mutex::new(conn),
            device_id: "ffi-purge-device".to_string(),
            vault_id: "ffi-purge-vault".to_string(),
        };

        let result = vault
            .evaluate_tombstone_purge_eligibility(
                tombstone.tombstone_id,
                "2030-01-01T00:00:00Z".to_string(),
            )
            .unwrap();
        assert!(!result.eligible);
        assert_eq!(result.blockers.len(), 1);
        assert_eq!(result.blockers[0].code, "retention-not-scheduled");
    }

    #[test]
    fn bounded_write_operation_limits_and_streaming_intent_hash_are_stable() {
        let limits = default_write_operation_limits();
        assert_eq!(limits.max_commands, 256);
        assert_eq!(limits.max_payload_bytes_per_command, 1024 * 1024);
        assert_eq!(limits.max_payload_bytes, 8 * 1024 * 1024);
        assert_eq!(limits.max_intent_bytes, 16 * 1024 * 1024);

        let commands = vec![MdbxWriteCommand::CreateProject {
            project_id: Uuid::new_v4().to_string(),
            title: "Mail".to_string(),
        }];
        let encoded = serde_json::to_vec(&commands).unwrap();
        assert_eq!(
            hash_write_operation_intent(&commands, encoded.len()).unwrap(),
            Sha256::digest(&encoded).to_vec()
        );
        assert!(hash_write_operation_intent(&commands, encoded.len() - 1)
            .unwrap_err()
            .to_string()
            .contains("serialized intent bytes"));

        let invalid = MdbxWriteOperationLimits {
            max_commands: HARD_MAX_WRITE_COMMANDS as u64 + 1,
            ..limits
        };
        assert!(invalid.into_internal().is_err());
    }

    #[test]
    fn bounded_write_operation_rejects_without_database_side_effects() {
        let conn = VaultConnection::open_in_memory().unwrap();
        initialize_vault(&conn, &VaultInitParams::default()).unwrap();
        let initial_commits: i64 = conn
            .inner()
            .query_row("SELECT COUNT(*) FROM commits", [], |row| row.get(0))
            .unwrap();
        let initial_projects: i64 = conn
            .inner()
            .query_row("SELECT COUNT(*) FROM projects", [], |row| row.get(0))
            .unwrap();
        let initial_head: String = conn
            .inner()
            .query_row(
                "SELECT head_commit_id FROM branches WHERE branch_name = 'main'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let vault = MdbxVault {
            conn: Mutex::new(conn),
            device_id: "ffi-bounded-write-device".to_string(),
            vault_id: "ffi-bounded-write-vault".to_string(),
        };

        let too_many = (0..=DEFAULT_MAX_WRITE_COMMANDS)
            .map(|index| MdbxWriteCommand::CreateProject {
                project_id: Uuid::new_v4().to_string(),
                title: format!("Collection {index}"),
            })
            .collect();
        assert!(vault
            .execute_write_operation(
                Uuid::new_v4().to_string(),
                "bulk-import".to_string(),
                too_many,
            )
            .unwrap_err()
            .to_string()
            .contains("write operation commands"));

        let oversized_payload = format!(
            "\"{}\"",
            "x".repeat(DEFAULT_MAX_WRITE_PAYLOAD_BYTES_PER_COMMAND)
        );
        assert!(vault
            .execute_write_operation(
                Uuid::new_v4().to_string(),
                "mail-import".to_string(),
                vec![MdbxWriteCommand::CreateEntry {
                    entry_id: Uuid::new_v4().to_string(),
                    project_id: Uuid::new_v4().to_string(),
                    entry_type: "com.monica.mail.message".to_string(),
                    title: "Oversized".to_string(),
                    payload_json: oversized_payload,
                }],
            )
            .unwrap_err()
            .to_string()
            .contains("command payload bytes"));

        let small_limits = MdbxWriteOperationLimits {
            max_commands: 2,
            max_payload_bytes_per_command: 16,
            max_payload_bytes: 16,
            max_intent_bytes: 4096,
        };
        let payload = r#"{"body":"1234"}"#.to_string();
        assert!(vault
            .execute_write_operation_with_limits(
                Uuid::new_v4().to_string(),
                "mail-import".to_string(),
                vec![
                    MdbxWriteCommand::CreateEntry {
                        entry_id: Uuid::new_v4().to_string(),
                        project_id: Uuid::new_v4().to_string(),
                        entry_type: "com.monica.mail.message".to_string(),
                        title: "First".to_string(),
                        payload_json: payload.clone(),
                    },
                    MdbxWriteCommand::CreateEntry {
                        entry_id: Uuid::new_v4().to_string(),
                        project_id: Uuid::new_v4().to_string(),
                        entry_type: "com.monica.mail.message".to_string(),
                        title: "Second".to_string(),
                        payload_json: payload,
                    },
                ],
                small_limits,
            )
            .unwrap_err()
            .to_string()
            .contains("write operation payload bytes"));

        let conn = vault.conn.lock().unwrap();
        assert_eq!(
            conn.inner()
                .query_row("SELECT COUNT(*) FROM commits", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            initial_commits
        );
        assert_eq!(
            conn.inner()
                .query_row("SELECT COUNT(*) FROM projects", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            initial_projects
        );
        assert_eq!(
            conn.inner()
                .query_row(
                    "SELECT head_commit_id FROM branches WHERE branch_name = 'main'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            initial_head
        );
    }

    #[test]
    fn write_operation_is_atomic_single_commit_and_idempotent_across_limit_apis() {
        let conn = VaultConnection::open_in_memory().unwrap();
        initialize_vault(&conn, &VaultInitParams::default()).unwrap();
        let initial_commits: i64 = conn
            .inner()
            .query_row("SELECT COUNT(*) FROM commits", [], |row| row.get(0))
            .unwrap();
        let vault = MdbxVault {
            conn: Mutex::new(conn),
            device_id: "ffi-write-device".to_string(),
            vault_id: "ffi-write-vault".to_string(),
        };
        let operation_id = Uuid::new_v4().to_string();
        let project_id = Uuid::new_v4().to_string();
        let entry_id = Uuid::new_v4().to_string();
        let commands = vec![
            MdbxWriteCommand::CreateProject {
                project_id: project_id.clone(),
                title: "Mail".to_string(),
            },
            MdbxWriteCommand::CreateEntry {
                entry_id: entry_id.clone(),
                project_id: project_id.clone(),
                entry_type: "com.monica.mail.message".to_string(),
                title: "Message".to_string(),
                payload_json: r#"{"body":"encrypted by storage"}"#.to_string(),
            },
        ];
        let explicit_limits = MdbxWriteOperationLimits {
            max_commands: 2,
            max_payload_bytes_per_command: 1024,
            max_payload_bytes: 1024,
            max_intent_bytes: 4096,
        };

        let first = vault
            .execute_write_operation_with_limits(
                operation_id.clone(),
                "mail-import".to_string(),
                commands.clone(),
                explicit_limits,
            )
            .unwrap();
        assert!(!first.already_committed);
        assert_eq!(first.project_ids, vec![project_id.clone()]);
        assert_eq!(first.entry_ids, vec![entry_id.clone()]);

        let retry = vault
            .execute_write_operation(
                operation_id.clone(),
                "mail-import".to_string(),
                commands.clone(),
            )
            .unwrap();
        assert!(retry.already_committed);
        assert_eq!(retry.commit_id, first.commit_id);

        let changed_commands = vec![commands[0].clone()];
        assert!(vault
            .execute_write_operation(operation_id, "mail-import".to_string(), changed_commands,)
            .unwrap_err()
            .to_string()
            .contains("reused for a different operation"));

        let failed_project_id = Uuid::new_v4().to_string();
        let missing_project_id = Uuid::new_v4().to_string();
        assert!(vault
            .execute_write_operation(
                Uuid::new_v4().to_string(),
                "mail-import".to_string(),
                vec![
                    MdbxWriteCommand::CreateProject {
                        project_id: failed_project_id.clone(),
                        title: "Rolled back".to_string(),
                    },
                    MdbxWriteCommand::CreateEntry {
                        entry_id: Uuid::new_v4().to_string(),
                        project_id: missing_project_id,
                        entry_type: "com.monica.mail.message".to_string(),
                        title: "Failure".to_string(),
                        payload_json: "{}".to_string(),
                    },
                ],
            )
            .is_err());

        let conn = vault.conn.lock().unwrap();
        assert_eq!(
            conn.inner()
                .query_row("SELECT COUNT(*) FROM commits", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            initial_commits + 1
        );
        assert_eq!(
            conn.inner()
                .query_row(
                    "SELECT COUNT(*) FROM projects WHERE project_id = ?1",
                    rusqlite::params![failed_project_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        let stored_entry = EntryRepo::get_by_id(&conn, &entry_id).unwrap().unwrap();
        assert_eq!(stored_entry.head_commit_id, first.commit_id);
    }

    #[test]
    fn generic_metadata_write_operation_is_atomic_idempotent_and_lifecycle_complete() {
        let vault = ffi_test_vault();
        let operation_id = Uuid::new_v4().to_string();
        let project_id = Uuid::new_v4().to_string();
        let first_entry_id = Uuid::new_v4().to_string();
        let second_entry_id = Uuid::new_v4().to_string();
        let relation_id = Uuid::new_v4().to_string();
        let label_id = Uuid::new_v4().to_string();
        let assignment_id = Uuid::new_v4().to_string();
        let commits_before = ffi_test_count(&vault, "commits");
        let commands = vec![
            MdbxWriteCommand::CreateProject {
                project_id: project_id.clone(),
                title: "Mail".to_string(),
            },
            MdbxWriteCommand::CreateEntry {
                entry_id: first_entry_id.clone(),
                project_id: project_id.clone(),
                entry_type: "com.monica.mail.message".to_string(),
                title: "First".to_string(),
                payload_json: r#"{"body":"first"}"#.to_string(),
            },
            MdbxWriteCommand::CreateEntry {
                entry_id: second_entry_id.clone(),
                project_id: project_id.clone(),
                entry_type: "com.monica.mail.message".to_string(),
                title: "Second".to_string(),
                payload_json: r#"{"body":"second"}"#.to_string(),
            },
            MdbxWriteCommand::CreateObjectRelation {
                relation_id: relation_id.clone(),
                source_object_id: first_entry_id.clone(),
                target_object_id: second_entry_id.clone(),
                relation_kind: "com.monica.mail.reply-to".to_string(),
                payload_json: r#"{"position":1}"#.to_string(),
                payload_schema_version: 1,
            },
            MdbxWriteCommand::CreateObjectLabel {
                label_id: label_id.clone(),
                collection_id: project_id.clone(),
                name: "Important".to_string(),
                payload_json: r#"{"color":"red"}"#.to_string(),
                payload_schema_version: 1,
            },
            MdbxWriteCommand::AssignObjectLabel {
                assignment_id: assignment_id.clone(),
                object_id: first_entry_id.clone(),
                label_id: label_id.clone(),
            },
        ];

        let created = vault
            .execute_write_operation(
                operation_id.clone(),
                "mail-thread-import".to_string(),
                commands.clone(),
            )
            .unwrap();
        assert!(!created.already_committed);
        assert_eq!(created.project_ids, vec![project_id.clone()]);
        assert_eq!(
            created.entry_ids,
            vec![first_entry_id.clone(), second_entry_id.clone()]
        );
        assert_eq!(created.relation_ids, vec![relation_id.clone()]);
        assert_eq!(created.label_ids, vec![label_id.clone()]);
        assert_eq!(created.label_assignment_ids, vec![assignment_id.clone()]);
        assert_eq!(ffi_test_count(&vault, "commits"), commits_before + 1);
        {
            let conn = vault.conn.lock().unwrap();
            assert_eq!(
                ObjectRelationRepo::get_by_id(&conn, &relation_id)
                    .unwrap()
                    .unwrap()
                    .head_commit_id,
                created.commit_id
            );
            assert_eq!(
                ObjectLabelRepo::get_by_id(&conn, &label_id)
                    .unwrap()
                    .unwrap()
                    .head_commit_id,
                created.commit_id
            );
            assert_eq!(
                ObjectLabelAssignmentRepo::get_by_id(&conn, &assignment_id)
                    .unwrap()
                    .unwrap()
                    .head_commit_id,
                created.commit_id
            );
        }

        let retry = vault
            .execute_write_operation(
                operation_id.clone(),
                "mail-thread-import".to_string(),
                commands.clone(),
            )
            .unwrap();
        assert!(retry.already_committed);
        assert_eq!(retry.commit_id, created.commit_id);
        let mut changed_commands = commands.clone();
        if let MdbxWriteCommand::CreateObjectRelation { payload_json, .. } =
            &mut changed_commands[3]
        {
            *payload_json = r#"{"position":2}"#.to_string();
        }
        assert!(vault
            .execute_write_operation(
                operation_id,
                "mail-thread-import".to_string(),
                changed_commands,
            )
            .unwrap_err()
            .to_string()
            .contains("reused for a different operation"));

        let updated = vault
            .execute_write_operation(
                Uuid::new_v4().to_string(),
                "mail-thread-update".to_string(),
                vec![
                    MdbxWriteCommand::UpdateObjectRelation {
                        relation_id: relation_id.clone(),
                        relation_kind: "com.monica.mail.thread-member".to_string(),
                        payload_json: r#"{"position":2}"#.to_string(),
                        payload_schema_version: 2,
                    },
                    MdbxWriteCommand::UpdateObjectLabel {
                        label_id: label_id.clone(),
                        name: "Priority".to_string(),
                        payload_json: r#"{"color":"orange"}"#.to_string(),
                        payload_schema_version: 2,
                    },
                ],
            )
            .unwrap();
        assert_eq!(updated.relation_ids, vec![relation_id.clone()]);
        assert_eq!(updated.label_ids, vec![label_id.clone()]);
        assert_eq!(ffi_test_count(&vault, "commits"), commits_before + 2);

        let deleted = vault
            .execute_write_operation(
                Uuid::new_v4().to_string(),
                "mail-thread-delete".to_string(),
                vec![
                    MdbxWriteCommand::RemoveObjectLabelAssignment {
                        assignment_id: assignment_id.clone(),
                    },
                    MdbxWriteCommand::DeleteObjectLabel {
                        label_id: label_id.clone(),
                    },
                    MdbxWriteCommand::DeleteObjectRelation {
                        relation_id: relation_id.clone(),
                    },
                ],
            )
            .unwrap();
        assert_eq!(deleted.relation_ids, vec![relation_id.clone()]);
        assert_eq!(deleted.label_ids, vec![label_id.clone()]);
        assert_eq!(deleted.label_assignment_ids, vec![assignment_id.clone()]);
        assert_eq!(ffi_test_count(&vault, "commits"), commits_before + 3);
        let conn = vault.conn.lock().unwrap();
        assert!(
            ObjectRelationRepo::get_by_id(&conn, &relation_id)
                .unwrap()
                .unwrap()
                .deleted
        );
        assert!(
            ObjectLabelRepo::get_by_id(&conn, &label_id)
                .unwrap()
                .unwrap()
                .deleted
        );
        assert!(
            ObjectLabelAssignmentRepo::get_by_id(&conn, &assignment_id)
                .unwrap()
                .unwrap()
                .deleted
        );
    }

    #[test]
    fn generic_metadata_write_operation_rolls_back_and_enforces_bounds() {
        let vault = ffi_test_vault();
        let project = vault.create_project("Mail".to_string()).unwrap();
        let first = vault
            .create_object(
                project.project_id.clone(),
                "com.monica.mail.message".to_string(),
                "First".to_string(),
                "{}".to_string(),
                1,
            )
            .unwrap();
        let second = vault
            .create_object(
                project.project_id.clone(),
                "com.monica.mail.message".to_string(),
                "Second".to_string(),
                "{}".to_string(),
                1,
            )
            .unwrap();
        let rolled_back_label_id = Uuid::new_v4().to_string();
        let commits_before = ffi_test_count(&vault, "commits");

        assert!(vault
            .execute_write_operation(
                Uuid::new_v4().to_string(),
                "mail-label-import".to_string(),
                vec![
                    MdbxWriteCommand::CreateObjectLabel {
                        label_id: rolled_back_label_id.clone(),
                        collection_id: project.project_id.clone(),
                        name: "Rolled back".to_string(),
                        payload_json: "{}".to_string(),
                        payload_schema_version: 1,
                    },
                    MdbxWriteCommand::AssignObjectLabel {
                        assignment_id: Uuid::new_v4().to_string(),
                        object_id: Uuid::new_v4().to_string(),
                        label_id: rolled_back_label_id.clone(),
                    },
                ],
            )
            .is_err());
        assert_eq!(ffi_test_count(&vault, "commits"), commits_before);
        assert_eq!(ffi_test_count(&vault, "object_labels"), 0);

        let limits = MdbxWriteOperationLimits {
            max_commands: 1,
            max_payload_bytes_per_command: 8,
            max_payload_bytes: 8,
            max_intent_bytes: 4096,
        };
        assert!(vault
            .execute_write_operation_with_limits(
                Uuid::new_v4().to_string(),
                "mail-relation-import".to_string(),
                vec![MdbxWriteCommand::CreateObjectRelation {
                    relation_id: Uuid::new_v4().to_string(),
                    source_object_id: first.object_id.clone(),
                    target_object_id: second.object_id.clone(),
                    relation_kind: "com.monica.mail.reply-to".to_string(),
                    payload_json: r#"{"position":1}"#.to_string(),
                    payload_schema_version: 1,
                }],
                limits,
            )
            .unwrap_err()
            .to_string()
            .contains("command payload bytes"));
        assert_eq!(ffi_test_count(&vault, "commits"), commits_before);
        assert_eq!(ffi_test_count(&vault, "object_relations"), 0);

        vault
            .set_extension_capabilities(vec!["com.monica.mail.store".to_string()])
            .unwrap();
        vault
            .set_collection_profile(
                project.project_id.clone(),
                "com.monica.mail".to_string(),
                b"profile".to_vec(),
                1,
                vec!["com.monica.mail.message".to_string()],
                vec!["com.monica.mail.store".to_string()],
            )
            .unwrap();
        vault.set_extension_capabilities(Vec::new()).unwrap();
        let commits_before_capability_failure = ffi_test_count(&vault, "commits");
        assert!(vault
            .execute_write_operation(
                Uuid::new_v4().to_string(),
                "mail-relation-import".to_string(),
                vec![MdbxWriteCommand::CreateObjectRelation {
                    relation_id: Uuid::new_v4().to_string(),
                    source_object_id: first.object_id,
                    target_object_id: second.object_id,
                    relation_kind: "com.monica.mail.reply-to".to_string(),
                    payload_json: "{}".to_string(),
                    payload_schema_version: 1,
                }],
            )
            .is_err());
        assert_eq!(
            ffi_test_count(&vault, "commits"),
            commits_before_capability_failure
        );
        assert_eq!(ffi_test_count(&vault, "object_relations"), 0);
    }

    #[test]
    fn composite_write_operation_creates_parent_and_attachment_in_one_commit() {
        let vault = ffi_test_vault();
        let project_id = Uuid::new_v4().to_string();
        let entry_id = Uuid::new_v4().to_string();
        let attachment_id = Uuid::new_v4().to_string();
        let operation_id = Uuid::new_v4().to_string();
        let mut limits = default_composite_write_operation_limits();
        limits.write_limits.max_commands = 2;
        limits.write_limits.max_payload_bytes_per_command = 1024;
        limits.write_limits.max_payload_bytes = 1024;
        limits.write_limits.max_intent_bytes = 4096;
        limits.attachment_limits.max_commands = 1;
        limits.attachment_limits.max_plaintext_bytes_per_command = 64;
        limits.attachment_limits.max_plaintext_bytes = 64;
        limits.attachment_limits.chunk_size = 3;
        let generic_commands = vec![
            MdbxWriteCommand::CreateProject {
                project_id: project_id.clone(),
                title: "Mail".to_string(),
            },
            MdbxWriteCommand::CreateEntry {
                entry_id: entry_id.clone(),
                project_id: project_id.clone(),
                entry_type: "com.monica.mail.message".to_string(),
                title: "Message".to_string(),
                payload_json: r#"{"body":"hello"}"#.to_string(),
            },
        ];
        let attachment_commands = vec![MdbxAttachmentBatchCommand::Create {
            attachment_id: attachment_id.clone(),
            project_id: project_id.clone(),
            entry_id: Some(entry_id.clone()),
            file_name: "message.eml".to_string(),
            media_type: Some("message/rfc822".to_string()),
            content: b"mail body".to_vec(),
        }];
        let commits_before = ffi_test_count(&vault, "commits");
        let first = vault
            .execute_composite_write_operation_with_limits(
                operation_id.clone(),
                "mail-import".to_string(),
                generic_commands.clone(),
                attachment_commands.clone(),
                limits,
            )
            .unwrap();
        assert!(!first.operation.already_committed);
        assert_eq!(first.operation.project_ids, vec![project_id.clone()]);
        assert_eq!(first.operation.entry_ids, vec![entry_id.clone()]);
        assert_eq!(first.attachments.len(), 1);
        assert_eq!(first.attachments[0].attachment_id, attachment_id);
        assert_eq!(ffi_test_count(&vault, "commits"), commits_before + 1);
        {
            let conn = vault.conn.lock().unwrap();
            let project = ProjectRepo::get_by_id(&conn, &project_id).unwrap().unwrap();
            let entry = EntryRepo::get_by_id(&conn, &entry_id).unwrap().unwrap();
            let attachment = AttachmentRepo::get_by_id(&conn, &attachment_id)
                .unwrap()
                .unwrap();
            assert_eq!(project.head_commit_id, first.operation.commit_id);
            assert_eq!(entry.head_commit_id, first.operation.commit_id);
            assert_eq!(attachment.head_commit_id, first.operation.commit_id);
        }
        assert_eq!(
            vault
                .read_attachment_content(attachment_id.clone(), 64)
                .unwrap(),
            b"mail body"
        );

        let retry = vault
            .execute_composite_write_operation_with_limits(
                operation_id.clone(),
                "mail-import".to_string(),
                generic_commands.clone(),
                attachment_commands.clone(),
                limits,
            )
            .unwrap();
        assert!(retry.operation.already_committed);
        assert_eq!(retry.operation.commit_id, first.operation.commit_id);
        assert_eq!(ffi_test_count(&vault, "commits"), commits_before + 1);

        let changed_attachment_commands = vec![MdbxAttachmentBatchCommand::Create {
            attachment_id,
            project_id: project_id.clone(),
            entry_id: Some(entry_id.clone()),
            file_name: "message.eml".to_string(),
            media_type: Some("message/rfc822".to_string()),
            content: b"changed body".to_vec(),
        }];
        assert!(vault
            .execute_composite_write_operation_with_limits(
                operation_id,
                "mail-import".to_string(),
                generic_commands,
                changed_attachment_commands,
                limits,
            )
            .unwrap_err()
            .to_string()
            .contains("reused for a different operation"));

        let failed_project_id = Uuid::new_v4().to_string();
        let failed_entry_id = Uuid::new_v4().to_string();
        let failed_attachment_id = Uuid::new_v4().to_string();
        assert!(vault
            .execute_composite_write_operation(
                Uuid::new_v4().to_string(),
                "mail-import".to_string(),
                vec![
                    MdbxWriteCommand::CreateProject {
                        project_id: failed_project_id.clone(),
                        title: "Rolled back".to_string(),
                    },
                    MdbxWriteCommand::CreateEntry {
                        entry_id: failed_entry_id.clone(),
                        project_id: failed_project_id.clone(),
                        entry_type: "com.monica.mail.message".to_string(),
                        title: "Failure".to_string(),
                        payload_json: "{}".to_string(),
                    },
                ],
                vec![MdbxAttachmentBatchCommand::Create {
                    attachment_id: failed_attachment_id.clone(),
                    project_id: failed_project_id.clone(),
                    entry_id: Some(Uuid::new_v4().to_string()),
                    file_name: "failure.eml".to_string(),
                    media_type: None,
                    content: b"failure".to_vec(),
                }],
            )
            .is_err());
        assert_eq!(ffi_test_count(&vault, "commits"), commits_before + 1);
        {
            let conn = vault.conn.lock().unwrap();
            assert!(ProjectRepo::get_by_id(&conn, &failed_project_id)
                .unwrap()
                .is_none());
            assert!(EntryRepo::get_by_id(&conn, &failed_entry_id)
                .unwrap()
                .is_none());
            assert!(AttachmentRepo::get_by_id(&conn, &failed_attachment_id)
                .unwrap()
                .is_none());
        }

        let bounded_project_id = Uuid::new_v4().to_string();
        let bounded_entry_id = Uuid::new_v4().to_string();
        let mut bounded_limits = default_composite_write_operation_limits();
        bounded_limits.write_limits.max_commands = 2;
        bounded_limits.write_limits.max_payload_bytes_per_command = 1024;
        bounded_limits.write_limits.max_payload_bytes = 1024;
        bounded_limits.write_limits.max_intent_bytes = 4096;
        bounded_limits.attachment_limits.max_commands = 1;
        bounded_limits
            .attachment_limits
            .max_plaintext_bytes_per_command = 4;
        bounded_limits.attachment_limits.max_plaintext_bytes = 4;
        bounded_limits.attachment_limits.chunk_size = 2;
        assert!(vault
            .execute_composite_write_operation_with_limits(
                Uuid::new_v4().to_string(),
                "mail-import".to_string(),
                vec![
                    MdbxWriteCommand::CreateProject {
                        project_id: bounded_project_id.clone(),
                        title: "Bounded".to_string(),
                    },
                    MdbxWriteCommand::CreateEntry {
                        entry_id: bounded_entry_id.clone(),
                        project_id: bounded_project_id.clone(),
                        entry_type: "com.monica.mail.message".to_string(),
                        title: "Bounded".to_string(),
                        payload_json: "{}".to_string(),
                    },
                ],
                vec![MdbxAttachmentBatchCommand::Create {
                    attachment_id: Uuid::new_v4().to_string(),
                    project_id: bounded_project_id.clone(),
                    entry_id: Some(bounded_entry_id),
                    file_name: "oversized.eml".to_string(),
                    media_type: None,
                    content: b"12345".to_vec(),
                }],
                bounded_limits,
            )
            .unwrap_err()
            .to_string()
            .contains("command plaintext bytes"));
        assert_eq!(ffi_test_count(&vault, "commits"), commits_before + 1);
        let conn = vault.conn.lock().unwrap();
        assert!(ProjectRepo::get_by_id(&conn, &bounded_project_id)
            .unwrap()
            .is_none());
    }

    #[test]
    fn every_write_command_has_a_typed_change_summary() {
        let commands = vec![
            MdbxWriteCommand::CreateProject {
                project_id: "project".to_string(),
                title: "Project".to_string(),
            },
            MdbxWriteCommand::CreateEntry {
                entry_id: "created".to_string(),
                project_id: "project".to_string(),
                entry_type: "login".to_string(),
                title: "Created".to_string(),
                payload_json: "{}".to_string(),
            },
            MdbxWriteCommand::UpdateEntry {
                entry_id: "updated".to_string(),
                project_id: "project".to_string(),
                entry_type: "login".to_string(),
                title: "Updated".to_string(),
                payload_json: "{}".to_string(),
            },
            MdbxWriteCommand::DeleteEntry {
                entry_id: "deleted".to_string(),
                project_id: "project".to_string(),
            },
            MdbxWriteCommand::RestoreEntry {
                entry_id: "restored".to_string(),
                project_id: "project".to_string(),
            },
            MdbxWriteCommand::MoveEntry {
                entry_id: "moved".to_string(),
                project_id: "project".to_string(),
                target_project_id: "target".to_string(),
            },
            MdbxWriteCommand::CreateObjectRelation {
                relation_id: "relation-created".to_string(),
                source_object_id: "source".to_string(),
                target_object_id: "target".to_string(),
                relation_kind: "com.monica.test.relation".to_string(),
                payload_json: "{}".to_string(),
                payload_schema_version: 1,
            },
            MdbxWriteCommand::UpdateObjectRelation {
                relation_id: "relation-updated".to_string(),
                relation_kind: "com.monica.test.relation".to_string(),
                payload_json: "{}".to_string(),
                payload_schema_version: 2,
            },
            MdbxWriteCommand::DeleteObjectRelation {
                relation_id: "relation-deleted".to_string(),
            },
            MdbxWriteCommand::CreateObjectLabel {
                label_id: "label-created".to_string(),
                collection_id: "project".to_string(),
                name: "Created".to_string(),
                payload_json: "{}".to_string(),
                payload_schema_version: 1,
            },
            MdbxWriteCommand::UpdateObjectLabel {
                label_id: "label-updated".to_string(),
                name: "Updated".to_string(),
                payload_json: "{}".to_string(),
                payload_schema_version: 2,
            },
            MdbxWriteCommand::DeleteObjectLabel {
                label_id: "label-deleted".to_string(),
            },
            MdbxWriteCommand::AssignObjectLabel {
                assignment_id: "assignment-created".to_string(),
                object_id: "created".to_string(),
                label_id: "label-created".to_string(),
            },
            MdbxWriteCommand::RemoveObjectLabelAssignment {
                assignment_id: "assignment-deleted".to_string(),
            },
        ];

        let changes = write_operation_changes(&commands);
        let actions = changes
            .iter()
            .map(|change| change.action.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            actions,
            vec![
                "create", "create", "update", "delete", "restore", "move", "create", "update",
                "delete", "create", "update", "delete", "create", "delete"
            ]
        );
        assert_eq!(changes[0].fields, vec!["title"]);
        assert_eq!(
            changes[1].fields,
            vec!["project_id", "entry_type", "title", "payload"]
        );
        assert_eq!(changes[2].fields, vec!["title", "payload"]);
        assert_eq!(changes[3].fields, vec!["deleted"]);
        assert_eq!(changes[4].fields, vec!["deleted"]);
        assert_eq!(changes[5].fields, vec!["project_id"]);
        assert_eq!(
            changes[6].fields,
            vec![
                "source_object_id",
                "target_object_id",
                "relation_kind",
                "payload",
                "payload_schema_version"
            ]
        );
        assert_eq!(
            changes[7].fields,
            vec!["relation_kind", "payload", "payload_schema_version"]
        );
        assert_eq!(changes[8].fields, vec!["deleted"]);
        assert_eq!(
            changes[9].fields,
            vec!["collection_id", "name", "payload", "payload_schema_version"]
        );
        assert_eq!(
            changes[10].fields,
            vec!["name", "payload", "payload_schema_version"]
        );
        assert_eq!(changes[11].fields, vec!["deleted"]);
        assert_eq!(changes[12].fields, vec!["object_id", "label_id"]);
        assert_eq!(changes[13].fields, vec!["deleted"]);
    }
}
