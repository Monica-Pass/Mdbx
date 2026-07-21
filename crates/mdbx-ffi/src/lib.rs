//! Generic UniFFI boundary for MDBX vault clients.
//!
//! This crate exposes vault, generic object, metadata, and attachment
//! operations. Product-specific payload meaning belongs in each client.

mod attachment_facade;
mod conflict_facade;
mod extension_facade;
mod history_facade;
mod lifecycle_facade;
mod object_facade;
mod security_facade;
mod sync_facade;
mod vault_facade;
mod write_facade;

#[cfg(test)]
use attachment_facade::*;
#[cfg(test)]
pub(crate) use security_facade::scope_from_core;
pub use security_facade::*;
pub(crate) use security_facade::{conservative_ffi_device_context, unix_now};
pub use sync_facade::*;
pub use vault_facade::*;
#[cfg(test)]
use write_facade::*;

use std::sync::Mutex;

use mdbx_core::model::{
    EntryType, ObjectSummary, ObjectTypeId, PayloadMigrationExecution, PayloadMigrationPlan,
    PayloadMigrationPlanItem, RelationKindId, Tombstone,
};
#[cfg(test)]
use mdbx_core::tiga::{TigaMode, TigaScope};
use mdbx_storage::backup::VaultBackupInfo;
use mdbx_storage::connection::VaultConnection;
use mdbx_storage::error::{StorageError, StorageResult};
use mdbx_storage::migration::MigrationInfo;
use mdbx_storage::recovery::{HealthCheckResult, HealthIssue, IssueSeverity};
use mdbx_storage::repo::{
    EntryRepo, PermanentPurgeReceipt, TombstonePurgeBlocker, TombstonePurgeEligibility,
    TombstonePurgeScheduleResult,
};
use uuid::Uuid;

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

#[derive(uniffi::Object)]
pub struct MdbxVault {
    conn: Mutex<VaultConnection>,
    device_id: String,
    vault_id: String,
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
mod tests;
