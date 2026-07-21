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

pub use attachment_facade::*;
pub use object_facade::*;
pub(crate) use object_facade::{
    entry_for_project, parse_object_type_id, parse_payload_json, parse_relation_kind,
};
#[cfg(test)]
pub(crate) use security_facade::scope_from_core;
pub use security_facade::*;
pub(crate) use security_facade::{conservative_ffi_device_context, unix_now};
pub use sync_facade::*;
pub use vault_facade::*;
pub(crate) use write_facade::validate_uuid;
pub use write_facade::*;
#[cfg(test)]
pub(crate) use write_facade::{
    DEFAULT_MAX_WRITE_COMMANDS, DEFAULT_MAX_WRITE_PAYLOAD_BYTES_PER_COMMAND,
    HARD_MAX_WRITE_COMMANDS,
};

use std::sync::Mutex;

use mdbx_core::model::Tombstone;
#[cfg(test)]
use mdbx_core::model::{EntryType, RelationKindId};
#[cfg(test)]
use mdbx_core::tiga::{TigaMode, TigaScope};
use mdbx_storage::backup::VaultBackupInfo;
use mdbx_storage::connection::VaultConnection;
use mdbx_storage::error::StorageError;
use mdbx_storage::migration::MigrationInfo;
use mdbx_storage::recovery::{HealthCheckResult, HealthIssue, IssueSeverity};
#[cfg(test)]
use mdbx_storage::repo::EntryRepo;
use mdbx_storage::repo::{
    PermanentPurgeReceipt, TombstonePurgeBlocker, TombstonePurgeEligibility,
    TombstonePurgeScheduleResult,
};
#[cfg(test)]
use uuid::Uuid;

uniffi::setup_scaffolding!();

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

#[cfg(test)]
mod tests;
