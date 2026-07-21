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
pub use conflict_facade::*;
pub use lifecycle_facade::*;
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

#[cfg(test)]
use mdbx_core::model::{EntryType, RelationKindId};
#[cfg(test)]
use mdbx_core::tiga::{TigaMode, TigaScope};
use mdbx_storage::connection::VaultConnection;
use mdbx_storage::error::StorageError;
use mdbx_storage::migration::MigrationInfo;
#[cfg(test)]
use mdbx_storage::repo::EntryRepo;
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
