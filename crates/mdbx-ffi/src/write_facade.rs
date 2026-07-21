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

pub(crate) const DEFAULT_MAX_WRITE_COMMANDS: usize = 256;
pub(crate) const HARD_MAX_WRITE_COMMANDS: usize = 4_096;
pub(crate) const DEFAULT_MAX_WRITE_PAYLOAD_BYTES_PER_COMMAND: usize = 1024 * 1024;
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
    pub(crate) fn into_internal(self) -> Result<InternalWriteOperationLimits, MdbxFfiError> {
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
pub(crate) struct InternalWriteOperationLimits {
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

pub(crate) fn validate_uuid(value: &str, field: &str) -> Result<(), MdbxFfiError> {
    Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| StorageError::Validation(format!("{field} {value} must be a UUID")).into())
}

fn parse_write_object_type(entry_type: &str) -> Result<EntryType, MdbxFfiError> {
    entry_type
        .parse()
        .map_err(|_| MdbxFfiError::InvalidEntryType {
            entry_type: entry_type.to_string(),
        })
}

use std::io::{self, Write};

use mdbx_core::model::EntryType;
use mdbx_storage::connection::VaultConnection;
use mdbx_storage::error::{StorageError, StorageResult};
use mdbx_storage::repo::{
    AttachmentRepo, CommitChange, CommitContext, CommitOperation, EntryRepo,
    ObjectLabelAssignmentCreateRequest, ObjectLabelAssignmentRepo, ObjectLabelCreateRequest,
    ObjectLabelRepo, ObjectRelationCreateRequest, ObjectRelationRepo, OperationExecution,
    ProjectRepo,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::attachment_facade::{
    attachment_batch_changes, attachment_batch_ids, attachment_record_from_core,
    execute_attachment_batch_commands, hash_attachment_batch_intent, update_attachment_intent_part,
    validate_attachment_batch_operation_inputs,
};
use super::{
    default_attachment_batch_limits, entry_for_project, parse_payload_json, parse_relation_kind,
    MdbxAttachmentBatchCommand, MdbxAttachmentBatchLimits, MdbxAttachmentRecord, MdbxFfiError,
    MdbxVault,
};

fn validate_write_operation(
    operation_id: &str,
    operation_kind: &str,
    commands: &[MdbxWriteCommand],
    limits: InternalWriteOperationLimits,
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
    if commands.len() > limits.max_commands {
        return Err(StorageError::ResourceLimit {
            resource: "write operation commands".to_string(),
            actual: commands.len() as u64,
            limit: limits.max_commands as u64,
        }
        .into());
    }
    let mut total_payload_bytes = 0usize;
    for command in commands {
        let Some(payload_json) = validate_write_command(command)? else {
            continue;
        };
        let payload_bytes = payload_json.len();
        if payload_bytes > limits.max_payload_bytes_per_command {
            return Err(StorageError::ResourceLimit {
                resource: "write operation command payload bytes".to_string(),
                actual: payload_bytes as u64,
                limit: limits.max_payload_bytes_per_command as u64,
            }
            .into());
        }
        total_payload_bytes = total_payload_bytes
            .checked_add(payload_bytes)
            .ok_or_else(|| StorageError::ResourceLimit {
                resource: "write operation payload bytes".to_string(),
                actual: u64::MAX,
                limit: limits.max_payload_bytes as u64,
            })?;
        if total_payload_bytes > limits.max_payload_bytes {
            return Err(StorageError::ResourceLimit {
                resource: "write operation payload bytes".to_string(),
                actual: total_payload_bytes as u64,
                limit: limits.max_payload_bytes as u64,
            }
            .into());
        }
        parse_payload_json(payload_json)?;
    }
    Ok(())
}

fn validate_write_command(command: &MdbxWriteCommand) -> Result<Option<&str>, MdbxFfiError> {
    let payload_json = match command {
        MdbxWriteCommand::CreateProject { project_id, .. } => {
            validate_uuid(project_id, "project_id")?;
            None
        }
        MdbxWriteCommand::CreateEntry {
            entry_id,
            project_id,
            entry_type,
            payload_json,
            ..
        }
        | MdbxWriteCommand::UpdateEntry {
            entry_id,
            project_id,
            entry_type,
            payload_json,
            ..
        } => {
            validate_uuid(entry_id, "entry_id")?;
            validate_uuid(project_id, "project_id")?;
            parse_write_object_type(entry_type)?;
            Some(payload_json.as_str())
        }
        MdbxWriteCommand::DeleteEntry {
            entry_id,
            project_id,
        }
        | MdbxWriteCommand::RestoreEntry {
            entry_id,
            project_id,
        } => {
            validate_uuid(entry_id, "entry_id")?;
            validate_uuid(project_id, "project_id")?;
            None
        }
        MdbxWriteCommand::MoveEntry {
            entry_id,
            project_id,
            target_project_id,
        } => {
            validate_uuid(entry_id, "entry_id")?;
            validate_uuid(project_id, "project_id")?;
            validate_uuid(target_project_id, "target_project_id")?;
            None
        }
        MdbxWriteCommand::CreateObjectRelation {
            relation_id,
            source_object_id,
            target_object_id,
            relation_kind,
            payload_json,
            payload_schema_version,
        } => {
            validate_uuid(relation_id, "relation_id")?;
            validate_uuid(source_object_id, "source_object_id")?;
            validate_uuid(target_object_id, "target_object_id")?;
            if source_object_id == target_object_id {
                return Err(StorageError::Validation(
                    "self relations require an explicit adapter object instead of an identity edge"
                        .to_string(),
                )
                .into());
            }
            parse_relation_kind(relation_kind)?;
            validate_write_payload_schema_version(*payload_schema_version)?;
            Some(payload_json.as_str())
        }
        MdbxWriteCommand::UpdateObjectRelation {
            relation_id,
            relation_kind,
            payload_json,
            payload_schema_version,
        } => {
            validate_uuid(relation_id, "relation_id")?;
            parse_relation_kind(relation_kind)?;
            validate_write_payload_schema_version(*payload_schema_version)?;
            Some(payload_json.as_str())
        }
        MdbxWriteCommand::DeleteObjectRelation { relation_id } => {
            validate_uuid(relation_id, "relation_id")?;
            None
        }
        MdbxWriteCommand::CreateObjectLabel {
            label_id,
            collection_id,
            name,
            payload_json,
            payload_schema_version,
        } => {
            validate_uuid(label_id, "label_id")?;
            validate_uuid(collection_id, "collection_id")?;
            validate_write_label_name(name)?;
            validate_write_payload_schema_version(*payload_schema_version)?;
            Some(payload_json.as_str())
        }
        MdbxWriteCommand::UpdateObjectLabel {
            label_id,
            name,
            payload_json,
            payload_schema_version,
        } => {
            validate_uuid(label_id, "label_id")?;
            validate_write_label_name(name)?;
            validate_write_payload_schema_version(*payload_schema_version)?;
            Some(payload_json.as_str())
        }
        MdbxWriteCommand::DeleteObjectLabel { label_id } => {
            validate_uuid(label_id, "label_id")?;
            None
        }
        MdbxWriteCommand::AssignObjectLabel {
            assignment_id,
            object_id,
            label_id,
        } => {
            validate_uuid(assignment_id, "assignment_id")?;
            validate_uuid(object_id, "object_id")?;
            validate_uuid(label_id, "label_id")?;
            None
        }
        MdbxWriteCommand::RemoveObjectLabelAssignment { assignment_id } => {
            validate_uuid(assignment_id, "assignment_id")?;
            None
        }
    };
    Ok(payload_json)
}

fn validate_write_payload_schema_version(value: u32) -> Result<(), MdbxFfiError> {
    if value == 0 {
        return Err(StorageError::Validation(
            "payload_schema_version must be greater than zero".to_string(),
        )
        .into());
    }
    Ok(())
}

fn validate_write_label_name(value: &str) -> Result<(), MdbxFfiError> {
    if value.trim().is_empty() || value.len() > 512 {
        return Err(StorageError::Validation(
            "object label name must contain 1 to 512 UTF-8 bytes".to_string(),
        )
        .into());
    }
    Ok(())
}

pub(crate) fn hash_write_operation_intent(
    commands: &[MdbxWriteCommand],
    limit: usize,
) -> Result<Vec<u8>, MdbxFfiError> {
    let mut writer = LimitedIntentHashWriter::new(limit);
    if let Err(error) = serde_json::to_writer(&mut writer, commands) {
        if let Some(actual) = writer.exceeded_at {
            return Err(StorageError::ResourceLimit {
                resource: "write operation serialized intent bytes".to_string(),
                actual: actual as u64,
                limit: limit as u64,
            }
            .into());
        }
        return Err(error.into());
    }
    Ok(writer.finalize())
}

struct LimitedIntentHashWriter {
    hasher: Sha256,
    bytes_written: usize,
    limit: usize,
    exceeded_at: Option<usize>,
}

impl LimitedIntentHashWriter {
    fn new(limit: usize) -> Self {
        Self {
            hasher: Sha256::new(),
            bytes_written: 0,
            limit,
            exceeded_at: None,
        }
    }

    fn finalize(self) -> Vec<u8> {
        self.hasher.finalize().to_vec()
    }
}

impl Write for LimitedIntentHashWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let actual = self
            .bytes_written
            .checked_add(buffer.len())
            .unwrap_or(usize::MAX);
        if actual > self.limit {
            self.exceeded_at = Some(actual);
            return Err(io::Error::other(
                "write operation serialized intent limit exceeded",
            ));
        }
        self.hasher.update(buffer);
        self.bytes_written = actual;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn write_operation_changes(commands: &[MdbxWriteCommand]) -> Vec<CommitChange> {
    let mut changes = Vec::new();
    for command in commands {
        let (object_type, object_id, action, fields): (&str, &String, &str, &[&str]) = match command
        {
            MdbxWriteCommand::CreateProject { project_id, .. } => {
                ("project", project_id, "create", &["title"])
            }
            MdbxWriteCommand::CreateEntry { entry_id, .. } => (
                "entry",
                entry_id,
                "create",
                &["project_id", "entry_type", "title", "payload"],
            ),
            MdbxWriteCommand::UpdateEntry { entry_id, .. } => {
                ("entry", entry_id, "update", &["title", "payload"])
            }
            MdbxWriteCommand::DeleteEntry { entry_id, .. } => {
                ("entry", entry_id, "delete", &["deleted"])
            }
            MdbxWriteCommand::RestoreEntry { entry_id, .. } => {
                ("entry", entry_id, "restore", &["deleted"])
            }
            MdbxWriteCommand::MoveEntry { entry_id, .. } => {
                ("entry", entry_id, "move", &["project_id"])
            }
            MdbxWriteCommand::CreateObjectRelation { relation_id, .. } => (
                "object-relation",
                relation_id,
                "create",
                &[
                    "source_object_id",
                    "target_object_id",
                    "relation_kind",
                    "payload",
                    "payload_schema_version",
                ],
            ),
            MdbxWriteCommand::UpdateObjectRelation { relation_id, .. } => (
                "object-relation",
                relation_id,
                "update",
                &["relation_kind", "payload", "payload_schema_version"],
            ),
            MdbxWriteCommand::DeleteObjectRelation { relation_id } => {
                ("object-relation", relation_id, "delete", &["deleted"])
            }
            MdbxWriteCommand::CreateObjectLabel { label_id, .. } => (
                "object-label",
                label_id,
                "create",
                &["collection_id", "name", "payload", "payload_schema_version"],
            ),
            MdbxWriteCommand::UpdateObjectLabel { label_id, .. } => (
                "object-label",
                label_id,
                "update",
                &["name", "payload", "payload_schema_version"],
            ),
            MdbxWriteCommand::DeleteObjectLabel { label_id } => {
                ("object-label", label_id, "delete", &["deleted"])
            }
            MdbxWriteCommand::AssignObjectLabel { assignment_id, .. } => (
                "object-label-assignment",
                assignment_id,
                "create",
                &["object_id", "label_id"],
            ),
            MdbxWriteCommand::RemoveObjectLabelAssignment { assignment_id } => (
                "object-label-assignment",
                assignment_id,
                "delete",
                &["deleted"],
            ),
        };
        let incoming = CommitChange {
            object_type: object_type.to_string(),
            object_id: object_id.clone(),
            action: action.to_string(),
            fields: fields.iter().map(|field| (*field).to_string()).collect(),
        };
        if let Some(existing) = changes.iter_mut().find(|change: &&mut CommitChange| {
            change.object_type == object_type && change.object_id == *object_id
        }) {
            if existing.action != incoming.action {
                existing.action = "change".to_string();
            }
            for field in incoming.fields {
                if !existing.fields.contains(&field) {
                    existing.fields.push(field);
                }
            }
        } else {
            changes.push(incoming);
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
                let entry_type = parse_write_object_type(entry_type)
                    .map_err(|error| StorageError::Validation(error.to_string()))?;
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
                let expected_type = parse_write_object_type(entry_type)
                    .map_err(|error| StorageError::Validation(error.to_string()))?;
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
            MdbxWriteCommand::CreateObjectRelation {
                relation_id,
                source_object_id,
                target_object_id,
                relation_kind,
                payload_json,
                payload_schema_version,
            } => {
                ObjectRelationRepo::create(
                    conn,
                    ctx,
                    ObjectRelationCreateRequest::new(
                        source_object_id,
                        target_object_id,
                        parse_relation_kind(relation_kind)
                            .map_err(|error| StorageError::Validation(error.to_string()))?,
                        parse_write_payload(payload_json)?,
                    )
                    .with_relation_id(relation_id)
                    .with_payload_schema_version(*payload_schema_version),
                )?;
            }
            MdbxWriteCommand::UpdateObjectRelation {
                relation_id,
                relation_kind,
                payload_json,
                payload_schema_version,
            } => {
                let mut relation = ObjectRelationRepo::get_by_id(conn, relation_id)?
                    .ok_or_else(|| StorageError::NotFound(relation_id.clone()))?;
                relation.relation_kind = parse_relation_kind(relation_kind)
                    .map_err(|error| StorageError::Validation(error.to_string()))?;
                relation.payload_ct = serde_json::to_vec(&parse_write_payload(payload_json)?)
                    .map_err(|error| StorageError::Validation(error.to_string()))?;
                relation.payload_schema_version = *payload_schema_version;
                ObjectRelationRepo::update(conn, ctx, &relation)?;
            }
            MdbxWriteCommand::DeleteObjectRelation { relation_id } => {
                ObjectRelationRepo::soft_delete(conn, ctx, relation_id)?;
            }
            MdbxWriteCommand::CreateObjectLabel {
                label_id,
                collection_id,
                name,
                payload_json,
                payload_schema_version,
            } => {
                ObjectLabelRepo::create(
                    conn,
                    ctx,
                    ObjectLabelCreateRequest::new(
                        collection_id,
                        name,
                        parse_write_payload(payload_json)?,
                    )
                    .with_label_id(label_id)
                    .with_payload_schema_version(*payload_schema_version),
                )?;
            }
            MdbxWriteCommand::UpdateObjectLabel {
                label_id,
                name,
                payload_json,
                payload_schema_version,
            } => {
                let mut label = ObjectLabelRepo::get_by_id(conn, label_id)?
                    .ok_or_else(|| StorageError::NotFound(label_id.clone()))?;
                label.name_ct = name.as_bytes().to_vec();
                label.payload_ct = serde_json::to_vec(&parse_write_payload(payload_json)?)
                    .map_err(|error| StorageError::Validation(error.to_string()))?;
                label.payload_schema_version = *payload_schema_version;
                ObjectLabelRepo::update(conn, ctx, &label)?;
            }
            MdbxWriteCommand::DeleteObjectLabel { label_id } => {
                ObjectLabelRepo::soft_delete(conn, ctx, label_id)?;
            }
            MdbxWriteCommand::AssignObjectLabel {
                assignment_id,
                object_id,
                label_id,
            } => {
                ObjectLabelAssignmentRepo::create(
                    conn,
                    ctx,
                    ObjectLabelAssignmentCreateRequest::new(object_id, label_id)
                        .with_assignment_id(assignment_id),
                )?;
            }
            MdbxWriteCommand::RemoveObjectLabelAssignment { assignment_id } => {
                ObjectLabelAssignmentRepo::soft_delete(conn, ctx, assignment_id)?;
            }
        }
    }
    Ok(())
}

fn parse_write_payload(payload_json: &str) -> StorageResult<serde_json::Value> {
    serde_json::from_str(payload_json).map_err(|error| StorageError::Validation(error.to_string()))
}

pub(crate) fn execute_write_operation_for_branch(
    vault: &MdbxVault,
    branch_id: Option<String>,
    operation_id: String,
    operation_kind: String,
    commands: Vec<MdbxWriteCommand>,
    limits: InternalWriteOperationLimits,
) -> Result<MdbxWriteOperationResult, MdbxFfiError> {
    validate_write_operation(&operation_id, &operation_kind, &commands, limits)?;
    let intent_hash = hash_write_operation_intent(&commands, limits.max_intent_bytes)?;
    let changed_objects = write_operation_changes(&commands);
    let mut operation = CommitOperation::new(
        operation_id,
        operation_kind,
        branch_id.as_deref().map(|_| "").unwrap_or("main"),
        "change",
        write_operation_scope(&changed_objects),
        changed_objects,
    )
    .with_intent_hash(intent_hash);
    if let Some(branch_id) = branch_id {
        operation = operation.with_branch_id(branch_id);
    }

    let conn = vault.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
    let ctx = CommitContext::new(vault.device_id.clone());
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

pub(crate) struct CompositeWriteOperation {
    pub(crate) branch_id: Option<String>,
    pub(crate) operation_id: String,
    pub(crate) operation_kind: String,
    pub(crate) commands: Vec<MdbxWriteCommand>,
    pub(crate) attachment_commands: Vec<MdbxAttachmentBatchCommand>,
    pub(crate) write_limits: InternalWriteOperationLimits,
    pub(crate) attachment_limits: MdbxAttachmentBatchLimits,
}

pub(crate) fn execute_composite_write_operation(
    vault: &MdbxVault,
    request: CompositeWriteOperation,
) -> Result<MdbxCompositeWriteOperationResult, MdbxFfiError> {
    if request.commands.is_empty() || request.attachment_commands.is_empty() {
        return Err(StorageError::Validation(
            "composite write operation requires generic and attachment commands".to_string(),
        )
        .into());
    }
    validate_write_operation(
        &request.operation_id,
        &request.operation_kind,
        &request.commands,
        request.write_limits,
    )?;
    let chunk_size = validate_attachment_batch_operation_inputs(
        &request.operation_id,
        &request.attachment_commands,
        request.attachment_limits,
    )?;
    let generic_intent_hash =
        hash_write_operation_intent(&request.commands, request.write_limits.max_intent_bytes)?;
    let attachment_intent_hash = hash_attachment_batch_intent(
        &request.operation_id,
        &request.attachment_commands,
        request.attachment_limits,
    );
    let intent_hash = hash_composite_write_intent(
        &request.operation_id,
        &request.operation_kind,
        &generic_intent_hash,
        &attachment_intent_hash,
    );
    let attachment_ids = attachment_batch_ids(&request.attachment_commands);
    let mut changed_objects = write_operation_changes(&request.commands);
    changed_objects.extend(attachment_batch_changes(&request.attachment_commands));
    let mut operation = CommitOperation::new(
        request.operation_id,
        request.operation_kind,
        request.branch_id.as_deref().map(|_| "").unwrap_or("main"),
        "change",
        write_operation_scope(&changed_objects),
        changed_objects,
    )
    .with_intent_hash(intent_hash);
    if let Some(branch_id) = request.branch_id {
        operation = operation.with_branch_id(branch_id);
    }

    let generic_commands = request.commands;
    let attachment_commands = request.attachment_commands;
    let conn = vault.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
    let ctx = CommitContext::new(vault.device_id.clone());
    let ids_for_action = attachment_ids.clone();
    let execution = ctx.run_operation(&conn, operation, |scoped| {
        execute_write_commands(&conn, scoped, &generic_commands)?;
        execute_attachment_batch_commands(
            &conn,
            scoped,
            attachment_commands,
            chunk_size,
            &ids_for_action,
        )
    })?;
    let (commit_id, already_committed) = match execution {
        OperationExecution::Applied { commit_id, .. } => (commit_id, false),
        OperationExecution::AlreadyCommitted { commit_id } => (commit_id, true),
    };
    let attachments = attachment_ids
        .iter()
        .map(|attachment_id| {
            AttachmentRepo::get_by_id(&conn, attachment_id)?
                .ok_or_else(|| StorageError::NotFound(attachment_id.clone()))
        })
        .collect::<StorageResult<Vec<_>>>()?
        .iter()
        .map(attachment_record_from_core)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(MdbxCompositeWriteOperationResult {
        operation: write_operation_result(&generic_commands, commit_id, already_committed),
        attachments,
    })
}

fn hash_composite_write_intent(
    operation_id: &str,
    operation_kind: &str,
    generic_intent_hash: &[u8],
    attachment_intent_hash: &[u8],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    update_attachment_intent_part(&mut hasher, b"mdbx-ffi-composite-write-v1");
    update_attachment_intent_part(&mut hasher, operation_id.as_bytes());
    update_attachment_intent_part(&mut hasher, operation_kind.as_bytes());
    update_attachment_intent_part(&mut hasher, generic_intent_hash);
    update_attachment_intent_part(&mut hasher, attachment_intent_hash);
    hasher.finalize().to_vec()
}

fn write_operation_result(
    commands: &[MdbxWriteCommand],
    commit_id: String,
    already_committed: bool,
) -> MdbxWriteOperationResult {
    let changes = write_operation_changes(commands);
    let mut project_ids = Vec::new();
    let mut entry_ids = Vec::new();
    let mut relation_ids = Vec::new();
    let mut label_ids = Vec::new();
    let mut label_assignment_ids = Vec::new();
    for change in changes {
        match change.object_type.as_str() {
            "project" => project_ids.push(change.object_id),
            "entry" => entry_ids.push(change.object_id),
            "object-relation" => relation_ids.push(change.object_id),
            "object-label" => label_ids.push(change.object_id),
            "object-label-assignment" => label_assignment_ids.push(change.object_id),
            _ => {}
        }
    }
    MdbxWriteOperationResult {
        commit_id,
        already_committed,
        project_ids,
        entry_ids,
        relation_ids,
        label_ids,
        label_assignment_ids,
    }
}

#[uniffi::export]
impl MdbxVault {
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
}
