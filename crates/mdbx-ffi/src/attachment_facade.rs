use std::io::{self, Cursor, Write};
use std::sync::Mutex;

use mdbx_core::model::Attachment;
use mdbx_storage::connection::VaultConnection;
use mdbx_storage::error::{StorageError, StorageResult};
use mdbx_storage::repo::{
    AttachmentRepo, AttachmentWriteOptions, CommitChange, CommitContext, CommitOperation,
    OperationExecution,
};
use sha2::{Digest, Sha256};

use super::{
    validate_uuid, MdbxAttachmentBatchCommand, MdbxAttachmentBatchLimits,
    MdbxAttachmentBatchResult, MdbxAttachmentContentLimits, MdbxAttachmentRecord,
    MdbxAttachmentWriteResult, MdbxFfiError, HARD_MAX_ATTACHMENT_BATCH_COMMANDS,
    HARD_MAX_ATTACHMENT_BATCH_PLAINTEXT_BYTES, HARD_MAX_ATTACHMENT_CHUNK_SIZE,
    HARD_MAX_ATTACHMENT_PLAINTEXT_BYTES,
};

pub(crate) struct AttachmentContentOperation<'a> {
    pub(crate) operation_id: String,
    pub(crate) operation_kind: String,
    pub(crate) attachment_id: String,
    pub(crate) fields: Vec<&'a str>,
    pub(crate) intent_hash: Vec<u8>,
}

pub(crate) fn execute_attachment_content_operation<F>(
    conn: &Mutex<VaultConnection>,
    device_id: &str,
    spec: AttachmentContentOperation<'_>,
    action: F,
) -> Result<MdbxAttachmentWriteResult, MdbxFfiError>
where
    F: FnOnce(&VaultConnection, &CommitContext) -> StorageResult<Attachment>,
{
    let AttachmentContentOperation {
        operation_id,
        operation_kind,
        attachment_id,
        fields,
        intent_hash,
    } = spec;
    let operation = CommitOperation::new(
        operation_id,
        operation_kind,
        "main",
        "change",
        "attachment",
        vec![CommitChange {
            object_type: "attachment".to_string(),
            object_id: attachment_id.clone(),
            action: "change".to_string(),
            fields: fields.into_iter().map(str::to_string).collect(),
        }],
    )
    .with_intent_hash(intent_hash);
    let conn = conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
    let ctx = CommitContext::new(device_id.to_string());
    let execution = ctx.run_operation(&conn, operation, |scoped| action(&conn, scoped))?;
    let (attachment, commit_id, already_committed) = match execution {
        OperationExecution::Applied { value, commit_id } => (value, commit_id, false),
        OperationExecution::AlreadyCommitted { commit_id } => {
            let value = AttachmentRepo::get_by_id(&conn, &attachment_id)?
                .ok_or_else(|| StorageError::NotFound(attachment_id.clone()))?;
            (value, commit_id, true)
        }
    };
    Ok(MdbxAttachmentWriteResult {
        attachment: attachment_record_from_core(&attachment)?,
        commit_id,
        already_committed,
    })
}

pub(crate) fn validate_attachment_batch_operation_inputs(
    operation_id: &str,
    commands: &[MdbxAttachmentBatchCommand],
    limits: MdbxAttachmentBatchLimits,
) -> Result<usize, MdbxFfiError> {
    if operation_id.trim().is_empty() {
        return Err(StorageError::Validation("operation_id must not be empty".to_string()).into());
    }
    if commands.is_empty() {
        return Err(
            StorageError::Validation("attachment batch requires commands".to_string()).into(),
        );
    }
    let max_commands = usize::try_from(limits.max_commands).map_err(|_| {
        StorageError::Validation("attachment batch max_commands is too large".to_string())
    })?;
    if max_commands == 0 || max_commands > HARD_MAX_ATTACHMENT_BATCH_COMMANDS {
        return Err(StorageError::Validation(format!(
            "attachment batch max_commands must be between 1 and {HARD_MAX_ATTACHMENT_BATCH_COMMANDS}"
        ))
        .into());
    }
    if commands.len() > max_commands {
        return Err(StorageError::ResourceLimit {
            resource: "attachment batch commands".to_string(),
            actual: commands.len() as u64,
            limit: max_commands as u64,
        }
        .into());
    }
    let max_per_command =
        usize::try_from(limits.max_plaintext_bytes_per_command).map_err(|_| {
            StorageError::Validation("attachment batch per-command limit is too large".to_string())
        })?;
    if max_per_command == 0 || max_per_command > HARD_MAX_ATTACHMENT_PLAINTEXT_BYTES {
        return Err(StorageError::Validation(format!(
            "attachment batch per-command bytes must be between 1 and {HARD_MAX_ATTACHMENT_PLAINTEXT_BYTES}"
        ))
        .into());
    }
    let max_total = usize::try_from(limits.max_plaintext_bytes).map_err(|_| {
        StorageError::Validation("attachment batch total limit is too large".to_string())
    })?;
    if max_total == 0 || max_total > HARD_MAX_ATTACHMENT_BATCH_PLAINTEXT_BYTES {
        return Err(StorageError::Validation(format!(
            "attachment batch total bytes must be between 1 and {HARD_MAX_ATTACHMENT_BATCH_PLAINTEXT_BYTES}"
        ))
        .into());
    }
    if max_per_command > max_total {
        return Err(StorageError::Validation(
            "attachment batch per-command limit cannot exceed total limit".to_string(),
        )
        .into());
    }
    let chunk_size = attachment_chunk_size(MdbxAttachmentContentLimits {
        chunk_size: limits.chunk_size,
        max_plaintext_bytes: limits.max_plaintext_bytes_per_command,
    })?;
    let mut total_plaintext_bytes = 0usize;
    for command in commands {
        match command {
            MdbxAttachmentBatchCommand::Create {
                attachment_id,
                project_id,
                entry_id,
                file_name,
                media_type,
                content,
            } => {
                validate_uuid(attachment_id, "attachment_id")?;
                validate_uuid(project_id, "project_id")?;
                if let Some(entry_id) = entry_id {
                    validate_uuid(entry_id, "entry_id")?;
                }
                validate_attachment_batch_text(file_name, "file_name")?;
                if let Some(media_type) = media_type {
                    validate_attachment_batch_text(media_type, "media_type")?;
                }
                add_attachment_batch_plaintext_bytes(
                    &mut total_plaintext_bytes,
                    content.len(),
                    max_per_command,
                    max_total,
                )?;
            }
            MdbxAttachmentBatchCommand::Replace {
                attachment_id,
                content,
            } => {
                validate_uuid(attachment_id, "attachment_id")?;
                add_attachment_batch_plaintext_bytes(
                    &mut total_plaintext_bytes,
                    content.len(),
                    max_per_command,
                    max_total,
                )?;
            }
            MdbxAttachmentBatchCommand::Rename {
                attachment_id,
                file_name,
                media_type,
            } => {
                validate_uuid(attachment_id, "attachment_id")?;
                validate_attachment_batch_text(file_name, "file_name")?;
                if let Some(media_type) = media_type {
                    validate_attachment_batch_text(media_type, "media_type")?;
                }
            }
            MdbxAttachmentBatchCommand::Delete { attachment_id } => {
                validate_uuid(attachment_id, "attachment_id")?;
            }
        }
    }
    Ok(chunk_size)
}

fn validate_attachment_batch_text(value: &str, field: &str) -> Result<(), MdbxFfiError> {
    if value.trim().is_empty() || value.len() > 512 {
        return Err(StorageError::Validation(format!(
            "attachment {field} must contain 1 to 512 UTF-8 bytes"
        ))
        .into());
    }
    Ok(())
}

fn add_attachment_batch_plaintext_bytes(
    total: &mut usize,
    actual: usize,
    per_command_limit: usize,
    total_limit: usize,
) -> Result<(), MdbxFfiError> {
    if actual > per_command_limit {
        return Err(StorageError::ResourceLimit {
            resource: "attachment batch command plaintext bytes".to_string(),
            actual: actual as u64,
            limit: per_command_limit as u64,
        }
        .into());
    }
    *total = total
        .checked_add(actual)
        .ok_or_else(|| StorageError::ResourceLimit {
            resource: "attachment batch plaintext bytes".to_string(),
            actual: u64::MAX,
            limit: total_limit as u64,
        })?;
    if *total > total_limit {
        return Err(StorageError::ResourceLimit {
            resource: "attachment batch plaintext bytes".to_string(),
            actual: *total as u64,
            limit: total_limit as u64,
        }
        .into());
    }
    Ok(())
}

pub(crate) fn attachment_batch_ids(commands: &[MdbxAttachmentBatchCommand]) -> Vec<String> {
    let mut ids = Vec::new();
    for command in commands {
        let id = match command {
            MdbxAttachmentBatchCommand::Create { attachment_id, .. }
            | MdbxAttachmentBatchCommand::Replace { attachment_id, .. }
            | MdbxAttachmentBatchCommand::Rename { attachment_id, .. }
            | MdbxAttachmentBatchCommand::Delete { attachment_id } => attachment_id,
        };
        if !ids.iter().any(|existing| existing == id) {
            ids.push(id.clone());
        }
    }
    ids
}

pub(crate) fn attachment_batch_changes(
    commands: &[MdbxAttachmentBatchCommand],
) -> Vec<CommitChange> {
    let mut changes = Vec::new();
    for command in commands {
        let (action, fields, object_id) = match command {
            MdbxAttachmentBatchCommand::Create { attachment_id, .. } => (
                "create",
                vec![
                    "project_id",
                    "entry_id",
                    "file_name",
                    "media_type",
                    "content",
                ],
                attachment_id,
            ),
            MdbxAttachmentBatchCommand::Replace { attachment_id, .. } => {
                ("update", vec!["content"], attachment_id)
            }
            MdbxAttachmentBatchCommand::Rename { attachment_id, .. } => {
                ("update", vec!["file_name", "media_type"], attachment_id)
            }
            MdbxAttachmentBatchCommand::Delete { attachment_id } => {
                ("delete", vec!["deleted"], attachment_id)
            }
        };
        let incoming = CommitChange {
            object_type: "attachment".to_string(),
            object_id: object_id.clone(),
            action: action.to_string(),
            fields: fields.into_iter().map(str::to_string).collect(),
        };
        if let Some(existing) = changes.iter_mut().find(|change: &&mut CommitChange| {
            change.object_type == "attachment" && change.object_id == *object_id
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

pub(crate) fn hash_attachment_batch_intent(
    operation_id: &str,
    commands: &[MdbxAttachmentBatchCommand],
    limits: MdbxAttachmentBatchLimits,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    update_attachment_intent_part(&mut hasher, b"mdbx-ffi-attachment-batch-v1");
    update_attachment_intent_part(&mut hasher, operation_id.as_bytes());
    update_attachment_intent_part(&mut hasher, &limits.chunk_size.to_le_bytes());
    update_attachment_intent_part(&mut hasher, &(commands.len() as u64).to_le_bytes());
    for command in commands {
        match command {
            MdbxAttachmentBatchCommand::Create {
                attachment_id,
                project_id,
                entry_id,
                file_name,
                media_type,
                content,
            } => {
                update_attachment_intent_part(&mut hasher, b"create");
                update_attachment_intent_part(&mut hasher, attachment_id.as_bytes());
                update_attachment_intent_part(&mut hasher, project_id.as_bytes());
                update_attachment_intent_option(&mut hasher, entry_id.as_deref());
                update_attachment_intent_part(&mut hasher, file_name.as_bytes());
                update_attachment_intent_option(&mut hasher, media_type.as_deref());
                update_attachment_intent_part(&mut hasher, content);
            }
            MdbxAttachmentBatchCommand::Replace {
                attachment_id,
                content,
            } => {
                update_attachment_intent_part(&mut hasher, b"replace");
                update_attachment_intent_part(&mut hasher, attachment_id.as_bytes());
                update_attachment_intent_part(&mut hasher, content);
            }
            MdbxAttachmentBatchCommand::Rename {
                attachment_id,
                file_name,
                media_type,
            } => {
                update_attachment_intent_part(&mut hasher, b"rename");
                update_attachment_intent_part(&mut hasher, attachment_id.as_bytes());
                update_attachment_intent_part(&mut hasher, file_name.as_bytes());
                update_attachment_intent_option(&mut hasher, media_type.as_deref());
            }
            MdbxAttachmentBatchCommand::Delete { attachment_id } => {
                update_attachment_intent_part(&mut hasher, b"delete");
                update_attachment_intent_part(&mut hasher, attachment_id.as_bytes());
            }
        }
    }
    hasher.finalize().to_vec()
}

pub(crate) fn execute_attachment_batch_operation(
    conn: &Mutex<VaultConnection>,
    device_id: &str,
    operation_id: String,
    commands: Vec<MdbxAttachmentBatchCommand>,
    chunk_size: usize,
    intent_hash: Vec<u8>,
    attachment_ids: Vec<String>,
) -> Result<MdbxAttachmentBatchResult, MdbxFfiError> {
    let operation = CommitOperation::new(
        operation_id,
        "attachment-batch",
        "main",
        "change",
        "attachment",
        attachment_batch_changes(&commands),
    )
    .with_intent_hash(intent_hash);
    let conn = conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
    let ctx = CommitContext::new(device_id.to_string());
    let ids_for_action = attachment_ids.clone();
    let execution = ctx.run_operation(&conn, operation, |scoped| {
        execute_attachment_batch_commands(&conn, scoped, commands, chunk_size, &ids_for_action)
    })?;
    let (attachments, commit_id, already_committed) = match execution {
        OperationExecution::Applied { value, commit_id } => (value, commit_id, false),
        OperationExecution::AlreadyCommitted { commit_id } => (
            attachment_ids
                .iter()
                .map(|attachment_id| {
                    AttachmentRepo::get_by_id(&conn, attachment_id)?
                        .ok_or_else(|| StorageError::NotFound(attachment_id.clone()))
                })
                .collect::<StorageResult<Vec<_>>>()?,
            commit_id,
            true,
        ),
    };
    Ok(MdbxAttachmentBatchResult {
        attachments: attachments
            .iter()
            .map(attachment_record_from_core)
            .collect::<Result<Vec<_>, _>>()?,
        commit_id,
        already_committed,
    })
}

pub(crate) fn execute_attachment_batch_commands(
    conn: &VaultConnection,
    ctx: &CommitContext,
    commands: Vec<MdbxAttachmentBatchCommand>,
    chunk_size: usize,
    attachment_ids: &[String],
) -> StorageResult<Vec<Attachment>> {
    for command in commands {
        match command {
            MdbxAttachmentBatchCommand::Create {
                attachment_id,
                project_id,
                entry_id,
                file_name,
                media_type,
                content,
            } => {
                let original_size = content.len() as u64;
                AttachmentRepo::add_with_id(
                    conn,
                    ctx,
                    &attachment_id,
                    mdbx_storage::repo::AttachmentCreateRequest {
                        project_id: &project_id,
                        entry_id: entry_id.as_deref(),
                        file_name: &file_name,
                        media_type: media_type.as_deref(),
                        content_hash: "",
                        original_size,
                    },
                )?;
                let mut reader = Cursor::new(content);
                AttachmentRepo::write_content_from_reader_with_options(
                    conn,
                    ctx,
                    &attachment_id,
                    &mut reader,
                    AttachmentWriteOptions::exact(chunk_size, original_size),
                )?;
            }
            MdbxAttachmentBatchCommand::Replace {
                attachment_id,
                content,
            } => {
                let original_size = content.len() as u64;
                let mut reader = Cursor::new(content);
                AttachmentRepo::write_content_from_reader_with_options(
                    conn,
                    ctx,
                    &attachment_id,
                    &mut reader,
                    AttachmentWriteOptions::exact(chunk_size, original_size),
                )?;
            }
            MdbxAttachmentBatchCommand::Rename {
                attachment_id,
                file_name,
                media_type,
            } => {
                AttachmentRepo::rename(
                    conn,
                    ctx,
                    &attachment_id,
                    &file_name,
                    media_type.as_deref(),
                )?;
            }
            MdbxAttachmentBatchCommand::Delete { attachment_id } => {
                AttachmentRepo::soft_delete(conn, ctx, &attachment_id)?;
            }
        }
    }
    attachment_ids
        .iter()
        .map(|attachment_id| {
            AttachmentRepo::get_by_id(conn, attachment_id)?
                .ok_or_else(|| StorageError::NotFound(attachment_id.clone()))
        })
        .collect()
}

pub(crate) fn attachment_record_from_core(
    attachment: &Attachment,
) -> Result<MdbxAttachmentRecord, MdbxFfiError> {
    let file_name = String::from_utf8(attachment.file_name_ct.clone()).map_err(|error| {
        MdbxFfiError::Serialization {
            message: format!("attachment file name is not UTF-8: {error}"),
        }
    })?;
    let media_type = attachment
        .media_type_ct
        .as_ref()
        .map(|value| {
            String::from_utf8(value.clone()).map_err(|error| MdbxFfiError::Serialization {
                message: format!("attachment media type is not UTF-8: {error}"),
            })
        })
        .transpose()?;
    Ok(MdbxAttachmentRecord {
        attachment_id: attachment.attachment_id.clone(),
        project_id: attachment.project_id.clone(),
        entry_id: attachment.entry_id.clone(),
        file_name,
        media_type,
        storage_mode: attachment.storage_mode.to_string(),
        content_hash: attachment.content_hash.clone(),
        original_size: attachment.original_size,
        stored_size: attachment.stored_size,
        chunk_count: attachment.chunk_count,
        deleted: attachment.deleted,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_attachment_operation_inputs(
    operation_id: &str,
    attachment_id: &str,
    project_id: &str,
    entry_id: Option<&str>,
    file_name: &str,
    content_size: usize,
    limits: MdbxAttachmentContentLimits,
) -> Result<(), MdbxFfiError> {
    if operation_id.trim().is_empty() {
        return Err(StorageError::Validation("operation_id must not be empty".to_string()).into());
    }
    validate_uuid(attachment_id, "attachment_id")?;
    validate_uuid(project_id, "project_id")?;
    if let Some(entry_id) = entry_id {
        validate_uuid(entry_id, "entry_id")?;
    }
    if file_name.trim().is_empty() {
        return Err(
            StorageError::Validation("attachment file_name must not be empty".to_string()).into(),
        );
    }
    attachment_chunk_size(limits)?;
    let max_plaintext_bytes = attachment_max_plaintext_bytes(limits)?;
    if content_size > max_plaintext_bytes {
        return Err(StorageError::ResourceLimit {
            resource: "attachment plaintext bytes".to_string(),
            actual: content_size as u64,
            limit: limits.max_plaintext_bytes,
        }
        .into());
    }
    Ok(())
}

pub(crate) fn attachment_chunk_size(
    limits: MdbxAttachmentContentLimits,
) -> Result<usize, MdbxFfiError> {
    let chunk_size = usize::try_from(limits.chunk_size)
        .map_err(|_| StorageError::Validation("attachment chunk_size is too large".to_string()))?;
    let max_plaintext_bytes = attachment_max_plaintext_bytes(limits)?;
    if chunk_size == 0 || chunk_size > HARD_MAX_ATTACHMENT_CHUNK_SIZE {
        return Err(StorageError::Validation(format!(
            "attachment chunk_size must be between 1 and {HARD_MAX_ATTACHMENT_CHUNK_SIZE}"
        ))
        .into());
    }
    if chunk_size > max_plaintext_bytes {
        return Err(StorageError::Validation(
            "attachment chunk_size cannot exceed max_plaintext_bytes".to_string(),
        )
        .into());
    }
    Ok(chunk_size)
}

pub(crate) fn attachment_max_plaintext_bytes(
    limits: MdbxAttachmentContentLimits,
) -> Result<usize, MdbxFfiError> {
    let max_plaintext_bytes = usize::try_from(limits.max_plaintext_bytes).map_err(|_| {
        StorageError::Validation("attachment max_plaintext_bytes is too large".to_string())
    })?;
    if max_plaintext_bytes == 0 || max_plaintext_bytes > HARD_MAX_ATTACHMENT_PLAINTEXT_BYTES {
        return Err(StorageError::Validation(format!(
            "attachment max_plaintext_bytes must be between 1 and {HARD_MAX_ATTACHMENT_PLAINTEXT_BYTES}"
        ))
        .into());
    }
    Ok(max_plaintext_bytes)
}

pub(crate) fn validate_attachment_read_limit(
    max_plaintext_bytes: u64,
) -> Result<usize, MdbxFfiError> {
    attachment_max_plaintext_bytes(MdbxAttachmentContentLimits {
        chunk_size: 1,
        max_plaintext_bytes,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn hash_attachment_intent(
    action: &str,
    operation_id: &str,
    attachment_id: &str,
    project_id: &str,
    entry_id: Option<&str>,
    file_name: &str,
    media_type: Option<&str>,
    chunk_size: usize,
    content: &[u8],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    update_attachment_intent_part(&mut hasher, b"mdbx-ffi-attachment-content-v1");
    update_attachment_intent_part(&mut hasher, action.as_bytes());
    update_attachment_intent_part(&mut hasher, operation_id.as_bytes());
    update_attachment_intent_part(&mut hasher, attachment_id.as_bytes());
    update_attachment_intent_part(&mut hasher, project_id.as_bytes());
    update_attachment_intent_option(&mut hasher, entry_id);
    update_attachment_intent_part(&mut hasher, file_name.as_bytes());
    update_attachment_intent_option(&mut hasher, media_type);
    update_attachment_intent_part(&mut hasher, &(chunk_size as u64).to_le_bytes());
    update_attachment_intent_part(&mut hasher, content);
    hasher.finalize().to_vec()
}

fn update_attachment_intent_option(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            update_attachment_intent_part(hasher, value.as_bytes());
        }
        None => hasher.update([0]),
    }
}

pub(crate) fn update_attachment_intent_part(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}

pub(crate) struct LimitedAttachmentContentWriter {
    pub(crate) bytes: Vec<u8>,
    limit: usize,
    pub(crate) exceeded_at: Option<usize>,
}

impl LimitedAttachmentContentWriter {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            exceeded_at: None,
        }
    }
}

impl Write for LimitedAttachmentContentWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let actual = self
            .bytes
            .len()
            .checked_add(buffer.len())
            .unwrap_or(usize::MAX);
        if actual > self.limit {
            self.exceeded_at = Some(actual);
            return Err(io::Error::other("attachment plaintext limit exceeded"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
