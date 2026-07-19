use mdbx_sync::ObjectPayload;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::connection::VaultConnection;
use crate::error::{StorageError, StorageResult};
use crate::key_epoch::RANDOM_KEY_EPOCH_PROFILE_ID;
use crate::tiga_policy::{optional_integrity_tag, verify_optional_integrity_tag};

pub const SYNC_STATE_OBJECT_TYPE: &str = "mdbx-storage/state-v1";
pub const LEGACY_CLI_SYNC_STATE_OBJECT_TYPE: &str = "mdbx-cli/state-v1";
pub const SYNC_STATE_OBJECT_ID: &str = "state";
const SYNC_STATE_FORMAT: &str = "mdbx-storage-sync-state-v1";
const LEGACY_CLI_SYNC_STATE_FORMAT: &str = "mdbx-cli-sync-state-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncStatePayload {
    pub format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_epoch_state: Option<KeyEpochState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tiga_vault_state: Option<TigaVaultStateRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tiga_policy_overrides: Option<Vec<TigaPolicyOverrideRow>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tiga_policy_exceptions: Option<Vec<TigaPolicyExceptionRow>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_audit_events: Option<Vec<SecurityAuditEventRow>>,
    pub projects: Vec<ProjectRow>,
    pub entries: Vec<EntryRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_relations: Option<Vec<ObjectRelationRow>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_labels: Option<Vec<ObjectLabelRow>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_label_assignments: Option<Vec<ObjectLabelAssignmentRow>>,
    pub attachments: Vec<AttachmentRow>,
    pub attachment_chunks: Vec<AttachmentChunkRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_tags: Option<Vec<ProjectTagSetRow>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tombstones: Option<Vec<TombstoneRow>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tombstone_acknowledgements: Option<Vec<TombstoneAcknowledgementRow>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purge_receipts: Option<Vec<PurgeReceiptRow>>,
    pub branches: Vec<BranchRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyEpochState {
    pub active_key_epoch_id: String,
    pub epochs: Vec<KeyEpochRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_tag: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyEpochRow {
    pub key_epoch_id: String,
    pub status: String,
    pub wrapped_epoch_key_ct: Vec<u8>,
    pub kdf_profile_id: String,
    pub created_at: String,
    pub activated_at: Option<String>,
    pub retired_at: Option<String>,
}

#[derive(Serialize)]
struct KeyEpochIntegrityValue<'a> {
    active_key_epoch_id: &'a str,
    epochs: &'a [KeyEpochRow],
}

impl KeyEpochState {
    fn integrity_value(&self) -> KeyEpochIntegrityValue<'_> {
        KeyEpochIntegrityValue {
            active_key_epoch_id: &self.active_key_epoch_id,
            epochs: &self.epochs,
        }
    }

    pub fn verify_integrity(&self, conn: &VaultConnection) -> StorageResult<()> {
        verify_optional_integrity_tag(
            conn,
            b"key-epoch-sync-state-v1",
            &self.integrity_value(),
            self.integrity_tag.as_deref(),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TigaVaultStateRow {
    pub default_tiga_mode: String,
    pub policy_version: u32,
    pub compliance_status: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TigaPolicyOverrideRow {
    pub scope_type: String,
    pub scope_id: String,
    pub policy_json: String,
    pub exception_id: Option<String>,
    pub updated_at: String,
    pub updated_by_device_id: String,
    pub integrity_tag: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TigaPolicyExceptionRow {
    pub exception_id: String,
    pub target_scope: String,
    pub target_id: String,
    pub approved_override_json: String,
    pub reason: String,
    pub expires_at_unix_secs: Option<i64>,
    pub created_at: String,
    pub created_by_session_id: Option<String>,
    pub revoked_at: Option<String>,
    pub integrity_tag: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityAuditEventRow {
    pub event_id: String,
    pub occurred_at: String,
    pub operation: String,
    pub outcome: String,
    pub scope_type: String,
    pub scope_id: String,
    pub session_id: Option<String>,
    pub device_id: Option<String>,
    pub reason_codes_json: String,
    pub constraints_json: String,
    pub exception_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_fingerprint: Option<Vec<u8>>,
    pub integrity_tag: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectRow {
    pub project_id: String,
    pub title_ct: Vec<u8>,
    pub summary_ct: Option<Vec<u8>>,
    pub group_id: Option<String>,
    pub icon_ref: Option<String>,
    pub favorite: bool,
    pub archived: bool,
    pub deleted: bool,
    pub tiga_mode_override: Option<String>,
    pub object_clock: String,
    pub head_commit_id: String,
    pub attachment_count: u32,
    pub created_at: String,
    pub updated_at: String,
    pub created_by_device_id: String,
    pub updated_by_device_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntryRow {
    pub entry_id: String,
    pub project_id: String,
    pub entry_type: String,
    pub title_ct: Option<Vec<u8>>,
    pub payload_ct: Vec<u8>,
    pub payload_schema_version: u32,
    pub tiga_mode_override: Option<String>,
    pub object_clock: String,
    pub head_commit_id: String,
    pub deleted: bool,
    pub created_at: String,
    pub updated_at: String,
    pub created_by_device_id: String,
    pub updated_by_device_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectRelationRow {
    pub relation_id: String,
    pub source_object_id: String,
    pub target_object_id: String,
    pub relation_kind: String,
    pub payload_ct: Vec<u8>,
    pub payload_schema_version: u32,
    pub object_clock: String,
    pub head_commit_id: String,
    pub deleted: bool,
    pub created_at: String,
    pub updated_at: String,
    pub created_by_device_id: String,
    pub updated_by_device_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectLabelRow {
    pub label_id: String,
    pub collection_id: String,
    pub name_ct: Vec<u8>,
    pub payload_ct: Vec<u8>,
    pub payload_schema_version: u32,
    pub object_clock: String,
    pub head_commit_id: String,
    pub deleted: bool,
    pub created_at: String,
    pub updated_at: String,
    pub created_by_device_id: String,
    pub updated_by_device_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectLabelAssignmentRow {
    pub assignment_id: String,
    pub object_id: String,
    pub label_id: String,
    pub object_clock: String,
    pub head_commit_id: String,
    pub deleted: bool,
    pub created_at: String,
    pub updated_at: String,
    pub created_by_device_id: String,
    pub updated_by_device_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttachmentRow {
    pub attachment_id: String,
    pub project_id: String,
    pub entry_id: Option<String>,
    pub file_name_ct: Vec<u8>,
    pub media_type_ct: Option<Vec<u8>>,
    pub storage_mode: String,
    pub content_hash: String,
    pub original_size: u64,
    pub stored_size: u64,
    pub chunk_count: u32,
    pub head_commit_id: String,
    pub deleted: bool,
    pub created_at: String,
    pub updated_at: String,
    pub created_by_device_id: String,
    pub updated_by_device_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttachmentChunkRow {
    pub attachment_id: String,
    pub chunk_index: u32,
    pub chunk_hash: String,
    pub chunk_ct: Option<Vec<u8>>,
    pub external_uri_ct: Option<Vec<u8>>,
    pub stored_size: u64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectTagSetRow {
    pub project_id: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TombstoneRow {
    pub tombstone_id: String,
    pub target_object_type: String,
    pub target_object_id: String,
    pub delete_clock: String,
    pub deleted_by_device_id: String,
    pub deleted_at: String,
    pub purge_eligible_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete_commit_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TombstoneAcknowledgementRow {
    pub tombstone_id: String,
    pub device_id: String,
    pub observed_commit_id: String,
    pub acknowledged_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PurgeReceiptRow {
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BranchRow {
    pub branch_id: String,
    pub branch_name: String,
    pub head_commit_id: String,
    pub created_at: String,
    pub updated_at: String,
}

pub fn collect_sync_state(conn: &VaultConnection) -> StorageResult<SyncStatePayload> {
    Ok(SyncStatePayload {
        format: SYNC_STATE_FORMAT.to_string(),
        key_epoch_state: Some(load_key_epoch_state(conn)?),
        tiga_vault_state: Some(load_tiga_vault_state(conn)?),
        tiga_policy_overrides: Some(load_tiga_policy_override_rows(conn)?),
        tiga_policy_exceptions: Some(load_tiga_policy_exception_rows(conn)?),
        security_audit_events: Some(load_security_audit_event_rows(conn)?),
        projects: load_project_rows(conn)?,
        entries: load_entry_rows(conn)?,
        object_relations: Some(load_object_relation_rows(conn)?),
        object_labels: Some(load_object_label_rows(conn)?),
        object_label_assignments: Some(load_object_label_assignment_rows(conn)?),
        attachments: load_attachment_rows(conn)?,
        attachment_chunks: load_attachment_chunk_rows(conn)?,
        project_tags: Some(load_project_tag_set_rows(conn)?),
        tombstones: Some(load_tombstone_rows(conn)?),
        tombstone_acknowledgements: Some(load_tombstone_acknowledgement_rows(conn)?),
        purge_receipts: Some(load_purge_receipt_rows(conn)?),
        branches: load_branch_rows(conn)?,
    })
}

fn load_key_epoch_state(conn: &VaultConnection) -> StorageResult<KeyEpochState> {
    let active_key_epoch_id: String = conn
        .inner()
        .query_row(
            "SELECT active_key_epoch_id FROM vault_meta LIMIT 1",
            [],
            |row| row.get(0),
        )
        .map_err(StorageError::Database)?;
    let mut stmt = conn.inner().prepare(
        "SELECT key_epoch_id, status, wrapped_epoch_key_ct, kdf_profile_id,
                created_at, activated_at, retired_at
         FROM key_epochs ORDER BY key_epoch_id",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(KeyEpochRow {
            key_epoch_id: row.get(0)?,
            status: row.get(1)?,
            wrapped_epoch_key_ct: row.get(2)?,
            kdf_profile_id: row.get(3)?,
            created_at: row.get(4)?,
            activated_at: row.get(5)?,
            retired_at: row.get(6)?,
        })
    })?;
    let epochs = collect_rows(rows)?;
    let integrity_value = KeyEpochIntegrityValue {
        active_key_epoch_id: &active_key_epoch_id,
        epochs: &epochs,
    };
    let integrity_tag = optional_integrity_tag(conn, b"key-epoch-sync-state-v1", &integrity_value)?;
    if epochs
        .iter()
        .any(|row| row.kdf_profile_id == RANDOM_KEY_EPOCH_PROFILE_ID)
        && integrity_tag.is_none()
    {
        return Err(StorageError::Validation(
            "vault must be unlocked to synchronize random key epochs".to_string(),
        ));
    }
    Ok(KeyEpochState {
        active_key_epoch_id,
        epochs,
        integrity_tag,
    })
}

fn load_tiga_vault_state(conn: &VaultConnection) -> StorageResult<TigaVaultStateRow> {
    conn.inner()
        .query_row(
            "SELECT default_tiga_mode, tiga_policy_version, tiga_compliance_status, updated_at
             FROM vault_meta",
            [],
            |row| {
                Ok(TigaVaultStateRow {
                    default_tiga_mode: row.get(0)?,
                    policy_version: row.get::<_, i64>(1)? as u32,
                    compliance_status: row.get(2)?,
                    updated_at: row.get(3)?,
                })
            },
        )
        .map_err(StorageError::Database)
}

fn load_tiga_policy_override_rows(
    conn: &VaultConnection,
) -> StorageResult<Vec<TigaPolicyOverrideRow>> {
    let mut stmt = conn.inner().prepare(
        "SELECT scope_type, scope_id, policy_json, exception_id, updated_at,
                updated_by_device_id, integrity_tag
         FROM tiga_policy_overrides ORDER BY scope_type, scope_id",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(TigaPolicyOverrideRow {
            scope_type: row.get(0)?,
            scope_id: row.get(1)?,
            policy_json: row.get(2)?,
            exception_id: row.get(3)?,
            updated_at: row.get(4)?,
            updated_by_device_id: row.get(5)?,
            integrity_tag: row.get(6)?,
        })
    })?;
    collect_rows(rows)
}

fn load_tiga_policy_exception_rows(
    conn: &VaultConnection,
) -> StorageResult<Vec<TigaPolicyExceptionRow>> {
    let mut stmt = conn.inner().prepare(
        "SELECT exception_id, target_scope, target_id, approved_override_json, reason,
                expires_at_unix_secs, created_at, created_by_session_id, revoked_at,
                integrity_tag
         FROM tiga_policy_exceptions ORDER BY created_at, exception_id",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(TigaPolicyExceptionRow {
            exception_id: row.get(0)?,
            target_scope: row.get(1)?,
            target_id: row.get(2)?,
            approved_override_json: row.get(3)?,
            reason: row.get(4)?,
            expires_at_unix_secs: row.get(5)?,
            created_at: row.get(6)?,
            created_by_session_id: row.get(7)?,
            revoked_at: row.get(8)?,
            integrity_tag: row.get(9)?,
        })
    })?;
    collect_rows(rows)
}

fn load_security_audit_event_rows(
    conn: &VaultConnection,
) -> StorageResult<Vec<SecurityAuditEventRow>> {
    let mut stmt = conn.inner().prepare(
        "SELECT event_id, occurred_at, operation, outcome, scope_type, scope_id,
                session_id, device_id, reason_codes_json, constraints_json,
                exception_id, operation_id, commit_id, policy_version,
                policy_fingerprint, integrity_tag
         FROM security_audit_events ORDER BY occurred_at, event_id",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(SecurityAuditEventRow {
            event_id: row.get(0)?,
            occurred_at: row.get(1)?,
            operation: row.get(2)?,
            outcome: row.get(3)?,
            scope_type: row.get(4)?,
            scope_id: row.get(5)?,
            session_id: row.get(6)?,
            device_id: row.get(7)?,
            reason_codes_json: row.get(8)?,
            constraints_json: row.get(9)?,
            exception_id: row.get(10)?,
            operation_id: row.get(11)?,
            commit_id: row.get(12)?,
            policy_version: row.get::<_, Option<i64>>(13)?.map(|value| value as u32),
            policy_fingerprint: row.get(14)?,
            integrity_tag: row.get(15)?,
        })
    })?;
    collect_rows(rows)
}

fn collect_rows<T>(
    rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>>,
) -> StorageResult<Vec<T>> {
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

pub fn collect_sync_state_payload(conn: &VaultConnection) -> StorageResult<ObjectPayload> {
    let state = collect_sync_state(conn)?;
    let ciphertext =
        serde_json::to_vec(&state).map_err(|e| StorageError::SchemaCreation(e.to_string()))?;
    Ok(ObjectPayload {
        object_type: SYNC_STATE_OBJECT_TYPE.to_string(),
        object_id: SYNC_STATE_OBJECT_ID.to_string(),
        ciphertext,
        associated_data: SYNC_STATE_OBJECT_TYPE.as_bytes().to_vec(),
    })
}

pub fn decode_sync_state_payload(
    payload: &ObjectPayload,
) -> StorageResult<Option<SyncStatePayload>> {
    if payload.object_id != SYNC_STATE_OBJECT_ID {
        return Ok(None);
    }
    if payload.object_type != SYNC_STATE_OBJECT_TYPE
        && payload.object_type != LEGACY_CLI_SYNC_STATE_OBJECT_TYPE
    {
        return Ok(None);
    }

    let state: SyncStatePayload = serde_json::from_slice(&payload.ciphertext)
        .map_err(|e| StorageError::SchemaCreation(e.to_string()))?;
    if state.format != SYNC_STATE_FORMAT && state.format != LEGACY_CLI_SYNC_STATE_FORMAT {
        return Err(StorageError::Validation(format!(
            "unsupported sync state format: {}",
            state.format
        )));
    }
    Ok(Some(state))
}

fn load_project_rows(conn: &VaultConnection) -> StorageResult<Vec<ProjectRow>> {
    let mut stmt = conn.inner().prepare(
        "SELECT project_id, title_ct, summary_ct, group_id, icon_ref,
                favorite, archived, deleted, tiga_mode_override, object_clock,
                head_commit_id, attachment_count, created_at, updated_at,
                created_by_device_id, updated_by_device_id
         FROM projects
         ORDER BY updated_at ASC, project_id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(ProjectRow {
            project_id: row.get(0)?,
            title_ct: row.get(1)?,
            summary_ct: row.get(2)?,
            group_id: row.get(3)?,
            icon_ref: row.get(4)?,
            favorite: row.get::<_, i32>(5)? != 0,
            archived: row.get::<_, i32>(6)? != 0,
            deleted: row.get::<_, i32>(7)? != 0,
            tiga_mode_override: row.get(8)?,
            object_clock: row.get(9)?,
            head_commit_id: row.get(10)?,
            attachment_count: row.get::<_, i64>(11)? as u32,
            created_at: row.get(12)?,
            updated_at: row.get(13)?,
            created_by_device_id: row.get(14)?,
            updated_by_device_id: row.get(15)?,
        })
    })?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn load_entry_rows(conn: &VaultConnection) -> StorageResult<Vec<EntryRow>> {
    let mut stmt = conn.inner().prepare(
        "SELECT entry_id, project_id, entry_type, title_ct, payload_ct,
                payload_schema_version, tiga_mode_override, object_clock,
                head_commit_id, deleted, created_at, updated_at,
                created_by_device_id, updated_by_device_id
         FROM entries
         ORDER BY updated_at ASC, entry_id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(EntryRow {
            entry_id: row.get(0)?,
            project_id: row.get(1)?,
            entry_type: row.get(2)?,
            title_ct: row.get(3)?,
            payload_ct: row.get(4)?,
            payload_schema_version: {
                let value = row.get::<_, i64>(5)?;
                u32::try_from(value).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        5,
                        rusqlite::types::Type::Integer,
                        Box::new(error),
                    )
                })?
            },
            tiga_mode_override: row.get(6)?,
            object_clock: row.get(7)?,
            head_commit_id: row.get(8)?,
            deleted: row.get::<_, i32>(9)? != 0,
            created_at: row.get(10)?,
            updated_at: row.get(11)?,
            created_by_device_id: row.get(12)?,
            updated_by_device_id: row.get(13)?,
        })
    })?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn load_object_relation_rows(conn: &VaultConnection) -> StorageResult<Vec<ObjectRelationRow>> {
    let mut stmt = conn.inner().prepare(
        "SELECT relation_id, source_object_id, target_object_id, relation_kind,
                payload_ct, payload_schema_version, object_clock, head_commit_id,
                deleted, created_at, updated_at, created_by_device_id,
                updated_by_device_id
         FROM object_relations ORDER BY updated_at ASC, relation_id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(ObjectRelationRow {
            relation_id: row.get(0)?,
            source_object_id: row.get(1)?,
            target_object_id: row.get(2)?,
            relation_kind: row.get(3)?,
            payload_ct: row.get(4)?,
            payload_schema_version: read_u32(row, 5)?,
            object_clock: row.get(6)?,
            head_commit_id: row.get(7)?,
            deleted: row.get::<_, i32>(8)? != 0,
            created_at: row.get(9)?,
            updated_at: row.get(10)?,
            created_by_device_id: row.get(11)?,
            updated_by_device_id: row.get(12)?,
        })
    })?;
    collect_rows(rows)
}

fn load_object_label_rows(conn: &VaultConnection) -> StorageResult<Vec<ObjectLabelRow>> {
    let mut stmt = conn.inner().prepare(
        "SELECT label_id, collection_id, name_ct, payload_ct, payload_schema_version,
                object_clock, head_commit_id, deleted, created_at, updated_at,
                created_by_device_id, updated_by_device_id
         FROM object_labels ORDER BY updated_at ASC, label_id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(ObjectLabelRow {
            label_id: row.get(0)?,
            collection_id: row.get(1)?,
            name_ct: row.get(2)?,
            payload_ct: row.get(3)?,
            payload_schema_version: read_u32(row, 4)?,
            object_clock: row.get(5)?,
            head_commit_id: row.get(6)?,
            deleted: row.get::<_, i32>(7)? != 0,
            created_at: row.get(8)?,
            updated_at: row.get(9)?,
            created_by_device_id: row.get(10)?,
            updated_by_device_id: row.get(11)?,
        })
    })?;
    collect_rows(rows)
}

fn load_object_label_assignment_rows(
    conn: &VaultConnection,
) -> StorageResult<Vec<ObjectLabelAssignmentRow>> {
    let mut stmt = conn.inner().prepare(
        "SELECT assignment_id, object_id, label_id, object_clock, head_commit_id,
                deleted, created_at, updated_at, created_by_device_id,
                updated_by_device_id
         FROM object_label_assignments ORDER BY updated_at ASC, assignment_id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(ObjectLabelAssignmentRow {
            assignment_id: row.get(0)?,
            object_id: row.get(1)?,
            label_id: row.get(2)?,
            object_clock: row.get(3)?,
            head_commit_id: row.get(4)?,
            deleted: row.get::<_, i32>(5)? != 0,
            created_at: row.get(6)?,
            updated_at: row.get(7)?,
            created_by_device_id: row.get(8)?,
            updated_by_device_id: row.get(9)?,
        })
    })?;
    collect_rows(rows)
}

fn load_attachment_rows(conn: &VaultConnection) -> StorageResult<Vec<AttachmentRow>> {
    let mut stmt = conn.inner().prepare(
        "SELECT attachment_id, project_id, entry_id, file_name_ct,
                media_type_ct, storage_mode, content_hash,
                original_size, stored_size, chunk_count, head_commit_id,
                deleted, created_at, updated_at,
                created_by_device_id, updated_by_device_id
         FROM attachments
         ORDER BY updated_at ASC, attachment_id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(AttachmentRow {
            attachment_id: row.get(0)?,
            project_id: row.get(1)?,
            entry_id: row.get(2)?,
            file_name_ct: row.get(3)?,
            media_type_ct: row.get(4)?,
            storage_mode: row.get(5)?,
            content_hash: row.get(6)?,
            original_size: row.get::<_, i64>(7)? as u64,
            stored_size: row.get::<_, i64>(8)? as u64,
            chunk_count: row.get::<_, i64>(9)? as u32,
            head_commit_id: row.get(10)?,
            deleted: row.get::<_, i32>(11)? != 0,
            created_at: row.get(12)?,
            updated_at: row.get(13)?,
            created_by_device_id: row.get(14)?,
            updated_by_device_id: row.get(15)?,
        })
    })?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn read_u32(row: &rusqlite::Row<'_>, column: usize) -> rusqlite::Result<u32> {
    let value = row.get::<_, i64>(column)?;
    u32::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn load_attachment_chunk_rows(conn: &VaultConnection) -> StorageResult<Vec<AttachmentChunkRow>> {
    let mut stmt = conn.inner().prepare(
        "SELECT attachment_id, chunk_index, chunk_hash, chunk_ct,
                external_uri_ct, stored_size, created_at
         FROM attachment_chunks
         ORDER BY attachment_id ASC, chunk_index ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(AttachmentChunkRow {
            attachment_id: row.get(0)?,
            chunk_index: row.get::<_, i64>(1)? as u32,
            chunk_hash: row.get(2)?,
            chunk_ct: row.get(3)?,
            external_uri_ct: row.get(4)?,
            stored_size: row.get::<_, i64>(5)? as u64,
            created_at: row.get(6)?,
        })
    })?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn load_project_tag_set_rows(conn: &VaultConnection) -> StorageResult<Vec<ProjectTagSetRow>> {
    let mut out = BTreeMap::<String, Vec<String>>::new();
    let mut project_stmt = conn
        .inner()
        .prepare("SELECT project_id FROM projects ORDER BY project_id ASC")?;
    let project_ids = project_stmt.query_map([], |row| row.get::<_, String>(0))?;
    for project_id in project_ids {
        out.insert(project_id?, Vec::new());
    }

    let mut stmt = conn.inner().prepare(
        "SELECT project_id, tag
         FROM project_tags
         ORDER BY project_id ASC, tag ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in rows {
        let (project_id, tag) = row?;
        out.entry(project_id).or_default().push(tag);
    }
    Ok(out
        .into_iter()
        .map(|(project_id, tags)| ProjectTagSetRow { project_id, tags })
        .collect())
}

fn load_tombstone_rows(conn: &VaultConnection) -> StorageResult<Vec<TombstoneRow>> {
    let mut stmt = conn.inner().prepare(
        "SELECT tombstone_id, target_object_type, target_object_id, delete_clock,
                deleted_by_device_id, deleted_at, purge_eligible_at, delete_commit_id
         FROM tombstones
         ORDER BY target_object_type ASC, target_object_id ASC, tombstone_id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(TombstoneRow {
            tombstone_id: row.get(0)?,
            target_object_type: row.get(1)?,
            target_object_id: row.get(2)?,
            delete_clock: row.get(3)?,
            deleted_by_device_id: row.get(4)?,
            deleted_at: row.get(5)?,
            purge_eligible_at: row.get(6)?,
            delete_commit_id: row.get(7)?,
        })
    })?;
    collect_rows(rows)
}

fn load_tombstone_acknowledgement_rows(
    conn: &VaultConnection,
) -> StorageResult<Vec<TombstoneAcknowledgementRow>> {
    let mut stmt = conn.inner().prepare(
        "SELECT tombstone_id, device_id, observed_commit_id, acknowledged_at
         FROM tombstone_acknowledgements
         ORDER BY tombstone_id ASC, device_id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(TombstoneAcknowledgementRow {
            tombstone_id: row.get(0)?,
            device_id: row.get(1)?,
            observed_commit_id: row.get(2)?,
            acknowledged_at: row.get(3)?,
        })
    })?;
    collect_rows(rows)
}

fn load_purge_receipt_rows(conn: &VaultConnection) -> StorageResult<Vec<PurgeReceiptRow>> {
    let mut stmt = conn.inner().prepare(
        "SELECT purge_id, tombstone_id, target_object_type, target_object_id,
                delete_commit_id, purge_commit_id, delete_clock,
                retention_eligible_at, purged_by_device_id, purged_at, integrity_tag
         FROM purge_receipts
         ORDER BY purged_at ASC, purge_id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(PurgeReceiptRow {
            purge_id: row.get(0)?,
            tombstone_id: row.get(1)?,
            target_object_type: row.get(2)?,
            target_object_id: row.get(3)?,
            delete_commit_id: row.get(4)?,
            purge_commit_id: row.get(5)?,
            delete_clock: row.get(6)?,
            retention_eligible_at: row.get(7)?,
            purged_by_device_id: row.get(8)?,
            purged_at: row.get(9)?,
            integrity_tag: row.get(10)?,
        })
    })?;
    collect_rows(rows)
}

fn load_branch_rows(conn: &VaultConnection) -> StorageResult<Vec<BranchRow>> {
    let mut stmt = conn.inner().prepare(
        "SELECT branch_id, branch_name, head_commit_id, created_at, updated_at
         FROM branches
         ORDER BY branch_name ASC, branch_id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(BranchRow {
            branch_id: row.get(0)?,
            branch_name: row.get(1)?,
            head_commit_id: row.get(2)?,
            created_at: row.get(3)?,
            updated_at: row.get(4)?,
        })
    })?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::{initialize_vault, VaultInitParams};
    use crate::repo::CommitContext;
    #[cfg(feature = "derived-search-index")]
    use crate::repo::ProjectRepo;
    #[cfg(feature = "derived-search-index")]
    use crate::search::SearchService;
    use crate::unlock::UnlockService;

    fn setup() -> (VaultConnection, CommitContext) {
        let conn = VaultConnection::open_in_memory().unwrap();
        initialize_vault(&conn, &VaultInitParams::default()).unwrap();
        let ctx = CommitContext::new("test-device".to_string());
        (conn, ctx)
    }

    #[cfg(feature = "derived-search-index")]
    #[test]
    fn collect_sync_state_includes_empty_project_tag_sets() {
        let (conn, ctx) = setup();
        let tagged = ProjectRepo::create(&conn, &ctx, "Tagged", None, None).unwrap();
        let empty = ProjectRepo::create(&conn, &ctx, "Empty", None, None).unwrap();
        SearchService::add_tag(&conn, &tagged.project_id, "work").unwrap();

        let state = collect_sync_state(&conn).unwrap();
        let tag_sets = state.project_tags.unwrap();
        let tagged_tags = tag_sets
            .iter()
            .find(|row| row.project_id == tagged.project_id)
            .unwrap();
        let empty_tags = tag_sets
            .iter()
            .find(|row| row.project_id == empty.project_id)
            .unwrap();

        assert_eq!(tagged_tags.tags, vec!["work".to_string()]);
        assert!(empty_tags.tags.is_empty());
    }

    #[test]
    fn collect_sync_state_includes_authenticated_key_epoch_state_when_unlocked() {
        let (mut conn, _) = setup();
        UnlockService::setup_password(&mut conn, "sync epoch password").unwrap();

        let state = collect_sync_state(&conn).unwrap().key_epoch_state.unwrap();
        assert_eq!(state.epochs.len(), 1);
        assert_eq!(state.epochs[0].key_epoch_id, state.active_key_epoch_id);
        assert_eq!(state.epochs[0].status, "active");
        assert!(state.integrity_tag.is_some());
        state.verify_integrity(&conn).unwrap();
    }

    #[test]
    fn legacy_sync_state_without_key_epochs_still_deserializes() {
        let payload = ObjectPayload {
            object_type: SYNC_STATE_OBJECT_TYPE.to_string(),
            object_id: SYNC_STATE_OBJECT_ID.to_string(),
            ciphertext: serde_json::to_vec(&serde_json::json!({
                "format": SYNC_STATE_FORMAT,
                "projects": [],
                "entries": [],
                "attachments": [],
                "attachment_chunks": [],
                "branches": []
            }))
            .unwrap(),
            associated_data: SYNC_STATE_OBJECT_TYPE.as_bytes().to_vec(),
        };

        let decoded = decode_sync_state_payload(&payload).unwrap().unwrap();
        assert!(decoded.key_epoch_state.is_none());
        assert!(decoded.tombstones.is_none());
        assert!(decoded.tombstone_acknowledgements.is_none());
        assert!(decoded.purge_receipts.is_none());
    }
}
