use rusqlite::params;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use uuid::Uuid;

use mdbx_core::model::attachment::{AttachmentChunk, StorageMode};
use mdbx_core::model::{Attachment, Entry, Project, Snapshot};
use mdbx_core::tiga::{AuthorizationDecision, TigaOperation, TigaScope};

use crate::connection::VaultConnection;
use crate::crypto_layer::{decrypt_field, encrypt_field, FieldKeyPurpose};
use crate::error::{StorageError, StorageResult};
use crate::repo::commit_ctx::CommitContext;
use crate::repo::object_version::ObjectVersionRepo;
use crate::sync_state::ProjectTagSetRow;
use crate::tiga::TigaService;
use crate::tiga_policy::TigaAuthorizationContext;

/// Snapshot 内部负载。
///
/// 解锁会话中会通过 metadata subkey 加密；未解锁/旧测试路径保留明文兼容。
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotPayload {
    vault_id: String,
    format_version: String,
    snapshot_created_at: String,
    projects: Vec<Project>,
    entries: Vec<Entry>,
    attachments: Vec<Attachment>,
    #[serde(default)]
    attachment_chunks: Option<Vec<AttachmentChunk>>,
    #[serde(default)]
    project_tags: Option<Vec<ProjectTagSetRow>>,
}

/// Snapshot 持久化仓库。
///
/// 负责创建和恢复检查点，捕获 projects / entries / attachments 元数据。
pub struct SnapshotRepo;

impl SnapshotRepo {
    // -----------------------------------------------------------------------
    // CREATE
    // -----------------------------------------------------------------------

    /// 创建 snapshot：捕获当前所有未删除对象的元数据。
    pub fn create_snapshot(conn: &VaultConnection, ctx: &CommitContext) -> StorageResult<Snapshot> {
        conn.with_immediate_transaction(|| {
            let now = chrono::Utc::now().to_rfc3339();
            let snapshot_id = Uuid::new_v4().to_string();

            let (vault_id, format_version): (String, String) = conn
                .inner()
                .query_row(
                    "SELECT vault_id, format_version FROM vault_meta",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(StorageError::Database)?;

            let payload = SnapshotPayload {
                vault_id,
                format_version,
                snapshot_created_at: now.clone(),
                projects: read_all_active_projects(conn)?,
                entries: read_all_active_entries(conn)?,
                attachments: read_all_active_attachments(conn)?,
                attachment_chunks: Some(read_all_active_attachment_chunks(conn)?),
                project_tags: Some(read_all_active_project_tags(conn)?),
            };

            let snapshot_json = serde_json::to_vec(&payload)
                .map_err(|e| StorageError::SchemaCreation(e.to_string()))?;
            let snapshot_ct = Self::encrypt_payload(conn, &snapshot_id, &snapshot_json)?;
            let snapshot_hash = compute_sha256_hex(&snapshot_ct);

            let commit_id =
                ctx.create_commit(conn, "snapshot", "multi", &[snapshot_id.clone()], &[])?;

            conn.inner().execute(
                "INSERT INTO snapshots (snapshot_id, base_commit_id, snapshot_ct,
                 snapshot_hash, created_at, created_by_device_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    snapshot_id,
                    commit_id,
                    snapshot_ct,
                    snapshot_hash,
                    now,
                    ctx.device_id,
                ],
            )?;

            Ok(Snapshot {
                snapshot_id,
                base_commit_id: commit_id,
                snapshot_ct,
                snapshot_hash,
                created_at: now,
                created_by_device_id: ctx.device_id.clone(),
            })
        })
    }

    // -----------------------------------------------------------------------
    // RESTORE
    // -----------------------------------------------------------------------

    /// 从 snapshot 恢复 projects / entries / attachments 元数据。
    ///
    /// 每个对象使用 INSERT OR REPLACE，保持原始 ID 不变。
    /// 恢复完成后创建一个 "snapshot" 类型的 commit。
    pub fn restore_snapshot_authorized(
        conn: &VaultConnection,
        ctx: &CommitContext,
        snapshot_id: &str,
        context: TigaAuthorizationContext<'_>,
    ) -> StorageResult<AuthorizationDecision> {
        let (_, decision) = TigaService::execute_authorized_with_commit(
            conn,
            &TigaScope::Vault,
            TigaOperation::RestoreSnapshot,
            context,
            || Self::restore_snapshot(conn, ctx, snapshot_id).map(|commit_id| ((), commit_id)),
        )?;
        Ok(decision)
    }

    pub(crate) fn restore_snapshot(
        conn: &VaultConnection,
        ctx: &CommitContext,
        snapshot_id: &str,
    ) -> StorageResult<String> {
        let snap = SnapshotRepo::get_by_id(conn, snapshot_id)?
            .ok_or_else(|| StorageError::NotFound(snapshot_id.to_string()))?;

        // 校验 hash
        let computed = compute_sha256_hex(&snap.snapshot_ct);
        if computed != snap.snapshot_hash {
            return Err(StorageError::ConstraintViolation(format!(
                "snapshot hash mismatch: expected {}, got {}",
                snap.snapshot_hash, computed
            )));
        }

        let snapshot_json = Self::decrypt_payload(conn, snapshot_id, &snap.snapshot_ct)?;
        let payload: SnapshotPayload = serde_json::from_slice(&snapshot_json)
            .map_err(|e| StorageError::SchemaCreation(e.to_string()))?;

        conn.with_immediate_transaction(|| {
            let now = chrono::Utc::now().to_rfc3339();
            let active_projects = active_ids(conn, "projects", "project_id")?;
            let active_entries = active_ids(conn, "entries", "entry_id")?;
            let active_attachments = active_ids(conn, "attachments", "attachment_id")?;

            let snapshot_projects = id_set(payload.projects.iter().map(|p| p.project_id.as_str()));
            let snapshot_entries = id_set(payload.entries.iter().map(|e| e.entry_id.as_str()));
            let snapshot_attachments =
                id_set(payload.attachments.iter().map(|a| a.attachment_id.as_str()));

            let removed_projects = difference(&active_projects, &snapshot_projects);
            let removed_entries = difference(&active_entries, &snapshot_entries);
            let removed_attachments = difference(&active_attachments, &snapshot_attachments);

            let mut changed_ids = vec![snapshot_id.to_string()];
            changed_ids.extend(snapshot_projects.iter().cloned());
            changed_ids.extend(snapshot_entries.iter().cloned());
            changed_ids.extend(snapshot_attachments.iter().cloned());
            changed_ids.extend(removed_projects.iter().cloned());
            changed_ids.extend(removed_entries.iter().cloned());
            changed_ids.extend(removed_attachments.iter().cloned());
            changed_ids.sort();
            changed_ids.dedup();

            let restore_commit_id = ctx.create_commit(
                conn,
                "snapshot",
                "multi",
                &changed_ids,
                &[snap.base_commit_id.clone()],
            )?;

            // Restore in dependency order, but give every row a new causal head.
            for project in &payload.projects {
                upsert_project(conn, project, &restore_commit_id, &now, &ctx.device_id)?;
                ObjectVersionRepo::record_project_current(
                    conn,
                    &restore_commit_id,
                    &project.project_id,
                )?;
            }
            for entry in &payload.entries {
                upsert_entry(conn, entry, &restore_commit_id, &now, &ctx.device_id)?;
                ObjectVersionRepo::record_entry_current(conn, &restore_commit_id, &entry.entry_id)?;
            }
            for attachment in &payload.attachments {
                upsert_attachment(conn, attachment, &restore_commit_id, &now, &ctx.device_id)?;
                ObjectVersionRepo::record_attachment_current(
                    conn,
                    &restore_commit_id,
                    &attachment.attachment_id,
                )?;
            }

            if let Some(chunks) = &payload.attachment_chunks {
                restore_attachment_chunks(conn, &snapshot_attachments, chunks)?;
            }
            if let Some(tag_sets) = &payload.project_tags {
                restore_project_tags(conn, &snapshot_projects, tag_sets)?;
            }

            // Objects created after the snapshot remain in history but leave the
            // active set through a tracked soft delete.
            soft_delete_for_restore(
                conn,
                ctx,
                "attachment",
                "attachments",
                "attachment_id",
                &removed_attachments,
                &restore_commit_id,
                &now,
            )?;
            soft_delete_for_restore(
                conn,
                ctx,
                "entry",
                "entries",
                "entry_id",
                &removed_entries,
                &restore_commit_id,
                &now,
            )?;
            soft_delete_for_restore(
                conn,
                ctx,
                "project",
                "projects",
                "project_id",
                &removed_projects,
                &restore_commit_id,
                &now,
            )?;

            for id in &removed_attachments {
                ObjectVersionRepo::record_attachment_current(conn, &restore_commit_id, id)?;
            }
            for id in &removed_entries {
                ObjectVersionRepo::record_entry_current(conn, &restore_commit_id, id)?;
            }
            for id in &removed_projects {
                ObjectVersionRepo::record_project_current(conn, &restore_commit_id, id)?;
            }

            Ok(restore_commit_id)
        })
    }

    // -----------------------------------------------------------------------
    // READ
    // -----------------------------------------------------------------------

    pub fn get_by_id(conn: &VaultConnection, snapshot_id: &str) -> StorageResult<Option<Snapshot>> {
        conn.inner()
            .query_row(
                "SELECT snapshot_id, base_commit_id, snapshot_ct, snapshot_hash,
                        created_at, created_by_device_id
                 FROM snapshots WHERE snapshot_id = ?1",
                params![snapshot_id],
                |row| {
                    Ok(Snapshot {
                        snapshot_id: row.get(0)?,
                        base_commit_id: row.get(1)?,
                        snapshot_ct: row.get(2)?,
                        snapshot_hash: row.get(3)?,
                        created_at: row.get(4)?,
                        created_by_device_id: row.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(StorageError::Database)
    }

    pub fn list_all(conn: &VaultConnection) -> StorageResult<Vec<Snapshot>> {
        let mut stmt = conn.inner().prepare(
            "SELECT snapshot_id, base_commit_id, snapshot_ct, snapshot_hash,
                    created_at, created_by_device_id
             FROM snapshots ORDER BY created_at DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(Snapshot {
                snapshot_id: row.get(0)?,
                base_commit_id: row.get(1)?,
                snapshot_ct: row.get(2)?,
                snapshot_hash: row.get(3)?,
                created_at: row.get(4)?,
                created_by_device_id: row.get(5)?,
            })
        })?;

        let mut snapshots = Vec::new();
        for row in rows {
            snapshots.push(row?);
        }
        Ok(snapshots)
    }

    /// 校验 snapshot 内部 hash 一致性。
    pub fn verify_integrity(conn: &VaultConnection, snapshot_id: &str) -> StorageResult<bool> {
        let snap = match SnapshotRepo::get_by_id(conn, snapshot_id)? {
            Some(s) => s,
            None => return Ok(false),
        };
        if compute_sha256_hex(&snap.snapshot_ct) != snap.snapshot_hash {
            return Ok(false);
        }

        if conn.keyring().is_none() {
            return Ok(true);
        }

        let plaintext = match Self::decrypt_payload(conn, snapshot_id, &snap.snapshot_ct) {
            Ok(plaintext) => plaintext,
            Err(_) => return Ok(false),
        };
        Ok(serde_json::from_slice::<SnapshotPayload>(&plaintext).is_ok())
    }

    // -----------------------------------------------------------------------
    // ENCRYPTION HELPERS
    // -----------------------------------------------------------------------

    fn encrypt_payload(
        conn: &VaultConnection,
        id: &str,
        plaintext: &[u8],
    ) -> StorageResult<Vec<u8>> {
        encrypt_field(
            conn,
            FieldKeyPurpose::Metadata,
            plaintext,
            "snapshot",
            id,
            "payload",
        )
    }

    fn decrypt_payload(
        conn: &VaultConnection,
        id: &str,
        ciphertext: &[u8],
    ) -> StorageResult<Vec<u8>> {
        decrypt_field(
            conn,
            FieldKeyPurpose::Metadata,
            ciphertext,
            "snapshot",
            id,
            "payload",
        )
    }
}

// ---------------------------------------------------------------------------
// 内部辅助函数
// ---------------------------------------------------------------------------

fn read_all_active_projects(conn: &VaultConnection) -> StorageResult<Vec<Project>> {
    let mut stmt = conn.inner().prepare(
        "SELECT project_id, title_ct, summary_ct, group_id, icon_ref,
                favorite, archived, deleted, tiga_mode_override, object_clock,
                head_commit_id, attachment_count, created_at, updated_at,
                created_by_device_id, updated_by_device_id
         FROM projects WHERE deleted = 0 ORDER BY updated_at DESC",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(Project {
            project_id: row.get(0)?,
            title_ct: row.get::<_, Vec<u8>>(1)?,
            summary_ct: row.get::<_, Option<Vec<u8>>>(2)?,
            group_id: row.get(3)?,
            icon_ref: row.get(4)?,
            favorite: row.get::<_, i32>(5)? != 0,
            archived: row.get::<_, i32>(6)? != 0,
            deleted: row.get::<_, i32>(7)? != 0,
            tiga_mode_override: row
                .get::<_, Option<String>>(8)?
                .and_then(|s| s.parse().ok()),
            object_clock: row.get(9)?,
            head_commit_id: row.get(10)?,
            attachment_count: row.get::<_, i32>(11)? as u32,
            created_at: row.get(12)?,
            updated_at: row.get(13)?,
            created_by_device_id: row.get(14)?,
            updated_by_device_id: row.get(15)?,
        })
    })?;

    let mut projects = Vec::new();
    for row in rows {
        projects.push(row?);
    }
    Ok(projects)
}

fn read_all_active_entries(conn: &VaultConnection) -> StorageResult<Vec<Entry>> {
    let mut stmt = conn.inner().prepare(
        "SELECT entry_id, project_id, entry_type, title_ct, payload_ct,
                payload_schema_version, tiga_mode_override, object_clock,
                head_commit_id, deleted, created_at, updated_at,
                created_by_device_id, updated_by_device_id
         FROM entries WHERE deleted = 0 ORDER BY updated_at DESC",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(Entry {
            entry_id: row.get(0)?,
            project_id: row.get(1)?,
            entry_type: {
                let s: String = row.get(2)?;
                s.parse().map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Text,
                        Box::new(StorageError::Validation(error)),
                    )
                })?
            },
            title_ct: row.get::<_, Option<Vec<u8>>>(3)?,
            payload_ct: row.get::<_, Vec<u8>>(4)?,
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
            tiga_mode_override: row
                .get::<_, Option<String>>(6)?
                .and_then(|s| s.parse().ok()),
            object_clock: row.get(7)?,
            head_commit_id: row.get(8)?,
            deleted: row.get::<_, i32>(9)? != 0,
            created_at: row.get(10)?,
            updated_at: row.get(11)?,
            created_by_device_id: row.get(12)?,
            updated_by_device_id: row.get(13)?,
        })
    })?;

    let mut entries = Vec::new();
    for row in rows {
        entries.push(row?);
    }
    Ok(entries)
}

fn read_all_active_attachments(conn: &VaultConnection) -> StorageResult<Vec<Attachment>> {
    let mut stmt = conn.inner().prepare(
        "SELECT attachment_id, project_id, entry_id, file_name_ct,
                media_type_ct, storage_mode, content_hash,
                original_size, stored_size, chunk_count, head_commit_id,
                deleted, created_at, updated_at,
                created_by_device_id, updated_by_device_id
         FROM attachments WHERE deleted = 0 ORDER BY updated_at DESC",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(Attachment {
            attachment_id: row.get(0)?,
            project_id: row.get(1)?,
            entry_id: row.get(2)?,
            file_name_ct: row.get::<_, Vec<u8>>(3)?,
            media_type_ct: row.get::<_, Option<Vec<u8>>>(4)?,
            storage_mode: {
                let s: String = row.get(5)?;
                s.parse().unwrap_or(StorageMode::EmbeddedInline)
            },
            content_hash: row.get(6)?,
            original_size: row.get::<_, i64>(7)? as u64,
            stored_size: row.get::<_, i64>(8)? as u64,
            chunk_count: row.get::<_, i32>(9)? as u32,
            head_commit_id: row.get(10)?,
            deleted: row.get::<_, i32>(11)? != 0,
            created_at: row.get(12)?,
            updated_at: row.get(13)?,
            created_by_device_id: row.get(14)?,
            updated_by_device_id: row.get(15)?,
        })
    })?;

    let mut attachments = Vec::new();
    for row in rows {
        attachments.push(row?);
    }
    Ok(attachments)
}

fn read_all_active_attachment_chunks(
    conn: &VaultConnection,
) -> StorageResult<Vec<AttachmentChunk>> {
    let mut stmt = conn.inner().prepare(
        "SELECT c.attachment_id, c.chunk_index, c.chunk_hash, c.chunk_ct,
                c.external_uri_ct, c.stored_size, c.created_at
         FROM attachment_chunks c
         JOIN attachments a ON a.attachment_id = c.attachment_id
         WHERE a.deleted = 0
         ORDER BY c.attachment_id ASC, c.chunk_index ASC",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(AttachmentChunk {
            attachment_id: row.get(0)?,
            chunk_index: row.get::<_, i64>(1)? as u32,
            chunk_hash: row.get(2)?,
            chunk_ct: row.get(3)?,
            external_uri_ct: row.get(4)?,
            stored_size: row.get::<_, i64>(5)? as u64,
            created_at: row.get(6)?,
        })
    })?;

    let mut chunks = Vec::new();
    for row in rows {
        chunks.push(row?);
    }
    Ok(chunks)
}

fn read_all_active_project_tags(conn: &VaultConnection) -> StorageResult<Vec<ProjectTagSetRow>> {
    let mut by_project: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut stmt = conn.inner().prepare(
        "SELECT p.project_id, t.tag
         FROM projects p
         LEFT JOIN project_tags t ON t.project_id = p.project_id
         WHERE p.deleted = 0
         ORDER BY p.project_id, t.tag",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
    })?;
    for row in rows {
        let (project_id, tag) = row?;
        let tags = by_project.entry(project_id).or_default();
        if let Some(tag) = tag {
            tags.push(tag);
        }
    }
    Ok(by_project
        .into_iter()
        .map(|(project_id, tags)| ProjectTagSetRow { project_id, tags })
        .collect())
}

fn upsert_project(
    conn: &VaultConnection,
    p: &Project,
    restore_commit_id: &str,
    now: &str,
    device_id: &str,
) -> StorageResult<()> {
    conn.inner().execute(
        "INSERT INTO projects (project_id, title_ct, summary_ct, group_id,
         icon_ref, favorite, archived, deleted, tiga_mode_override, object_clock,
         head_commit_id, attachment_count, created_at, updated_at,
         created_by_device_id, updated_by_device_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
         ON CONFLICT(project_id) DO UPDATE SET
            title_ct = excluded.title_ct,
            summary_ct = excluded.summary_ct,
            group_id = excluded.group_id,
            icon_ref = excluded.icon_ref,
            favorite = excluded.favorite,
            archived = excluded.archived,
            deleted = 0,
            tiga_mode_override = excluded.tiga_mode_override,
            object_clock = excluded.object_clock,
            head_commit_id = excluded.head_commit_id,
            attachment_count = excluded.attachment_count,
            updated_at = excluded.updated_at,
            updated_by_device_id = excluded.updated_by_device_id",
        params![
            p.project_id,
            p.title_ct,
            p.summary_ct,
            p.group_id,
            p.icon_ref,
            p.favorite as i32,
            p.archived as i32,
            p.tiga_mode_override.as_ref().map(|m| m.to_string()),
            bump_clock(&p.object_clock),
            restore_commit_id,
            p.attachment_count as i32,
            p.created_at,
            now,
            p.created_by_device_id,
            device_id,
        ],
    )?;
    Ok(())
}

fn upsert_entry(
    conn: &VaultConnection,
    e: &Entry,
    restore_commit_id: &str,
    now: &str,
    device_id: &str,
) -> StorageResult<()> {
    conn.inner().execute(
        "INSERT INTO entries (entry_id, project_id, entry_type, title_ct,
         payload_ct, payload_schema_version, tiga_mode_override, object_clock,
         head_commit_id, deleted, created_at, updated_at,
         created_by_device_id, updated_by_device_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, ?10, ?11, ?12, ?13)
         ON CONFLICT(entry_id) DO UPDATE SET
            project_id = excluded.project_id,
            entry_type = excluded.entry_type,
            title_ct = excluded.title_ct,
            payload_ct = excluded.payload_ct,
            payload_schema_version = excluded.payload_schema_version,
            tiga_mode_override = excluded.tiga_mode_override,
            object_clock = excluded.object_clock,
            head_commit_id = excluded.head_commit_id,
            deleted = 0,
            updated_at = excluded.updated_at,
            updated_by_device_id = excluded.updated_by_device_id",
        params![
            e.entry_id,
            e.project_id,
            e.entry_type.to_string(),
            e.title_ct,
            e.payload_ct,
            e.payload_schema_version as i64,
            e.tiga_mode_override.as_ref().map(|m| m.to_string()),
            bump_clock(&e.object_clock),
            restore_commit_id,
            e.created_at,
            now,
            e.created_by_device_id,
            device_id,
        ],
    )?;
    Ok(())
}

fn upsert_attachment(
    conn: &VaultConnection,
    a: &Attachment,
    restore_commit_id: &str,
    now: &str,
    device_id: &str,
) -> StorageResult<()> {
    conn.inner().execute(
        "INSERT INTO attachments (attachment_id, project_id, entry_id,
         file_name_ct, media_type_ct, storage_mode, content_hash,
         original_size, stored_size, chunk_count, head_commit_id,
         deleted, created_at, updated_at, created_by_device_id, updated_by_device_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0, ?12, ?13, ?14, ?15)
         ON CONFLICT(attachment_id) DO UPDATE SET
            project_id = excluded.project_id,
            entry_id = excluded.entry_id,
            file_name_ct = excluded.file_name_ct,
            media_type_ct = excluded.media_type_ct,
            storage_mode = excluded.storage_mode,
            content_hash = excluded.content_hash,
            original_size = excluded.original_size,
            stored_size = excluded.stored_size,
            chunk_count = excluded.chunk_count,
            head_commit_id = excluded.head_commit_id,
            deleted = 0,
            updated_at = excluded.updated_at,
            updated_by_device_id = excluded.updated_by_device_id",
        params![
            a.attachment_id,
            a.project_id,
            a.entry_id,
            a.file_name_ct,
            a.media_type_ct,
            a.storage_mode.to_string(),
            a.content_hash,
            a.original_size as i64,
            a.stored_size as i64,
            a.chunk_count as i32,
            restore_commit_id,
            a.created_at,
            now,
            a.created_by_device_id,
            device_id,
        ],
    )?;
    Ok(())
}

fn restore_attachment_chunks(
    conn: &VaultConnection,
    attachment_ids: &HashSet<String>,
    chunks: &[AttachmentChunk],
) -> StorageResult<()> {
    for attachment_id in attachment_ids {
        conn.inner().execute(
            "DELETE FROM attachment_chunks WHERE attachment_id = ?1",
            params![attachment_id],
        )?;
    }

    for chunk in chunks {
        conn.inner().execute(
            "INSERT OR REPLACE INTO attachment_chunks (attachment_id, chunk_index,
             chunk_hash, chunk_ct, external_uri_ct, stored_size, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                chunk.attachment_id,
                chunk.chunk_index as i64,
                chunk.chunk_hash,
                chunk.chunk_ct,
                chunk.external_uri_ct,
                chunk.stored_size as i64,
                chunk.created_at,
            ],
        )?;
    }

    Ok(())
}

fn restore_project_tags(
    conn: &VaultConnection,
    project_ids: &HashSet<String>,
    tag_sets: &[ProjectTagSetRow],
) -> StorageResult<()> {
    for project_id in project_ids {
        conn.inner().execute(
            "DELETE FROM project_tags WHERE project_id = ?1",
            params![project_id],
        )?;
    }
    for row in tag_sets {
        for tag in &row.tags {
            conn.inner().execute(
                "INSERT OR IGNORE INTO project_tags (project_id, tag) VALUES (?1, ?2)",
                params![row.project_id, tag],
            )?;
        }
    }
    Ok(())
}

fn active_ids(
    conn: &VaultConnection,
    table: &str,
    id_column: &str,
) -> StorageResult<HashSet<String>> {
    let mut stmt = conn.inner().prepare(&format!(
        "SELECT {id_column} FROM {table} WHERE deleted = 0"
    ))?;
    let rows = stmt.query_map([], |row| row.get(0))?;
    let mut ids = HashSet::new();
    for row in rows {
        ids.insert(row?);
    }
    Ok(ids)
}

fn id_set<'a>(ids: impl Iterator<Item = &'a str>) -> HashSet<String> {
    ids.map(str::to_string).collect()
}

fn difference(left: &HashSet<String>, right: &HashSet<String>) -> Vec<String> {
    let mut ids: Vec<String> = left.difference(right).cloned().collect();
    ids.sort();
    ids
}

#[allow(clippy::too_many_arguments)]
fn soft_delete_for_restore(
    conn: &VaultConnection,
    ctx: &CommitContext,
    object_type: &str,
    table: &str,
    id_column: &str,
    object_ids: &[String],
    restore_commit_id: &str,
    now: &str,
) -> StorageResult<()> {
    for object_id in object_ids {
        ctx.create_tombstone(conn, object_type, object_id)?;
        if table == "attachments" {
            conn.inner().execute(
                &format!(
                    "UPDATE {table} SET deleted = 1, head_commit_id = ?2,
                     updated_at = ?3, updated_by_device_id = ?4 WHERE {id_column} = ?1"
                ),
                params![object_id, restore_commit_id, now, ctx.device_id],
            )?;
        } else {
            let clock: String = conn.inner().query_row(
                &format!("SELECT object_clock FROM {table} WHERE {id_column} = ?1"),
                params![object_id],
                |row| row.get(0),
            )?;
            conn.inner().execute(
                &format!(
                    "UPDATE {table} SET deleted = 1, object_clock = ?2,
                     head_commit_id = ?3, updated_at = ?4,
                     updated_by_device_id = ?5 WHERE {id_column} = ?1"
                ),
                params![
                    object_id,
                    bump_clock(&clock),
                    restore_commit_id,
                    now,
                    ctx.device_id
                ],
            )?;
        }
    }
    Ok(())
}

fn bump_clock(clock: &str) -> String {
    let counter = serde_json::from_str::<serde_json::Value>(clock)
        .ok()
        .and_then(|value| value.get("counter")?.as_u64())
        .unwrap_or(0);
    format!(r#"{{"counter":{}}}"#, counter + 1)
}

fn compute_sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::{initialize_vault, VaultInitParams};
    use crate::repo::attachment::AttachmentRepo;
    use crate::repo::entry::EntryRepo;
    use crate::repo::project::ProjectRepo;
    use crate::search::SearchService;
    use crate::tiga::TigaService;
    use mdbx_core::model::{EntryType, UnlockMethodType, VaultSession};
    use mdbx_core::tiga::{AuthorizationOutcome, DeviceAssurance, DeviceContext, SessionAssurance};

    fn setup() -> (VaultConnection, CommitContext) {
        let conn = VaultConnection::open_in_memory().unwrap();
        let params = VaultInitParams::default();
        initialize_vault(&conn, &params).unwrap();
        let ctx = CommitContext::new("test-device".to_string());
        (conn, ctx)
    }

    fn login_payload() -> serde_json::Value {
        serde_json::json!({"username": "alice", "password": "s3cret"})
    }

    fn restore_session(now: i64) -> VaultSession {
        VaultSession {
            session_id: "restore-session".to_string(),
            unlock_method: UnlockMethodType::Password,
            created_at: chrono::DateTime::from_timestamp(now, 0)
                .unwrap()
                .to_rfc3339(),
            assurance: SessionAssurance::from_unlock_method(UnlockMethodType::Password, now),
        }
    }

    fn restore_device() -> DeviceContext {
        DeviceContext {
            device_id: Some("test-device".to_string()),
            assurance: DeviceAssurance::Standard,
            secure_clipboard_available: false,
            screen_capture_protection_available: false,
            secure_temp_files_available: true,
        }
    }

    // -----------------------------------------------------------------------
    // CREATE SNAPSHOT
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_empty_snapshot() {
        let (conn, ctx) = setup();
        let snap = SnapshotRepo::create_snapshot(&conn, &ctx).unwrap();

        assert!(!snap.snapshot_id.is_empty());
        assert!(!snap.base_commit_id.is_empty());
        assert!(!snap.snapshot_ct.is_empty());
        assert_eq!(snap.snapshot_hash.len(), 64);
        assert_eq!(snap.created_by_device_id, "test-device");

        // 验证 payload 可反序列化
        let payload: SnapshotPayload = serde_json::from_slice(&snap.snapshot_ct).unwrap();
        assert_eq!(payload.format_version, crate::migration::FORMAT_V2);
        assert!(payload.projects.is_empty());
        assert!(payload.entries.is_empty());
        assert!(payload.attachments.is_empty());
        assert!(payload.attachment_chunks.unwrap().is_empty());
    }

    #[test]
    fn authorized_restore_is_atomic_with_security_audit() {
        let (conn, ctx) = setup();
        let snapshot = SnapshotRepo::create_snapshot(&conn, &ctx).unwrap();
        let session = restore_session(1_000);
        let device = restore_device();
        let decision = SnapshotRepo::restore_snapshot_authorized(
            &conn,
            &ctx,
            &snapshot.snapshot_id,
            TigaAuthorizationContext {
                session: Some(&session),
                device: &device,
                now_unix_secs: 1_010,
            },
        )
        .unwrap();
        assert_eq!(decision.outcome, AuthorizationOutcome::Allow);
        let events = TigaService::list_security_audit_events(&conn, 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, TigaOperation::RestoreSnapshot);
        let commit_id = events[0]
            .commit_id
            .as_deref()
            .expect("authorized restore must reference its commit");
        let operation_id = events[0]
            .operation_id
            .as_deref()
            .expect("authorized restore must reference its operation");
        let stored_operation: String = conn
            .inner()
            .query_row(
                "SELECT operation_id FROM commit_operations WHERE commit_id = ?1",
                params![commit_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_operation, operation_id);
        assert_eq!(
            events[0].policy_version,
            Some(mdbx_core::tiga::TIGA_POLICY_VERSION)
        );
        assert_eq!(
            events[0].policy_fingerprint.as_deref().map(<[u8]>::len),
            Some(32)
        );
    }

    #[test]
    fn restore_without_session_is_denied_before_snapshot_changes() {
        let (conn, ctx) = setup();
        let snapshot = SnapshotRepo::create_snapshot(&conn, &ctx).unwrap();
        let device = restore_device();
        let before_commits: i64 = conn
            .inner()
            .query_row("SELECT COUNT(*) FROM commits", [], |row| row.get(0))
            .unwrap();
        let error = SnapshotRepo::restore_snapshot_authorized(
            &conn,
            &ctx,
            &snapshot.snapshot_id,
            TigaAuthorizationContext {
                session: None,
                device: &device,
                now_unix_secs: 1_010,
            },
        )
        .unwrap_err();
        assert!(matches!(error, StorageError::Authorization(_)));
        let after_commits: i64 = conn
            .inner()
            .query_row("SELECT COUNT(*) FROM commits", [], |row| row.get(0))
            .unwrap();
        assert_eq!(before_commits, after_commits);
        assert_eq!(
            TigaService::list_security_audit_events(&conn, 10)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn test_snapshot_captures_projects() {
        let (conn, ctx) = setup();
        ProjectRepo::create(&conn, &ctx, "Alpha", None, None).unwrap();
        ProjectRepo::create(&conn, &ctx, "Beta", None, None).unwrap();

        let snap = SnapshotRepo::create_snapshot(&conn, &ctx).unwrap();
        let payload: SnapshotPayload = serde_json::from_slice(&snap.snapshot_ct).unwrap();

        assert_eq!(payload.projects.len(), 2);
        let titles: Vec<&str> = payload
            .projects
            .iter()
            .map(|p| std::str::from_utf8(&p.title_ct).unwrap())
            .collect();
        assert!(titles.contains(&"Alpha"));
        assert!(titles.contains(&"Beta"));
    }

    #[test]
    fn test_snapshot_excludes_deleted() {
        let (conn, ctx) = setup();
        let p1 = ProjectRepo::create(&conn, &ctx, "Keep", None, None).unwrap();
        let p2 = ProjectRepo::create(&conn, &ctx, "Delete", None, None).unwrap();
        ProjectRepo::soft_delete(&conn, &ctx, &p2.project_id).unwrap();

        let snap = SnapshotRepo::create_snapshot(&conn, &ctx).unwrap();
        let payload: SnapshotPayload = serde_json::from_slice(&snap.snapshot_ct).unwrap();

        assert_eq!(payload.projects.len(), 1);
        assert_eq!(payload.projects[0].project_id, p1.project_id);
    }

    #[test]
    fn test_snapshot_captures_entries() {
        let (conn, ctx) = setup();
        let project = ProjectRepo::create(&conn, &ctx, "P", None, None).unwrap();
        EntryRepo::create(
            &conn,
            &ctx,
            &project.project_id,
            EntryType::Login,
            Some("E1"),
            &login_payload(),
        )
        .unwrap();
        EntryRepo::create(
            &conn,
            &ctx,
            &project.project_id,
            EntryType::Note,
            Some("E2"),
            &serde_json::json!({"text":"hi"}),
        )
        .unwrap();

        let snap = SnapshotRepo::create_snapshot(&conn, &ctx).unwrap();
        let payload: SnapshotPayload = serde_json::from_slice(&snap.snapshot_ct).unwrap();

        assert_eq!(payload.entries.len(), 2);
        for e in &payload.entries {
            assert_eq!(e.project_id, project.project_id);
        }
    }

    #[test]
    fn snapshot_restores_custom_object_type_and_payload_schema_version() {
        let (conn, ctx) = setup();
        let project = ProjectRepo::create(&conn, &ctx, "Generic", None, None).unwrap();
        let object = EntryRepo::create_with_payload_schema_version(
            &conn,
            &ctx,
            &project.project_id,
            EntryType::custom("com.monica.steam.mafile").unwrap(),
            Some("Steam Guard"),
            &serde_json::json!({"account_name": "alice", "device_id": "android:test"}),
            5,
        )
        .unwrap();

        let snapshot = SnapshotRepo::create_snapshot(&conn, &ctx).unwrap();
        conn.inner()
            .execute(
                "DELETE FROM entries WHERE entry_id = ?1",
                params![object.entry_id],
            )
            .unwrap();
        SnapshotRepo::restore_snapshot(&conn, &ctx, &snapshot.snapshot_id).unwrap();

        let restored = EntryRepo::get_by_id(&conn, &object.entry_id)
            .unwrap()
            .unwrap();
        assert_eq!(restored.entry_type.as_str(), "com.monica.steam.mafile");
        assert_eq!(restored.payload_schema_version, 5);
    }

    #[test]
    fn test_snapshot_captures_attachments() {
        let (conn, ctx) = setup();
        let project = ProjectRepo::create(&conn, &ctx, "P", None, None).unwrap();
        AttachmentRepo::add(
            &conn,
            &ctx,
            &project.project_id,
            None,
            "a.txt",
            None,
            "h1",
            100,
        )
        .unwrap();
        AttachmentRepo::add(
            &conn,
            &ctx,
            &project.project_id,
            None,
            "b.txt",
            None,
            "h2",
            200,
        )
        .unwrap();

        let snap = SnapshotRepo::create_snapshot(&conn, &ctx).unwrap();
        let payload: SnapshotPayload = serde_json::from_slice(&snap.snapshot_ct).unwrap();

        assert_eq!(payload.attachments.len(), 2);
    }

    #[test]
    fn test_snapshot_captures_attachment_chunks() {
        let (conn, ctx) = setup();
        let project = ProjectRepo::create(&conn, &ctx, "P", None, None).unwrap();
        let att = AttachmentRepo::add(
            &conn,
            &ctx,
            &project.project_id,
            None,
            "chunked.bin",
            Some("application/octet-stream"),
            "",
            13,
        )
        .unwrap();
        AttachmentRepo::write_chunked_content(
            &conn,
            &ctx,
            &att.attachment_id,
            b"hello snapshot",
            5,
        )
        .unwrap();

        let snap = SnapshotRepo::create_snapshot(&conn, &ctx).unwrap();
        let payload: SnapshotPayload = serde_json::from_slice(&snap.snapshot_ct).unwrap();

        assert_eq!(payload.attachments.len(), 1);
        let chunks = payload.attachment_chunks.unwrap();
        assert_eq!(chunks.len(), 3);
        assert!(chunks
            .iter()
            .all(|chunk| chunk.attachment_id == att.attachment_id));
    }

    #[test]
    fn test_snapshot_commit_created() {
        let (conn, ctx) = setup();
        let snap = SnapshotRepo::create_snapshot(&conn, &ctx).unwrap();

        let (commit_kind, change_scope): (String, String) = conn
            .inner()
            .query_row(
                "SELECT commit_kind, change_scope FROM commits WHERE commit_id = ?1",
                params![snap.base_commit_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(commit_kind, "snapshot");
        assert_eq!(change_scope, "multi");
    }

    // -----------------------------------------------------------------------
    // RESTORE SNAPSHOT
    // -----------------------------------------------------------------------

    #[test]
    fn test_restore_rebuilds_projects() {
        let (conn, ctx) = setup();

        // 创建一些数据并拍快照
        ProjectRepo::create(&conn, &ctx, "Original", None, None).unwrap();
        let snap = SnapshotRepo::create_snapshot(&conn, &ctx).unwrap();

        // 清空 projects（模拟数据丢失）
        conn.inner().execute("DELETE FROM entries", []).unwrap();
        conn.inner().execute("DELETE FROM attachments", []).unwrap();
        conn.inner().execute("DELETE FROM projects", []).unwrap();

        // 恢复
        SnapshotRepo::restore_snapshot(&conn, &ctx, &snap.snapshot_id).unwrap();

        let restored = ProjectRepo::list_all(&conn).unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].title_ct, b"Original");
    }

    #[test]
    fn test_restore_rebuilds_entries() {
        let (conn, ctx) = setup();
        let project = ProjectRepo::create(&conn, &ctx, "P", None, None).unwrap();
        EntryRepo::create(
            &conn,
            &ctx,
            &project.project_id,
            EntryType::Login,
            Some("MyLogin"),
            &login_payload(),
        )
        .unwrap();

        let snap = SnapshotRepo::create_snapshot(&conn, &ctx).unwrap();

        // 清空
        conn.inner().execute("DELETE FROM entries", []).unwrap();
        conn.inner().execute("DELETE FROM attachments", []).unwrap();
        conn.inner().execute("DELETE FROM projects", []).unwrap();

        // 恢复
        SnapshotRepo::restore_snapshot(&conn, &ctx, &snap.snapshot_id).unwrap();

        let entries = read_all_active_entries(&conn).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entry_type, EntryType::Login);
        assert_eq!(entries[0].title_ct, Some(b"MyLogin".to_vec()));
    }

    #[test]
    fn test_restore_rebuilds_attachments() {
        let (conn, ctx) = setup();
        let project = ProjectRepo::create(&conn, &ctx, "P", None, None).unwrap();
        AttachmentRepo::add(
            &conn,
            &ctx,
            &project.project_id,
            None,
            "photo.png",
            Some("image/png"),
            "abc123",
            512,
        )
        .unwrap();

        let snap = SnapshotRepo::create_snapshot(&conn, &ctx).unwrap();

        // 清空
        conn.inner().execute("DELETE FROM attachments", []).unwrap();
        conn.inner().execute("DELETE FROM entries", []).unwrap();
        conn.inner().execute("DELETE FROM projects", []).unwrap();

        // 恢复
        SnapshotRepo::restore_snapshot(&conn, &ctx, &snap.snapshot_id).unwrap();

        let attachments = read_all_active_attachments(&conn).unwrap();
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].file_name_ct, b"photo.png");
        assert_eq!(attachments[0].media_type_ct, Some(b"image/png".to_vec()));
        assert_eq!(attachments[0].content_hash, "abc123");
        assert_eq!(attachments[0].original_size, 512);
    }

    #[test]
    fn test_restore_rebuilds_attachment_chunks_and_content() {
        let (conn, ctx) = setup();
        let project = ProjectRepo::create(&conn, &ctx, "P", None, None).unwrap();
        let att = AttachmentRepo::add(
            &conn,
            &ctx,
            &project.project_id,
            None,
            "video.bin",
            Some("application/octet-stream"),
            "",
            17,
        )
        .unwrap();
        let content = b"restorable content";
        AttachmentRepo::write_chunked_content(&conn, &ctx, &att.attachment_id, content, 4).unwrap();

        let snap = SnapshotRepo::create_snapshot(&conn, &ctx).unwrap();

        conn.inner()
            .execute("DELETE FROM attachment_chunks", [])
            .unwrap();
        conn.inner().execute("DELETE FROM attachments", []).unwrap();
        conn.inner().execute("DELETE FROM entries", []).unwrap();
        conn.inner().execute("DELETE FROM projects", []).unwrap();

        SnapshotRepo::restore_snapshot(&conn, &ctx, &snap.snapshot_id).unwrap();

        let restored = AttachmentRepo::read_content(&conn, &att.attachment_id).unwrap();
        assert_eq!(restored, content);
        assert!(AttachmentRepo::verify_chunks_integrity(&conn, &att.attachment_id).unwrap());
    }

    #[test]
    fn test_restore_creates_commit() {
        let (conn, ctx) = setup();
        ProjectRepo::create(&conn, &ctx, "P", None, None).unwrap();
        let snap = SnapshotRepo::create_snapshot(&conn, &ctx).unwrap();

        // 清空并恢复
        conn.inner().execute("DELETE FROM entries", []).unwrap();
        conn.inner().execute("DELETE FROM attachments", []).unwrap();
        conn.inner().execute("DELETE FROM projects", []).unwrap();
        SnapshotRepo::restore_snapshot(&conn, &ctx, &snap.snapshot_id).unwrap();

        // 恢复后应有新的 snapshot commit
        let count: i32 = conn
            .inner()
            .query_row(
                "SELECT COUNT(*) FROM commits WHERE commit_kind = 'snapshot'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            count >= 2,
            "expected at least 2 snapshot commits, got {}",
            count
        );
    }

    #[test]
    fn test_restore_hash_mismatch_rejected() {
        let (conn, ctx) = setup();
        let mut snap = SnapshotRepo::create_snapshot(&conn, &ctx).unwrap();

        // 篡改 snapshot_ct 但不改 hash
        snap.snapshot_ct = b"corrupted".to_vec();
        conn.inner()
            .execute(
                "UPDATE snapshots SET snapshot_ct = ?1 WHERE snapshot_id = ?2",
                params![snap.snapshot_ct, snap.snapshot_id],
            )
            .unwrap();

        let result = SnapshotRepo::restore_snapshot(&conn, &ctx, &snap.snapshot_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_restore_nonexistent() {
        let (conn, ctx) = setup();
        let result = SnapshotRepo::restore_snapshot(&conn, &ctx, "nonexistent");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // READ
    // -----------------------------------------------------------------------

    #[test]
    fn test_get_by_id() {
        let (conn, ctx) = setup();
        let created = SnapshotRepo::create_snapshot(&conn, &ctx).unwrap();

        let found = SnapshotRepo::get_by_id(&conn, &created.snapshot_id)
            .unwrap()
            .unwrap();
        assert_eq!(found.snapshot_id, created.snapshot_id);
        assert_eq!(found.snapshot_hash, created.snapshot_hash);
    }

    #[test]
    fn test_get_nonexistent() {
        let (conn, _ctx) = setup();
        let result = SnapshotRepo::get_by_id(&conn, "nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_list_all() {
        let (conn, ctx) = setup();
        SnapshotRepo::create_snapshot(&conn, &ctx).unwrap();
        SnapshotRepo::create_snapshot(&conn, &ctx).unwrap();

        let all = SnapshotRepo::list_all(&conn).unwrap();
        assert_eq!(all.len(), 2);
        // 按时间降序排列
        assert!(all[0].created_at >= all[1].created_at);
    }

    // -----------------------------------------------------------------------
    // VERIFY INTEGRITY
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_integrity_passes() {
        let (conn, ctx) = setup();
        let snap = SnapshotRepo::create_snapshot(&conn, &ctx).unwrap();
        assert!(SnapshotRepo::verify_integrity(&conn, &snap.snapshot_id).unwrap());
    }

    #[test]
    fn test_verify_integrity_fails_on_tamper() {
        let (conn, ctx) = setup();
        let snap = SnapshotRepo::create_snapshot(&conn, &ctx).unwrap();

        conn.inner()
            .execute(
                "UPDATE snapshots SET snapshot_ct = ?1 WHERE snapshot_id = ?2",
                params![b"tampered payload", snap.snapshot_id],
            )
            .unwrap();

        assert!(!SnapshotRepo::verify_integrity(&conn, &snap.snapshot_id).unwrap());
    }

    #[test]
    fn test_verify_integrity_nonexistent() {
        let (conn, _ctx) = setup();
        assert!(!SnapshotRepo::verify_integrity(&conn, "nonexistent").unwrap());
    }

    // -----------------------------------------------------------------------
    // ROUNDTRIP
    // -----------------------------------------------------------------------

    #[test]
    fn test_full_roundtrip() {
        let (conn, ctx) = setup();

        // 创建完整数据集
        let p1 =
            ProjectRepo::create(&conn, &ctx, "Work", Some("group-1"), Some("icon-work")).unwrap();
        let p2 = ProjectRepo::create(&conn, &ctx, "Personal", None, None).unwrap();

        let e1 = EntryRepo::create(
            &conn,
            &ctx,
            &p1.project_id,
            EntryType::Login,
            Some("GitHub"),
            &serde_json::json!({"username": "gh", "password": "pass1"}),
        )
        .unwrap();
        let _e2 = EntryRepo::create(
            &conn,
            &ctx,
            &p2.project_id,
            EntryType::Note,
            Some("Ideas"),
            &serde_json::json!({"text": "build something"}),
        )
        .unwrap();

        let a1 = AttachmentRepo::add(
            &conn,
            &ctx,
            &p1.project_id,
            Some(&e1.entry_id),
            "screenshot.png",
            Some("image/png"),
            "hash1",
            1024,
        )
        .unwrap();
        let _a2 = AttachmentRepo::add(
            &conn,
            &ctx,
            &p2.project_id,
            None,
            "notes.txt",
            Some("text/plain"),
            "hash2",
            2048,
        )
        .unwrap();

        // 拍快照
        let snap = SnapshotRepo::create_snapshot(&conn, &ctx).unwrap();

        // 清空
        conn.inner()
            .execute("DELETE FROM attachment_chunks", [])
            .unwrap();
        conn.inner().execute("DELETE FROM attachments", []).unwrap();
        conn.inner().execute("DELETE FROM entries", []).unwrap();
        conn.inner().execute("DELETE FROM projects", []).unwrap();

        // 恢复
        SnapshotRepo::restore_snapshot(&conn, &ctx, &snap.snapshot_id).unwrap();

        // 验证完整恢复
        let projects = ProjectRepo::list_all(&conn).unwrap();
        assert_eq!(projects.len(), 2);

        let entries = read_all_active_entries(&conn).unwrap();
        assert_eq!(entries.len(), 2);

        let attachments = read_all_active_attachments(&conn).unwrap();
        assert_eq!(attachments.len(), 2);

        // 验证字段完整性
        let p1_restored = projects
            .iter()
            .find(|p| p.project_id == p1.project_id)
            .unwrap();
        assert_eq!(p1_restored.title_ct, b"Work");
        assert_eq!(p1_restored.group_id.as_deref(), Some("group-1"));
        assert_eq!(p1_restored.icon_ref.as_deref(), Some("icon-work"));

        let e1_restored = entries.iter().find(|e| e.entry_id == e1.entry_id).unwrap();
        assert_eq!(e1_restored.project_id, p1.project_id);
        assert_eq!(e1_restored.entry_type, EntryType::Login);
        assert_eq!(e1_restored.title_ct, Some(b"GitHub".to_vec()));

        let a1_restored = attachments
            .iter()
            .find(|a| a.attachment_id == a1.attachment_id)
            .unwrap();
        assert_eq!(a1_restored.entry_id, Some(e1.entry_id));
        assert_eq!(a1_restored.storage_mode, StorageMode::EmbeddedInline);
    }

    #[test]
    fn restore_reinstates_exact_active_set_tags_and_causal_heads() {
        let (conn, ctx) = setup();
        let original = ProjectRepo::create(&conn, &ctx, "Original", None, None).unwrap();
        SearchService::set_tags_tracked(
            &conn,
            &ctx,
            &original.project_id,
            &["snapshot-tag".to_string()],
        )
        .unwrap();
        let snapshot = SnapshotRepo::create_snapshot(&conn, &ctx).unwrap();

        SearchService::set_tags_tracked(
            &conn,
            &ctx,
            &original.project_id,
            &["later-tag".to_string()],
        )
        .unwrap();
        let later_project = ProjectRepo::create(&conn, &ctx, "Later", None, None).unwrap();
        let later_entry = EntryRepo::create(
            &conn,
            &ctx,
            &later_project.project_id,
            EntryType::Login,
            Some("Later login"),
            &login_payload(),
        )
        .unwrap();
        let later_attachment = AttachmentRepo::add(
            &conn,
            &ctx,
            &later_project.project_id,
            Some(&later_entry.entry_id),
            "later.bin",
            None,
            "",
            0,
        )
        .unwrap();

        SnapshotRepo::restore_snapshot(&conn, &ctx, &snapshot.snapshot_id).unwrap();

        assert_eq!(ProjectRepo::list_all(&conn).unwrap().len(), 1);
        assert_eq!(ProjectRepo::list_deleted(&conn).unwrap().len(), 1);
        assert!(
            EntryRepo::get_by_id(&conn, &later_entry.entry_id)
                .unwrap()
                .unwrap()
                .deleted
        );
        assert!(
            AttachmentRepo::get_by_id(&conn, &later_attachment.attachment_id)
                .unwrap()
                .unwrap()
                .deleted
        );
        assert_eq!(
            SearchService::list_tags(&conn, &original.project_id).unwrap(),
            vec!["snapshot-tag".to_string()]
        );

        let restore_head: String = conn
            .inner()
            .query_row(
                "SELECT head_commit_id FROM branches WHERE branch_name = 'main'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        for (object_type, object_id) in [
            ("project", original.project_id.as_str()),
            ("project", later_project.project_id.as_str()),
            ("entry", later_entry.entry_id.as_str()),
            ("attachment", later_attachment.attachment_id.as_str()),
        ] {
            let count: i64 = conn
                .inner()
                .query_row(
                    "SELECT COUNT(*) FROM object_versions
                     WHERE object_type = ?1 AND object_id = ?2 AND commit_id = ?3",
                    params![object_type, object_id, restore_head],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                count, 1,
                "missing restore version for {object_type}:{object_id}"
            );
        }
    }

    #[test]
    fn restore_failure_rolls_back_commit_heads_and_rows() {
        let (conn, ctx) = setup();
        let project = ProjectRepo::create(&conn, &ctx, "P", None, None).unwrap();
        EntryRepo::create(
            &conn,
            &ctx,
            &project.project_id,
            EntryType::Login,
            Some("Login"),
            &login_payload(),
        )
        .unwrap();
        let snapshot = SnapshotRepo::create_snapshot(&conn, &ctx).unwrap();

        let mut payload: SnapshotPayload = serde_json::from_slice(&snapshot.snapshot_ct).unwrap();
        payload.entries[0].project_id = "missing-project".to_string();
        let invalid_payload = serde_json::to_vec(&payload).unwrap();
        conn.inner()
            .execute(
                "UPDATE snapshots SET snapshot_ct = ?1, snapshot_hash = ?2
                 WHERE snapshot_id = ?3",
                params![
                    invalid_payload,
                    compute_sha256_hex(&invalid_payload),
                    snapshot.snapshot_id
                ],
            )
            .unwrap();

        let before_commits: i64 = conn
            .inner()
            .query_row("SELECT COUNT(*) FROM commits", [], |row| row.get(0))
            .unwrap();
        let before_head: String = conn
            .inner()
            .query_row(
                "SELECT head_commit_id FROM branches WHERE branch_name = 'main'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        let session = restore_session(1_000);
        let device = restore_device();
        assert!(SnapshotRepo::restore_snapshot_authorized(
            &conn,
            &ctx,
            &snapshot.snapshot_id,
            TigaAuthorizationContext {
                session: Some(&session),
                device: &device,
                now_unix_secs: 1_010,
            },
        )
        .is_err());

        let after_commits: i64 = conn
            .inner()
            .query_row("SELECT COUNT(*) FROM commits", [], |row| row.get(0))
            .unwrap();
        let after_head: String = conn
            .inner()
            .query_row(
                "SELECT head_commit_id FROM branches WHERE branch_name = 'main'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(after_commits, before_commits);
        assert_eq!(after_head, before_head);
        assert!(TigaService::list_security_audit_events(&conn, 10)
            .unwrap()
            .is_empty());
        assert_eq!(ProjectRepo::list_all(&conn).unwrap().len(), 1);
        assert_eq!(
            EntryRepo::list_by_project(&conn, &project.project_id)
                .unwrap()
                .len(),
            1
        );
    }
}
