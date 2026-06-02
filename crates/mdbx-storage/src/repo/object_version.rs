use rusqlite::params;
use rusqlite::OptionalExtension;

use crate::connection::VaultConnection;
use crate::error::{StorageError, StorageResult};
use crate::sync_state::{AttachmentRow, EntryRow, ProjectRow};

pub struct ObjectVersionRepo;

impl ObjectVersionRepo {
    pub fn record_entry_current(
        conn: &VaultConnection,
        commit_id: &str,
        entry_id: &str,
    ) -> StorageResult<()> {
        let row = Self::current_entry_row(conn, entry_id)?;
        Self::record_entry_row(conn, commit_id, &row)
    }

    pub fn record_entry_row(
        conn: &VaultConnection,
        commit_id: &str,
        row: &EntryRow,
    ) -> StorageResult<()> {
        let snapshot_ct =
            serde_json::to_vec(row).map_err(|e| StorageError::SchemaCreation(e.to_string()))?;
        let now = chrono::Utc::now().to_rfc3339();

        conn.inner().execute(
            "INSERT OR REPLACE INTO object_versions
                (object_type, object_id, commit_id, snapshot_ct, created_at)
             VALUES ('entry', ?1, ?2, ?3, ?4)",
            params![row.entry_id, commit_id, snapshot_ct, now],
        )?;
        Ok(())
    }

    pub fn record_project_current(
        conn: &VaultConnection,
        commit_id: &str,
        project_id: &str,
    ) -> StorageResult<()> {
        let row = Self::current_project_row(conn, project_id)?;
        Self::record_project_row(conn, commit_id, &row)
    }

    pub fn record_project_row(
        conn: &VaultConnection,
        commit_id: &str,
        row: &ProjectRow,
    ) -> StorageResult<()> {
        let snapshot_ct =
            serde_json::to_vec(row).map_err(|e| StorageError::SchemaCreation(e.to_string()))?;
        let now = chrono::Utc::now().to_rfc3339();

        conn.inner().execute(
            "INSERT OR REPLACE INTO object_versions
                (object_type, object_id, commit_id, snapshot_ct, created_at)
             VALUES ('project', ?1, ?2, ?3, ?4)",
            params![row.project_id, commit_id, snapshot_ct, now],
        )?;
        Ok(())
    }

    pub fn record_attachment_current(
        conn: &VaultConnection,
        commit_id: &str,
        attachment_id: &str,
    ) -> StorageResult<()> {
        let row = Self::current_attachment_row(conn, attachment_id)?;
        Self::record_attachment_row(conn, commit_id, &row)
    }

    pub fn record_attachment_row(
        conn: &VaultConnection,
        commit_id: &str,
        row: &AttachmentRow,
    ) -> StorageResult<()> {
        let snapshot_ct =
            serde_json::to_vec(row).map_err(|e| StorageError::SchemaCreation(e.to_string()))?;
        let now = chrono::Utc::now().to_rfc3339();

        conn.inner().execute(
            "INSERT OR REPLACE INTO object_versions
                (object_type, object_id, commit_id, snapshot_ct, created_at)
             VALUES ('attachment', ?1, ?2, ?3, ?4)",
            params![row.attachment_id, commit_id, snapshot_ct, now],
        )?;
        Ok(())
    }

    pub fn get_entry(
        conn: &VaultConnection,
        entry_id: &str,
        commit_id: &str,
    ) -> StorageResult<Option<EntryRow>> {
        let snapshot: Option<Vec<u8>> = conn
            .inner()
            .query_row(
                "SELECT snapshot_ct FROM object_versions
                 WHERE object_type = 'entry' AND object_id = ?1 AND commit_id = ?2",
                params![entry_id, commit_id],
                |row| row.get(0),
            )
            .optional()?;

        snapshot
            .map(|bytes| {
                serde_json::from_slice(&bytes)
                    .map_err(|e| StorageError::SchemaCreation(e.to_string()))
            })
            .transpose()
    }

    pub fn get_project(
        conn: &VaultConnection,
        project_id: &str,
        commit_id: &str,
    ) -> StorageResult<Option<ProjectRow>> {
        let snapshot: Option<Vec<u8>> = conn
            .inner()
            .query_row(
                "SELECT snapshot_ct FROM object_versions
                 WHERE object_type = 'project' AND object_id = ?1 AND commit_id = ?2",
                params![project_id, commit_id],
                |row| row.get(0),
            )
            .optional()?;

        snapshot
            .map(|bytes| {
                serde_json::from_slice(&bytes)
                    .map_err(|e| StorageError::SchemaCreation(e.to_string()))
            })
            .transpose()
    }

    pub fn get_attachment(
        conn: &VaultConnection,
        attachment_id: &str,
        commit_id: &str,
    ) -> StorageResult<Option<AttachmentRow>> {
        let snapshot: Option<Vec<u8>> = conn
            .inner()
            .query_row(
                "SELECT snapshot_ct FROM object_versions
                 WHERE object_type = 'attachment' AND object_id = ?1 AND commit_id = ?2",
                params![attachment_id, commit_id],
                |row| row.get(0),
            )
            .optional()?;

        snapshot
            .map(|bytes| {
                serde_json::from_slice(&bytes)
                    .map_err(|e| StorageError::SchemaCreation(e.to_string()))
            })
            .transpose()
    }

    pub fn current_entry_row(conn: &VaultConnection, entry_id: &str) -> StorageResult<EntryRow> {
        conn.inner()
            .query_row(
                "SELECT entry_id, project_id, entry_type, title_ct, payload_ct,
                        payload_schema_version, tiga_mode_override, object_clock,
                        head_commit_id, deleted, created_at, updated_at,
                        created_by_device_id, updated_by_device_id
                 FROM entries WHERE entry_id = ?1",
                params![entry_id],
                |row| {
                    Ok(EntryRow {
                        entry_id: row.get(0)?,
                        project_id: row.get(1)?,
                        entry_type: row.get(2)?,
                        title_ct: row.get(3)?,
                        payload_ct: row.get(4)?,
                        payload_schema_version: row.get::<_, i64>(5)? as u32,
                        tiga_mode_override: row.get(6)?,
                        object_clock: row.get(7)?,
                        head_commit_id: row.get(8)?,
                        deleted: row.get::<_, i32>(9)? != 0,
                        created_at: row.get(10)?,
                        updated_at: row.get(11)?,
                        created_by_device_id: row.get(12)?,
                        updated_by_device_id: row.get(13)?,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| StorageError::NotFound(entry_id.to_string()))
    }

    pub fn current_project_row(
        conn: &VaultConnection,
        project_id: &str,
    ) -> StorageResult<ProjectRow> {
        conn.inner()
            .query_row(
                "SELECT project_id, title_ct, summary_ct, group_id, icon_ref,
                        favorite, archived, deleted, tiga_mode_override, object_clock,
                        head_commit_id, attachment_count, created_at, updated_at,
                        created_by_device_id, updated_by_device_id
                 FROM projects WHERE project_id = ?1",
                params![project_id],
                |row| {
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
                },
            )
            .optional()?
            .ok_or_else(|| StorageError::NotFound(project_id.to_string()))
    }

    pub fn current_attachment_row(
        conn: &VaultConnection,
        attachment_id: &str,
    ) -> StorageResult<AttachmentRow> {
        conn.inner()
            .query_row(
                "SELECT attachment_id, project_id, entry_id, file_name_ct,
                        media_type_ct, storage_mode, content_hash,
                        original_size, stored_size, chunk_count, head_commit_id,
                        deleted, created_at, updated_at,
                        created_by_device_id, updated_by_device_id
                 FROM attachments WHERE attachment_id = ?1",
                params![attachment_id],
                |row| {
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
                },
            )
            .optional()?
            .ok_or_else(|| StorageError::NotFound(attachment_id.to_string()))
    }
}
