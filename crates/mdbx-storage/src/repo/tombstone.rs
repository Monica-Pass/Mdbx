use std::collections::HashSet;

use rusqlite::params;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use mdbx_core::model::Tombstone;
use mdbx_core::model::TombstoneTargetType;
use mdbx_core::tiga::{AuthorizationDecision, TigaOperation, TigaScope};

use crate::connection::VaultConnection;
use crate::error::{StorageError, StorageResult};
use crate::repo::{CommitChange, CommitContext, CommitOperation};
use crate::tiga::TigaService;
use crate::tiga_policy::TigaAuthorizationContext;

/// 墓碑查询仓库。
///
/// 墓碑记录由 CommitContext::create_tombstone 写入，
/// 本仓库只负责查询和批量操作。
pub struct TombstoneRepo;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TombstonePurgeBlocker {
    RetentionNotScheduled,
    RetentionPeriodActive { eligible_at: String },
    InvalidRetentionTimestamp { value: String },
    MissingDeleteCommit,
    DeleteCommitMissing { commit_id: String },
    TargetMissing,
    TargetNotDeleted,
    UnresolvedConflict,
    DeviceHasNotAcknowledgedDelete { device_id: String },
    UnsupportedTargetType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TombstonePurgeEligibility {
    pub tombstone_id: String,
    pub eligible: bool,
    pub blockers: Vec<TombstonePurgeBlocker>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TombstonePurgeScheduleResult {
    pub tombstone_id: String,
    pub purge_eligible_at: String,
    pub commit_id: String,
}

impl TombstoneRepo {
    /// 按类型列出所有墓碑。
    pub fn list_by_type(
        conn: &VaultConnection,
        target_type: TombstoneTargetType,
    ) -> StorageResult<Vec<Tombstone>> {
        TombstoneRepo::list_where(
            conn,
            "target_object_type = ?1",
            params![target_type.to_string()],
        )
    }

    /// 列出所有墓碑。
    pub fn list_all(conn: &VaultConnection) -> StorageResult<Vec<Tombstone>> {
        TombstoneRepo::list_where(conn, "1=1", [])
    }

    /// 根据目标对象 ID 查找墓碑记录。
    pub fn find_by_target(
        conn: &VaultConnection,
        target_object_id: &str,
    ) -> StorageResult<Option<Tombstone>> {
        let mut stmt = conn.inner().prepare(
            "SELECT tombstone_id, target_object_type, target_object_id,
                    delete_clock, deleted_by_device_id, deleted_at, purge_eligible_at,
                    delete_commit_id
             FROM tombstones WHERE target_object_id = ?1
             ORDER BY deleted_at DESC LIMIT 1",
        )?;

        stmt.query_row(params![target_object_id], |row| {
            Ok(Tombstone {
                tombstone_id: row.get(0)?,
                target_object_type: read_target_type(row, 1)?,
                target_object_id: row.get(2)?,
                delete_clock: row.get(3)?,
                deleted_by_device_id: row.get(4)?,
                deleted_at: row.get(5)?,
                purge_eligible_at: row.get(6)?,
                delete_commit_id: row.get(7)?,
            })
        })
        .optional()
        .map_err(StorageError::Database)
    }

    /// 检查目标对象是否已有墓碑记录。
    pub fn is_tombstoned(conn: &VaultConnection, target_object_id: &str) -> StorageResult<bool> {
        let count: i32 = conn
            .inner()
            .query_row(
                "SELECT COUNT(*) FROM tombstones WHERE target_object_id = ?1",
                params![target_object_id],
                |row| row.get(0),
            )
            .map_err(StorageError::Database)?;
        Ok(count > 0)
    }

    /// 分类型统计墓碑数量。
    pub fn count_by_type(
        conn: &VaultConnection,
        target_type: TombstoneTargetType,
    ) -> StorageResult<u32> {
        let count: i32 = conn
            .inner()
            .query_row(
                "SELECT COUNT(*) FROM tombstones WHERE target_object_type = ?1",
                params![target_type.to_string()],
                |row| row.get(0),
            )
            .map_err(StorageError::Database)?;
        Ok(count as u32)
    }

    /// MDBX1 兼容符号。MDBX2 禁止绕过资格评估进行物理清理。
    pub fn purge(conn: &VaultConnection, tombstone_id: &str) -> StorageResult<()> {
        let exists: bool = conn.inner().query_row(
            "SELECT EXISTS(SELECT 1 FROM tombstones WHERE tombstone_id = ?1)",
            params![tombstone_id],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(StorageError::NotFound(tombstone_id.to_string()));
        }
        Err(StorageError::ConstraintViolation(
            "legacy tombstone purge is disabled; use MDBX2 authorized purge after eligibility evaluation"
                .to_string(),
        ))
    }

    /// 评估墓碑是否具备进入授权清理阶段的条件。
    pub fn evaluate_purge_eligibility(
        conn: &VaultConnection,
        tombstone_id: &str,
        now: &str,
    ) -> StorageResult<TombstonePurgeEligibility> {
        let now = chrono::DateTime::parse_from_rfc3339(now).map_err(|error| {
            StorageError::Validation(format!("invalid eligibility evaluation time: {error}"))
        })?;
        let tombstone = Self::find_by_id(conn, tombstone_id)?
            .ok_or_else(|| StorageError::NotFound(tombstone_id.to_string()))?;
        let mut blockers = Vec::new();

        match tombstone.purge_eligible_at.as_deref() {
            None => blockers.push(TombstonePurgeBlocker::RetentionNotScheduled),
            Some(value) => match chrono::DateTime::parse_from_rfc3339(value) {
                Ok(eligible_at) if eligible_at > now => {
                    blockers.push(TombstonePurgeBlocker::RetentionPeriodActive {
                        eligible_at: value.to_string(),
                    });
                }
                Ok(_) => {}
                Err(_) => blockers.push(TombstonePurgeBlocker::InvalidRetentionTimestamp {
                    value: value.to_string(),
                }),
            },
        }

        match Self::target_deleted_state(conn, &tombstone)? {
            Some(true) => {}
            Some(false) => blockers.push(TombstonePurgeBlocker::TargetNotDeleted),
            None if tombstone.target_object_type == TombstoneTargetType::Branch => {
                blockers.push(TombstonePurgeBlocker::UnsupportedTargetType);
            }
            None => blockers.push(TombstonePurgeBlocker::TargetMissing),
        }

        let unresolved_conflicts: i64 = conn.inner().query_row(
            "SELECT COUNT(*) FROM conflicts
             WHERE object_type = ?1 AND object_id = ?2 AND resolution = 'unresolved'",
            params![
                tombstone.target_object_type.to_string(),
                tombstone.target_object_id
            ],
            |row| row.get(0),
        )?;
        if unresolved_conflicts > 0 {
            blockers.push(TombstonePurgeBlocker::UnresolvedConflict);
        }

        match tombstone.delete_commit_id.as_deref() {
            None => blockers.push(TombstonePurgeBlocker::MissingDeleteCommit),
            Some(delete_commit_id) => {
                let commit_exists: bool = conn.inner().query_row(
                    "SELECT EXISTS(SELECT 1 FROM commits WHERE commit_id = ?1)",
                    params![delete_commit_id],
                    |row| row.get(0),
                )?;
                if !commit_exists {
                    blockers.push(TombstonePurgeBlocker::DeleteCommitMissing {
                        commit_id: delete_commit_id.to_string(),
                    });
                } else {
                    let mut stmt = conn.inner().prepare(
                        "SELECT device_id FROM device_heads
                         WHERE revoked = 0 ORDER BY device_id",
                    )?;
                    let devices = stmt.query_map([], |row| row.get::<_, String>(0))?;
                    for device_id in devices {
                        let device_id = device_id?;
                        let observed_commit_id = conn
                            .inner()
                            .query_row(
                                "SELECT observed_commit_id
                                 FROM tombstone_acknowledgements
                                 WHERE tombstone_id = ?1 AND device_id = ?2",
                                params![tombstone.tombstone_id, device_id],
                                |row| row.get::<_, String>(0),
                            )
                            .optional()?;
                        let acknowledged = match observed_commit_id {
                            Some(observed_commit_id) => Self::is_ancestor_commit(
                                conn,
                                delete_commit_id,
                                &observed_commit_id,
                            )?,
                            None => false,
                        };
                        if !acknowledged {
                            blockers.push(TombstonePurgeBlocker::DeviceHasNotAcknowledgedDelete {
                                device_id,
                            });
                        }
                    }
                }
            }
        }

        Ok(TombstonePurgeEligibility {
            tombstone_id: tombstone.tombstone_id,
            eligible: blockers.is_empty(),
            blockers,
        })
    }

    /// 在 TIGA 管理授权后安排墓碑的最早清理时间。
    pub fn schedule_purge_authorized(
        conn: &VaultConnection,
        ctx: &CommitContext,
        tombstone_id: &str,
        purge_eligible_at: &str,
        context: TigaAuthorizationContext<'_>,
    ) -> StorageResult<(TombstonePurgeScheduleResult, AuthorizationDecision)> {
        let eligible_at =
            chrono::DateTime::parse_from_rfc3339(purge_eligible_at).map_err(|error| {
                StorageError::Validation(format!("invalid purge schedule: {error}"))
            })?;
        let tombstone = Self::find_by_id(conn, tombstone_id)?
            .ok_or_else(|| StorageError::NotFound(tombstone_id.to_string()))?;
        let deleted_at =
            chrono::DateTime::parse_from_rfc3339(&tombstone.deleted_at).map_err(|error| {
                StorageError::Validation(format!(
                    "tombstone {} has invalid deleted_at: {error}",
                    tombstone.tombstone_id
                ))
            })?;
        if eligible_at < deleted_at {
            return Err(StorageError::Validation(
                "purge schedule cannot precede the deletion time".to_string(),
            ));
        }

        let (result, decision) = TigaService::execute_authorized_with_commit(
            conn,
            &TigaScope::Vault,
            TigaOperation::ManageDeletedObjectRetention,
            context,
            || {
                let operation = CommitOperation::new(
                    schedule_operation_id(tombstone_id, purge_eligible_at),
                    "schedule-deleted-object-purge",
                    "main",
                    "change",
                    tombstone.target_object_type.to_string(),
                    vec![CommitChange {
                        object_type: tombstone.target_object_type.to_string(),
                        object_id: tombstone.target_object_id.clone(),
                        action: "schedule-purge".to_string(),
                        fields: vec!["purge_eligible_at".to_string()],
                    }],
                );
                let commit_id = ctx.create_operation_commit(conn, &operation)?;
                let affected = conn.inner().execute(
                    "UPDATE tombstones SET purge_eligible_at = ?1
                     WHERE tombstone_id = ?2",
                    params![purge_eligible_at, tombstone_id],
                )?;
                if affected != 1 {
                    return Err(StorageError::NotFound(tombstone_id.to_string()));
                }
                Ok((
                    TombstonePurgeScheduleResult {
                        tombstone_id: tombstone_id.to_string(),
                        purge_eligible_at: purge_eligible_at.to_string(),
                        commit_id: commit_id.clone(),
                    },
                    commit_id,
                ))
            },
        )?;
        Ok((result, decision))
    }

    fn list_where(
        conn: &VaultConnection,
        where_clause: &str,
        params: impl rusqlite::Params,
    ) -> StorageResult<Vec<Tombstone>> {
        let sql = format!(
            "SELECT tombstone_id, target_object_type, target_object_id,
                    delete_clock, deleted_by_device_id, deleted_at, purge_eligible_at,
                    delete_commit_id
             FROM tombstones WHERE {} ORDER BY deleted_at DESC",
            where_clause
        );

        let mut stmt = conn.inner().prepare(&sql)?;
        let rows = stmt.query_map(params, |row| {
            Ok(Tombstone {
                tombstone_id: row.get(0)?,
                target_object_type: read_target_type(row, 1)?,
                target_object_id: row.get(2)?,
                delete_clock: row.get(3)?,
                deleted_by_device_id: row.get(4)?,
                deleted_at: row.get(5)?,
                purge_eligible_at: row.get(6)?,
                delete_commit_id: row.get(7)?,
            })
        })?;

        let mut tombstones = Vec::new();
        for row in rows {
            tombstones.push(row?);
        }
        Ok(tombstones)
    }

    fn find_by_id(conn: &VaultConnection, tombstone_id: &str) -> StorageResult<Option<Tombstone>> {
        conn.inner()
            .query_row(
                "SELECT tombstone_id, target_object_type, target_object_id,
                        delete_clock, deleted_by_device_id, deleted_at,
                        purge_eligible_at, delete_commit_id
                 FROM tombstones WHERE tombstone_id = ?1",
                params![tombstone_id],
                |row| {
                    Ok(Tombstone {
                        tombstone_id: row.get(0)?,
                        target_object_type: read_target_type(row, 1)?,
                        target_object_id: row.get(2)?,
                        delete_clock: row.get(3)?,
                        deleted_by_device_id: row.get(4)?,
                        deleted_at: row.get(5)?,
                        purge_eligible_at: row.get(6)?,
                        delete_commit_id: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(StorageError::Database)
    }

    fn target_deleted_state(
        conn: &VaultConnection,
        tombstone: &Tombstone,
    ) -> StorageResult<Option<bool>> {
        let (table, id_column) = match tombstone.target_object_type {
            TombstoneTargetType::Project => ("projects", "project_id"),
            TombstoneTargetType::Entry => ("entries", "entry_id"),
            TombstoneTargetType::Attachment => ("attachments", "attachment_id"),
            TombstoneTargetType::ObjectRelation => ("object_relations", "relation_id"),
            TombstoneTargetType::ObjectLabel => ("object_labels", "label_id"),
            TombstoneTargetType::ObjectLabelAssignment => {
                ("object_label_assignments", "assignment_id")
            }
            TombstoneTargetType::Branch => return Ok(None),
        };
        let sql = format!("SELECT deleted FROM {table} WHERE {id_column} = ?1");
        conn.inner()
            .query_row(&sql, params![tombstone.target_object_id], |row| {
                row.get::<_, bool>(0)
            })
            .optional()
            .map_err(StorageError::Database)
    }

    fn is_ancestor_commit(
        conn: &VaultConnection,
        ancestor: &str,
        descendant: &str,
    ) -> StorageResult<bool> {
        if ancestor == descendant {
            return Ok(true);
        }
        let mut stack = vec![descendant.to_string()];
        let mut seen = HashSet::new();
        while let Some(commit_id) = stack.pop() {
            if !seen.insert(commit_id.clone()) {
                continue;
            }
            let mut stmt = conn
                .inner()
                .prepare("SELECT parent_commit_id FROM commit_parents WHERE commit_id = ?1")?;
            let parents = stmt.query_map(params![commit_id], |row| row.get::<_, String>(0))?;
            for parent in parents {
                let parent = parent?;
                if parent == ancestor {
                    return Ok(true);
                }
                stack.push(parent);
            }
        }
        Ok(false)
    }
}

fn schedule_operation_id(tombstone_id: &str, purge_eligible_at: &str) -> String {
    let digest =
        Sha256::digest([tombstone_id.as_bytes(), b"\0", purge_eligible_at.as_bytes()].concat());
    let encoded = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("tombstone-purge-schedule-{encoded}")
}

fn read_target_type(
    row: &rusqlite::Row<'_>,
    column: usize,
) -> rusqlite::Result<TombstoneTargetType> {
    let value = row.get::<_, String>(column)?;
    value.parse().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
        )
    })
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::{initialize_vault, VaultInitParams};
    use crate::repo::attachment::AttachmentRepo;
    use crate::repo::commit_ctx::CommitContext;
    use crate::repo::entry::EntryRepo;
    use crate::repo::project::ProjectRepo;
    use mdbx_core::model::{UnlockMethodType, VaultSession};
    use mdbx_core::tiga::{AuthorizationOutcome, DeviceAssurance, DeviceContext, SessionAssurance};

    fn setup() -> (VaultConnection, CommitContext, String) {
        let conn = VaultConnection::open_in_memory().unwrap();
        let params = VaultInitParams {
            device_id: "test-device".to_string(),
            ..VaultInitParams::default()
        };
        initialize_vault(&conn, &params).unwrap();
        let ctx = CommitContext::new("test-device".to_string());
        let project = ProjectRepo::create(&conn, &ctx, "Tombstone Project", None, None).unwrap();
        (conn, ctx, project.project_id)
    }

    fn administrative_session(now: i64) -> VaultSession {
        VaultSession {
            session_id: "purge-admin-session".to_string(),
            unlock_method: UnlockMethodType::Password,
            created_at: chrono::DateTime::from_timestamp(now, 0)
                .unwrap()
                .to_rfc3339(),
            assurance: SessionAssurance::from_unlock_method(UnlockMethodType::Password, now),
        }
    }

    fn administrative_device() -> DeviceContext {
        DeviceContext {
            device_id: Some("test-device".to_string()),
            assurance: DeviceAssurance::Standard,
            secure_clipboard_available: false,
            screen_capture_protection_available: false,
            secure_temp_files_available: true,
        }
    }

    #[test]
    fn test_tombstone_written_on_project_delete() {
        let (conn, ctx, project_id) = setup();
        ProjectRepo::soft_delete(&conn, &ctx, &project_id).unwrap();

        let ts = TombstoneRepo::find_by_target(&conn, &project_id)
            .unwrap()
            .unwrap();
        assert_eq!(ts.target_object_type, TombstoneTargetType::Project);
        assert_eq!(ts.target_object_id, project_id);
        assert_eq!(ts.deleted_by_device_id, "test-device");
        assert!(!ts.tombstone_id.is_empty());
        assert!(ts.delete_commit_id.is_some());
    }

    #[test]
    fn test_tombstone_written_on_entry_delete() {
        let (conn, ctx, project_id) = setup();
        let entry = EntryRepo::create(
            &conn,
            &ctx,
            &project_id,
            mdbx_core::model::EntryType::Note,
            Some("Test Note"),
            &serde_json::json!({"text":"hi"}),
        )
        .unwrap();
        EntryRepo::soft_delete(&conn, &ctx, &entry.entry_id).unwrap();

        let ts = TombstoneRepo::find_by_target(&conn, &entry.entry_id)
            .unwrap()
            .unwrap();
        assert_eq!(ts.target_object_type, TombstoneTargetType::Entry);
        assert_eq!(ts.target_object_id, entry.entry_id);
    }

    #[test]
    fn test_tombstone_written_on_attachment_delete() {
        let (conn, ctx, project_id) = setup();
        let att = AttachmentRepo::add(
            &conn,
            &ctx,
            &project_id,
            None,
            "file.txt",
            None,
            "hash",
            100,
        )
        .unwrap();
        AttachmentRepo::soft_delete(&conn, &ctx, &att.attachment_id).unwrap();

        let ts = TombstoneRepo::find_by_target(&conn, &att.attachment_id)
            .unwrap()
            .unwrap();
        assert_eq!(ts.target_object_type, TombstoneTargetType::Attachment);
    }

    #[test]
    fn tombstone_target_type_known_generic_roundtrips() {
        let (conn, ctx, _project_id) = setup();
        let target_id = uuid::Uuid::new_v4().to_string();
        ctx.create_tombstone(&conn, "object-label", &target_id)
            .unwrap();

        let tombstone = TombstoneRepo::find_by_target(&conn, &target_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            tombstone.target_object_type,
            TombstoneTargetType::ObjectLabel
        );
    }

    #[test]
    fn tombstone_target_type_unknown_is_rejected_without_project_fallback() {
        let (conn, ctx, _project_id) = setup();
        let target_id = uuid::Uuid::new_v4().to_string();
        ctx.create_tombstone(&conn, "com.example.future-family", &target_id)
            .unwrap();

        let find_error = TombstoneRepo::find_by_target(&conn, &target_id).unwrap_err();
        assert!(find_error
            .to_string()
            .contains("unknown TombstoneTargetType"));
        let list_error = TombstoneRepo::list_all(&conn).unwrap_err();
        assert!(list_error
            .to_string()
            .contains("unknown TombstoneTargetType"));
        assert_eq!(
            TombstoneRepo::count_by_type(&conn, TombstoneTargetType::Project).unwrap(),
            0
        );
    }

    #[test]
    fn test_list_by_type() {
        let (conn, ctx, project_id) = setup();

        // 创建并删除 2 个 project
        let p1 = ProjectRepo::create(&conn, &ctx, "P1", None, None).unwrap();
        let p2 = ProjectRepo::create(&conn, &ctx, "P2", None, None).unwrap();
        ProjectRepo::soft_delete(&conn, &ctx, &p1.project_id).unwrap();
        ProjectRepo::soft_delete(&conn, &ctx, &p2.project_id).unwrap();

        // 再删一个 entry（不同类型）
        let entry = EntryRepo::create(
            &conn,
            &ctx,
            &project_id,
            mdbx_core::model::EntryType::Note,
            None,
            &serde_json::json!({"text":"x"}),
        )
        .unwrap();
        EntryRepo::soft_delete(&conn, &ctx, &entry.entry_id).unwrap();

        let project_tombstones =
            TombstoneRepo::list_by_type(&conn, TombstoneTargetType::Project).unwrap();
        let entry_tombstones =
            TombstoneRepo::list_by_type(&conn, TombstoneTargetType::Entry).unwrap();

        assert_eq!(project_tombstones.len(), 2);
        assert_eq!(entry_tombstones.len(), 1);
    }

    #[test]
    fn test_list_all() {
        let (conn, ctx, project_id) = setup();
        ProjectRepo::soft_delete(&conn, &ctx, &project_id).unwrap();

        let all = TombstoneRepo::list_all(&conn).unwrap();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn test_is_tombstoned() {
        let (conn, ctx, project_id) = setup();

        assert!(!TombstoneRepo::is_tombstoned(&conn, &project_id).unwrap());
        ProjectRepo::soft_delete(&conn, &ctx, &project_id).unwrap();
        assert!(TombstoneRepo::is_tombstoned(&conn, &project_id).unwrap());
    }

    #[test]
    fn test_count_by_type() {
        let (conn, ctx, project_id) = setup();

        assert_eq!(
            TombstoneRepo::count_by_type(&conn, TombstoneTargetType::Project).unwrap(),
            0
        );

        ProjectRepo::soft_delete(&conn, &ctx, &project_id).unwrap();
        assert_eq!(
            TombstoneRepo::count_by_type(&conn, TombstoneTargetType::Project).unwrap(),
            1
        );
    }

    #[test]
    fn legacy_purge_is_disabled_and_preserves_tombstone() {
        let (conn, ctx, project_id) = setup();
        ProjectRepo::soft_delete(&conn, &ctx, &project_id).unwrap();

        let ts = TombstoneRepo::find_by_target(&conn, &project_id)
            .unwrap()
            .unwrap();
        let error = TombstoneRepo::purge(&conn, &ts.tombstone_id).unwrap_err();
        assert!(error
            .to_string()
            .contains("legacy tombstone purge is disabled"));

        assert!(TombstoneRepo::find_by_target(&conn, &project_id)
            .unwrap()
            .is_some());
    }

    #[test]
    fn purge_eligibility_requires_retention_schedule() {
        let (conn, ctx, project_id) = setup();
        ProjectRepo::soft_delete(&conn, &ctx, &project_id).unwrap();
        let tombstone = TombstoneRepo::find_by_target(&conn, &project_id)
            .unwrap()
            .unwrap();

        let eligibility = TombstoneRepo::evaluate_purge_eligibility(
            &conn,
            &tombstone.tombstone_id,
            "2030-01-01T00:00:00Z",
        )
        .unwrap();
        assert!(!eligibility.eligible);
        assert_eq!(
            eligibility.blockers,
            vec![TombstonePurgeBlocker::RetentionNotScheduled]
        );
    }

    #[test]
    fn tombstone_purge_schedule_is_authorized_audited_and_idempotent() {
        let (conn, ctx, project_id) = setup();
        ProjectRepo::soft_delete(&conn, &ctx, &project_id).unwrap();
        let tombstone = TombstoneRepo::find_by_target(&conn, &project_id)
            .unwrap()
            .unwrap();
        let session = administrative_session(1_000);
        let device = administrative_device();
        let context = TigaAuthorizationContext {
            session: Some(&session),
            device: &device,
            now_unix_secs: 1_010,
        };

        let (first, decision) = TombstoneRepo::schedule_purge_authorized(
            &conn,
            &ctx,
            &tombstone.tombstone_id,
            "2030-01-01T00:00:00Z",
            context,
        )
        .unwrap();
        assert_eq!(decision.outcome, AuthorizationOutcome::Allow);
        let commit_count: i64 = conn
            .inner()
            .query_row("SELECT COUNT(*) FROM commits", [], |row| row.get(0))
            .unwrap();

        let (retry, _) = TombstoneRepo::schedule_purge_authorized(
            &conn,
            &ctx,
            &tombstone.tombstone_id,
            "2030-01-01T00:00:00Z",
            context,
        )
        .unwrap();
        assert_eq!(retry.commit_id, first.commit_id);
        let retry_commit_count: i64 = conn
            .inner()
            .query_row("SELECT COUNT(*) FROM commits", [], |row| row.get(0))
            .unwrap();
        assert_eq!(retry_commit_count, commit_count);

        let stored: String = conn
            .inner()
            .query_row(
                "SELECT purge_eligible_at FROM tombstones WHERE tombstone_id = ?1",
                params![tombstone.tombstone_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, "2030-01-01T00:00:00Z");
        let events = TigaService::list_security_audit_events(&conn, 10).unwrap();
        assert!(events.iter().all(|event| {
            event.operation == TigaOperation::ManageDeletedObjectRetention
                && event.commit_id.as_deref() == Some(first.commit_id.as_str())
        }));
    }

    #[test]
    fn tombstone_purge_schedule_denial_preserves_state() {
        let (conn, ctx, project_id) = setup();
        ProjectRepo::soft_delete(&conn, &ctx, &project_id).unwrap();
        let tombstone = TombstoneRepo::find_by_target(&conn, &project_id)
            .unwrap()
            .unwrap();
        let device = administrative_device();

        let error = TombstoneRepo::schedule_purge_authorized(
            &conn,
            &ctx,
            &tombstone.tombstone_id,
            "2030-01-01T00:00:00Z",
            TigaAuthorizationContext {
                session: None,
                device: &device,
                now_unix_secs: 1_010,
            },
        )
        .unwrap_err();
        assert!(matches!(error, StorageError::Authorization(_)));
        let stored: Option<String> = conn
            .inner()
            .query_row(
                "SELECT purge_eligible_at FROM tombstones WHERE tombstone_id = ?1",
                params![tombstone.tombstone_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(stored.is_none());
    }

    #[test]
    fn purge_eligibility_requires_every_active_device_to_acknowledge_delete() {
        let (conn, ctx, project_id) = setup();
        let pre_delete_head: String = conn
            .inner()
            .query_row(
                "SELECT head_commit_id FROM device_heads WHERE device_id = ?1",
                params![ctx.device_id],
                |row| row.get(0),
            )
            .unwrap();
        ProjectRepo::soft_delete(&conn, &ctx, &project_id).unwrap();
        let tombstone = TombstoneRepo::find_by_target(&conn, &project_id)
            .unwrap()
            .unwrap();
        conn.inner()
            .execute(
                "UPDATE tombstones SET purge_eligible_at = '2029-01-01T00:00:00Z'
                 WHERE tombstone_id = ?1",
                params![tombstone.tombstone_id],
            )
            .unwrap();
        conn.inner()
            .execute(
                "INSERT INTO device_heads (device_id, head_commit_id, last_seen_at, revoked)
                 VALUES ('stale-device', ?1, '2029-01-01T00:00:00Z', 0)",
                params![pre_delete_head],
            )
            .unwrap();

        let blocked = TombstoneRepo::evaluate_purge_eligibility(
            &conn,
            &tombstone.tombstone_id,
            "2030-01-01T00:00:00Z",
        )
        .unwrap();
        assert_eq!(
            blocked.blockers,
            vec![TombstonePurgeBlocker::DeviceHasNotAcknowledgedDelete {
                device_id: "stale-device".to_string(),
            }]
        );

        conn.inner()
            .execute(
                "UPDATE device_heads SET revoked = 1 WHERE device_id = 'stale-device'",
                [],
            )
            .unwrap();
        let eligible = TombstoneRepo::evaluate_purge_eligibility(
            &conn,
            &tombstone.tombstone_id,
            "2030-01-01T00:00:00Z",
        )
        .unwrap();
        assert!(eligible.eligible);
        assert!(eligible.blockers.is_empty());
    }

    #[test]
    fn test_purge_nonexistent() {
        let (conn, _ctx, _project_id) = setup();
        assert!(TombstoneRepo::purge(&conn, "nonexistent").is_err());
    }

    #[test]
    fn test_find_nonexistent_returns_none() {
        let (conn, _ctx, _project_id) = setup();
        let result = TombstoneRepo::find_by_target(&conn, "nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_create_on_tombstoned_project_blocked() {
        let (conn, ctx, _project_id) = setup();
        let p = ProjectRepo::create(&conn, &ctx, "ToDelete", None, None).unwrap();
        ProjectRepo::soft_delete(&conn, &ctx, &p.project_id).unwrap();

        // 尝试在已删除 project 下创建 entry 应被阻止
        let result = EntryRepo::create(
            &conn,
            &ctx,
            &p.project_id,
            mdbx_core::model::EntryType::Note,
            None,
            &serde_json::json!({"text":"no"}),
        );
        assert!(result.is_err());
    }
}
