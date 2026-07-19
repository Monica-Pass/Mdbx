use std::collections::{BTreeMap, HashSet};

use rusqlite::params;
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use mdbx_core::model::Commit;

use crate::commit_integrity::{compute_commit_integrity_tag, CommitIntegrityInput};
use crate::connection::VaultConnection;
use crate::error::{StorageError, StorageResult};

/// 一个用户级变更中的对象摘要。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct CommitChange {
    pub object_type: String,
    pub object_id: String,
    pub action: String,
    #[serde(default)]
    pub fields: Vec<String>,
}

/// MDBX2 的 operation-level commit 请求。
///
/// `operation_id` 由客户端在用户动作开始时生成，并在重试时复用。
/// `create_commit` 仍然提供 MDBX1 兼容入口，它会构造一个兼容 operation。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct CommitOperation {
    pub operation_id: String,
    pub operation_kind: String,
    pub branch_name: String,
    pub commit_kind: String,
    pub change_scope: String,
    pub changed_objects: Vec<CommitChange>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub parents: Vec<String>,
}

impl CommitOperation {
    pub fn new(
        operation_id: impl Into<String>,
        operation_kind: impl Into<String>,
        branch_name: impl Into<String>,
        commit_kind: impl Into<String>,
        change_scope: impl Into<String>,
        changed_objects: Vec<CommitChange>,
    ) -> Self {
        Self {
            operation_id: operation_id.into(),
            operation_kind: operation_kind.into(),
            branch_name: branch_name.into(),
            commit_kind: commit_kind.into(),
            change_scope: change_scope.into(),
            changed_objects,
            message: None,
            parents: Vec::new(),
        }
    }

    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    pub fn with_parents(mut self, parents: Vec<String>) -> Self {
        self.parents = parents;
        self
    }
}

/// 执行 mutation 所需的上下文：设备身份 + commit 生成。
pub struct CommitContext {
    pub device_id: String,
}

impl CommitContext {
    pub fn new(device_id: String) -> Self {
        Self { device_id }
    }

    /// 在当前 SQLite 写事务中原子分配设备序列号。
    fn next_local_seq(&self, conn: &VaultConnection) -> StorageResult<u64> {
        conn.inner()
            .query_row(
                "INSERT INTO commit_device_sequences (device_id, last_local_seq)
                 VALUES (?1, COALESCE((SELECT MAX(local_seq) + 1 FROM commits WHERE device_id = ?1), 1))
                 ON CONFLICT(device_id) DO UPDATE SET last_local_seq = last_local_seq + 1
                 RETURNING last_local_seq",
                params![self.device_id],
                |row| row.get::<_, i64>(0),
            )
            .map(|value| value as u64)
            .map_err(StorageError::Database)
    }

    fn current_head(
        &self,
        conn: &VaultConnection,
        table: &str,
        id_column: &str,
        object_id: &str,
    ) -> StorageResult<Option<String>> {
        let sql = format!(
            "SELECT head_commit_id FROM {} WHERE {} = ?1",
            table, id_column
        );
        conn.inner()
            .query_row(&sql, params![object_id], |row| row.get(0))
            .optional()
            .map_err(StorageError::Database)
            .map(|r| r.flatten())
    }

    fn current_branch_head(
        &self,
        conn: &VaultConnection,
        branch_name: &str,
    ) -> StorageResult<Option<String>> {
        conn.inner()
            .query_row(
                "SELECT head_commit_id FROM branches WHERE branch_name = ?1
                 ORDER BY updated_at DESC LIMIT 1",
                params![branch_name],
                |row| row.get(0),
            )
            .optional()
            .map_err(StorageError::Database)
    }

    /// 创建一个 operation-level commit，并在重试时按 operation_id 幂等返回。
    pub fn create_operation_commit(
        &self,
        conn: &VaultConnection,
        operation: &CommitOperation,
    ) -> StorageResult<String> {
        conn.with_immediate_transaction(|| self.create_operation_commit_inner(conn, operation))
    }

    fn create_operation_commit_inner(
        &self,
        conn: &VaultConnection,
        operation: &CommitOperation,
    ) -> StorageResult<String> {
        Self::validate_operation(operation)?;
        let request_hash = Self::operation_request_hash(operation)?;

        if let Some((commit_id, stored_hash)) = conn
            .inner()
            .query_row(
                "SELECT commit_id, request_hash FROM commit_operations WHERE operation_id = ?1",
                params![operation.operation_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(StorageError::Database)?
        {
            if stored_hash != request_hash {
                return Err(StorageError::Validation(format!(
                    "operation {} was reused with different content",
                    operation.operation_id
                )));
            }
            return Ok(commit_id);
        }

        let now = chrono::Utc::now().to_rfc3339();
        let local_seq = self.next_local_seq(conn)?;
        let commit_id = Uuid::new_v4().to_string();
        let resolved_parents = if operation.parents.is_empty() {
            self.current_branch_head(conn, &operation.branch_name)?
                .into_iter()
                .collect()
        } else {
            operation.parents.clone()
        };
        Self::validate_parents(conn, &resolved_parents)?;

        let vector_clock =
            Self::merge_vector_clocks(conn, &resolved_parents, &self.device_id, local_seq)?;
        let changed_ids = operation
            .changed_objects
            .iter()
            .map(|change| change.object_id.clone())
            .collect::<Vec<_>>();
        let changed_json = serde_json::to_vec(&deduplicate(changed_ids))
            .map_err(|error| StorageError::SchemaCreation(error.to_string()))?;
        let changed_object_ids_ct =
            Self::encrypt_history(conn, &commit_id, "changed-object-ids", &changed_json)?;
        let summary_json = serde_json::to_vec(&operation.changed_objects)
            .map_err(|error| StorageError::SchemaCreation(error.to_string()))?;
        let change_summary_ct =
            Self::encrypt_history(conn, &commit_id, "change-summary", &summary_json)?;
        let message_ct = operation
            .message
            .as_deref()
            .map(|message| Self::encrypt_history(conn, &commit_id, "message", message.as_bytes()))
            .transpose()?;
        let integrity_tag = compute_commit_integrity_tag(
            conn.keyring(),
            &CommitIntegrityInput {
                commit_id: &commit_id,
                device_id: &self.device_id,
                local_seq,
                commit_kind: &operation.commit_kind,
                change_scope: &operation.change_scope,
                changed_object_ids_ct: &changed_object_ids_ct,
                vector_clock: &vector_clock,
                message_ct: message_ct.as_deref(),
                created_at: &now,
                parents: &resolved_parents,
            },
        )?;
        let operation_integrity = Self::operation_integrity(
            conn,
            operation,
            &commit_id,
            &change_summary_ct,
            &request_hash,
            &now,
        )?;

        conn.inner().execute(
            "INSERT INTO commits (commit_id, device_id, local_seq, commit_kind,
             change_scope, changed_object_ids_ct, vector_clock, message_ct,
             created_at, integrity_tag)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                commit_id,
                self.device_id,
                local_seq as i64,
                operation.commit_kind,
                operation.change_scope,
                changed_object_ids_ct,
                vector_clock,
                message_ct,
                now,
                integrity_tag,
            ],
        )?;

        for parent_id in &resolved_parents {
            conn.inner().execute(
                "INSERT INTO commit_parents (commit_id, parent_commit_id) VALUES (?1, ?2)",
                params![commit_id, parent_id],
            )?;
        }

        conn.inner().execute(
            "INSERT INTO commit_operations
             (operation_id, commit_id, operation_kind, branch_name, change_summary_ct,
              request_hash, created_at, integrity_tag)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                operation.operation_id,
                commit_id,
                operation.operation_kind,
                operation.branch_name,
                change_summary_ct,
                request_hash,
                now,
                operation_integrity,
            ],
        )?;

        conn.inner().execute(
            "INSERT INTO device_heads (device_id, head_commit_id, last_seen_at, revoked)
             VALUES (?1, ?2, ?3, 0)
             ON CONFLICT(device_id) DO UPDATE SET
                head_commit_id = excluded.head_commit_id,
                last_seen_at = excluded.last_seen_at",
            params![self.device_id, commit_id, now],
        )?;

        let branch_updated = conn.inner().execute(
            "UPDATE branches SET head_commit_id = ?1, updated_at = ?2 WHERE branch_name = ?3",
            params![commit_id, now, operation.branch_name],
        )?;
        if branch_updated == 0 {
            return Err(StorageError::NotFound(format!(
                "branch {} not found",
                operation.branch_name
            )));
        }

        Ok(commit_id)
    }

    /// 旧调用方的兼容入口：仍生成一条 legacy commit，但同时具备幂等元数据。
    pub fn create_commit(
        &self,
        conn: &VaultConnection,
        commit_kind: &str,
        change_scope: &str,
        changed_object_ids: &[String],
        parents: &[String],
    ) -> StorageResult<String> {
        let changed_objects = changed_object_ids
            .iter()
            .map(|object_id| CommitChange {
                object_type: change_scope.to_string(),
                object_id: object_id.clone(),
                action: "change".to_string(),
                fields: Vec::new(),
            })
            .collect();
        let operation = CommitOperation::new(
            Uuid::new_v4().to_string(),
            format!("legacy-{commit_kind}"),
            "main",
            commit_kind,
            change_scope,
            changed_objects,
        )
        .with_parents(parents.to_vec());
        self.create_operation_commit(conn, &operation)
    }

    pub(crate) fn encrypt_history(
        conn: &VaultConnection,
        commit_id: &str,
        field: &str,
        plaintext: &[u8],
    ) -> StorageResult<Vec<u8>> {
        let subkey = conn
            .keyring()
            .map(|kr| kr.history_subkey.clone())
            .unwrap_or_default();
        crate::crypto_layer::encrypt_field(
            conn.keyring(),
            &subkey,
            plaintext,
            "commit",
            commit_id,
            field,
        )
        .map_err(StorageError::Crypto)
    }

    /// 写入 tombstone 记录。
    pub fn create_tombstone(
        &self,
        conn: &VaultConnection,
        target_object_type: &str,
        target_object_id: &str,
    ) -> StorageResult<String> {
        let tombstone_id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let delete_clock = format!(r#"{{"tombstone":"{}"}}"#, tombstone_id);

        conn.inner().execute(
            "INSERT INTO tombstones (tombstone_id, target_object_type, target_object_id,
             delete_clock, deleted_by_device_id, deleted_at, purge_eligible_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
            params![
                tombstone_id,
                target_object_type,
                target_object_id,
                delete_clock,
                self.device_id,
                now,
            ],
        )?;

        Ok(tombstone_id)
    }

    /// 便捷方法：为单个对象的变更创建 commit。
    pub fn commit_object_change(
        &self,
        conn: &VaultConnection,
        object_table: &str,
        object_id: &str,
        commit_kind: &str,
        change_scope: &str,
    ) -> StorageResult<String> {
        let parent_head = self.current_head(
            conn,
            object_table,
            &format!("{}_id", change_scope),
            object_id,
        )?;
        let parents: Vec<String> = parent_head.into_iter().collect();

        self.create_commit(
            conn,
            commit_kind,
            change_scope,
            &[object_id.to_string()],
            &parents,
        )
    }

    fn validate_operation(operation: &CommitOperation) -> StorageResult<()> {
        for (name, value) in [
            ("operation_id", operation.operation_id.as_str()),
            ("operation_kind", operation.operation_kind.as_str()),
            ("branch_name", operation.branch_name.as_str()),
            ("commit_kind", operation.commit_kind.as_str()),
            ("change_scope", operation.change_scope.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(StorageError::Validation(format!(
                    "{name} must not be empty"
                )));
            }
        }
        Ok(())
    }

    fn validate_parents(conn: &VaultConnection, parents: &[String]) -> StorageResult<()> {
        for parent in parents {
            let exists: bool = conn.inner().query_row(
                "SELECT EXISTS(SELECT 1 FROM commits WHERE commit_id = ?1)",
                params![parent],
                |row| row.get(0),
            )?;
            if !exists {
                return Err(StorageError::NotFound(format!("parent commit {parent}")));
            }
        }
        Ok(())
    }

    fn merge_vector_clocks(
        conn: &VaultConnection,
        parents: &[String],
        device_id: &str,
        local_seq: u64,
    ) -> StorageResult<String> {
        let mut merged = BTreeMap::<String, u64>::new();
        for parent in parents {
            let encoded: String = conn.inner().query_row(
                "SELECT vector_clock FROM commits WHERE commit_id = ?1",
                params![parent],
                |row| row.get(0),
            )?;
            let clock =
                serde_json::from_str::<BTreeMap<String, u64>>(&encoded).map_err(|error| {
                    StorageError::Validation(format!(
                        "invalid vector clock on parent {parent}: {error}"
                    ))
                })?;
            for (device, sequence) in clock {
                merged
                    .entry(device)
                    .and_modify(|current| *current = (*current).max(sequence))
                    .or_insert(sequence);
            }
        }
        merged.insert(device_id.to_string(), local_seq);
        serde_json::to_string(&merged)
            .map_err(|error| StorageError::SchemaCreation(error.to_string()))
    }

    fn operation_request_hash(operation: &CommitOperation) -> StorageResult<Vec<u8>> {
        let encoded = serde_json::to_vec(operation)
            .map_err(|error| StorageError::SchemaCreation(error.to_string()))?;
        Ok(Sha256::digest(encoded).to_vec())
    }

    fn operation_integrity(
        conn: &VaultConnection,
        operation: &CommitOperation,
        commit_id: &str,
        change_summary_ct: &[u8],
        request_hash: &[u8],
        created_at: &str,
    ) -> StorageResult<Vec<u8>> {
        let parts = [
            b"mdbx-operation-integrity-v1".as_slice(),
            operation.operation_id.as_bytes(),
            commit_id.as_bytes(),
            operation.operation_kind.as_bytes(),
            operation.branch_name.as_bytes(),
            change_summary_ct,
            request_hash,
            created_at.as_bytes(),
        ];
        match conn.keyring() {
            Some(keyring) => mdbx_crypto::integrity::hmac_sha256(&keyring.integrity_subkey, &parts)
                .map_err(StorageError::Crypto),
            None => {
                let mut hasher = Sha256::new();
                for part in parts {
                    hasher.update((part.len() as u64).to_le_bytes());
                    hasher.update(part);
                }
                Ok(hasher.finalize().to_vec())
            }
        }
    }

    pub(crate) fn verify_operation_integrity(
        conn: &VaultConnection,
        commit: &Commit,
        operation: &mdbx_sync::CommitOperationMetadata,
    ) -> StorageResult<()> {
        let parts = [
            b"mdbx-operation-integrity-v1".as_slice(),
            operation.operation_id.as_bytes(),
            commit.commit_id.as_bytes(),
            operation.operation_kind.as_bytes(),
            operation.branch_name.as_bytes(),
            operation.change_summary_ct.as_slice(),
            operation.request_hash.as_slice(),
            commit.created_at.as_bytes(),
        ];
        let expected = match conn.keyring() {
            Some(keyring) => mdbx_crypto::integrity::hmac_sha256(&keyring.integrity_subkey, &parts)
                .map_err(StorageError::Crypto)?,
            None => {
                let mut hasher = Sha256::new();
                for part in parts {
                    hasher.update((part.len() as u64).to_le_bytes());
                    hasher.update(part);
                }
                hasher.finalize().to_vec()
            }
        };
        if expected != operation.integrity_tag {
            return Err(StorageError::Validation(format!(
                "incoming operation {} integrity mismatch",
                operation.operation_id
            )));
        }
        Ok(())
    }
}

fn deduplicate(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::{initialize_vault, VaultInitParams};

    fn initialized() -> (VaultConnection, CommitContext) {
        let conn = VaultConnection::open_in_memory().unwrap();
        initialize_vault(
            &conn,
            &VaultInitParams {
                device_id: "device-a".to_string(),
                ..Default::default()
            },
        )
        .unwrap();
        (conn, CommitContext::new("device-a".to_string()))
    }

    fn operation(id: &str) -> CommitOperation {
        CommitOperation::new(
            id,
            "batch-move",
            "main",
            "change",
            "entry",
            vec![
                CommitChange {
                    object_type: "entry".to_string(),
                    object_id: "entry-1".to_string(),
                    action: "move".to_string(),
                    fields: vec!["project_id".to_string()],
                },
                CommitChange {
                    object_type: "entry".to_string(),
                    object_id: "entry-2".to_string(),
                    action: "move".to_string(),
                    fields: vec!["project_id".to_string()],
                },
            ],
        )
        .with_message("Move two entries")
    }

    #[test]
    fn operation_retry_is_idempotent() {
        let (conn, ctx) = initialized();
        let request = operation("operation-1");

        let first = ctx.create_operation_commit(&conn, &request).unwrap();
        let second = ctx.create_operation_commit(&conn, &request).unwrap();

        assert_eq!(first, second);
        let commit_count: i64 = conn
            .inner()
            .query_row("SELECT COUNT(*) FROM commits", [], |row| row.get(0))
            .unwrap();
        assert_eq!(commit_count, 2);
    }

    #[test]
    fn operation_id_reuse_with_different_content_is_rejected() {
        let (conn, ctx) = initialized();
        ctx.create_operation_commit(&conn, &operation("operation-1"))
            .unwrap();
        let changed = operation("operation-1").with_message("different");

        let error = ctx.create_operation_commit(&conn, &changed).unwrap_err();

        assert!(error.to_string().contains("reused with different content"));
    }

    #[test]
    fn operation_targets_the_requested_branch() {
        let (conn, ctx) = initialized();
        let main_head: String = conn
            .inner()
            .query_row(
                "SELECT head_commit_id FROM branches WHERE branch_name = 'main'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        conn.inner()
            .execute(
                "INSERT INTO branches
                 (branch_id, branch_name, head_commit_id, created_at, updated_at)
                 VALUES ('branch-review', 'review', ?1, '2026-07-19T00:00:00Z',
                         '2026-07-19T00:00:00Z')",
                params![main_head],
            )
            .unwrap();
        let mut request = operation("operation-review");
        request.branch_name = "review".to_string();

        let commit_id = ctx.create_operation_commit(&conn, &request).unwrap();

        let heads: (String, String) = conn
            .inner()
            .query_row(
                "SELECT
                    MAX(CASE WHEN branch_name = 'main' THEN head_commit_id END),
                    MAX(CASE WHEN branch_name = 'review' THEN head_commit_id END)
                 FROM branches",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(heads.0, main_head);
        assert_eq!(heads.1, commit_id);
    }

    #[test]
    fn vector_clock_merges_parent_causality() {
        let (conn, ctx) = initialized();
        let parent = ctx
            .create_operation_commit(&conn, &operation("operation-parent"))
            .unwrap();
        conn.inner()
            .execute(
                "UPDATE commits SET vector_clock = '{\"device-a\":1,\"device-b\":9}'
                 WHERE commit_id = ?1",
                params![parent],
            )
            .unwrap();

        let child = ctx
            .create_operation_commit(&conn, &operation("operation-child"))
            .unwrap();
        let encoded: String = conn
            .inner()
            .query_row(
                "SELECT vector_clock FROM commits WHERE commit_id = ?1",
                params![child],
                |row| row.get(0),
            )
            .unwrap();
        let clock: BTreeMap<String, u64> = serde_json::from_str(&encoded).unwrap();
        assert_eq!(clock.get("device-a"), Some(&2));
        assert_eq!(clock.get("device-b"), Some(&9));
    }

    #[test]
    fn failed_branch_does_not_consume_a_sequence() {
        let (conn, ctx) = initialized();
        let mut invalid = operation("operation-invalid");
        invalid.branch_name = "missing".to_string();
        assert!(ctx.create_operation_commit(&conn, &invalid).is_err());

        let commit_id = ctx
            .create_operation_commit(&conn, &operation("operation-valid"))
            .unwrap();
        let local_seq: i64 = conn
            .inner()
            .query_row(
                "SELECT local_seq FROM commits WHERE commit_id = ?1",
                params![commit_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(local_seq, 1);
    }
}
