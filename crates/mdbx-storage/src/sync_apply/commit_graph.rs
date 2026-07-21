use std::collections::HashSet;

use rusqlite::{params, OptionalExtension};

use mdbx_sync::SerializedCommit;

use crate::connection::VaultConnection;
use crate::error::{StorageError, StorageResult};
use crate::repo::BranchRepo;
use crate::sync_state::BranchRow;

pub(super) fn apply_branches(conn: &VaultConnection, branches: &[BranchRow]) -> StorageResult<()> {
    for row in branches {
        if !commit_exists(conn, &row.head_commit_id)? {
            continue;
        }
        let local_head: Option<String> = conn
            .inner()
            .query_row(
                "SELECT head_commit_id FROM branches WHERE branch_id = ?1",
                params![row.branch_id],
                |row| row.get(0),
            )
            .optional()?;

        let should_upsert = match local_head {
            None => true,
            Some(local_head) if local_head == row.head_commit_id => false,
            Some(local_head) => is_ancestor_commit(conn, &local_head, &row.head_commit_id)?,
        };
        if should_upsert {
            conn.inner().execute(
                "INSERT INTO branches (branch_id, branch_name, head_commit_id, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(branch_id) DO UPDATE SET
                    branch_name = excluded.branch_name,
                    head_commit_id = excluded.head_commit_id,
                    updated_at = excluded.updated_at",
                params![
                    row.branch_id,
                    row.branch_name,
                    row.head_commit_id,
                    row.created_at,
                    row.updated_at,
                ],
            )?;
        }
    }
    Ok(())
}

pub(super) fn object_apply_decision(
    conn: &VaultConnection,
    table: &str,
    id_column: &str,
    object_id: &str,
    incoming_head: &str,
) -> StorageResult<ObjectDecision> {
    let sql = format!(
        "SELECT head_commit_id FROM {} WHERE {} = ?1",
        table, id_column
    );
    let local_head: Option<String> = conn
        .inner()
        .query_row(&sql, params![object_id], |row| row.get(0))
        .optional()?;

    let Some(local_head) = local_head else {
        return Ok(ObjectDecision::Insert);
    };
    if local_head == incoming_head {
        return Ok(ObjectDecision::Skip);
    }
    if is_ancestor_commit(conn, &local_head, incoming_head)? {
        return Ok(ObjectDecision::FastForward);
    }
    if is_ancestor_commit(conn, incoming_head, &local_head)? {
        return Ok(ObjectDecision::Skip);
    }
    Ok(ObjectDecision::Conflict { local_head })
}

pub(super) fn is_ancestor_commit(
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
        let parents = parent_ids_for_commit(conn, &commit_id)?;
        for parent in parents {
            if parent == ancestor {
                return Ok(true);
            }
            stack.push(parent);
        }
    }
    Ok(false)
}

pub(super) fn parent_ids_for_commit(
    conn: &VaultConnection,
    commit_id: &str,
) -> StorageResult<Vec<String>> {
    let mut stmt = conn.inner().prepare(
        "SELECT parent_commit_id FROM commit_parents
         WHERE commit_id = ?1
         ORDER BY parent_commit_id",
    )?;
    let rows = stmt.query_map(params![commit_id], |row| row.get(0))?;
    let mut parents = Vec::new();
    for row in rows {
        parents.push(row?);
    }
    Ok(parents)
}

pub(super) fn nearest_known_common_parent(
    conn: &VaultConnection,
    left: &str,
    right: &str,
) -> StorageResult<Option<String>> {
    let left_ancestors = ancestor_set(conn, left)?;
    let mut stack = vec![right.to_string()];
    let mut seen = HashSet::new();
    while let Some(commit_id) = stack.pop() {
        if !seen.insert(commit_id.clone()) {
            continue;
        }
        if left_ancestors.contains(&commit_id) {
            return Ok(Some(commit_id));
        }
        stack.extend(parent_ids_for_commit(conn, &commit_id)?);
    }
    Ok(None)
}

fn ancestor_set(conn: &VaultConnection, head: &str) -> StorageResult<HashSet<String>> {
    let mut result = HashSet::new();
    let mut stack = vec![head.to_string()];
    while let Some(commit_id) = stack.pop() {
        if !result.insert(commit_id.clone()) {
            continue;
        }
        stack.extend(parent_ids_for_commit(conn, &commit_id)?);
    }
    Ok(result)
}

pub(super) fn commit_exists(conn: &VaultConnection, commit_id: &str) -> StorageResult<bool> {
    let count: i64 = conn.inner().query_row(
        "SELECT COUNT(*) FROM commits WHERE commit_id = ?1",
        params![commit_id],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

pub(super) fn sync_device_head(
    conn: &VaultConnection,
    serialized: &SerializedCommit,
) -> StorageResult<()> {
    conn.inner().execute(
        "INSERT INTO device_heads (device_id, head_commit_id, last_seen_at, revoked)
         VALUES (?1, ?2, ?3, 0)
         ON CONFLICT(device_id) DO UPDATE SET
            head_commit_id = excluded.head_commit_id,
            last_seen_at = excluded.last_seen_at",
        params![
            serialized.commit.device_id,
            serialized.commit.commit_id,
            serialized.commit.created_at
        ],
    )?;
    Ok(())
}

pub(super) fn current_branch_head(
    conn: &VaultConnection,
    branch_id: Option<&str>,
    branch_name: &str,
) -> StorageResult<Option<String>> {
    if let Some(branch_id) = branch_id {
        return Ok(BranchRepo::get_by_id(conn, branch_id)?.map(|branch| branch.head_commit_id));
    }
    match BranchRepo::resolve_unique_name(conn, branch_name) {
        Ok(branch) => Ok(Some(branch.head_commit_id)),
        Err(StorageError::NotFound(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

pub(super) fn advance_branch(
    conn: &VaultConnection,
    branch_id: Option<&str>,
    branch_name: &str,
    commit_id: &str,
) -> StorageResult<()> {
    let branch = match branch_id {
        Some(branch_id) => BranchRepo::require_by_id(conn, branch_id)?,
        None => BranchRepo::resolve_unique_name(conn, branch_name)?,
    };
    let now = chrono::Utc::now().to_rfc3339();
    let updated = conn.inner().execute(
        "UPDATE branches SET head_commit_id = ?1, updated_at = ?2 WHERE branch_id = ?3",
        params![commit_id, now, branch.branch_id],
    )?;
    if updated != 1 {
        return Err(StorageError::NotFound(format!(
            "branch ID {} not found",
            branch.branch_id
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ObjectDecision {
    Insert,
    FastForward,
    Conflict { local_head: String },
    Skip,
}
