use mdbx_storage::repo::{BranchRepo, CommitHistoryItem, CommitHistoryPage, CommitHistoryRepo};

use super::{
    MdbxBranchInfo, MdbxCommitChange, MdbxCommitHistoryItem, MdbxCommitHistoryItemV2,
    MdbxCommitHistoryPage, MdbxCommitHistoryPageV2, MdbxFfiError, MdbxVault,
};

#[uniffi::export]
impl MdbxVault {
    pub fn list_branches(&self) -> Result<Vec<MdbxBranchInfo>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(BranchRepo::list(&conn)?
            .into_iter()
            .map(|branch| MdbxBranchInfo {
                branch_id: branch.branch_id,
                branch_name: branch.branch_name,
                head_commit_id: branch.head_commit_id,
                created_at: branch.created_at,
                updated_at: branch.updated_at,
            })
            .collect())
    }

    pub fn list_commit_history(
        &self,
        page_size: u32,
        cursor: Option<String>,
    ) -> Result<MdbxCommitHistoryPage, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let page = CommitHistoryRepo::list(&conn, page_size as usize, cursor.as_deref())?;
        Ok(commit_history_page_from_storage(page))
    }

    pub fn get_commit_history(
        &self,
        commit_id: String,
    ) -> Result<Option<MdbxCommitHistoryItem>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(CommitHistoryRepo::get(&conn, &commit_id)?.map(commit_history_item_from_storage))
    }

    pub fn list_commit_history_v2(
        &self,
        page_size: u32,
        cursor: Option<String>,
    ) -> Result<MdbxCommitHistoryPageV2, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let page = CommitHistoryRepo::list(&conn, page_size as usize, cursor.as_deref())?;
        Ok(commit_history_page_v2_from_storage(page))
    }

    pub fn get_commit_history_v2(
        &self,
        commit_id: String,
    ) -> Result<Option<MdbxCommitHistoryItemV2>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(CommitHistoryRepo::get(&conn, &commit_id)?.map(commit_history_item_v2_from_storage))
    }
}

fn commit_history_page_from_storage(page: CommitHistoryPage) -> MdbxCommitHistoryPage {
    MdbxCommitHistoryPage {
        items: page
            .items
            .into_iter()
            .map(commit_history_item_from_storage)
            .collect(),
        next_cursor: page.next_cursor,
    }
}

fn commit_history_page_v2_from_storage(page: CommitHistoryPage) -> MdbxCommitHistoryPageV2 {
    MdbxCommitHistoryPageV2 {
        items: page
            .items
            .into_iter()
            .map(commit_history_item_v2_from_storage)
            .collect(),
        next_cursor: page.next_cursor,
    }
}

fn commit_history_item_v2_from_storage(item: CommitHistoryItem) -> MdbxCommitHistoryItemV2 {
    MdbxCommitHistoryItemV2 {
        branch_id: item.branch_id.clone(),
        item: commit_history_item_from_storage(item),
    }
}

fn commit_history_item_from_storage(item: CommitHistoryItem) -> MdbxCommitHistoryItem {
    MdbxCommitHistoryItem {
        commit_id: item.commit_id,
        device_id: item.device_id,
        local_seq: item.local_seq,
        commit_kind: item.commit_kind,
        change_scope: item.change_scope,
        created_at: item.created_at,
        operation_id: item.operation_id,
        operation_kind: item.operation_kind,
        branch_name: item.branch_name,
        message: item.message,
        changes: item
            .changes
            .into_iter()
            .map(|change| MdbxCommitChange {
                object_type: change.object_type,
                object_id: change.object_id,
                action: change.action,
                fields: change.fields,
            })
            .collect(),
        parent_ids: item.parent_ids,
        legacy: item.legacy,
    }
}
