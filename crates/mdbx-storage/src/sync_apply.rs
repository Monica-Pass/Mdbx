use rusqlite::params;
use rusqlite::OptionalExtension;
use std::collections::HashSet;

#[path = "sync_apply/generic_metadata.rs"]
mod generic_metadata_apply;
#[path = "sync_apply/key_epoch.rs"]
mod key_epoch_apply;
#[path = "sync_apply/lifecycle.rs"]
mod lifecycle_apply;
#[path = "sync_apply/tiga.rs"]
mod tiga_apply;

use mdbx_core::model::{ConflictObjectType, ObjectTypeId};
#[cfg(test)]
use mdbx_core::tiga::TigaPolicyOverride;
use mdbx_sync::{CommitBatch, CommitOperationMetadata, ObjectPayload, SerializedCommit};

use crate::commit_integrity::{compute_commit_integrity_tag, CommitIntegrityInput};
use crate::conflict::ConflictDetector;
use crate::connection::VaultConnection;
use crate::error::{StorageError, StorageResult};
use crate::repo::{
    BranchRepo, CollectionProfileRepo, CommitContext, ConflictRepo, EntryRepo, ObjectVersionRepo,
    TombstoneRepo,
};
use crate::sync_delta::{
    decode_sync_delta_body, decode_sync_delta_object_payload, load_sync_delta_envelope,
    persist_envelope, SyncDeltaBatchKind, SyncDeltaEnvelope, SyncDeltaLimits,
};
#[cfg(test)]
use crate::sync_delta::{DeletedSyncEntity, SyncDeltaBody};
use crate::sync_state::{
    decode_sync_state_payload_with_limits, AttachmentChunkRow, AttachmentRow, BranchRow, EntryRow,
    ProjectRow, ProjectTagSetRow, SyncStateLimits, SyncStatePayload,
};
#[cfg(test)]
use crate::sync_state::{SecurityAuditEventRow, TigaPolicyOverrideRow, TigaVaultStateRow};
#[cfg(test)]
use crate::tiga_policy::optional_integrity_tag;
use crate::unlock::UnlockService;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyBatchResult {
    pub applied_commits: u32,
    pub skipped_commits: u32,
    pub conflict_count: u32,
    pub missing_parent_count: u32,
}

pub struct SyncApplyRepo;

#[derive(Debug, Clone, Default)]
struct PayloadApplyResult {
    conflicts: u32,
    received_delta: bool,
    received_complete_state: bool,
    delta_commit_ids: Vec<String>,
}

impl SyncApplyRepo {
    pub fn apply_auxiliary_delta(
        conn: &VaultConnection,
        ctx: &CommitContext,
        envelope: &SyncDeltaEnvelope,
    ) -> StorageResult<u32> {
        Self::apply_auxiliary_delta_with_limits(conn, ctx, envelope, SyncDeltaLimits::default())
    }

    pub fn apply_auxiliary_delta_with_limits(
        conn: &VaultConnection,
        ctx: &CommitContext,
        envelope: &SyncDeltaEnvelope,
        limits: SyncDeltaLimits,
    ) -> StorageResult<u32> {
        envelope.verify(conn, limits)?;
        if envelope.batch_kind != SyncDeltaBatchKind::Auxiliary {
            return Err(StorageError::Validation(
                "auxiliary sync apply requires an auxiliary delta".to_string(),
            ));
        }
        if let Some(existing) = load_sync_delta_envelope(conn, &envelope.batch_id, limits)? {
            if existing == *envelope {
                return Ok(0);
            }
            return Err(StorageError::Validation(format!(
                "sync delta batch {} conflicts with stored content",
                envelope.batch_id
            )));
        }
        conn.with_immediate_transaction_and_sync_limits(limits, || {
            let body = decode_sync_delta_body(envelope, limits)?;
            let conflicts = Self::apply_sync_state(
                conn,
                ctx,
                "",
                &body.state,
                key_epoch_apply::MergeMode::FastForward,
                false,
                false,
            )?;
            lifecycle_apply::apply_delta_device_heads(conn, &body.device_heads)?;
            lifecycle_apply::apply_delta_deletions(conn, &body)?;
            persist_envelope(conn, envelope)?;
            Self::discard_received_delta_mutations(conn, &[])?;
            Ok(conflicts)
        })
    }

    /// Applies legacy-compatible sync batches through an immutable connection.
    /// Key epoch state may be inspected but cannot change through this entry.
    pub fn apply_batch(
        conn: &VaultConnection,
        ctx: &CommitContext,
        batch: &CommitBatch,
    ) -> StorageResult<ApplyBatchResult> {
        Self::apply_batch_with_limits(conn, ctx, batch, SyncStateLimits::default())
    }

    /// Applies a sync batch with an explicit bounded complete-state contract.
    pub fn apply_batch_with_limits(
        conn: &VaultConnection,
        ctx: &CommitContext,
        batch: &CommitBatch,
        sync_limits: SyncStateLimits,
    ) -> StorageResult<ApplyBatchResult> {
        Self::apply_batch_inner(conn, ctx, batch, false, sync_limits)
    }

    /// Applies sync batches through a mutable connection. Epoch changes require
    /// verified unlock state and refresh all epoch keyrings before returning.
    pub fn apply_batch_mut(
        conn: &mut VaultConnection,
        ctx: &CommitContext,
        batch: &CommitBatch,
    ) -> StorageResult<ApplyBatchResult> {
        Self::apply_batch_mut_with_limits(conn, ctx, batch, SyncStateLimits::default())
    }

    /// Mutable sync apply with an explicit bounded complete-state contract.
    pub fn apply_batch_mut_with_limits(
        conn: &mut VaultConnection,
        ctx: &CommitContext,
        batch: &CommitBatch,
        sync_limits: SyncStateLimits,
    ) -> StorageResult<ApplyBatchResult> {
        let result = Self::apply_batch_inner(conn, ctx, batch, true, sync_limits)?;
        if conn.active_key_epoch_id().is_some() {
            if let Err(error) = UnlockService::refresh_verified_keyring(conn) {
                conn.clear_session();
                return Err(error);
            }
        }
        Ok(result)
    }

    /// Atomically apply one incremental transfer segment.
    ///
    /// Commit-associated deltas are carried by `batch`; audit-only and other
    /// auxiliary deltas are applied in the same SQLite transaction. A failure
    /// anywhere in the segment leaves no partially applied domain state.
    pub fn apply_incremental_batch_mut(
        conn: &mut VaultConnection,
        ctx: &CommitContext,
        batch: &CommitBatch,
        auxiliary_deltas: &[SyncDeltaEnvelope],
    ) -> StorageResult<ApplyBatchResult> {
        let delta_limits = SyncDeltaLimits::default();
        for envelope in auxiliary_deltas {
            envelope.verify(conn, delta_limits)?;
            if envelope.batch_kind != SyncDeltaBatchKind::Auxiliary {
                return Err(StorageError::Validation(
                    "incremental auxiliary payload contains a commit delta".to_string(),
                ));
            }
        }

        let mut result = conn.with_immediate_transaction_mut(|conn| {
            let mut result =
                Self::apply_batch_inner(conn, ctx, batch, true, SyncStateLimits::default())?;
            if result.missing_parent_count != 0 {
                return Err(StorageError::Validation(format!(
                    "incremental segment is missing {} commit parent(s)",
                    result.missing_parent_count
                )));
            }
            for envelope in auxiliary_deltas {
                result.conflict_count = result
                    .conflict_count
                    .checked_add(Self::apply_auxiliary_delta_with_limits(
                        conn,
                        ctx,
                        envelope,
                        delta_limits,
                    )?)
                    .ok_or_else(|| {
                        StorageError::Validation("incremental conflict count overflow".to_string())
                    })?;
            }
            Ok(result)
        })?;

        if conn.active_key_epoch_id().is_some() {
            if let Err(error) = UnlockService::refresh_verified_keyring(conn) {
                conn.clear_session();
                return Err(error);
            }
        }
        result.missing_parent_count = 0;
        Ok(result)
    }

    fn apply_batch_inner(
        conn: &VaultConnection,
        ctx: &CommitContext,
        batch: &CommitBatch,
        allow_key_epoch_changes: bool,
        sync_limits: SyncStateLimits,
    ) -> StorageResult<ApplyBatchResult> {
        let mut result = ApplyBatchResult::default();

        for serialized in &batch.commits {
            match Self::apply_commit(conn, ctx, serialized, allow_key_epoch_changes, sync_limits)? {
                ApplyOutcome::Applied => result.applied_commits += 1,
                ApplyOutcome::Skipped => result.skipped_commits += 1,
                ApplyOutcome::Conflict => {
                    result.applied_commits += 1;
                    result.conflict_count += 1;
                }
                ApplyOutcome::MissingParent => result.missing_parent_count += 1,
            }
        }

        Ok(result)
    }

    fn apply_commit(
        conn: &VaultConnection,
        ctx: &CommitContext,
        serialized: &SerializedCommit,
        allow_key_epoch_changes: bool,
        sync_limits: SyncStateLimits,
    ) -> StorageResult<ApplyOutcome> {
        if Self::commit_exists(conn, &serialized.commit.commit_id)? {
            return conn.with_immediate_transaction(|| {
                if let Some(operation) = &serialized.operation {
                    CommitContext::verify_operation_integrity(conn, &serialized.commit, operation)?;
                    Self::insert_operation(
                        conn,
                        &serialized.commit.commit_id,
                        &serialized.commit.created_at,
                        operation,
                    )?;
                }
                let payload_result = Self::apply_fast_forward_payloads(
                    conn,
                    ctx,
                    serialized,
                    allow_key_epoch_changes,
                    sync_limits,
                )?;
                if payload_result.received_delta {
                    Self::discard_received_delta_mutations(conn, &payload_result.delta_commit_ids)?;
                }
                Ok(ApplyOutcome::Skipped)
            });
        }

        for parent in &serialized.parent_ids {
            if !Self::commit_exists(conn, parent)? {
                return Ok(ApplyOutcome::MissingParent);
            }
        }

        let branch_id = serialized
            .operation
            .as_ref()
            .and_then(|operation| operation.branch_id.as_deref());
        let branch_name = serialized
            .operation
            .as_ref()
            .map(|operation| operation.branch_name.as_str())
            .unwrap_or("main");
        let local_head = Self::current_branch_head(conn, branch_id, branch_name)?;
        let fast_forward = local_head
            .as_deref()
            .map(|head| serialized.parent_ids.iter().any(|parent| parent == head))
            .unwrap_or(true);

        conn.with_immediate_transaction(|| {
            Self::insert_commit(conn, serialized)?;
            Self::acknowledge_received_tombstones(conn, ctx, serialized)?;
            if fast_forward {
                let payload_result = Self::apply_fast_forward_payloads(
                    conn,
                    ctx,
                    serialized,
                    allow_key_epoch_changes,
                    sync_limits,
                )?;
                let payload_conflicts = payload_result.conflicts;
                if payload_conflicts == 0 {
                    Self::advance_branch(
                        conn,
                        branch_id,
                        branch_name,
                        &serialized.commit.commit_id,
                    )?;
                }
                Self::sync_device_head(conn, serialized)?;
                if payload_result.received_delta {
                    Self::discard_received_delta_mutations(conn, &payload_result.delta_commit_ids)?;
                }
                Ok(if payload_conflicts == 0 {
                    ApplyOutcome::Applied
                } else {
                    ApplyOutcome::Conflict
                })
            } else {
                let payload_result = Self::apply_divergent_payloads(
                    conn,
                    ctx,
                    serialized,
                    local_head.as_deref(),
                    allow_key_epoch_changes,
                    sync_limits,
                )?;
                let payload_conflicts = payload_result.conflicts;
                Self::sync_device_head(conn, serialized)?;
                if payload_result.received_delta {
                    Self::discard_received_delta_mutations(conn, &payload_result.delta_commit_ids)?;
                }
                Ok(if payload_conflicts == 0 {
                    ApplyOutcome::Applied
                } else {
                    ApplyOutcome::Conflict
                })
            }
        })
    }

    fn insert_commit(conn: &VaultConnection, serialized: &SerializedCommit) -> StorageResult<()> {
        let commit = &serialized.commit;
        let commit_integrity_input = CommitIntegrityInput {
            commit_id: &commit.commit_id,
            device_id: &commit.device_id,
            local_seq: commit.local_seq,
            commit_kind: &commit.commit_kind.to_string(),
            change_scope: &commit.change_scope.to_string(),
            changed_object_ids_ct: &commit.changed_object_ids_ct,
            vector_clock: &commit.vector_clock,
            message_ct: commit.message_ct.as_deref(),
            created_at: &commit.created_at,
            parents: &serialized.parent_ids,
        };
        let expected = compute_commit_integrity_tag(conn.keyring(), &commit_integrity_input)?;
        if expected != commit.integrity_tag {
            return Err(StorageError::Validation(format!(
                "incoming commit {} integrity mismatch",
                commit.commit_id
            )));
        }

        conn.inner().execute(
            "INSERT INTO commits (commit_id, device_id, local_seq, commit_kind, change_scope,
             changed_object_ids_ct, vector_clock, message_ct, created_at, integrity_tag)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                commit.commit_id,
                commit.device_id,
                commit.local_seq as i64,
                commit.commit_kind.to_string(),
                commit.change_scope.to_string(),
                &commit.changed_object_ids_ct,
                commit.vector_clock,
                commit.message_ct.as_deref(),
                commit.created_at,
                &commit.integrity_tag,
            ],
        )?;

        conn.inner().execute(
            "INSERT INTO commit_device_sequences (device_id, last_local_seq)
             VALUES (?1, ?2)
             ON CONFLICT(device_id) DO UPDATE SET
                last_local_seq = MAX(last_local_seq, excluded.last_local_seq)",
            params![commit.device_id, commit.local_seq as i64],
        )?;

        for parent_id in &serialized.parent_ids {
            conn.inner().execute(
                "INSERT OR IGNORE INTO commit_parents (commit_id, parent_commit_id) VALUES (?1, ?2)",
                params![commit.commit_id, parent_id],
            )?;
        }

        if let Some(operation) = &serialized.operation {
            CommitContext::verify_operation_integrity(conn, &serialized.commit, operation)?;
            Self::insert_operation(
                conn,
                &serialized.commit.commit_id,
                &serialized.commit.created_at,
                operation,
            )?;
        }

        for tombstone in &serialized.tombstones {
            if TombstoneRepo::is_permanently_purged(
                conn,
                &tombstone.target_object_type,
                &tombstone.target_object_id,
            )? {
                continue;
            }
            conn.inner().execute(
                "INSERT INTO tombstones (tombstone_id, target_object_type, target_object_id,
                 delete_clock, deleted_by_device_id, deleted_at, purge_eligible_at,
                 delete_commit_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7)
                 ON CONFLICT(tombstone_id) DO UPDATE SET
                    target_object_type = excluded.target_object_type,
                    target_object_id = excluded.target_object_id,
                    delete_clock = excluded.delete_clock,
                    deleted_by_device_id = excluded.deleted_by_device_id,
                    deleted_at = excluded.deleted_at,
                    delete_commit_id = excluded.delete_commit_id",
                params![
                    tombstone.tombstone_id,
                    tombstone.target_object_type,
                    tombstone.target_object_id,
                    tombstone.delete_clock,
                    tombstone.deleted_by_device_id,
                    tombstone.deleted_at,
                    serialized.commit.commit_id,
                ],
            )?;
            conn.inner().execute(
                "INSERT INTO tombstone_acknowledgements
                    (tombstone_id, device_id, observed_commit_id, acknowledged_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(tombstone_id, device_id) DO UPDATE SET
                    observed_commit_id = excluded.observed_commit_id,
                    acknowledged_at = excluded.acknowledged_at",
                params![
                    tombstone.tombstone_id,
                    tombstone.deleted_by_device_id,
                    serialized.commit.commit_id,
                    tombstone.deleted_at,
                ],
            )?;
        }

        Ok(())
    }

    fn acknowledge_received_tombstones(
        conn: &VaultConnection,
        ctx: &CommitContext,
        serialized: &SerializedCommit,
    ) -> StorageResult<()> {
        for tombstone in &serialized.tombstones {
            if TombstoneRepo::is_permanently_purged(
                conn,
                &tombstone.target_object_type,
                &tombstone.target_object_id,
            )? {
                continue;
            }
            conn.inner().execute(
                "INSERT INTO tombstone_acknowledgements
                    (tombstone_id, device_id, observed_commit_id, acknowledged_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(tombstone_id, device_id) DO UPDATE SET
                    observed_commit_id = excluded.observed_commit_id,
                    acknowledged_at = excluded.acknowledged_at",
                params![
                    tombstone.tombstone_id,
                    ctx.device_id,
                    serialized.commit.commit_id,
                    chrono::Utc::now().to_rfc3339(),
                ],
            )?;
        }
        Ok(())
    }

    fn insert_operation(
        conn: &VaultConnection,
        commit_id: &str,
        created_at: &str,
        operation: &CommitOperationMetadata,
    ) -> StorageResult<()> {
        let existing: Option<(String, Vec<u8>)> = conn
            .inner()
            .query_row(
                "SELECT commit_id, request_hash FROM commit_operations WHERE operation_id = ?1",
                params![operation.operation_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((existing_commit_id, request_hash)) = existing {
            if existing_commit_id != commit_id || request_hash != operation.request_hash {
                return Err(StorageError::Validation(format!(
                    "incoming operation {} conflicts with existing metadata",
                    operation.operation_id
                )));
            }
            return Ok(());
        }

        conn.inner().execute(
            "INSERT INTO commit_operations
             (operation_id, commit_id, operation_kind, branch_id, branch_name,
              change_summary_ct, request_hash, created_at, integrity_tag)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                operation.operation_id,
                commit_id,
                operation.operation_kind,
                operation.branch_id,
                operation.branch_name,
                operation.change_summary_ct,
                operation.request_hash,
                created_at,
                operation.integrity_tag,
            ],
        )?;
        Ok(())
    }

    fn apply_fast_forward_payloads(
        conn: &VaultConnection,
        ctx: &CommitContext,
        serialized: &SerializedCommit,
        allow_key_epoch_changes: bool,
        sync_limits: SyncStateLimits,
    ) -> StorageResult<PayloadApplyResult> {
        let mut result = PayloadApplyResult::default();
        for payload in &serialized.object_payloads {
            if let Some(envelope) =
                decode_sync_delta_object_payload(conn, payload, SyncDeltaLimits::default())?
            {
                if result.received_delta || result.received_complete_state {
                    return Err(StorageError::Validation(
                        "a commit cannot carry multiple sync delta envelopes".to_string(),
                    ));
                }
                result.conflicts += Self::apply_commit_sync_delta(
                    conn,
                    ctx,
                    serialized,
                    &envelope,
                    key_epoch_apply::MergeMode::FastForward,
                    allow_key_epoch_changes,
                )?;
                result.received_delta = true;
                result.delta_commit_ids = envelope.commit_ids.clone();
            } else if let Some(state) = decode_sync_state_payload_with_limits(payload, sync_limits)?
            {
                if result.received_delta || result.received_complete_state {
                    return Err(StorageError::Validation(
                        "a commit cannot mix complete sync state and a state delta".to_string(),
                    ));
                }
                result.conflicts += Self::apply_sync_state(
                    conn,
                    ctx,
                    &serialized.commit.commit_id,
                    &state,
                    key_epoch_apply::MergeMode::FastForward,
                    allow_key_epoch_changes,
                    true,
                )?;
                result.received_complete_state = true;
            }
        }
        Ok(result)
    }

    fn apply_divergent_payloads(
        conn: &VaultConnection,
        ctx: &CommitContext,
        serialized: &SerializedCommit,
        local_head: Option<&str>,
        allow_key_epoch_changes: bool,
        sync_limits: SyncStateLimits,
    ) -> StorageResult<PayloadApplyResult> {
        let mut result = PayloadApplyResult::default();
        for payload in &serialized.object_payloads {
            if let Some(envelope) =
                decode_sync_delta_object_payload(conn, payload, SyncDeltaLimits::default())?
            {
                if result.received_delta || result.received_complete_state {
                    return Err(StorageError::Validation(
                        "a commit cannot carry multiple sync delta envelopes".to_string(),
                    ));
                }
                result.conflicts += Self::apply_commit_sync_delta(
                    conn,
                    ctx,
                    serialized,
                    &envelope,
                    key_epoch_apply::MergeMode::Divergent,
                    allow_key_epoch_changes,
                )?;
                result.received_delta = true;
                result.delta_commit_ids = envelope.commit_ids.clone();
            } else if let Some(state) = decode_sync_state_payload_with_limits(payload, sync_limits)?
            {
                if result.received_delta || result.received_complete_state {
                    return Err(StorageError::Validation(
                        "a commit cannot mix complete sync state and a state delta".to_string(),
                    ));
                }
                result.conflicts += Self::apply_sync_state(
                    conn,
                    ctx,
                    &serialized.commit.commit_id,
                    &state,
                    key_epoch_apply::MergeMode::Divergent,
                    allow_key_epoch_changes,
                    true,
                )?;
                result.received_complete_state = true;
            } else {
                result.conflicts +=
                    Self::record_payload_conflict(conn, ctx, serialized, payload, local_head)?;
            }
        }
        Ok(result)
    }

    fn apply_commit_sync_delta(
        conn: &VaultConnection,
        ctx: &CommitContext,
        serialized: &SerializedCommit,
        envelope: &SyncDeltaEnvelope,
        merge_mode: key_epoch_apply::MergeMode,
        allow_key_epoch_changes: bool,
    ) -> StorageResult<u32> {
        if envelope.batch_kind != SyncDeltaBatchKind::Commit {
            return Err(StorageError::Validation(
                "a serialized commit requires a commit-associated sync delta".to_string(),
            ));
        }
        if envelope.commit_ids.last() != Some(&serialized.commit.commit_id) {
            return Err(StorageError::Validation(
                "sync delta must be attached to its final associated commit".to_string(),
            ));
        }
        for commit_id in &envelope.commit_ids {
            if !Self::commit_exists(conn, commit_id)? {
                return Err(StorageError::ConstraintViolation(format!(
                    "sync delta references unavailable commit {commit_id}"
                )));
            }
        }
        if let Some(existing) =
            load_sync_delta_envelope(conn, &envelope.batch_id, SyncDeltaLimits::default())?
        {
            if existing == *envelope {
                return Ok(0);
            }
            return Err(StorageError::Validation(format!(
                "sync delta batch {} conflicts with stored content",
                envelope.batch_id
            )));
        }
        let body = decode_sync_delta_body(envelope, SyncDeltaLimits::default())?;
        let conflicts = Self::apply_sync_state(
            conn,
            ctx,
            &serialized.commit.commit_id,
            &body.state,
            merge_mode,
            allow_key_epoch_changes,
            false,
        )?;
        lifecycle_apply::apply_delta_device_heads(conn, &body.device_heads)?;
        lifecycle_apply::apply_delta_deletions(conn, &body)?;
        persist_envelope(conn, envelope)?;
        Ok(conflicts)
    }

    fn discard_received_delta_mutations(
        conn: &VaultConnection,
        incoming_commit_ids: &[String],
    ) -> StorageResult<()> {
        let incoming = incoming_commit_ids.iter().collect::<HashSet<_>>();
        let mut stmt = conn.inner().prepare(
            "SELECT mutation_seq, entity_id FROM sync_delta_mutations
             WHERE entity_kind = 'commit' ORDER BY mutation_seq",
        )?;
        let commits = stmt.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut first_local_sequence = None;
        for row in commits {
            let (sequence, commit_id) = row?;
            if !incoming.contains(&commit_id) {
                first_local_sequence = Some(sequence);
                break;
            }
        }
        match first_local_sequence {
            Some(sequence) => {
                conn.inner().execute(
                    "DELETE FROM sync_delta_mutations WHERE mutation_seq < ?1",
                    [sequence],
                )?;
            }
            None => crate::schema::v14::discard_captured_mutations(conn.inner())?,
        }
        Ok(())
    }

    fn apply_sync_state(
        conn: &VaultConnection,
        ctx: &CommitContext,
        incoming_commit_id: &str,
        state: &SyncStatePayload,
        key_epoch_merge_mode: key_epoch_apply::MergeMode,
        allow_key_epoch_changes: bool,
        complete_tombstone_state: bool,
    ) -> StorageResult<u32> {
        let mut conflicts = 0;
        if let Some(key_epoch_state) = &state.key_epoch_state {
            key_epoch_apply::apply(
                conn,
                key_epoch_state,
                key_epoch_merge_mode,
                allow_key_epoch_changes,
            )?;
        }
        if let Some(receipts) = &state.purge_receipts {
            lifecycle_apply::apply_purge_receipts(conn, receipts)?;
        }
        conflicts += Self::apply_projects(conn, ctx, incoming_commit_id, &state.projects)?;
        conflicts += Self::apply_entries(conn, ctx, incoming_commit_id, &state.entries)?;
        if let Some(labels) = &state.object_labels {
            conflicts += generic_metadata_apply::apply_object_labels(conn, ctx, labels)?;
        }
        if let Some(relations) = &state.object_relations {
            conflicts += generic_metadata_apply::apply_object_relations(conn, ctx, relations)?;
        }
        if let Some(assignments) = &state.object_label_assignments {
            conflicts +=
                generic_metadata_apply::apply_object_label_assignments(conn, ctx, assignments)?;
        }
        let replace_attachment_chunks =
            Self::apply_attachments(conn, ctx, incoming_commit_id, &state.attachments)?;
        conflicts += replace_attachment_chunks.conflict_count;
        Self::apply_attachment_chunks(
            conn,
            &state.attachment_chunks,
            &replace_attachment_chunks.ids,
        )?;
        if let Some(project_tags) = &state.project_tags {
            Self::apply_project_tags(conn, project_tags)?;
        }
        if let Some(vault_state) = &state.tiga_vault_state {
            tiga_apply::apply_tiga_vault_state(conn, vault_state)?;
        }
        if let Some(exceptions) = &state.tiga_policy_exceptions {
            tiga_apply::apply_tiga_policy_exceptions(conn, exceptions)?;
        }
        if let Some(overrides) = &state.tiga_policy_overrides {
            tiga_apply::apply_tiga_policy_overrides(conn, overrides)?;
        }
        if let Some(audit_events) = &state.security_audit_events {
            tiga_apply::apply_security_audit_events(conn, audit_events)?;
        }
        Self::apply_branches(conn, &state.branches)?;
        if let Some(tombstones) = &state.tombstones {
            if complete_tombstone_state
                && matches!(
                    key_epoch_merge_mode,
                    key_epoch_apply::MergeMode::FastForward
                )
                && conflicts == 0
            {
                lifecycle_apply::apply_complete_tombstone_state(conn, tombstones)?;
            } else if !complete_tombstone_state {
                lifecycle_apply::apply_delta_tombstone_state(conn, tombstones)?;
            }
        }
        if let Some(acknowledgements) = &state.tombstone_acknowledgements {
            lifecycle_apply::apply_tombstone_acknowledgements(conn, acknowledgements)?;
        }
        Ok(conflicts)
    }

    fn apply_projects(
        conn: &VaultConnection,
        ctx: &CommitContext,
        _incoming_commit_id: &str,
        projects: &[ProjectRow],
    ) -> StorageResult<u32> {
        let mut conflicts = 0;
        for row in projects {
            if TombstoneRepo::is_permanently_purged(conn, "project", &row.project_id)? {
                continue;
            }
            if Self::commit_exists(conn, &row.head_commit_id)? {
                ObjectVersionRepo::record_project_row(conn, &row.head_commit_id, row)?;
            }
            match Self::object_apply_decision(
                conn,
                "projects",
                "project_id",
                &row.project_id,
                &row.head_commit_id,
            )? {
                ObjectDecision::Insert => {
                    conn.inner().execute(
                        "INSERT INTO projects (project_id, title_ct, summary_ct, group_id, icon_ref,
                         favorite, archived, deleted, tiga_mode_override, object_clock,
                         head_commit_id, attachment_count, created_at, updated_at,
                         created_by_device_id, updated_by_device_id)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
                        params![
                            row.project_id,
                            row.title_ct,
                            row.summary_ct,
                            row.group_id,
                            row.icon_ref,
                            row.favorite as i32,
                            row.archived as i32,
                            row.deleted as i32,
                            row.tiga_mode_override,
                            row.object_clock,
                            row.head_commit_id,
                            row.attachment_count as i64,
                            row.created_at,
                            row.updated_at,
                            row.created_by_device_id,
                            row.updated_by_device_id,
                        ],
                    )?;
                    if let Some(profile) = &row.collection_profile {
                        if profile.project_id != row.project_id {
                            return Err(StorageError::ConstraintViolation(
                                "collection profile project ID does not match project row"
                                    .to_string(),
                            ));
                        }
                        CollectionProfileRepo::apply_synced_row(conn, profile)?;
                    }
                    ObjectVersionRepo::record_project_current(
                        conn,
                        &row.head_commit_id,
                        &row.project_id,
                    )?;
                }
                ObjectDecision::FastForward => {
                    conn.inner().execute(
                        "UPDATE projects SET title_ct = ?2, summary_ct = ?3, group_id = ?4,
                         icon_ref = ?5, favorite = ?6, archived = ?7, deleted = ?8,
                         tiga_mode_override = ?9, object_clock = ?10, head_commit_id = ?11,
                         attachment_count = ?12, created_at = ?13, updated_at = ?14,
                         created_by_device_id = ?15, updated_by_device_id = ?16
                         WHERE project_id = ?1",
                        params![
                            row.project_id,
                            row.title_ct,
                            row.summary_ct,
                            row.group_id,
                            row.icon_ref,
                            row.favorite as i32,
                            row.archived as i32,
                            row.deleted as i32,
                            row.tiga_mode_override,
                            row.object_clock,
                            row.head_commit_id,
                            row.attachment_count as i64,
                            row.created_at,
                            row.updated_at,
                            row.created_by_device_id,
                            row.updated_by_device_id,
                        ],
                    )?;
                    if let Some(profile) = &row.collection_profile {
                        if profile.project_id != row.project_id {
                            return Err(StorageError::ConstraintViolation(
                                "collection profile project ID does not match project row"
                                    .to_string(),
                            ));
                        }
                        CollectionProfileRepo::apply_synced_row(conn, profile)?;
                    }
                    ObjectVersionRepo::record_project_current(
                        conn,
                        &row.head_commit_id,
                        &row.project_id,
                    )?;
                }
                ObjectDecision::Conflict { local_head } => {
                    conflicts +=
                        Self::merge_or_record_project_conflict(conn, ctx, row, &local_head)?;
                }
                ObjectDecision::Skip => {}
            }
        }
        Ok(conflicts)
    }

    fn apply_entries(
        conn: &VaultConnection,
        ctx: &CommitContext,
        _incoming_commit_id: &str,
        entries: &[EntryRow],
    ) -> StorageResult<u32> {
        let mut conflicts = 0;
        for row in entries {
            if TombstoneRepo::is_permanently_purged(conn, "entry", &row.entry_id)? {
                continue;
            }
            let object_type: ObjectTypeId =
                row.entry_type.parse().map_err(StorageError::Validation)?;
            CollectionProfileRepo::ensure_object_sync_allowed(conn, &row.project_id, &object_type)?;
            if Self::commit_exists(conn, &row.head_commit_id)? {
                ObjectVersionRepo::record_entry_row(conn, &row.head_commit_id, row)?;
            }
            match Self::object_apply_decision(
                conn,
                "entries",
                "entry_id",
                &row.entry_id,
                &row.head_commit_id,
            )? {
                ObjectDecision::Insert => {
                    conn.inner().execute(
                        "INSERT INTO entries (entry_id, project_id, entry_type, title_ct,
                         payload_ct, payload_schema_version, tiga_mode_override, object_clock,
                         head_commit_id, deleted, created_at, updated_at,
                         created_by_device_id, updated_by_device_id)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                        params![
                            row.entry_id,
                            row.project_id,
                            row.entry_type,
                            row.title_ct,
                            row.payload_ct,
                            row.payload_schema_version as i64,
                            row.tiga_mode_override,
                            row.object_clock,
                            row.head_commit_id,
                            row.deleted as i32,
                            row.created_at,
                            row.updated_at,
                            row.created_by_device_id,
                            row.updated_by_device_id,
                        ],
                    )?;
                    ObjectVersionRepo::record_entry_row(conn, &row.head_commit_id, row)?;
                }
                ObjectDecision::FastForward => {
                    conn.inner().execute(
                        "UPDATE entries SET project_id = ?2, entry_type = ?3, title_ct = ?4,
                         payload_ct = ?5, payload_schema_version = ?6, tiga_mode_override = ?7,
                         object_clock = ?8, head_commit_id = ?9, deleted = ?10,
                         created_at = ?11, updated_at = ?12,
                         created_by_device_id = ?13, updated_by_device_id = ?14
                         WHERE entry_id = ?1",
                        params![
                            row.entry_id,
                            row.project_id,
                            row.entry_type,
                            row.title_ct,
                            row.payload_ct,
                            row.payload_schema_version as i64,
                            row.tiga_mode_override,
                            row.object_clock,
                            row.head_commit_id,
                            row.deleted as i32,
                            row.created_at,
                            row.updated_at,
                            row.created_by_device_id,
                            row.updated_by_device_id,
                        ],
                    )?;
                    ObjectVersionRepo::record_entry_row(conn, &row.head_commit_id, row)?;
                }
                ObjectDecision::Conflict { local_head } => {
                    conflicts += Self::merge_or_record_entry_conflict(conn, ctx, row, &local_head)?;
                }
                ObjectDecision::Skip => {}
            }
        }
        Ok(conflicts)
    }

    fn apply_attachments(
        conn: &VaultConnection,
        ctx: &CommitContext,
        _incoming_commit_id: &str,
        attachments: &[AttachmentRow],
    ) -> StorageResult<AttachmentApplyResult> {
        let mut result = AttachmentApplyResult::default();
        for row in attachments {
            if TombstoneRepo::is_permanently_purged(conn, "attachment", &row.attachment_id)? {
                continue;
            }
            if Self::commit_exists(conn, &row.head_commit_id)? {
                ObjectVersionRepo::record_attachment_row(conn, &row.head_commit_id, row)?;
            }
            match Self::object_apply_decision(
                conn,
                "attachments",
                "attachment_id",
                &row.attachment_id,
                &row.head_commit_id,
            )? {
                ObjectDecision::Insert => {
                    conn.inner().execute(
                        "INSERT INTO attachments (attachment_id, project_id, entry_id,
                         file_name_ct, media_type_ct, storage_mode, content_hash,
                         original_size, stored_size, chunk_count, head_commit_id,
                         deleted, created_at, updated_at, created_by_device_id, updated_by_device_id)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
                        params![
                            row.attachment_id,
                            row.project_id,
                            row.entry_id,
                            row.file_name_ct,
                            row.media_type_ct,
                            row.storage_mode,
                            row.content_hash,
                            row.original_size as i64,
                            row.stored_size as i64,
                            row.chunk_count as i64,
                            row.head_commit_id,
                            row.deleted as i32,
                            row.created_at,
                            row.updated_at,
                            row.created_by_device_id,
                            row.updated_by_device_id,
                        ],
                    )?;
                    ObjectVersionRepo::record_attachment_row(conn, &row.head_commit_id, row)?;
                    result.ids.insert(row.attachment_id.clone());
                }
                ObjectDecision::FastForward => {
                    conn.inner().execute(
                        "UPDATE attachments SET project_id = ?2, entry_id = ?3,
                         file_name_ct = ?4, media_type_ct = ?5, storage_mode = ?6,
                         content_hash = ?7, original_size = ?8, stored_size = ?9,
                         chunk_count = ?10, head_commit_id = ?11, deleted = ?12,
                         created_at = ?13, updated_at = ?14,
                         created_by_device_id = ?15, updated_by_device_id = ?16
                         WHERE attachment_id = ?1",
                        params![
                            row.attachment_id,
                            row.project_id,
                            row.entry_id,
                            row.file_name_ct,
                            row.media_type_ct,
                            row.storage_mode,
                            row.content_hash,
                            row.original_size as i64,
                            row.stored_size as i64,
                            row.chunk_count as i64,
                            row.head_commit_id,
                            row.deleted as i32,
                            row.created_at,
                            row.updated_at,
                            row.created_by_device_id,
                            row.updated_by_device_id,
                        ],
                    )?;
                    conn.inner().execute(
                        "DELETE FROM attachment_chunks WHERE attachment_id = ?1",
                        params![row.attachment_id],
                    )?;
                    ObjectVersionRepo::record_attachment_row(conn, &row.head_commit_id, row)?;
                    result.ids.insert(row.attachment_id.clone());
                }
                ObjectDecision::Conflict { local_head } => {
                    let merge =
                        Self::merge_or_record_attachment_conflict(conn, ctx, row, &local_head)?;
                    result.conflict_count += merge.conflict_count;
                    if merge.replace_incoming_chunks {
                        result.ids.insert(row.attachment_id.clone());
                    }
                }
                ObjectDecision::Skip => {}
            }
        }
        Ok(result)
    }

    fn apply_attachment_chunks(
        conn: &VaultConnection,
        chunks: &[AttachmentChunkRow],
        replace_attachment_ids: &HashSet<String>,
    ) -> StorageResult<()> {
        for row in chunks {
            if !replace_attachment_ids.contains(&row.attachment_id) {
                continue;
            }
            conn.inner().execute(
                "INSERT OR REPLACE INTO attachment_chunks (attachment_id, chunk_index,
                 chunk_hash, chunk_ct, external_uri_ct, stored_size, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    row.attachment_id,
                    row.chunk_index as i64,
                    row.chunk_hash,
                    row.chunk_ct,
                    row.external_uri_ct,
                    row.stored_size as i64,
                    row.created_at,
                ],
            )?;
        }
        Ok(())
    }

    fn apply_project_tags(
        conn: &VaultConnection,
        tag_sets: &[ProjectTagSetRow],
    ) -> StorageResult<()> {
        for row in tag_sets {
            if TombstoneRepo::is_permanently_purged(conn, "project", &row.project_id)? {
                continue;
            }
            conn.inner().execute(
                "DELETE FROM project_tags WHERE project_id = ?1",
                params![row.project_id],
            )?;
            for tag in &row.tags {
                let trimmed = tag.trim().to_lowercase();
                if trimmed.is_empty() {
                    continue;
                }
                conn.inner().execute(
                    "INSERT OR IGNORE INTO project_tags (project_id, tag) VALUES (?1, ?2)",
                    params![row.project_id, trimmed],
                )?;
            }
        }
        Ok(())
    }

    fn apply_branches(conn: &VaultConnection, branches: &[BranchRow]) -> StorageResult<()> {
        for row in branches {
            if !Self::commit_exists(conn, &row.head_commit_id)? {
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
                Some(local_head) => {
                    Self::is_ancestor_commit(conn, &local_head, &row.head_commit_id)?
                }
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

    fn object_apply_decision(
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
        if Self::is_ancestor_commit(conn, &local_head, incoming_head)? {
            return Ok(ObjectDecision::FastForward);
        }
        if Self::is_ancestor_commit(conn, incoming_head, &local_head)? {
            return Ok(ObjectDecision::Skip);
        }
        Ok(ObjectDecision::Conflict { local_head })
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
            let parents = Self::parent_ids_for_commit(conn, &commit_id)?;
            for parent in parents {
                if parent == ancestor {
                    return Ok(true);
                }
                stack.push(parent);
            }
        }
        Ok(false)
    }

    fn parent_ids_for_commit(
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

    fn merge_or_record_entry_conflict(
        conn: &VaultConnection,
        ctx: &CommitContext,
        incoming: &EntryRow,
        local_commit_id: &str,
    ) -> StorageResult<u32> {
        let incoming_commit_id = &incoming.head_commit_id;
        let Some(base_commit_id) =
            Self::nearest_known_common_parent(conn, local_commit_id, incoming_commit_id)?
        else {
            return Self::record_entry_field_conflict(
                conn,
                ctx,
                &incoming.entry_id,
                "unknown",
                local_commit_id,
                incoming_commit_id,
                &[String::from("<base>")],
            );
        };

        let Some(base_row) =
            ObjectVersionRepo::get_entry(conn, &incoming.entry_id, &base_commit_id)?
        else {
            return Self::record_entry_field_conflict(
                conn,
                ctx,
                &incoming.entry_id,
                &base_commit_id,
                local_commit_id,
                incoming_commit_id,
                &[String::from("<base>")],
            );
        };

        let local_row =
            match ObjectVersionRepo::get_entry(conn, &incoming.entry_id, local_commit_id)? {
                Some(row) => row,
                None => ObjectVersionRepo::current_entry_row(conn, &incoming.entry_id)?,
            };

        let mut structural_conflicts = Vec::new();
        if local_row.deleted != incoming.deleted {
            structural_conflicts.push("deleted".to_string());
        }
        if merge_value(
            &base_row.project_id,
            &local_row.project_id,
            &incoming.project_id,
        )
        .is_none()
        {
            structural_conflicts.push("project_id".to_string());
        }
        if merge_value(
            &base_row.entry_type,
            &local_row.entry_type,
            &incoming.entry_type,
        )
        .is_none()
        {
            structural_conflicts.push("entry_type".to_string());
        }
        if merge_value(&base_row.title_ct, &local_row.title_ct, &incoming.title_ct).is_none() {
            structural_conflicts.push("title_ct".to_string());
        }
        if merge_value(
            &base_row.tiga_mode_override,
            &local_row.tiga_mode_override,
            &incoming.tiga_mode_override,
        )
        .is_none()
        {
            structural_conflicts.push("tiga_mode_override".to_string());
        }
        if !structural_conflicts.is_empty() {
            return Self::record_entry_field_conflict(
                conn,
                ctx,
                &incoming.entry_id,
                &base_commit_id,
                local_commit_id,
                incoming_commit_id,
                &structural_conflicts,
            );
        }

        let base_payload =
            Self::entry_payload_json(conn, &base_row.entry_id, &base_row.payload_ct)?;
        let local_payload =
            Self::entry_payload_json(conn, &local_row.entry_id, &local_row.payload_ct)?;
        let incoming_payload =
            Self::entry_payload_json(conn, &incoming.entry_id, &incoming.payload_ct)?;
        let payload_conflicts = ConflictDetector::detect_entry_conflict(
            &base_payload,
            &local_payload,
            &incoming_payload,
        );

        if !ConflictDetector::is_safe_to_auto_merge(&payload_conflicts) {
            return Self::record_entry_field_conflict(
                conn,
                ctx,
                &incoming.entry_id,
                &base_commit_id,
                local_commit_id,
                incoming_commit_id,
                &payload_conflicts,
            );
        }

        let merged_payload = ConflictDetector::build_merged_payload(
            &base_payload,
            &local_payload,
            &incoming_payload,
        );
        Self::apply_merged_entry(
            conn,
            ctx,
            EntryMergeInput {
                base: &base_row,
                local: &local_row,
                incoming,
                local_commit_id,
                incoming_commit_id,
                merged_payload: &merged_payload,
            },
        )?;
        Ok(0)
    }

    fn apply_merged_entry(
        conn: &VaultConnection,
        ctx: &CommitContext,
        input: EntryMergeInput<'_>,
    ) -> StorageResult<()> {
        let EntryMergeInput {
            base,
            local,
            incoming,
            local_commit_id,
            incoming_commit_id,
            merged_payload,
        } = input;
        let mut parents = vec![local_commit_id.to_string()];
        if incoming_commit_id != local_commit_id {
            parents.push(incoming_commit_id.to_string());
        }
        let commit_id = ctx.create_commit(
            conn,
            "merge",
            "entry",
            &[incoming.entry_id.clone()],
            &parents,
        )?;
        let payload_plain = serde_json::to_vec(merged_payload)
            .map_err(|e| StorageError::SchemaCreation(e.to_string()))?;
        let payload_ct = EntryRepo::encrypt_payload_blob(conn, &incoming.entry_id, &payload_plain)?;
        let now = chrono::Utc::now().to_rfc3339();
        let project_id = merge_value(&base.project_id, &local.project_id, &incoming.project_id)
            .unwrap_or_else(|| local.project_id.clone());
        let entry_type = merge_value(&base.entry_type, &local.entry_type, &incoming.entry_type)
            .unwrap_or_else(|| local.entry_type.clone());
        let title_ct = merge_value(&base.title_ct, &local.title_ct, &incoming.title_ct)
            .unwrap_or_else(|| local.title_ct.clone());
        let tiga_mode_override = merge_value(
            &base.tiga_mode_override,
            &local.tiga_mode_override,
            &incoming.tiga_mode_override,
        )
        .unwrap_or_else(|| local.tiga_mode_override.clone());

        conn.inner().execute(
            "UPDATE entries SET project_id = ?2, entry_type = ?3, title_ct = ?4,
             payload_ct = ?5, payload_schema_version = ?6, tiga_mode_override = ?7,
             object_clock = ?8, head_commit_id = ?9, deleted = 0,
             updated_at = ?10, updated_by_device_id = ?11
             WHERE entry_id = ?1",
            params![
                incoming.entry_id,
                project_id,
                entry_type,
                title_ct,
                payload_ct,
                std::cmp::max(
                    local.payload_schema_version,
                    incoming.payload_schema_version
                ) as i64,
                tiga_mode_override,
                bump_object_clock(&local.object_clock),
                commit_id,
                now,
                ctx.device_id,
            ],
        )?;
        ObjectVersionRepo::record_entry_current(conn, &commit_id, &incoming.entry_id)?;
        Ok(())
    }

    fn merge_or_record_project_conflict(
        conn: &VaultConnection,
        ctx: &CommitContext,
        incoming: &ProjectRow,
        local_commit_id: &str,
    ) -> StorageResult<u32> {
        let incoming_commit_id = &incoming.head_commit_id;
        let Some(base_commit_id) =
            Self::nearest_known_common_parent(conn, local_commit_id, incoming_commit_id)?
        else {
            return Self::record_project_field_conflict(
                conn,
                ctx,
                &incoming.project_id,
                "unknown",
                local_commit_id,
                incoming_commit_id,
                &[String::from("<base>")],
            );
        };

        let Some(base_row) =
            ObjectVersionRepo::get_project(conn, &incoming.project_id, &base_commit_id)?
        else {
            return Self::record_project_field_conflict(
                conn,
                ctx,
                &incoming.project_id,
                &base_commit_id,
                local_commit_id,
                incoming_commit_id,
                &[String::from("<base>")],
            );
        };

        let local_row =
            match ObjectVersionRepo::get_project(conn, &incoming.project_id, local_commit_id)? {
                Some(row) => row,
                None => ObjectVersionRepo::current_project_row(conn, &incoming.project_id)?,
            };

        let local_profile = local_row
            .collection_profile
            .clone()
            .or_else(|| base_row.collection_profile.clone());
        let incoming_profile = incoming
            .collection_profile
            .clone()
            .or_else(|| base_row.collection_profile.clone());

        let mut structural_conflicts = Vec::new();
        if local_row.deleted != incoming.deleted {
            structural_conflicts.push("deleted".to_string());
        }
        if merge_value(&base_row.title_ct, &local_row.title_ct, &incoming.title_ct).is_none() {
            structural_conflicts.push("title_ct".to_string());
        }
        if merge_value(
            &base_row.summary_ct,
            &local_row.summary_ct,
            &incoming.summary_ct,
        )
        .is_none()
        {
            structural_conflicts.push("summary_ct".to_string());
        }
        if merge_value(&base_row.group_id, &local_row.group_id, &incoming.group_id).is_none() {
            structural_conflicts.push("group_id".to_string());
        }
        if merge_value(&base_row.icon_ref, &local_row.icon_ref, &incoming.icon_ref).is_none() {
            structural_conflicts.push("icon_ref".to_string());
        }
        if merge_value(&base_row.favorite, &local_row.favorite, &incoming.favorite).is_none() {
            structural_conflicts.push("favorite".to_string());
        }
        if merge_value(&base_row.archived, &local_row.archived, &incoming.archived).is_none() {
            structural_conflicts.push("archived".to_string());
        }
        if merge_value(
            &base_row.tiga_mode_override,
            &local_row.tiga_mode_override,
            &incoming.tiga_mode_override,
        )
        .is_none()
        {
            structural_conflicts.push("tiga_mode_override".to_string());
        }
        if merge_value(
            &base_row.collection_profile,
            &local_profile,
            &incoming_profile,
        )
        .is_none()
        {
            structural_conflicts.push("collection_profile".to_string());
        }

        if !structural_conflicts.is_empty() {
            return Self::record_project_field_conflict(
                conn,
                ctx,
                &incoming.project_id,
                &base_commit_id,
                local_commit_id,
                incoming_commit_id,
                &structural_conflicts,
            );
        }

        Self::apply_merged_project(
            conn,
            ctx,
            &base_row,
            &local_row,
            incoming,
            local_commit_id,
            incoming_commit_id,
        )?;
        Ok(0)
    }

    fn apply_merged_project(
        conn: &VaultConnection,
        ctx: &CommitContext,
        base: &ProjectRow,
        local: &ProjectRow,
        incoming: &ProjectRow,
        local_commit_id: &str,
        incoming_commit_id: &str,
    ) -> StorageResult<()> {
        let mut parents = vec![local_commit_id.to_string()];
        if incoming_commit_id != local_commit_id {
            parents.push(incoming_commit_id.to_string());
        }
        let commit_id = ctx.create_commit(
            conn,
            "merge",
            "project",
            &[incoming.project_id.clone()],
            &parents,
        )?;
        let now = chrono::Utc::now().to_rfc3339();
        let attachment_count = merge_value(
            &base.attachment_count,
            &local.attachment_count,
            &incoming.attachment_count,
        )
        .unwrap_or_else(|| std::cmp::max(local.attachment_count, incoming.attachment_count));
        let local_profile = local
            .collection_profile
            .clone()
            .or_else(|| base.collection_profile.clone());
        let incoming_profile = incoming
            .collection_profile
            .clone()
            .or_else(|| base.collection_profile.clone());
        let collection_profile =
            merge_value(&base.collection_profile, &local_profile, &incoming_profile)
                .unwrap_or(local_profile);

        conn.inner().execute(
            "UPDATE projects SET title_ct = ?2, summary_ct = ?3, group_id = ?4,
             icon_ref = ?5, favorite = ?6, archived = ?7, deleted = ?8,
             tiga_mode_override = ?9, object_clock = ?10, head_commit_id = ?11,
             attachment_count = ?12, updated_at = ?13, updated_by_device_id = ?14
             WHERE project_id = ?1",
            params![
                incoming.project_id,
                merge_value(&base.title_ct, &local.title_ct, &incoming.title_ct)
                    .unwrap_or_else(|| local.title_ct.clone()),
                merge_value(&base.summary_ct, &local.summary_ct, &incoming.summary_ct)
                    .unwrap_or_else(|| local.summary_ct.clone()),
                merge_value(&base.group_id, &local.group_id, &incoming.group_id)
                    .unwrap_or_else(|| local.group_id.clone()),
                merge_value(&base.icon_ref, &local.icon_ref, &incoming.icon_ref)
                    .unwrap_or_else(|| local.icon_ref.clone()),
                merge_value(&base.favorite, &local.favorite, &incoming.favorite)
                    .unwrap_or(local.favorite) as i32,
                merge_value(&base.archived, &local.archived, &incoming.archived)
                    .unwrap_or(local.archived) as i32,
                local.deleted as i32,
                merge_value(
                    &base.tiga_mode_override,
                    &local.tiga_mode_override,
                    &incoming.tiga_mode_override,
                )
                .unwrap_or_else(|| local.tiga_mode_override.clone()),
                bump_object_clock(&local.object_clock),
                commit_id,
                attachment_count as i64,
                now,
                ctx.device_id,
            ],
        )?;
        if let Some(profile) = &collection_profile {
            CollectionProfileRepo::apply_synced_row(conn, profile)?;
        }
        ObjectVersionRepo::record_project_current(conn, &commit_id, &incoming.project_id)?;
        Ok(())
    }

    fn merge_or_record_attachment_conflict(
        conn: &VaultConnection,
        ctx: &CommitContext,
        incoming: &AttachmentRow,
        local_commit_id: &str,
    ) -> StorageResult<AttachmentMergeResult> {
        let incoming_commit_id = &incoming.head_commit_id;
        let Some(base_commit_id) =
            Self::nearest_known_common_parent(conn, local_commit_id, incoming_commit_id)?
        else {
            let conflict_count = Self::record_attachment_field_conflict(
                conn,
                ctx,
                &incoming.attachment_id,
                "unknown",
                local_commit_id,
                incoming_commit_id,
                &[String::from("<base>")],
            )?;
            return Ok(AttachmentMergeResult {
                conflict_count,
                replace_incoming_chunks: false,
            });
        };

        let Some(base_row) =
            ObjectVersionRepo::get_attachment(conn, &incoming.attachment_id, &base_commit_id)?
        else {
            let conflict_count = Self::record_attachment_field_conflict(
                conn,
                ctx,
                &incoming.attachment_id,
                &base_commit_id,
                local_commit_id,
                incoming_commit_id,
                &[String::from("<base>")],
            )?;
            return Ok(AttachmentMergeResult {
                conflict_count,
                replace_incoming_chunks: false,
            });
        };

        let local_row = match ObjectVersionRepo::get_attachment(
            conn,
            &incoming.attachment_id,
            local_commit_id,
        )? {
            Some(row) => row,
            None => ObjectVersionRepo::current_attachment_row(conn, &incoming.attachment_id)?,
        };

        let mut structural_conflicts = Vec::new();
        if local_row.deleted != incoming.deleted {
            structural_conflicts.push("deleted".to_string());
        }
        if merge_value(
            &base_row.project_id,
            &local_row.project_id,
            &incoming.project_id,
        )
        .is_none()
        {
            structural_conflicts.push("project_id".to_string());
        }
        if merge_value(&base_row.entry_id, &local_row.entry_id, &incoming.entry_id).is_none() {
            structural_conflicts.push("entry_id".to_string());
        }
        if merge_value(
            &base_row.file_name_ct,
            &local_row.file_name_ct,
            &incoming.file_name_ct,
        )
        .is_none()
        {
            structural_conflicts.push("file_name_ct".to_string());
        }
        if merge_value(
            &base_row.media_type_ct,
            &local_row.media_type_ct,
            &incoming.media_type_ct,
        )
        .is_none()
        {
            structural_conflicts.push("media_type_ct".to_string());
        }

        let local_content_changed = attachment_content_changed(&base_row, &local_row);
        let incoming_content_changed = attachment_content_changed(&base_row, incoming);
        let content_matches = attachment_content_matches(&local_row, incoming);
        let replace_incoming_chunks = if content_matches {
            false
        } else if local_content_changed && incoming_content_changed {
            structural_conflicts.push("content_hash".to_string());
            false
        } else {
            !local_content_changed && incoming_content_changed
        };

        if !structural_conflicts.is_empty() {
            let conflict_count = Self::record_attachment_field_conflict(
                conn,
                ctx,
                &incoming.attachment_id,
                &base_commit_id,
                local_commit_id,
                incoming_commit_id,
                &structural_conflicts,
            )?;
            return Ok(AttachmentMergeResult {
                conflict_count,
                replace_incoming_chunks: false,
            });
        }

        Self::apply_merged_attachment(
            conn,
            ctx,
            AttachmentMergeInput {
                base: &base_row,
                local: &local_row,
                incoming,
                local_commit_id,
                incoming_commit_id,
                use_incoming_content: replace_incoming_chunks,
            },
        )?;
        Ok(AttachmentMergeResult {
            conflict_count: 0,
            replace_incoming_chunks,
        })
    }

    fn apply_merged_attachment(
        conn: &VaultConnection,
        ctx: &CommitContext,
        input: AttachmentMergeInput<'_>,
    ) -> StorageResult<()> {
        let AttachmentMergeInput {
            base,
            local,
            incoming,
            local_commit_id,
            incoming_commit_id,
            use_incoming_content,
        } = input;
        let mut parents = vec![local_commit_id.to_string()];
        if incoming_commit_id != local_commit_id {
            parents.push(incoming_commit_id.to_string());
        }
        let commit_id = ctx.create_commit(
            conn,
            "merge",
            "attachment",
            &[incoming.attachment_id.clone()],
            &parents,
        )?;
        let now = chrono::Utc::now().to_rfc3339();
        let content_source = if use_incoming_content {
            incoming
        } else {
            local
        };

        if use_incoming_content {
            conn.inner().execute(
                "DELETE FROM attachment_chunks WHERE attachment_id = ?1",
                params![incoming.attachment_id],
            )?;
        }

        conn.inner().execute(
            "UPDATE attachments SET project_id = ?2, entry_id = ?3,
             file_name_ct = ?4, media_type_ct = ?5, storage_mode = ?6,
             content_hash = ?7, original_size = ?8, stored_size = ?9,
             chunk_count = ?10, head_commit_id = ?11, deleted = ?12,
             updated_at = ?13, updated_by_device_id = ?14
             WHERE attachment_id = ?1",
            params![
                incoming.attachment_id,
                merge_value(&base.project_id, &local.project_id, &incoming.project_id)
                    .unwrap_or_else(|| local.project_id.clone()),
                merge_value(&base.entry_id, &local.entry_id, &incoming.entry_id)
                    .unwrap_or_else(|| local.entry_id.clone()),
                merge_value(
                    &base.file_name_ct,
                    &local.file_name_ct,
                    &incoming.file_name_ct,
                )
                .unwrap_or_else(|| local.file_name_ct.clone()),
                merge_value(
                    &base.media_type_ct,
                    &local.media_type_ct,
                    &incoming.media_type_ct,
                )
                .unwrap_or_else(|| local.media_type_ct.clone()),
                content_source.storage_mode,
                content_source.content_hash,
                content_source.original_size as i64,
                content_source.stored_size as i64,
                content_source.chunk_count as i64,
                commit_id,
                local.deleted as i32,
                now,
                ctx.device_id,
            ],
        )?;
        ObjectVersionRepo::record_attachment_current(conn, &commit_id, &incoming.attachment_id)?;
        Ok(())
    }

    fn entry_payload_json(
        conn: &VaultConnection,
        entry_id: &str,
        payload_ct: &[u8],
    ) -> StorageResult<serde_json::Value> {
        let plaintext = EntryRepo::decrypt_payload_blob(conn, entry_id, payload_ct)?;
        serde_json::from_slice(&plaintext).map_err(|e| {
            StorageError::Validation(format!(
                "entry {} payload is not valid JSON: {}",
                entry_id, e
            ))
        })
    }

    fn record_entry_field_conflict(
        conn: &VaultConnection,
        ctx: &CommitContext,
        entry_id: &str,
        base_commit_id: &str,
        local_commit_id: &str,
        incoming_commit_id: &str,
        fields: &[String],
    ) -> StorageResult<u32> {
        if ConflictRepo::has_unresolved_conflict(conn, ConflictObjectType::Entry, entry_id)? {
            return Ok(0);
        }
        ConflictRepo::create(
            conn,
            ctx,
            ConflictObjectType::Entry,
            entry_id,
            base_commit_id,
            local_commit_id,
            incoming_commit_id,
            fields,
        )?;
        Ok(1)
    }

    fn record_project_field_conflict(
        conn: &VaultConnection,
        ctx: &CommitContext,
        project_id: &str,
        base_commit_id: &str,
        local_commit_id: &str,
        incoming_commit_id: &str,
        fields: &[String],
    ) -> StorageResult<u32> {
        if ConflictRepo::has_unresolved_conflict(conn, ConflictObjectType::Project, project_id)? {
            return Ok(0);
        }
        ConflictRepo::create(
            conn,
            ctx,
            ConflictObjectType::Project,
            project_id,
            base_commit_id,
            local_commit_id,
            incoming_commit_id,
            fields,
        )?;
        Ok(1)
    }

    fn record_attachment_field_conflict(
        conn: &VaultConnection,
        ctx: &CommitContext,
        attachment_id: &str,
        base_commit_id: &str,
        local_commit_id: &str,
        incoming_commit_id: &str,
        fields: &[String],
    ) -> StorageResult<u32> {
        if ConflictRepo::has_unresolved_conflict(
            conn,
            ConflictObjectType::Attachment,
            attachment_id,
        )? {
            return Ok(0);
        }
        ConflictRepo::create(
            conn,
            ctx,
            ConflictObjectType::Attachment,
            attachment_id,
            base_commit_id,
            local_commit_id,
            incoming_commit_id,
            fields,
        )?;
        Ok(1)
    }

    fn nearest_known_common_parent(
        conn: &VaultConnection,
        left: &str,
        right: &str,
    ) -> StorageResult<Option<String>> {
        let left_ancestors = Self::ancestor_set(conn, left)?;
        let mut stack = vec![right.to_string()];
        let mut seen = HashSet::new();
        while let Some(commit_id) = stack.pop() {
            if !seen.insert(commit_id.clone()) {
                continue;
            }
            if left_ancestors.contains(&commit_id) {
                return Ok(Some(commit_id));
            }
            stack.extend(Self::parent_ids_for_commit(conn, &commit_id)?);
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
            stack.extend(Self::parent_ids_for_commit(conn, &commit_id)?);
        }
        Ok(result)
    }

    fn commit_exists(conn: &VaultConnection, commit_id: &str) -> StorageResult<bool> {
        let count: i64 = conn.inner().query_row(
            "SELECT COUNT(*) FROM commits WHERE commit_id = ?1",
            params![commit_id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    fn record_payload_conflict(
        conn: &VaultConnection,
        ctx: &CommitContext,
        serialized: &SerializedCommit,
        payload: &ObjectPayload,
        local_head: Option<&str>,
    ) -> StorageResult<u32> {
        let local_head = local_head.ok_or_else(|| {
            StorageError::Validation("missing local branch head for conflict detection".into())
        })?;

        let object_type = conflict_object_type(&payload.object_type);
        let Some(object_type) = object_type else {
            return Ok(0);
        };
        let local_exists = match payload.object_type.as_str() {
            "project" => exists(conn, "projects", "project_id", &payload.object_id)?,
            "entry" => exists(conn, "entries", "entry_id", &payload.object_id)?,
            "attachment" => exists(conn, "attachments", "attachment_id", &payload.object_id)?,
            _ => false,
        };
        if !local_exists || local_head == serialized.commit.commit_id {
            return Ok(0);
        }
        if ConflictRepo::has_unresolved_conflict(conn, object_type.clone(), &payload.object_id)? {
            return Ok(0);
        }

        let base_commit_id =
            Self::nearest_known_common_parent(conn, local_head, &serialized.commit.commit_id)?
                .unwrap_or_else(|| local_head.to_string());
        ConflictRepo::create(
            conn,
            ctx,
            object_type,
            &payload.object_id,
            &base_commit_id,
            local_head,
            &serialized.commit.commit_id,
            &[String::from("payload_ct")],
        )?;
        Ok(1)
    }

    fn sync_device_head(
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

    fn current_branch_head(
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

    fn advance_branch(
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApplyOutcome {
    Applied,
    Skipped,
    Conflict,
    MissingParent,
}

fn conflict_object_type(value: &str) -> Option<ConflictObjectType> {
    match value {
        "project" => Some(ConflictObjectType::Project),
        "entry" => Some(ConflictObjectType::Entry),
        "attachment" => Some(ConflictObjectType::Attachment),
        _ => None,
    }
}

#[derive(Debug, Clone, Default)]
struct AttachmentApplyResult {
    ids: HashSet<String>,
    conflict_count: u32,
}

#[derive(Debug, Clone, Copy, Default)]
struct AttachmentMergeResult {
    conflict_count: u32,
    replace_incoming_chunks: bool,
}

struct EntryMergeInput<'a> {
    base: &'a EntryRow,
    local: &'a EntryRow,
    incoming: &'a EntryRow,
    local_commit_id: &'a str,
    incoming_commit_id: &'a str,
    merged_payload: &'a serde_json::Value,
}

struct AttachmentMergeInput<'a> {
    base: &'a AttachmentRow,
    local: &'a AttachmentRow,
    incoming: &'a AttachmentRow,
    local_commit_id: &'a str,
    incoming_commit_id: &'a str,
    use_incoming_content: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ObjectDecision {
    Insert,
    FastForward,
    Conflict { local_head: String },
    Skip,
}

fn exists(
    conn: &VaultConnection,
    table: &str,
    id_column: &str,
    object_id: &str,
) -> StorageResult<bool> {
    let sql = format!("SELECT COUNT(*) FROM {} WHERE {} = ?1", table, id_column);
    let count: i64 = conn
        .inner()
        .query_row(&sql, params![object_id], |row| row.get(0))?;
    Ok(count > 0)
}

fn merge_value<T: Clone + PartialEq>(base: &T, local: &T, incoming: &T) -> Option<T> {
    if local == incoming || incoming == base {
        Some(local.clone())
    } else if local == base && incoming != base {
        Some(incoming.clone())
    } else {
        None
    }
}

fn attachment_content_changed(base: &AttachmentRow, candidate: &AttachmentRow) -> bool {
    base.storage_mode != candidate.storage_mode
        || base.content_hash != candidate.content_hash
        || base.original_size != candidate.original_size
        || base.stored_size != candidate.stored_size
        || base.chunk_count != candidate.chunk_count
}

fn attachment_content_matches(left: &AttachmentRow, right: &AttachmentRow) -> bool {
    left.storage_mode == right.storage_mode
        && left.content_hash == right.content_hash
        && left.original_size == right.original_size
        && left.stored_size == right.stored_size
        && left.chunk_count == right.chunk_count
}

fn bump_object_clock(clock: &str) -> String {
    let counter: u64 = serde_json::from_str::<serde_json::Value>(clock)
        .ok()
        .and_then(|v| v.get("counter")?.as_u64())
        .unwrap_or(0);
    format!(r#"{{"counter":{}}}"#, counter + 1)
}

fn validate_payload_schema_version(value: u32) -> StorageResult<()> {
    if value == 0 {
        return Err(StorageError::Validation(
            "payload_schema_version must be greater than zero".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit_integrity::compute_commit_integrity_tag;
    use crate::commit_integrity::CommitIntegrityInput;
    use crate::init::{initialize_vault, VaultInitParams};
    use crate::key_epoch::{KeyEpochRotationResult, KeyEpochService};
    use crate::repo::{
        AttachmentRepo, CollectionProfileRepo, CollectionProfileSpec, CommitChange,
        CommitOperation, EntryRepo, ObjectLabelAssignmentCreateRequest, ObjectLabelAssignmentRepo,
        ObjectLabelCreateRequest, ObjectLabelRepo, ObjectRelationCreateRequest, ObjectRelationRepo,
        ObjectVersionRepo, ProjectRepo, TombstoneRepo,
    };
    use crate::sync_delta::{sync_delta_object_payload, NewSyncDeltaEnvelope, SyncDeltaLimits};
    use crate::sync_state::{collect_sync_state, collect_sync_state_payload, SyncStateLimits};
    use crate::tiga::TigaService;
    use crate::tiga_policy::TigaAuthorizationContext;
    use crate::unlock::UnlockService;
    use mdbx_core::model::{
        ChangeScope, CollectionTypeId, Commit, CommitKind, ConflictObjectType, ConflictResolution,
        EntryType, ExtensionCapabilityId, ObjectTypeId, RelationKindId, UnlockMethodType,
        VaultSession,
    };
    use mdbx_core::tiga::{
        DeviceAssurance, DeviceContext, SessionAssurance, TigaScope, TIGA_POLICY_VERSION,
    };

    #[test]
    fn synced_tiga_scope_accepts_attachment_ids() {
        assert_eq!(
            tiga_apply::tiga_scope_from_parts("attachment", "attachment-1").unwrap(),
            TigaScope::Attachment {
                attachment_id: "attachment-1".to_string()
            }
        );
    }
    use mdbx_crypto::keyring::Keyring;
    use mdbx_sync::{CommitBatch, ObjectPayload, SerializedCommit, TombstoneRecord};
    use std::path::{Path, PathBuf};
    use uuid::Uuid;

    fn setup() -> (VaultConnection, CommitContext) {
        let conn = VaultConnection::open_in_memory().unwrap();
        initialize_vault(&conn, &VaultInitParams::default()).unwrap();
        let ctx = CommitContext::new("device-a".to_string());
        (conn, ctx)
    }

    #[test]
    fn synced_tiga_records_reject_invalid_authenticated_tags() {
        let mut conn = VaultConnection::open_in_memory().unwrap();
        initialize_vault(&conn, &VaultInitParams::default()).unwrap();
        conn.attach_keyring(Keyring::from_vault_key(&[9_u8; 32], b"sync-tiga-test").unwrap());

        let policy = TigaPolicyOverride {
            clipboard_allowed: Some(false),
            ..Default::default()
        };
        let mut policy_tag = optional_integrity_tag(&conn, b"tiga-policy-override", &policy)
            .unwrap()
            .unwrap();
        policy_tag[0] ^= 1;
        let error = tiga_apply::apply_tiga_policy_overrides(
            &conn,
            &[TigaPolicyOverrideRow {
                scope_type: "vault".to_string(),
                scope_id: String::new(),
                policy_json: serde_json::to_string(&policy).unwrap(),
                exception_id: None,
                updated_at: "2026-07-19T00:00:00Z".to_string(),
                updated_by_device_id: "remote".to_string(),
                integrity_tag: Some(policy_tag),
            }],
        )
        .unwrap_err();
        assert!(error.to_string().contains("integrity tag mismatch"));

        let state_error = tiga_apply::apply_tiga_vault_state(
            &conn,
            &TigaVaultStateRow {
                default_tiga_mode: "multi".to_string(),
                policy_version: TIGA_POLICY_VERSION + 1,
                compliance_status: "compliant".to_string(),
                updated_at: "2026-07-19T00:00:00Z".to_string(),
            },
        )
        .unwrap_err();
        assert!(state_error
            .to_string()
            .contains("unsupported incoming Tiga policy version"));
    }

    #[test]
    fn synced_tiga_policy_conflicts_merge_to_stricter_fields() {
        let (conn, _) = setup();
        let local = TigaPolicyOverride {
            clipboard_allowed: Some(true),
            clipboard_ttl_secs: Some(30),
            minimum_auth_factors: Some(2),
            ..Default::default()
        };
        conn.inner()
            .execute(
                "INSERT INTO tiga_policy_overrides
                    (scope_type, scope_id, policy_json, exception_id, updated_at,
                     updated_by_device_id, integrity_tag)
                 VALUES ('vault', '', ?1, NULL, '2026-01-01T00:00:00Z', 'local', NULL)",
                params![serde_json::to_string(&local).unwrap()],
            )
            .unwrap();
        let incoming = TigaPolicyOverride {
            clipboard_allowed: Some(false),
            clipboard_ttl_secs: Some(10),
            minimum_auth_factors: Some(1),
            ..Default::default()
        };
        tiga_apply::apply_tiga_policy_overrides(
            &conn,
            &[TigaPolicyOverrideRow {
                scope_type: "vault".to_string(),
                scope_id: String::new(),
                policy_json: serde_json::to_string(&incoming).unwrap(),
                exception_id: None,
                updated_at: "2026-01-02T00:00:00Z".to_string(),
                updated_by_device_id: "remote".to_string(),
                integrity_tag: None,
            }],
        )
        .unwrap();
        let stored: String = conn
            .inner()
            .query_row(
                "SELECT policy_json FROM tiga_policy_overrides
                 WHERE scope_type = 'vault' AND scope_id = ''",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let stored: TigaPolicyOverride = serde_json::from_str(&stored).unwrap();
        assert_eq!(stored.clipboard_allowed, Some(false));
        assert_eq!(stored.clipboard_ttl_secs, Some(10));
        assert_eq!(stored.minimum_auth_factors, Some(2));
    }

    #[test]
    fn synced_tiga_vault_state_never_lowers_profile_or_compliance() {
        let (conn, _) = setup();
        conn.inner()
            .execute(
                "UPDATE vault_meta SET default_tiga_mode = 'power',
                 tiga_compliance_status = 'remediation-required'",
                [],
            )
            .unwrap();
        tiga_apply::apply_tiga_vault_state(
            &conn,
            &TigaVaultStateRow {
                default_tiga_mode: "sky".to_string(),
                policy_version: 1,
                compliance_status: "compliant".to_string(),
                updated_at: "2026-01-02T00:00:00Z".to_string(),
            },
        )
        .unwrap();
        let state: (String, i64, String) = conn
            .inner()
            .query_row(
                "SELECT default_tiga_mode, tiga_policy_version, tiga_compliance_status
                 FROM vault_meta",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(state.0, "power");
        assert_eq!(state.1, i64::from(TIGA_POLICY_VERSION));
        assert_eq!(state.2, "remediation-required");
    }

    #[test]
    fn synced_audit_event_id_cannot_be_rewritten() {
        let (conn, _) = setup();
        let mut event = SecurityAuditEventRow {
            event_id: "event-1".to_string(),
            occurred_at: "2026-01-01T00:00:00Z".to_string(),
            operation: "copy-secret".to_string(),
            outcome: "allow".to_string(),
            scope_type: "vault".to_string(),
            scope_id: String::new(),
            session_id: None,
            device_id: Some("device-a".to_string()),
            reason_codes_json: "[]".to_string(),
            constraints_json: "[]".to_string(),
            exception_id: None,
            operation_id: None,
            commit_id: None,
            policy_version: None,
            policy_fingerprint: None,
            integrity_tag: None,
        };
        tiga_apply::apply_security_audit_events(&conn, &[event.clone()]).unwrap();
        event.outcome = "deny".to_string();
        let error = tiga_apply::apply_security_audit_events(&conn, &[event]).unwrap_err();
        assert!(error.to_string().contains("was rewritten"));
    }

    fn make_commit(
        commit_id: &str,
        device_id: &str,
        local_seq: u64,
        parents: Vec<String>,
        changed: Vec<String>,
        object_id: &str,
        payload_object_type: &str,
    ) -> SerializedCommit {
        let commit = Commit {
            commit_id: commit_id.to_string(),
            device_id: device_id.to_string(),
            local_seq,
            commit_kind: CommitKind::Change,
            change_scope: ChangeScope::Project,
            changed_object_ids_ct: serde_json::to_vec(&changed).unwrap(),
            vector_clock: format!(r#"{{"{}":{}}}"#, device_id, local_seq),
            message_ct: None,
            created_at: "2026-05-22T00:00:00Z".to_string(),
            integrity_tag: vec![],
        };
        let tag = compute_commit_integrity_tag(
            None,
            &CommitIntegrityInput {
                commit_id: &commit.commit_id,
                device_id: &commit.device_id,
                local_seq: commit.local_seq,
                commit_kind: &commit.commit_kind.to_string(),
                change_scope: &commit.change_scope.to_string(),
                changed_object_ids_ct: &commit.changed_object_ids_ct,
                vector_clock: &commit.vector_clock,
                message_ct: None,
                created_at: &commit.created_at,
                parents: &parents,
            },
        )
        .unwrap();
        SerializedCommit {
            commit: Commit {
                integrity_tag: tag,
                ..commit
            },
            operation: None,
            parent_ids: parents,
            tombstones: vec![TombstoneRecord {
                tombstone_id: format!("t-{}", commit_id),
                target_object_type: payload_object_type.to_string(),
                target_object_id: object_id.to_string(),
                delete_clock: "{}".to_string(),
                deleted_by_device_id: device_id.to_string(),
                deleted_at: "2026-05-22T00:00:00Z".to_string(),
            }],
            object_payloads: vec![ObjectPayload {
                object_type: payload_object_type.to_string(),
                object_id: object_id.to_string(),
                ciphertext: vec![1, 2, 3],
                associated_data: vec![],
            }],
        }
    }

    #[test]
    fn synced_device_head_preserves_local_revocation() {
        let (conn, _) = setup();
        let first = make_commit(
            "remote-1",
            "remote-device",
            1,
            Vec::new(),
            vec!["project-1".to_string()],
            "project-1",
            "project",
        );
        SyncApplyRepo::insert_commit(&conn, &first).unwrap();
        conn.inner()
            .execute(
                "INSERT INTO device_heads (device_id, head_commit_id, last_seen_at, revoked)
                 VALUES (?1, ?2, ?3, 1)",
                params![
                    first.commit.device_id,
                    first.commit.commit_id,
                    first.commit.created_at
                ],
            )
            .unwrap();

        let second = make_commit(
            "remote-2",
            "remote-device",
            2,
            vec!["remote-1".to_string()],
            vec!["project-1".to_string()],
            "project-1",
            "project",
        );
        SyncApplyRepo::insert_commit(&conn, &second).unwrap();
        SyncApplyRepo::sync_device_head(&conn, &second).unwrap();

        let stored: (String, i64) = conn
            .inner()
            .query_row(
                "SELECT head_commit_id, revoked FROM device_heads WHERE device_id = ?1",
                params![second.commit.device_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(stored.0, second.commit.commit_id);
        assert_eq!(stored.1, 1);
    }

    #[test]
    fn receiving_tombstone_records_local_and_deleting_device_acknowledgements() {
        let (conn, ctx) = setup();
        let serialized = make_commit(
            "remote-delete",
            "remote-device",
            1,
            Vec::new(),
            vec!["project-1".to_string()],
            "project-1",
            "project",
        );

        SyncApplyRepo::insert_commit(&conn, &serialized).unwrap();
        SyncApplyRepo::acknowledge_received_tombstones(&conn, &ctx, &serialized).unwrap();

        let mut stmt = conn
            .inner()
            .prepare(
                "SELECT device_id, observed_commit_id FROM tombstone_acknowledgements
                 WHERE tombstone_id = 't-remote-delete' ORDER BY device_id",
            )
            .unwrap();
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .map(|row| row.unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            rows,
            vec![
                ("device-a".to_string(), "remote-delete".to_string()),
                ("remote-device".to_string(), "remote-delete".to_string()),
            ]
        );
    }

    fn temp_vault_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("mdbx-sync-{}-{}.mdbx", label, Uuid::new_v4()))
    }

    fn remove_vault_files(path: &Path) {
        for suffix in ["", "-wal", "-shm"] {
            let mut candidate = path.as_os_str().to_os_string();
            candidate.push(suffix);
            let _ = std::fs::remove_file(PathBuf::from(candidate));
        }
    }

    fn rotation_device(device_id: &str) -> DeviceContext {
        DeviceContext {
            device_id: Some(device_id.to_string()),
            assurance: DeviceAssurance::Standard,
            secure_clipboard_available: true,
            screen_capture_protection_available: true,
            secure_temp_files_available: true,
        }
    }

    fn rotate_epoch_for_sync(
        conn: &mut VaultConnection,
        ctx: &CommitContext,
        device_id: &str,
    ) -> KeyEpochRotationResult {
        let session = conn.active_session().cloned().unwrap();
        let device = rotation_device(device_id);
        KeyEpochService::rotate_authorized(
            conn,
            ctx,
            TigaAuthorizationContext {
                session: Some(&session),
                device: &device,
                now_unix_secs: session.assurance.authenticated_at_unix_secs + 1,
            },
        )
        .unwrap()
    }

    fn create_key_epoch_sync_pair(label: &str) -> (PathBuf, PathBuf, String) {
        let source_path = temp_vault_path(&format!("{label}-source"));
        let target_path = temp_vault_path(&format!("{label}-target"));
        let base_project_id;
        {
            let mut source = VaultConnection::create(&source_path).unwrap();
            initialize_vault(
                &source,
                &VaultInitParams {
                    vault_id: Some(format!("{label}-vault")),
                    device_id: "device-a".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
            UnlockService::setup_password(&mut source, "epoch sync password").unwrap();
            let base = ProjectRepo::create(
                &source,
                &CommitContext::new("device-a".to_string()),
                "Base",
                None,
                None,
            )
            .unwrap();
            base_project_id = base.project_id;
            checkpoint(&source);
        }
        std::fs::copy(&source_path, &target_path).unwrap();
        (source_path, target_path, base_project_id)
    }

    fn checkpoint(conn: &VaultConnection) {
        conn.inner()
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
    }

    fn serialized_commits_from(conn: &VaultConnection) -> Vec<SerializedCommit> {
        let mut stmt = conn
            .inner()
            .prepare(
                "SELECT commit_id, device_id, local_seq, commit_kind, change_scope,
                        changed_object_ids_ct, vector_clock, message_ct, created_at, integrity_tag
                 FROM commits
                 ORDER BY created_at ASC, device_id ASC, local_seq ASC",
            )
            .unwrap();

        let rows = stmt
            .query_map([], |row| {
                let commit_id: String = row.get(0)?;
                Ok(SerializedCommit {
                    parent_ids: SyncApplyRepo::parent_ids_for_commit(conn, &commit_id).unwrap(),
                    tombstones: vec![],
                    object_payloads: vec![],
                    operation: operation_for_commit(conn, &commit_id).unwrap(),
                    commit: Commit {
                        commit_id,
                        device_id: row.get(1)?,
                        local_seq: row.get::<_, i64>(2)? as u64,
                        commit_kind: parse_commit_kind_for_test(&row.get::<_, String>(3)?),
                        change_scope: parse_change_scope_for_test(&row.get::<_, String>(4)?),
                        changed_object_ids_ct: row.get(5)?,
                        vector_clock: row.get(6)?,
                        message_ct: row.get(7)?,
                        created_at: row.get(8)?,
                        integrity_tag: row.get(9)?,
                    },
                })
            })
            .unwrap();

        rows.map(|row| row.unwrap()).collect()
    }

    fn parse_commit_kind_for_test(value: &str) -> CommitKind {
        match value {
            "merge" => CommitKind::Merge,
            "snapshot" => CommitKind::Snapshot,
            "key-rotation" => CommitKind::KeyRotation,
            _ => CommitKind::Change,
        }
    }

    fn parse_change_scope_for_test(value: &str) -> ChangeScope {
        match value {
            "project" => ChangeScope::Project,
            "entry" => ChangeScope::Entry,
            "attachment" => ChangeScope::Attachment,
            "object-relation" => ChangeScope::ObjectRelation,
            "object-label" => ChangeScope::ObjectLabel,
            "object-label-assignment" => ChangeScope::ObjectLabelAssignment,
            "vault-meta" => ChangeScope::VaultMeta,
            "key-epoch" => ChangeScope::KeyEpoch,
            _ => ChangeScope::Multi,
        }
    }

    fn operation_for_commit(
        conn: &VaultConnection,
        commit_id: &str,
    ) -> rusqlite::Result<Option<CommitOperationMetadata>> {
        conn.inner()
            .query_row(
                "SELECT operation_id, operation_kind, branch_id, branch_name,
                        change_summary_ct, request_hash, integrity_tag
                 FROM commit_operations WHERE commit_id = ?1",
                params![commit_id],
                |row| {
                    Ok(CommitOperationMetadata {
                        operation_id: row.get(0)?,
                        operation_kind: row.get(1)?,
                        branch_id: row.get(2)?,
                        branch_name: row.get(3)?,
                        change_summary_ct: row.get(4)?,
                        request_hash: row.get(5)?,
                        integrity_tag: row.get(6)?,
                    })
                },
            )
            .optional()
    }

    fn update_entry_payload(
        conn: &VaultConnection,
        ctx: &CommitContext,
        entry_id: &str,
        payload: serde_json::Value,
    ) -> mdbx_core::model::Entry {
        let mut entry = EntryRepo::get_by_id(conn, entry_id).unwrap().unwrap();
        entry.payload_ct = serde_json::to_vec(&payload).unwrap();
        EntryRepo::update(conn, ctx, &entry).unwrap()
    }

    fn update_project_for_test(
        conn: &VaultConnection,
        ctx: &CommitContext,
        project_id: &str,
        mutate: impl FnOnce(&mut mdbx_core::model::Project),
    ) -> mdbx_core::model::Project {
        let mut project = ProjectRepo::get_by_id(conn, project_id).unwrap().unwrap();
        mutate(&mut project);
        ProjectRepo::update(conn, ctx, &project).unwrap()
    }

    fn attach_state_payload_to_commit(
        conn: &VaultConnection,
        commits: &mut [SerializedCommit],
        commit_id: &str,
    ) {
        let payload = collect_sync_state_payload(conn).unwrap();
        commits
            .iter_mut()
            .find(|commit| commit.commit.commit_id == commit_id)
            .unwrap()
            .object_payloads
            .push(payload);
    }

    fn latest_delta_envelope_for_test(conn: &VaultConnection) -> SyncDeltaEnvelope {
        let batch_id: String = conn
            .inner()
            .query_row(
                "SELECT batch_id FROM sync_delta_batches ORDER BY batch_seq DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        load_sync_delta_envelope(conn, &batch_id, SyncDeltaLimits::default())
            .unwrap()
            .unwrap()
    }

    fn delta_envelope_for_commit_test(
        conn: &VaultConnection,
        commit_id: &str,
    ) -> SyncDeltaEnvelope {
        let batch_id: String = conn
            .inner()
            .query_row(
                "SELECT b.batch_id
                 FROM sync_delta_batches b
                 JOIN sync_delta_batch_commits bc ON bc.batch_id = b.batch_id
                 WHERE bc.commit_id = ?1
                 ORDER BY b.batch_seq DESC LIMIT 1",
                [commit_id],
                |row| row.get(0),
            )
            .unwrap();
        load_sync_delta_envelope(conn, &batch_id, SyncDeltaLimits::default())
            .unwrap()
            .unwrap()
    }

    fn attach_delta_payload_to_commits(
        conn: &VaultConnection,
        commits: &mut [SerializedCommit],
        envelope: &SyncDeltaEnvelope,
    ) {
        let commit_id = envelope.commit_ids.last().unwrap();
        let payload = sync_delta_object_payload(envelope, SyncDeltaLimits::default()).unwrap();
        commits
            .iter_mut()
            .find(|commit| &commit.commit.commit_id == commit_id)
            .unwrap()
            .object_payloads
            .push(payload);
        envelope.verify(conn, SyncDeltaLimits::default()).unwrap();
    }

    fn rebuild_delta_envelope(
        conn: &VaultConnection,
        template: &SyncDeltaEnvelope,
        batch_id: &str,
        batch_kind: SyncDeltaBatchKind,
        commit_ids: Vec<String>,
        body: &SyncDeltaBody,
    ) -> SyncDeltaEnvelope {
        let logical_row_count = body
            .state
            .total_rows()
            .unwrap()
            .checked_add(body.device_heads.len())
            .and_then(|count| count.checked_add(body.deletions.len()))
            .unwrap();
        SyncDeltaEnvelope::new(
            conn,
            NewSyncDeltaEnvelope {
                batch_id: batch_id.to_string(),
                batch_kind,
                commit_ids,
                logical_row_count: u32::try_from(logical_row_count).unwrap(),
                payload: serde_json::to_vec(body).unwrap(),
                created_at: template.created_at.clone(),
            },
            SyncDeltaLimits::default(),
        )
        .unwrap()
    }

    fn attach_tombstones_to_commit(
        conn: &VaultConnection,
        commits: &mut [SerializedCommit],
        commit_id: &str,
    ) {
        let mut stmt = conn
            .inner()
            .prepare(
                "SELECT tombstone_id, target_object_type, target_object_id,
                        delete_clock, deleted_by_device_id, deleted_at
                 FROM tombstones",
            )
            .unwrap();
        let tombstones = stmt
            .query_map([], |row| {
                Ok(TombstoneRecord {
                    tombstone_id: row.get(0)?,
                    target_object_type: row.get(1)?,
                    target_object_id: row.get(2)?,
                    delete_clock: row.get(3)?,
                    deleted_by_device_id: row.get(4)?,
                    deleted_at: row.get(5)?,
                })
            })
            .unwrap()
            .map(|row| row.unwrap())
            .collect::<Vec<_>>();

        commits
            .iter_mut()
            .find(|commit| commit.commit.commit_id == commit_id)
            .unwrap()
            .tombstones
            .extend(tombstones);
    }

    fn entry_payload_json(conn: &VaultConnection, entry_id: &str) -> serde_json::Value {
        let entry = EntryRepo::get_by_id(conn, entry_id).unwrap().unwrap();
        serde_json::from_slice(&entry.payload_ct).unwrap()
    }

    fn entry_tombstone_count(conn: &VaultConnection, entry_id: &str) -> i64 {
        conn.inner()
            .query_row(
                "SELECT COUNT(*) FROM tombstones
                 WHERE target_object_type = 'entry' AND target_object_id = ?1",
                params![entry_id],
                |row| row.get(0),
            )
            .unwrap()
    }

    #[test]
    fn sync_delta_apply_fast_forward_converges_and_persists_received_batch() {
        let source_path = temp_vault_path("delta-apply-ff-source");
        let target_path = temp_vault_path("delta-apply-ff-target");
        let project_id;
        {
            let source = VaultConnection::create(&source_path).unwrap();
            initialize_vault(
                &source,
                &VaultInitParams {
                    vault_id: Some("delta-apply-ff-vault".to_string()),
                    device_id: "device-a".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
            project_id = ProjectRepo::create(
                &source,
                &CommitContext::new("device-a".to_string()),
                "Before",
                None,
                None,
            )
            .unwrap()
            .project_id;
            checkpoint(&source);
        }
        std::fs::copy(&source_path, &target_path).unwrap();

        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        update_project_for_test(
            &source,
            &CommitContext::new("device-a".to_string()),
            &project_id,
            |project| project.icon_ref = Some("mail".to_string()),
        );
        let envelope = latest_delta_envelope_for_test(&source);
        let mut commits = serialized_commits_from(&source)
            .into_iter()
            .filter(|commit| {
                !SyncApplyRepo::commit_exists(&target, &commit.commit.commit_id).unwrap()
            })
            .collect::<Vec<_>>();
        attach_delta_payload_to_commits(&source, &mut commits, &envelope);

        let result = SyncApplyRepo::apply_batch(
            &target,
            &CommitContext::new("device-b".to_string()),
            &CommitBatch {
                batch_index: 0,
                commits,
                is_last: true,
            },
        )
        .unwrap();
        assert_eq!(result.applied_commits, 1);
        assert_eq!(result.conflict_count, 0);
        let applied = ProjectRepo::get_by_id(&target, &project_id)
            .unwrap()
            .unwrap();
        assert_eq!(applied.icon_ref.as_deref(), Some("mail"));
        assert!(
            load_sync_delta_envelope(&target, &envelope.batch_id, SyncDeltaLimits::default())
                .unwrap()
                .is_some()
        );
        let pending: i64 = target
            .inner()
            .query_row("SELECT COUNT(*) FROM sync_delta_mutations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(pending, 0);

        drop(source);
        drop(target);
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn sync_delta_apply_tamper_rolls_back_commit_state_and_batch() {
        let source_path = temp_vault_path("delta-apply-tamper-source");
        let target_path = temp_vault_path("delta-apply-tamper-target");
        let project_id;
        {
            let source = VaultConnection::create(&source_path).unwrap();
            initialize_vault(
                &source,
                &VaultInitParams {
                    vault_id: Some("delta-apply-tamper-vault".to_string()),
                    device_id: "device-a".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
            project_id = ProjectRepo::create(
                &source,
                &CommitContext::new("device-a".to_string()),
                "Before",
                None,
                None,
            )
            .unwrap()
            .project_id;
            checkpoint(&source);
        }
        std::fs::copy(&source_path, &target_path).unwrap();

        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        let updated = update_project_for_test(
            &source,
            &CommitContext::new("device-a".to_string()),
            &project_id,
            |project| project.icon_ref = Some("tampered".to_string()),
        );
        let envelope = latest_delta_envelope_for_test(&source);
        let mut commits = serialized_commits_from(&source)
            .into_iter()
            .filter(|commit| {
                !SyncApplyRepo::commit_exists(&target, &commit.commit.commit_id).unwrap()
            })
            .collect::<Vec<_>>();
        attach_delta_payload_to_commits(&source, &mut commits, &envelope);
        let payload = &mut commits[0].object_payloads[0];
        let last = payload.ciphertext.len() - 1;
        payload.ciphertext[last] ^= 1;

        let error = SyncApplyRepo::apply_batch(
            &target,
            &CommitContext::new("device-b".to_string()),
            &CommitBatch {
                batch_index: 0,
                commits,
                is_last: true,
            },
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("schema creation failed")
                || error.to_string().contains("digest mismatch")
        );
        assert!(!SyncApplyRepo::commit_exists(&target, &updated.head_commit_id).unwrap());
        assert_eq!(
            ProjectRepo::get_by_id(&target, &project_id)
                .unwrap()
                .unwrap()
                .icon_ref,
            None
        );
        assert!(
            load_sync_delta_envelope(&target, &envelope.batch_id, SyncDeltaLimits::default())
                .unwrap()
                .is_none()
        );

        drop(source);
        drop(target);
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn sync_delta_apply_divergence_preserves_local_merge_delta() {
        let (source_path, target_path, project_id) =
            create_project_divergence("delta-apply-divergent");
        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        update_project_for_test(
            &source,
            &CommitContext::new("device-a".to_string()),
            &project_id,
            |project| project.icon_ref = Some("remote-icon".to_string()),
        );
        update_project_for_test(
            &target,
            &CommitContext::new("device-b".to_string()),
            &project_id,
            |project| project.group_id = Some("local-group".to_string()),
        );
        let envelope = latest_delta_envelope_for_test(&source);
        let mut commits = serialized_commits_from(&source)
            .into_iter()
            .filter(|commit| {
                !SyncApplyRepo::commit_exists(&target, &commit.commit.commit_id).unwrap()
            })
            .collect::<Vec<_>>();
        attach_delta_payload_to_commits(&source, &mut commits, &envelope);

        let result = SyncApplyRepo::apply_batch(
            &target,
            &CommitContext::new("device-b".to_string()),
            &CommitBatch {
                batch_index: 0,
                commits,
                is_last: true,
            },
        )
        .unwrap();
        assert_eq!(result.applied_commits, 1);
        assert_eq!(result.conflict_count, 0);
        let merged = ProjectRepo::get_by_id(&target, &project_id)
            .unwrap()
            .unwrap();
        assert_eq!(merged.icon_ref.as_deref(), Some("remote-icon"));
        assert_eq!(merged.group_id.as_deref(), Some("local-group"));
        let merge_delta_count: i64 = target
            .inner()
            .query_row(
                "SELECT COUNT(*)
                 FROM sync_delta_batch_commits bc
                 JOIN commits c ON c.commit_id = bc.commit_id
                 WHERE c.commit_kind = 'merge'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(merge_delta_count >= 1);
        assert!(
            load_sync_delta_envelope(&target, &envelope.batch_id, SyncDeltaLimits::default())
                .unwrap()
                .is_some()
        );

        drop(source);
        drop(target);
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn sync_delta_apply_auxiliary_audit_is_atomic_and_idempotent() {
        let source_path = temp_vault_path("delta-apply-aux-source");
        let target_path = temp_vault_path("delta-apply-aux-target");
        {
            let source = VaultConnection::create(&source_path).unwrap();
            initialize_vault(
                &source,
                &VaultInitParams {
                    vault_id: Some("delta-apply-aux-vault".to_string()),
                    device_id: "device-a".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
            checkpoint(&source);
        }
        std::fs::copy(&source_path, &target_path).unwrap();
        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        source
            .with_immediate_transaction(|| {
                source.inner().execute(
                    "INSERT INTO security_audit_events
                        (event_id, occurred_at, operation, outcome, scope_type, scope_id,
                         reason_codes_json, constraints_json)
                     VALUES ('remote-aux-audit', '2026-07-20T00:00:00Z',
                             'copy-secret', 'deny', 'vault', '', '[]', '[]')",
                    [],
                )?;
                Ok(())
            })
            .unwrap();
        let envelope = latest_delta_envelope_for_test(&source);
        assert_eq!(envelope.batch_kind, SyncDeltaBatchKind::Auxiliary);

        let ctx = CommitContext::new("device-b".to_string());
        assert_eq!(
            SyncApplyRepo::apply_auxiliary_delta(&target, &ctx, &envelope).unwrap(),
            0
        );
        assert_eq!(
            SyncApplyRepo::apply_auxiliary_delta(&target, &ctx, &envelope).unwrap(),
            0
        );
        let event_count: i64 = target
            .inner()
            .query_row(
                "SELECT COUNT(*) FROM security_audit_events
                 WHERE event_id = 'remote-aux-audit'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(event_count, 1);
        let batch_count: i64 = target
            .inner()
            .query_row(
                "SELECT COUNT(*) FROM sync_delta_batches WHERE batch_id = ?1",
                [&envelope.batch_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(batch_count, 1);

        drop(source);
        drop(target);
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn incremental_segment_rolls_back_commits_when_auxiliary_decode_fails() {
        let source_path = temp_vault_path("incremental-atomic-source");
        let target_path = temp_vault_path("incremental-atomic-target");
        {
            let source = VaultConnection::create(&source_path).unwrap();
            initialize_vault(
                &source,
                &VaultInitParams {
                    vault_id: Some("incremental-atomic-vault".to_string()),
                    device_id: "device-a".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
            checkpoint(&source);
        }
        std::fs::copy(&source_path, &target_path).unwrap();

        let source = VaultConnection::open(&source_path).unwrap();
        let project = ProjectRepo::create(
            &source,
            &CommitContext::new("device-a".to_string()),
            "Atomic project",
            None,
            None,
        )
        .unwrap();
        let commit_envelope = latest_delta_envelope_for_test(&source);
        let mut commits = serialized_commits_from(&source)
            .into_iter()
            .filter(|commit| commit.commit.commit_id == project.head_commit_id)
            .collect::<Vec<_>>();
        attach_delta_payload_to_commits(&source, &mut commits, &commit_envelope);
        let malformed_auxiliary = crate::sync_delta::SyncDeltaEnvelope::new(
            &source,
            crate::sync_delta::NewSyncDeltaEnvelope {
                batch_id: "malformed-auxiliary".to_string(),
                batch_kind: SyncDeltaBatchKind::Auxiliary,
                commit_ids: Vec::new(),
                logical_row_count: 0,
                payload: b"not-a-sync-delta-body".to_vec(),
                created_at: "2026-07-21T00:00:00Z".to_string(),
            },
            SyncDeltaLimits::default(),
        )
        .unwrap();

        let mut target = VaultConnection::open(&target_path).unwrap();
        let error = SyncApplyRepo::apply_incremental_batch_mut(
            &mut target,
            &CommitContext::new("device-b".to_string()),
            &CommitBatch::new(commits, 0, true),
            &[malformed_auxiliary],
        )
        .unwrap_err();
        assert!(error.to_string().contains("schema creation failed"));
        assert!(!SyncApplyRepo::commit_exists(&target, &project.head_commit_id).unwrap());
        assert!(ProjectRepo::get_by_id(&target, &project.project_id)
            .unwrap()
            .is_none());
        assert!(load_sync_delta_envelope(
            &target,
            &commit_envelope.batch_id,
            SyncDeltaLimits::default()
        )
        .unwrap()
        .is_none());

        drop(source);
        drop(target);
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn sync_delta_apply_auxiliary_metadata_deletion_converges() {
        let source_path = temp_vault_path("delta-apply-delete-source");
        let target_path = temp_vault_path("delta-apply-delete-target");
        {
            let source = VaultConnection::create(&source_path).unwrap();
            initialize_vault(
                &source,
                &VaultInitParams {
                    vault_id: Some("delta-apply-delete-vault".to_string()),
                    device_id: "device-a".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
            source
                .with_immediate_transaction(|| {
                    source.inner().execute(
                        "INSERT INTO tiga_policy_overrides
                            (scope_type, scope_id, policy_json, updated_at,
                             updated_by_device_id)
                         VALUES ('vault', '', '{}', '2026-07-20T00:00:00Z', 'device-a')",
                        [],
                    )?;
                    Ok(())
                })
                .unwrap();
            checkpoint(&source);
        }
        std::fs::copy(&source_path, &target_path).unwrap();
        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        source
            .with_immediate_transaction(|| {
                source.inner().execute(
                    "DELETE FROM tiga_policy_overrides
                     WHERE scope_type = 'vault' AND scope_id = ''",
                    [],
                )?;
                Ok(())
            })
            .unwrap();
        let envelope = latest_delta_envelope_for_test(&source);

        SyncApplyRepo::apply_auxiliary_delta(
            &target,
            &CommitContext::new("device-b".to_string()),
            &envelope,
        )
        .unwrap();
        let remaining: i64 = target
            .inner()
            .query_row("SELECT COUNT(*) FROM tiga_policy_overrides", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(remaining, 0);

        drop(source);
        drop(target);
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn sync_delta_apply_late_payload_repairs_an_existing_commit() {
        let source_path = temp_vault_path("delta-apply-late-source");
        let target_path = temp_vault_path("delta-apply-late-target");
        let project_id;
        {
            let source = VaultConnection::create(&source_path).unwrap();
            initialize_vault(
                &source,
                &VaultInitParams {
                    vault_id: Some("delta-apply-late-vault".to_string()),
                    device_id: "device-a".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
            project_id = ProjectRepo::create(
                &source,
                &CommitContext::new("device-a".to_string()),
                "Before",
                None,
                None,
            )
            .unwrap()
            .project_id;
            checkpoint(&source);
        }
        std::fs::copy(&source_path, &target_path).unwrap();
        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        update_project_for_test(
            &source,
            &CommitContext::new("device-a".to_string()),
            &project_id,
            |project| project.icon_ref = Some("late".to_string()),
        );
        let envelope = latest_delta_envelope_for_test(&source);
        let mut commit = serialized_commits_from(&source)
            .into_iter()
            .find(|commit| commit.commit.commit_id == *envelope.commit_ids.last().unwrap())
            .unwrap();
        let commit_without_delta = commit.clone();
        let ctx = CommitContext::new("device-b".to_string());
        SyncApplyRepo::apply_batch(
            &target,
            &ctx,
            &CommitBatch {
                batch_index: 0,
                commits: vec![commit_without_delta],
                is_last: true,
            },
        )
        .unwrap();
        assert_eq!(
            ProjectRepo::get_by_id(&target, &project_id)
                .unwrap()
                .unwrap()
                .icon_ref,
            None
        );

        commit
            .object_payloads
            .push(sync_delta_object_payload(&envelope, SyncDeltaLimits::default()).unwrap());
        let result = SyncApplyRepo::apply_batch(
            &target,
            &ctx,
            &CommitBatch {
                batch_index: 1,
                commits: vec![commit],
                is_last: true,
            },
        )
        .unwrap();
        assert_eq!(result.skipped_commits, 1);
        assert_eq!(
            ProjectRepo::get_by_id(&target, &project_id)
                .unwrap()
                .unwrap()
                .icon_ref
                .as_deref(),
            Some("late")
        );
        assert!(
            load_sync_delta_envelope(&target, &envelope.batch_id, SyncDeltaLimits::default())
                .unwrap()
                .is_some()
        );

        drop(source);
        drop(target);
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn sync_delta_apply_replaces_attachment_chunks_atomically() {
        let (source_path, target_path, attachment_id) =
            create_attachment_divergence("delta-apply-attachment");
        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        AttachmentRepo::write_inline_content(
            &source,
            &CommitContext::new("device-a".to_string()),
            &attachment_id,
            b"delta replacement content",
        )
        .unwrap();
        let envelope = latest_delta_envelope_for_test(&source);
        let mut commits = serialized_commits_from(&source)
            .into_iter()
            .filter(|commit| {
                !SyncApplyRepo::commit_exists(&target, &commit.commit.commit_id).unwrap()
            })
            .collect::<Vec<_>>();
        attach_delta_payload_to_commits(&source, &mut commits, &envelope);

        SyncApplyRepo::apply_batch(
            &target,
            &CommitContext::new("device-b".to_string()),
            &CommitBatch {
                batch_index: 0,
                commits,
                is_last: true,
            },
        )
        .unwrap();
        assert_eq!(
            AttachmentRepo::read_content(&target, &attachment_id).unwrap(),
            b"delta replacement content"
        );
        let chunk_count: i64 = target
            .inner()
            .query_row(
                "SELECT COUNT(*) FROM attachment_chunks WHERE attachment_id = ?1",
                [&attachment_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(chunk_count, 1);

        drop(source);
        drop(target);
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn sync_delta_apply_mutable_refreshes_rotated_key_epoch() {
        let (source_path, target_path, _) = create_key_epoch_sync_pair("delta-apply-key-epoch");
        let mut source = VaultConnection::open(&source_path).unwrap();
        let mut target = VaultConnection::open(&target_path).unwrap();
        UnlockService::unlock_with_password(&mut source, "epoch sync password").unwrap();
        UnlockService::unlock_with_password(&mut target, "epoch sync password").unwrap();
        let rotation = rotate_epoch_for_sync(
            &mut source,
            &CommitContext::new("device-a".to_string()),
            "device-a",
        );
        let envelope = delta_envelope_for_commit_test(&source, &rotation.commit_id);
        let mut commit = serialized_commits_from(&source)
            .into_iter()
            .find(|commit| commit.commit.commit_id == rotation.commit_id)
            .unwrap();
        commit
            .object_payloads
            .push(sync_delta_object_payload(&envelope, SyncDeltaLimits::default()).unwrap());

        SyncApplyRepo::apply_batch_mut(
            &mut target,
            &CommitContext::new("device-b".to_string()),
            &CommitBatch::new(vec![commit], 0, true),
        )
        .unwrap();
        assert_eq!(
            target.active_key_epoch_id(),
            Some(rotation.active_epoch_id.as_str())
        );
        assert!(target
            .keyring_for_epoch(&rotation.previous_epoch_id)
            .is_some());
        assert!(target
            .keyring_for_epoch(&rotation.active_epoch_id)
            .is_some());

        drop(source);
        drop(target);
        remove_vault_files(&source_path);
        remove_vault_files(&target_path);
    }

    #[test]
    fn sync_delta_apply_immutable_rejects_key_epoch_changes_atomically() {
        let (source_path, target_path, _) =
            create_key_epoch_sync_pair("delta-apply-key-epoch-immutable");
        let mut source = VaultConnection::open(&source_path).unwrap();
        let mut target = VaultConnection::open(&target_path).unwrap();
        UnlockService::unlock_with_password(&mut source, "epoch sync password").unwrap();
        UnlockService::unlock_with_password(&mut target, "epoch sync password").unwrap();
        let original_epoch_id = target.active_key_epoch_id().unwrap().to_string();
        let rotation = rotate_epoch_for_sync(
            &mut source,
            &CommitContext::new("device-a".to_string()),
            "device-a",
        );
        let envelope = delta_envelope_for_commit_test(&source, &rotation.commit_id);
        let mut commit = serialized_commits_from(&source)
            .into_iter()
            .find(|commit| commit.commit.commit_id == rotation.commit_id)
            .unwrap();
        commit
            .object_payloads
            .push(sync_delta_object_payload(&envelope, SyncDeltaLimits::default()).unwrap());

        let error = SyncApplyRepo::apply_batch(
            &target,
            &CommitContext::new("device-b".to_string()),
            &CommitBatch::new(vec![commit], 0, true),
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("key epoch changes require mutable sync apply"));
        assert_eq!(
            target.active_key_epoch_id(),
            Some(original_epoch_id.as_str())
        );
        assert!(!SyncApplyRepo::commit_exists(&target, &rotation.commit_id).unwrap());
        assert!(
            load_sync_delta_envelope(&target, &envelope.batch_id, SyncDeltaLimits::default())
                .unwrap()
                .is_none()
        );

        drop(source);
        drop(target);
        remove_vault_files(&source_path);
        remove_vault_files(&target_path);
    }

    #[test]
    fn sync_delta_apply_rejects_missing_commit_association_atomically() {
        let (source_path, target_path, project_id) =
            create_project_divergence("delta-apply-missing-association");
        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        let updated = update_project_for_test(
            &source,
            &CommitContext::new("device-a".to_string()),
            &project_id,
            |project| project.icon_ref = Some("must-rollback".to_string()),
        );
        let template = latest_delta_envelope_for_test(&source);
        let body = decode_sync_delta_body(&template, SyncDeltaLimits::default()).unwrap();
        let envelope = rebuild_delta_envelope(
            &source,
            &template,
            "delta-missing-associated-commit",
            SyncDeltaBatchKind::Commit,
            vec![
                "missing-associated-commit".to_string(),
                updated.head_commit_id.clone(),
            ],
            &body,
        );
        let mut commit = serialized_commits_from(&source)
            .into_iter()
            .find(|commit| commit.commit.commit_id == updated.head_commit_id)
            .unwrap();
        commit
            .object_payloads
            .push(sync_delta_object_payload(&envelope, SyncDeltaLimits::default()).unwrap());

        let error = SyncApplyRepo::apply_batch(
            &target,
            &CommitContext::new("device-b".to_string()),
            &CommitBatch::new(vec![commit], 0, true),
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("references unavailable commit missing-associated-commit"));
        assert!(!SyncApplyRepo::commit_exists(&target, &updated.head_commit_id).unwrap());
        assert_eq!(
            ProjectRepo::get_by_id(&target, &project_id)
                .unwrap()
                .unwrap()
                .icon_ref,
            None
        );
        assert!(
            load_sync_delta_envelope(&target, &envelope.batch_id, SyncDeltaLimits::default())
                .unwrap()
                .is_none()
        );

        drop(source);
        drop(target);
        remove_vault_files(&source_path);
        remove_vault_files(&target_path);
    }

    #[test]
    fn sync_delta_apply_rejects_row_count_mismatch_atomically() {
        let (source_path, target_path, project_id) =
            create_project_divergence("delta-apply-row-mismatch");
        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        let updated = update_project_for_test(
            &source,
            &CommitContext::new("device-a".to_string()),
            &project_id,
            |project| project.icon_ref = Some("invalid-row-count".to_string()),
        );
        let mut envelope = latest_delta_envelope_for_test(&source);
        envelope.logical_row_count += 1;
        let mut commit = serialized_commits_from(&source)
            .into_iter()
            .find(|commit| commit.commit.commit_id == updated.head_commit_id)
            .unwrap();
        commit
            .object_payloads
            .push(sync_delta_object_payload(&envelope, SyncDeltaLimits::default()).unwrap());

        let error = SyncApplyRepo::apply_batch(
            &target,
            &CommitContext::new("device-b".to_string()),
            &CommitBatch::new(vec![commit], 0, true),
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("sync delta logical row count mismatch"));
        assert!(!SyncApplyRepo::commit_exists(&target, &updated.head_commit_id).unwrap());
        assert_eq!(
            ProjectRepo::get_by_id(&target, &project_id)
                .unwrap()
                .unwrap()
                .icon_ref,
            None
        );

        drop(source);
        drop(target);
        remove_vault_files(&source_path);
        remove_vault_files(&target_path);
    }

    #[test]
    fn sync_delta_apply_rejects_foreign_vault_atomically() {
        let (source_path, target_path, project_id) =
            create_project_divergence("delta-apply-foreign-vault");
        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        let updated = update_project_for_test(
            &source,
            &CommitContext::new("device-a".to_string()),
            &project_id,
            |project| project.icon_ref = Some("foreign".to_string()),
        );
        let envelope = latest_delta_envelope_for_test(&source);
        target
            .inner()
            .execute("UPDATE vault_meta SET vault_id = 'different-vault-id'", [])
            .unwrap();
        let mut commit = serialized_commits_from(&source)
            .into_iter()
            .find(|commit| commit.commit.commit_id == updated.head_commit_id)
            .unwrap();
        commit
            .object_payloads
            .push(sync_delta_object_payload(&envelope, SyncDeltaLimits::default()).unwrap());

        let error = SyncApplyRepo::apply_batch(
            &target,
            &CommitContext::new("device-b".to_string()),
            &CommitBatch::new(vec![commit], 0, true),
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("sync delta belongs to a different vault"));
        assert!(!SyncApplyRepo::commit_exists(&target, &updated.head_commit_id).unwrap());
        assert_eq!(
            ProjectRepo::get_by_id(&target, &project_id)
                .unwrap()
                .unwrap()
                .icon_ref,
            None
        );

        drop(source);
        drop(target);
        remove_vault_files(&source_path);
        remove_vault_files(&target_path);
    }

    #[test]
    fn sync_delta_apply_auxiliary_limit_rejects_before_writing() {
        let source_path = temp_vault_path("delta-apply-limit-source");
        let target_path = temp_vault_path("delta-apply-limit-target");
        {
            let source = VaultConnection::create(&source_path).unwrap();
            initialize_vault(
                &source,
                &VaultInitParams {
                    vault_id: Some("delta-apply-limit-vault".to_string()),
                    device_id: "device-a".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
            checkpoint(&source);
        }
        std::fs::copy(&source_path, &target_path).unwrap();
        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        source
            .with_immediate_transaction(|| {
                for event_id in ["limited-incoming-a", "limited-incoming-b"] {
                    source.inner().execute(
                        "INSERT INTO security_audit_events
                            (event_id, occurred_at, operation, outcome, scope_type, scope_id,
                             reason_codes_json, constraints_json)
                         VALUES (?1, '2026-07-20T00:00:00Z', 'copy-secret', 'deny',
                                 'vault', '', '[]', '[]')",
                        [event_id],
                    )?;
                }
                Ok(())
            })
            .unwrap();
        let envelope = latest_delta_envelope_for_test(&source);
        let defaults = SyncDeltaLimits::default();
        let limits =
            SyncDeltaLimits::new(defaults.max_payload_bytes(), 1, defaults.max_commits()).unwrap();

        let error = SyncApplyRepo::apply_auxiliary_delta_with_limits(
            &target,
            &CommitContext::new("device-b".to_string()),
            &envelope,
            limits,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            StorageError::ResourceLimit { resource, .. } if resource == "sync delta rows"
        ));
        let event_count: i64 = target
            .inner()
            .query_row(
                "SELECT COUNT(*) FROM security_audit_events
                 WHERE event_id IN ('limited-incoming-a', 'limited-incoming-b')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(event_count, 0);
        assert!(
            load_sync_delta_envelope(&target, &envelope.batch_id, SyncDeltaLimits::default())
                .unwrap()
                .is_none()
        );

        drop(source);
        drop(target);
        remove_vault_files(&source_path);
        remove_vault_files(&target_path);
    }

    #[test]
    fn sync_delta_apply_rejects_reused_batch_id_with_different_content() {
        let (source_path, target_path, project_id) =
            create_project_divergence("delta-apply-batch-id-conflict");
        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        let updated = update_project_for_test(
            &source,
            &CommitContext::new("device-a".to_string()),
            &project_id,
            |project| project.icon_ref = Some("accepted".to_string()),
        );
        let envelope = latest_delta_envelope_for_test(&source);
        let mut commit = serialized_commits_from(&source)
            .into_iter()
            .find(|commit| commit.commit.commit_id == updated.head_commit_id)
            .unwrap();
        commit
            .object_payloads
            .push(sync_delta_object_payload(&envelope, SyncDeltaLimits::default()).unwrap());
        let ctx = CommitContext::new("device-b".to_string());
        SyncApplyRepo::apply_batch(
            &target,
            &ctx,
            &CommitBatch::new(vec![commit.clone()], 0, true),
        )
        .unwrap();

        let mut conflicting = envelope.clone();
        conflicting.created_at = "2026-07-20T23:59:59Z".to_string();
        commit.object_payloads.clear();
        commit
            .object_payloads
            .push(sync_delta_object_payload(&conflicting, SyncDeltaLimits::default()).unwrap());
        let error =
            SyncApplyRepo::apply_batch(&target, &ctx, &CommitBatch::new(vec![commit], 1, true))
                .unwrap_err();
        assert!(error.to_string().contains("conflicts with stored content"));
        let stored =
            load_sync_delta_envelope(&target, &envelope.batch_id, SyncDeltaLimits::default())
                .unwrap()
                .unwrap();
        assert_eq!(stored, envelope);

        drop(source);
        drop(target);
        remove_vault_files(&source_path);
        remove_vault_files(&target_path);
    }

    #[test]
    fn sync_delta_apply_sparse_tombstones_preserve_unrelated_local_rows() {
        let source_path = temp_vault_path("delta-apply-sparse-tombstone-source");
        let target_path = temp_vault_path("delta-apply-sparse-tombstone-target");
        {
            let source = VaultConnection::create(&source_path).unwrap();
            initialize_vault(
                &source,
                &VaultInitParams {
                    vault_id: Some("delta-apply-sparse-tombstone-vault".to_string()),
                    device_id: "device-a".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
            checkpoint(&source);
        }
        std::fs::copy(&source_path, &target_path).unwrap();
        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        source
            .with_immediate_transaction(|| {
                source.inner().execute(
                    "INSERT INTO tombstones
                        (tombstone_id, target_object_type, target_object_id, delete_clock,
                         deleted_by_device_id, deleted_at, purge_eligible_at, delete_commit_id)
                     VALUES ('remote-tombstone', 'entry', 'remote-entry', '{}',
                             'device-a', '2026-07-20T01:00:00Z', NULL, NULL)",
                    [],
                )?;
                Ok(())
            })
            .unwrap();
        target
            .with_immediate_transaction(|| {
                target.inner().execute(
                    "INSERT INTO tombstones
                        (tombstone_id, target_object_type, target_object_id, delete_clock,
                         deleted_by_device_id, deleted_at, purge_eligible_at, delete_commit_id)
                     VALUES ('local-tombstone', 'entry', 'local-entry', '{}',
                             'device-b', '2026-07-20T00:00:00Z', NULL, NULL)",
                    [],
                )?;
                Ok(())
            })
            .unwrap();
        let envelope = latest_delta_envelope_for_test(&source);

        SyncApplyRepo::apply_auxiliary_delta(
            &target,
            &CommitContext::new("device-b".to_string()),
            &envelope,
        )
        .unwrap();
        let tombstone_ids = TombstoneRepo::list_all(&target)
            .unwrap()
            .into_iter()
            .map(|row| row.tombstone_id)
            .collect::<HashSet<_>>();
        assert!(tombstone_ids.contains("local-tombstone"));
        assert!(tombstone_ids.contains("remote-tombstone"));

        drop(source);
        drop(target);
        remove_vault_files(&source_path);
        remove_vault_files(&target_path);
    }

    #[test]
    fn sync_delta_apply_device_revocation_is_monotonic() {
        let source_path = temp_vault_path("delta-apply-device-head-source");
        let target_path = temp_vault_path("delta-apply-device-head-target");
        {
            let source = VaultConnection::create(&source_path).unwrap();
            initialize_vault(
                &source,
                &VaultInitParams {
                    vault_id: Some("delta-apply-device-head-vault".to_string()),
                    device_id: "device-a".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
            checkpoint(&source);
        }
        std::fs::copy(&source_path, &target_path).unwrap();
        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        source
            .with_immediate_transaction(|| {
                source.inner().execute(
                    "UPDATE device_heads SET last_seen_at = '2026-07-20T02:00:00Z', revoked = 0
                     WHERE device_id = 'device-a'",
                    [],
                )?;
                Ok(())
            })
            .unwrap();
        target
            .with_immediate_transaction(|| {
                target.inner().execute(
                    "UPDATE device_heads SET last_seen_at = '2026-07-20T01:00:00Z', revoked = 1
                     WHERE device_id = 'device-a'",
                    [],
                )?;
                Ok(())
            })
            .unwrap();
        let envelope = latest_delta_envelope_for_test(&source);

        SyncApplyRepo::apply_auxiliary_delta(
            &target,
            &CommitContext::new("device-b".to_string()),
            &envelope,
        )
        .unwrap();
        let stored: (String, bool) = target
            .inner()
            .query_row(
                "SELECT last_seen_at, revoked FROM device_heads WHERE device_id = 'device-a'",
                [],
                |row| Ok((row.get(0)?, row.get::<_, i32>(1)? != 0)),
            )
            .unwrap();
        assert_eq!(stored.0, "2026-07-20T02:00:00Z");
        assert!(stored.1);

        drop(source);
        drop(target);
        remove_vault_files(&source_path);
        remove_vault_files(&target_path);
    }

    #[test]
    fn sync_delta_apply_rejects_physical_deletion_without_purge_receipt() {
        let (source_path, target_path, project_id) =
            create_project_divergence("delta-apply-unauthorized-delete");
        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        let template = latest_delta_envelope_for_test(&source);
        let mut body = decode_sync_delta_body(&template, SyncDeltaLimits::default()).unwrap();
        body.deletions.push(DeletedSyncEntity {
            entity_kind: "project".to_string(),
            entity_id: project_id.clone(),
        });
        let envelope = rebuild_delta_envelope(
            &source,
            &template,
            "delta-unauthorized-physical-delete",
            SyncDeltaBatchKind::Auxiliary,
            vec![],
            &body,
        );

        let error = SyncApplyRepo::apply_auxiliary_delta(
            &target,
            &CommitContext::new("device-b".to_string()),
            &envelope,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("physical project deletion lacks a matching purge receipt"));
        assert!(ProjectRepo::get_by_id(&target, &project_id)
            .unwrap()
            .is_some());
        assert!(
            load_sync_delta_envelope(&target, &envelope.batch_id, SyncDeltaLimits::default())
                .unwrap()
                .is_none()
        );

        drop(source);
        drop(target);
        remove_vault_files(&source_path);
        remove_vault_files(&target_path);
    }

    fn create_project_divergence(label: &str) -> (PathBuf, PathBuf, String) {
        let source_path = temp_vault_path(&format!("{}-source", label));
        let target_path = temp_vault_path(&format!("{}-target", label));
        let project_id;

        {
            let source = VaultConnection::create(&source_path).unwrap();
            initialize_vault(
                &source,
                &VaultInitParams {
                    vault_id: Some(format!("{}-vault", label)),
                    device_id: "device-a".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
            let source_ctx = CommitContext::new("device-a".to_string());
            let project =
                ProjectRepo::create(&source, &source_ctx, "P", Some("base"), None).unwrap();
            project_id = project.project_id.clone();
            checkpoint(&source);
        }
        std::fs::copy(&source_path, &target_path).unwrap();
        (source_path, target_path, project_id)
    }

    fn create_attachment_divergence(label: &str) -> (PathBuf, PathBuf, String) {
        let source_path = temp_vault_path(&format!("{}-source", label));
        let target_path = temp_vault_path(&format!("{}-target", label));
        let attachment_id;

        {
            let source = VaultConnection::create(&source_path).unwrap();
            initialize_vault(
                &source,
                &VaultInitParams {
                    vault_id: Some(format!("{}-vault", label)),
                    device_id: "device-a".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
            let source_ctx = CommitContext::new("device-a".to_string());
            let project = ProjectRepo::create(&source, &source_ctx, "P", None, None).unwrap();
            let attachment = AttachmentRepo::add(
                &source,
                &source_ctx,
                &project.project_id,
                None,
                "base.txt",
                Some("text/plain"),
                "",
                0,
            )
            .unwrap();
            AttachmentRepo::write_inline_content(
                &source,
                &source_ctx,
                &attachment.attachment_id,
                b"base content",
            )
            .unwrap();
            attachment_id = attachment.attachment_id.clone();
            checkpoint(&source);
        }
        std::fs::copy(&source_path, &target_path).unwrap();
        (source_path, target_path, attachment_id)
    }

    fn create_divergent_password_conflict(label: &str) -> (PathBuf, PathBuf, String) {
        let source_path = temp_vault_path(&format!("{}-source", label));
        let target_path = temp_vault_path(&format!("{}-target", label));
        let entry_id;

        {
            let source = VaultConnection::create(&source_path).unwrap();
            initialize_vault(
                &source,
                &VaultInitParams {
                    vault_id: Some(format!("{}-vault", label)),
                    device_id: "device-a".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
            let source_ctx = CommitContext::new("device-a".to_string());
            let project = ProjectRepo::create(&source, &source_ctx, "P", None, None).unwrap();
            let entry = EntryRepo::create(
                &source,
                &source_ctx,
                &project.project_id,
                EntryType::Login,
                Some("Login"),
                &serde_json::json!({
                    "username": "alice",
                    "password": "old",
                    "url": "https://old.example"
                }),
            )
            .unwrap();
            entry_id = entry.entry_id.clone();
            checkpoint(&source);
        }
        std::fs::copy(&source_path, &target_path).unwrap();

        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        let source_ctx = CommitContext::new("device-a".to_string());
        let target_ctx = CommitContext::new("device-b".to_string());

        let incoming = update_entry_payload(
            &source,
            &source_ctx,
            &entry_id,
            serde_json::json!({
                "username": "alice",
                "password": "remote-secret",
                "url": "https://old.example"
            }),
        );
        let _local = update_entry_payload(
            &target,
            &target_ctx,
            &entry_id,
            serde_json::json!({
                "username": "alice",
                "password": "local-secret",
                "url": "https://old.example"
            }),
        );

        let mut commits = serialized_commits_from(&source);
        attach_state_payload_to_commit(&source, &mut commits, &incoming.head_commit_id);
        let result =
            SyncApplyRepo::apply_batch(&target, &target_ctx, &CommitBatch::new(commits, 0, true))
                .unwrap();
        assert_eq!(result.conflict_count, 1);

        drop(source);
        drop(target);
        (source_path, target_path, entry_id)
    }

    fn create_delete_modify_conflict(
        label: &str,
        remote_deletes: bool,
    ) -> (PathBuf, PathBuf, String) {
        let source_path = temp_vault_path(&format!("{}-source", label));
        let target_path = temp_vault_path(&format!("{}-target", label));
        let entry_id;

        {
            let source = VaultConnection::create(&source_path).unwrap();
            initialize_vault(
                &source,
                &VaultInitParams {
                    vault_id: Some(format!("{}-vault", label)),
                    device_id: "device-a".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
            let source_ctx = CommitContext::new("device-a".to_string());
            let project = ProjectRepo::create(&source, &source_ctx, "P", None, None).unwrap();
            let entry = EntryRepo::create(
                &source,
                &source_ctx,
                &project.project_id,
                EntryType::Login,
                Some("Login"),
                &serde_json::json!({
                    "username": "alice",
                    "password": "old"
                }),
            )
            .unwrap();
            entry_id = entry.entry_id.clone();
            checkpoint(&source);
        }
        std::fs::copy(&source_path, &target_path).unwrap();

        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        let source_ctx = CommitContext::new("device-a".to_string());
        let target_ctx = CommitContext::new("device-b".to_string());

        let incoming_head = if remote_deletes {
            EntryRepo::soft_delete(&source, &source_ctx, &entry_id).unwrap();
            EntryRepo::get_by_id(&source, &entry_id)
                .unwrap()
                .unwrap()
                .head_commit_id
        } else {
            update_entry_payload(
                &source,
                &source_ctx,
                &entry_id,
                serde_json::json!({
                    "username": "alice",
                    "password": "remote-change"
                }),
            )
            .head_commit_id
        };

        if remote_deletes {
            update_entry_payload(
                &target,
                &target_ctx,
                &entry_id,
                serde_json::json!({
                    "username": "alice",
                    "password": "local-change"
                }),
            );
        } else {
            EntryRepo::soft_delete(&target, &target_ctx, &entry_id).unwrap();
        }

        let mut commits = serialized_commits_from(&source);
        attach_state_payload_to_commit(&source, &mut commits, &incoming_head);
        attach_tombstones_to_commit(&source, &mut commits, &incoming_head);
        let result =
            SyncApplyRepo::apply_batch(&target, &target_ctx, &CommitBatch::new(commits, 0, true))
                .unwrap();
        assert_eq!(result.conflict_count, 1);

        drop(source);
        drop(target);
        (source_path, target_path, entry_id)
    }

    #[test]
    fn apply_fast_forward_commit() {
        let (conn, ctx) = setup();
        let project = ProjectRepo::create(&conn, &ctx, "P", None, None).unwrap();
        let main_head: String = conn
            .inner()
            .query_row(
                "SELECT head_commit_id FROM branches WHERE branch_name = 'main'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let incoming = make_commit(
            "remote-1",
            "device-b",
            1,
            vec![main_head],
            vec![project.project_id.clone()],
            &project.project_id,
            "project",
        );
        let batch = CommitBatch::new(vec![incoming], 0, true);
        let result = SyncApplyRepo::apply_batch(&conn, &ctx, &batch).unwrap();
        assert_eq!(result.applied_commits, 1);
        assert_eq!(result.conflict_count, 0);
    }

    #[test]
    fn sync_state_resource_limit_rolls_back_commit_tombstone_and_branch_head() {
        let (conn, ctx) = setup();
        let original_head: String = conn
            .inner()
            .query_row(
                "SELECT head_commit_id FROM branches WHERE branch_name = 'main'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let payload = collect_sync_state_payload(&conn).unwrap();
        let payload_len = payload.ciphertext.len();
        let mut incoming = make_commit(
            "remote-over-limit",
            "device-b",
            1,
            vec![original_head.clone()],
            vec!["project-over-limit".to_string()],
            "project-over-limit",
            "project",
        );
        incoming.object_payloads = vec![payload];
        let batch = CommitBatch::new(vec![incoming], 0, true);
        let limits = SyncStateLimits::new(payload_len, 2).unwrap();

        assert!(matches!(
            SyncApplyRepo::apply_batch_with_limits(&conn, &ctx, &batch, limits),
            Err(StorageError::ResourceLimit { resource, .. })
                if resource == "sync state rows"
        ));
        let commit_exists: bool = conn
            .inner()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM commits WHERE commit_id = 'remote-over-limit')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let tombstone_exists: bool = conn
            .inner()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM tombstones WHERE tombstone_id = 't-remote-over-limit')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let current_head: String = conn
            .inner()
            .query_row(
                "SELECT head_commit_id FROM branches WHERE branch_name = 'main'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!commit_exists);
        assert!(!tombstone_exists);
        assert_eq!(current_head, original_head);
    }

    #[test]
    fn incoming_commit_advances_the_device_sequence_floor() {
        let (conn, ctx) = setup();
        let main_head: String = conn
            .inner()
            .query_row(
                "SELECT head_commit_id FROM branches WHERE branch_name = 'main'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let incoming = make_commit(
            "remote-seq-50",
            "device-a",
            50,
            vec![main_head],
            Vec::new(),
            "unused",
            "project",
        );
        SyncApplyRepo::apply_batch(&conn, &ctx, &CommitBatch::new(vec![incoming], 0, true))
            .unwrap();

        let operation = CommitOperation::new(
            "local-after-sync",
            "change",
            "main",
            "change",
            "project",
            Vec::new(),
        );
        let commit_id = ctx.create_operation_commit(&conn, &operation).unwrap();
        let local_seq: i64 = conn
            .inner()
            .query_row(
                "SELECT local_seq FROM commits WHERE commit_id = ?1",
                params![commit_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(local_seq, 51);
    }

    #[test]
    fn operation_metadata_roundtrips_through_sync() {
        let source_path = temp_vault_path("operation-source");
        let target_path = temp_vault_path("operation-target");
        let source = VaultConnection::create(&source_path).unwrap();
        initialize_vault(
            &source,
            &VaultInitParams {
                device_id: "device-a".to_string(),
                ..Default::default()
            },
        )
        .unwrap();
        checkpoint(&source);
        std::fs::copy(&source_path, &target_path).unwrap();

        let source_ctx = CommitContext::new("device-a".to_string());
        let operation = CommitOperation::new(
            "sync-operation-1",
            "batch-move",
            "main",
            "change",
            "entry",
            vec![CommitChange {
                object_type: "entry".to_string(),
                object_id: "entry-1".to_string(),
                action: "move".to_string(),
                fields: vec!["project_id".to_string()],
            }],
        );
        let commit_id = source_ctx
            .create_operation_commit(&source, &operation)
            .unwrap();
        checkpoint(&source);

        let target = VaultConnection::open(&target_path).unwrap();
        let target_ctx = CommitContext::new("device-b".to_string());
        let commits = serialized_commits_from(&source);
        let result =
            SyncApplyRepo::apply_batch(&target, &target_ctx, &CommitBatch::new(commits, 0, true))
                .unwrap();
        assert_eq!(result.applied_commits, 1);

        let stored: (String, String, Option<String>, String) = target
            .inner()
            .query_row(
                "SELECT operation_id, operation_kind, branch_id, branch_name
                 FROM commit_operations WHERE commit_id = ?1",
                params![commit_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        let source_branch_id: String = source
            .inner()
            .query_row(
                "SELECT branch_id FROM branches WHERE branch_name = 'main'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            stored,
            (
                "sync-operation-1".to_string(),
                "batch-move".to_string(),
                Some(source_branch_id),
                "main".to_string()
            )
        );

        drop(source);
        drop(target);
        for path in [&source_path, &target_path] {
            let _ = std::fs::remove_file(path);
            let _ = std::fs::remove_file(format!("{}-wal", path.display()));
            let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        }
    }

    #[test]
    fn apply_divergent_commit_creates_conflict() {
        let (conn, ctx) = setup();
        let project = ProjectRepo::create(&conn, &ctx, "P", None, None).unwrap();
        let updated = ProjectRepo::update(
            &conn,
            &ctx,
            &ProjectRepo::get_by_id(&conn, &project.project_id)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let incoming = make_commit(
            "remote-2",
            "device-b",
            1,
            vec![project.head_commit_id.clone()],
            vec![project.project_id.clone()],
            &updated.project_id,
            "project",
        );
        let batch = CommitBatch::new(vec![incoming], 0, true);
        let result = SyncApplyRepo::apply_batch(&conn, &ctx, &batch).unwrap();
        assert_eq!(result.conflict_count, 1);
        assert!(!ConflictRepo::list_unresolved(&conn).unwrap().is_empty());
    }

    #[test]
    fn apply_fast_forward_state_payload_materializes_objects() {
        let source_path = temp_vault_path("source");
        let target_path = temp_vault_path("target");

        {
            let source = VaultConnection::create(&source_path).unwrap();
            initialize_vault(
                &source,
                &VaultInitParams {
                    vault_id: Some("sync-state-test-vault".to_string()),
                    device_id: "device-a".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
            checkpoint(&source);
        }
        std::fs::copy(&source_path, &target_path).unwrap();

        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        let source_ctx = CommitContext::new("device-a".to_string());
        let target_ctx = CommitContext::new("device-b".to_string());

        let project =
            ProjectRepo::create(&source, &source_ctx, "Synced Project", Some("work"), None)
                .unwrap();
        let entry = EntryRepo::create(
            &source,
            &source_ctx,
            &project.project_id,
            EntryType::Login,
            Some("Synced Login"),
            &serde_json::json!({
                "username": "alice",
                "password": "synced-secret",
                "url": "https://sync.example"
            }),
        )
        .unwrap();
        let attachment = AttachmentRepo::add(
            &source,
            &source_ctx,
            &project.project_id,
            Some(&entry.entry_id),
            "proof.txt",
            Some("text/plain"),
            "",
            0,
        )
        .unwrap();
        AttachmentRepo::write_inline_content(
            &source,
            &source_ctx,
            &attachment.attachment_id,
            b"hello from source",
        )
        .unwrap();

        let mut commits = serialized_commits_from(&source);
        commits
            .last_mut()
            .unwrap()
            .object_payloads
            .push(collect_sync_state_payload(&source).unwrap());

        let batch = CommitBatch::new(commits, 0, true);
        let result = SyncApplyRepo::apply_batch(&target, &target_ctx, &batch).unwrap();

        assert!(result.applied_commits >= 4);
        assert_eq!(result.conflict_count, 0);

        let synced_project = ProjectRepo::get_by_id(&target, &project.project_id)
            .unwrap()
            .unwrap();
        assert_eq!(synced_project.title_ct, b"Synced Project");

        let synced_entry = EntryRepo::get_by_id(&target, &entry.entry_id)
            .unwrap()
            .unwrap();
        assert_eq!(synced_entry.project_id, project.project_id);
        assert_eq!(synced_entry.title_ct, Some(b"Synced Login".to_vec()));

        let synced_attachment = AttachmentRepo::get_by_id(&target, &attachment.attachment_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            synced_attachment.entry_id.as_deref(),
            Some(entry.entry_id.as_str())
        );
        assert_eq!(
            AttachmentRepo::read_content(&target, &attachment.attachment_id).unwrap(),
            b"hello from source"
        );

        drop(source);
        drop(target);
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn collection_profile_and_opaque_object_survive_sync_without_target_adapter() {
        let source_path = temp_vault_path("profile-source");
        let target_path = temp_vault_path("profile-target");

        {
            let source = VaultConnection::create(&source_path).unwrap();
            initialize_vault(
                &source,
                &VaultInitParams {
                    vault_id: Some("profile-sync-vault".to_string()),
                    device_id: "device-a".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
            checkpoint(&source);
        }
        std::fs::copy(&source_path, &target_path).unwrap();

        let mut source = VaultConnection::open(&source_path).unwrap();
        source.set_extension_capabilities([
            ExtensionCapabilityId::new("com.monica.mail.store").unwrap()
        ]);
        let target = VaultConnection::open(&target_path).unwrap();
        let source_ctx = CommitContext::new("device-a".to_string());
        let target_ctx = CommitContext::new("device-b".to_string());

        let project = ProjectRepo::create(&source, &source_ctx, "Mail", None, None).unwrap();
        CollectionProfileRepo::set(
            &source,
            &source_ctx,
            CollectionProfileSpec {
                collection_id: project.project_id.clone(),
                collection_type_id: CollectionTypeId::new("com.monica.mail").unwrap(),
                payload: br#"{"account":"primary"}"#.to_vec(),
                payload_schema_version: 1,
                allowed_object_type_ids: vec![
                    ObjectTypeId::custom("com.monica.mail.message").unwrap()
                ],
                required_capability_ids: vec![
                    ExtensionCapabilityId::new("com.monica.mail.store").unwrap()
                ],
            },
        )
        .unwrap();
        let entry = EntryRepo::create(
            &source,
            &source_ctx,
            &project.project_id,
            ObjectTypeId::custom("com.monica.mail.message").unwrap(),
            Some("Message"),
            &serde_json::json!({"body":"opaque"}),
        )
        .unwrap();
        checkpoint(&source);

        let mut commits = serialized_commits_from(&source);
        attach_state_payload_to_commit(&source, &mut commits, &entry.head_commit_id);
        let result =
            SyncApplyRepo::apply_batch(&target, &target_ctx, &CommitBatch::new(commits, 0, true))
                .unwrap();
        assert_eq!(result.conflict_count, 0);

        let profile = CollectionProfileRepo::get_by_collection_id(&target, &project.project_id)
            .unwrap()
            .unwrap();
        assert_eq!(profile.collection_type_id.as_str(), "com.monica.mail");
        assert_eq!(profile.payload_ct, br#"{"account":"primary"}"#);
        let synced = EntryRepo::get_by_id(&target, &entry.entry_id)
            .unwrap()
            .unwrap();
        assert_eq!(synced.entry_type.as_str(), "com.monica.mail.message");

        drop(source);
        drop(target);
        remove_vault_files(&source_path);
        remove_vault_files(&target_path);
    }

    #[test]
    fn purge_receipt_sync_removes_stale_object_and_blocks_old_state_revival() {
        let source_path = temp_vault_path("purge-receipt-source");
        let target_path = temp_vault_path("purge-receipt-target");
        let project_id;

        {
            let mut source = VaultConnection::create(&source_path).unwrap();
            initialize_vault(
                &source,
                &VaultInitParams {
                    vault_id: Some("purge-receipt-vault".to_string()),
                    device_id: "device-a".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
            UnlockService::setup_password(&mut source, "purge receipt password").unwrap();
            let source_ctx = CommitContext::new("device-a".to_string());
            project_id = ProjectRepo::create(&source, &source_ctx, "Purged", None, None)
                .unwrap()
                .project_id;
            checkpoint(&source);
        }
        std::fs::copy(&source_path, &target_path).unwrap();

        let mut source = VaultConnection::open(&source_path).unwrap();
        let mut target = VaultConnection::open(&target_path).unwrap();
        let session =
            UnlockService::unlock_with_password(&mut source, "purge receipt password").unwrap();
        UnlockService::unlock_with_password(&mut target, "purge receipt password").unwrap();
        let source_ctx = CommitContext::new("device-a".to_string());
        let target_ctx = CommitContext::new("device-b".to_string());
        let stale_state = collect_sync_state(&target).unwrap();

        ProjectRepo::soft_delete(&source, &source_ctx, &project_id).unwrap();
        let tombstone = TombstoneRepo::find_by_target(&source, &project_id)
            .unwrap()
            .unwrap();
        let device = rotation_device("device-a");
        let now = chrono::Utc::now().timestamp() + 1;
        let context = TigaAuthorizationContext {
            session: Some(&session),
            device: &device,
            now_unix_secs: now,
        };
        TombstoneRepo::schedule_purge_authorized(
            &source,
            &source_ctx,
            &tombstone.tombstone_id,
            &tombstone.deleted_at,
            context,
        )
        .unwrap();
        let (receipt, _) =
            TombstoneRepo::purge_authorized(&source, &source_ctx, &tombstone.tombstone_id, context)
                .unwrap();

        let mut commits = serialized_commits_from(&source);
        attach_state_payload_to_commit(&source, &mut commits, &receipt.purge_commit_id);
        SyncApplyRepo::apply_batch(&target, &target_ctx, &CommitBatch::new(commits, 0, true))
            .unwrap();
        assert!(ProjectRepo::get_by_id(&target, &project_id)
            .unwrap()
            .is_none());
        assert!(
            TombstoneRepo::find_purge_receipt_by_target(&target, "project", &project_id)
                .unwrap()
                .is_some()
        );

        SyncApplyRepo::apply_projects(
            &target,
            &target_ctx,
            &receipt.purge_commit_id,
            &stale_state.projects,
        )
        .unwrap();
        assert!(ProjectRepo::get_by_id(&target, &project_id)
            .unwrap()
            .is_none());
        assert_eq!(
            target
                .inner()
                .query_row(
                    "SELECT COUNT(*) FROM object_versions
                     WHERE object_type = 'project' AND object_id = ?1",
                    params![project_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );

        drop(source);
        drop(target);
        remove_vault_files(&source_path);
        remove_vault_files(&target_path);
    }

    #[test]
    fn sync_state_preserves_custom_object_type_and_payload_schema_version() {
        let source_path = temp_vault_path("custom-object-source");
        let target_path = temp_vault_path("custom-object-target");

        {
            let source = VaultConnection::create(&source_path).unwrap();
            initialize_vault(
                &source,
                &VaultInitParams {
                    vault_id: Some("custom-object-sync-vault".to_string()),
                    device_id: "device-a".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
            checkpoint(&source);
        }
        std::fs::copy(&source_path, &target_path).unwrap();

        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        let source_ctx = CommitContext::new("device-a".to_string());
        let target_ctx = CommitContext::new("device-b".to_string());
        let project = ProjectRepo::create(&source, &source_ctx, "Mail", None, None).unwrap();
        let object = EntryRepo::create_with_payload_schema_version(
            &source,
            &source_ctx,
            &project.project_id,
            EntryType::custom("com.monica.mail.message").unwrap(),
            Some("Encrypted message"),
            &serde_json::json!({"subject": "sync", "body": "opaque"}),
            12,
        )
        .unwrap();

        let mut commits = serialized_commits_from(&source);
        commits
            .last_mut()
            .unwrap()
            .object_payloads
            .push(collect_sync_state_payload(&source).unwrap());
        SyncApplyRepo::apply_batch(&target, &target_ctx, &CommitBatch::new(commits, 0, true))
            .unwrap();

        let synced = EntryRepo::get_by_id(&target, &object.entry_id)
            .unwrap()
            .unwrap();
        assert_eq!(synced.entry_type.as_str(), "com.monica.mail.message");
        assert_eq!(synced.payload_schema_version, 12);

        drop(source);
        drop(target);
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn relation_sync_roundtrips_generic_metadata_and_versions() {
        let source_path = temp_vault_path("relation-sync-source");
        let target_path = temp_vault_path("relation-sync-target");
        {
            let source = VaultConnection::create(&source_path).unwrap();
            initialize_vault(
                &source,
                &VaultInitParams {
                    vault_id: Some("relation-sync-vault".to_string()),
                    device_id: "device-a".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
            checkpoint(&source);
        }
        std::fs::copy(&source_path, &target_path).unwrap();

        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        let source_ctx = CommitContext::new("device-a".to_string());
        let target_ctx = CommitContext::new("device-b".to_string());
        let project = ProjectRepo::create(&source, &source_ctx, "Mail", None, None).unwrap();
        let first = EntryRepo::create(
            &source,
            &source_ctx,
            &project.project_id,
            EntryType::custom("com.monica.mail.message").unwrap(),
            Some("First"),
            &serde_json::json!({"body": "first"}),
        )
        .unwrap();
        let second = EntryRepo::create(
            &source,
            &source_ctx,
            &project.project_id,
            EntryType::custom("com.monica.mail.message").unwrap(),
            Some("Second"),
            &serde_json::json!({"body": "second"}),
        )
        .unwrap();
        let relation = ObjectRelationRepo::create(
            &source,
            &source_ctx,
            ObjectRelationCreateRequest::new(
                &first.entry_id,
                &second.entry_id,
                RelationKindId::new("com.monica.mail.reply-to").unwrap(),
                serde_json::json!({"position": 1}),
            )
            .with_payload_schema_version(4),
        )
        .unwrap();
        let label = ObjectLabelRepo::create(
            &source,
            &source_ctx,
            ObjectLabelCreateRequest::new(
                &project.project_id,
                "Important",
                serde_json::json!({"color": "red"}),
            ),
        )
        .unwrap();
        let assignment = ObjectLabelAssignmentRepo::create(
            &source,
            &source_ctx,
            ObjectLabelAssignmentCreateRequest::new(&first.entry_id, &label.label_id),
        )
        .unwrap();

        let mut commits = serialized_commits_from(&source);
        commits
            .last_mut()
            .unwrap()
            .object_payloads
            .push(collect_sync_state_payload(&source).unwrap());
        let result =
            SyncApplyRepo::apply_batch(&target, &target_ctx, &CommitBatch::new(commits, 0, true))
                .unwrap();
        assert_eq!(result.conflict_count, 0);

        let synced_relation = ObjectRelationRepo::get_by_id(&target, &relation.relation_id)
            .unwrap()
            .unwrap();
        let synced_label = ObjectLabelRepo::get_by_id(&target, &label.label_id)
            .unwrap()
            .unwrap();
        let synced_assignment =
            ObjectLabelAssignmentRepo::get_by_id(&target, &assignment.assignment_id)
                .unwrap()
                .unwrap();
        assert_eq!(synced_relation.relation_kind, relation.relation_kind);
        assert_eq!(synced_relation.payload_schema_version, 4);
        assert_eq!(synced_label.name_ct, label.name_ct);
        assert_eq!(synced_assignment.object_id, first.entry_id);
        assert!(ObjectVersionRepo::get_object_relation(
            &target,
            &relation.relation_id,
            &relation.head_commit_id,
        )
        .unwrap()
        .is_some());

        drop(source);
        drop(target);
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn duplicate_assignment_conflict_maps_incoming_state_to_local_logical_identity() {
        let source_path = temp_vault_path("assignment-conflict-source");
        let target_path = temp_vault_path("assignment-conflict-target");
        let object_id;
        let label_id;
        {
            let source = VaultConnection::create(&source_path).unwrap();
            initialize_vault(
                &source,
                &VaultInitParams {
                    vault_id: Some("assignment-conflict-vault".to_string()),
                    device_id: "device-a".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
            let ctx = CommitContext::new("device-a".to_string());
            let project = ProjectRepo::create(&source, &ctx, "Mail", None, None).unwrap();
            object_id = EntryRepo::create(
                &source,
                &ctx,
                &project.project_id,
                EntryType::custom("com.monica.mail.message").unwrap(),
                Some("Message"),
                &serde_json::json!({"body":"message"}),
            )
            .unwrap()
            .entry_id;
            label_id = ObjectLabelRepo::create(
                &source,
                &ctx,
                ObjectLabelCreateRequest::new(
                    &project.project_id,
                    "Important",
                    serde_json::json!({}),
                ),
            )
            .unwrap()
            .label_id;
            checkpoint(&source);
        }
        std::fs::copy(&source_path, &target_path).unwrap();

        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        let source_ctx = CommitContext::new("device-a".to_string());
        let target_ctx = CommitContext::new("device-b".to_string());
        let incoming_assignment = ObjectLabelAssignmentRepo::create(
            &source,
            &source_ctx,
            ObjectLabelAssignmentCreateRequest::new(&object_id, &label_id),
        )
        .unwrap();
        let local_assignment = ObjectLabelAssignmentRepo::create(
            &target,
            &target_ctx,
            ObjectLabelAssignmentCreateRequest::new(&object_id, &label_id),
        )
        .unwrap();
        assert_ne!(
            incoming_assignment.assignment_id,
            local_assignment.assignment_id
        );

        let mut commits = serialized_commits_from(&source);
        commits
            .last_mut()
            .unwrap()
            .object_payloads
            .push(collect_sync_state_payload(&source).unwrap());
        let result =
            SyncApplyRepo::apply_batch(&target, &target_ctx, &CommitBatch::new(commits, 0, true))
                .unwrap();
        assert_eq!(result.conflict_count, 1);

        let conflict = ConflictRepo::list_by_object(
            &target,
            ConflictObjectType::ObjectLabelAssignment,
            &local_assignment.assignment_id,
        )
        .unwrap()
        .pop()
        .unwrap();
        let logical_incoming = ObjectVersionRepo::get_object_label_assignment(
            &target,
            &local_assignment.assignment_id,
            &conflict.incoming_commit_id,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            logical_incoming.assignment_id,
            local_assignment.assignment_id
        );
        assert_eq!(logical_incoming.object_id, object_id);
        assert_eq!(logical_incoming.label_id, label_id);

        ConflictRepo::resolve_object_label_assignment(
            &target,
            &target_ctx,
            &conflict.conflict_id,
            ConflictResolution::IncomingWins,
        )
        .unwrap();
        assert!(
            ObjectLabelAssignmentRepo::get_by_id(&target, &local_assignment.assignment_id)
                .unwrap()
                .is_some()
        );
        assert!(
            ObjectLabelAssignmentRepo::get_by_id(&target, &incoming_assignment.assignment_id)
                .unwrap()
                .is_none()
        );

        drop(source);
        drop(target);
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn divergent_relation_changes_create_a_typed_conflict() {
        let source_path = temp_vault_path("relation-conflict-source");
        let target_path = temp_vault_path("relation-conflict-target");
        let relation_id;
        {
            let source = VaultConnection::create(&source_path).unwrap();
            initialize_vault(
                &source,
                &VaultInitParams {
                    vault_id: Some("relation-conflict-vault".to_string()),
                    device_id: "device-a".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
            let ctx = CommitContext::new("device-a".to_string());
            let project = ProjectRepo::create(&source, &ctx, "Mail", None, None).unwrap();
            let first = EntryRepo::create(
                &source,
                &ctx,
                &project.project_id,
                EntryType::custom("com.monica.mail.message").unwrap(),
                Some("First"),
                &serde_json::json!({}),
            )
            .unwrap();
            let second = EntryRepo::create(
                &source,
                &ctx,
                &project.project_id,
                EntryType::custom("com.monica.mail.message").unwrap(),
                Some("Second"),
                &serde_json::json!({}),
            )
            .unwrap();
            relation_id = ObjectRelationRepo::create(
                &source,
                &ctx,
                ObjectRelationCreateRequest::new(
                    first.entry_id,
                    second.entry_id,
                    RelationKindId::new("com.monica.mail.reply-to").unwrap(),
                    serde_json::json!({"position": 1}),
                ),
            )
            .unwrap()
            .relation_id;
            checkpoint(&source);
        }
        std::fs::copy(&source_path, &target_path).unwrap();

        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        let source_ctx = CommitContext::new("device-a".to_string());
        let target_ctx = CommitContext::new("device-b".to_string());
        let mut remote = ObjectRelationRepo::get_by_id(&source, &relation_id)
            .unwrap()
            .unwrap();
        remote.payload_ct = serde_json::to_vec(&serde_json::json!({"position": 2})).unwrap();
        ObjectRelationRepo::update(&source, &source_ctx, &remote).unwrap();
        let mut local = ObjectRelationRepo::get_by_id(&target, &relation_id)
            .unwrap()
            .unwrap();
        local.payload_ct = serde_json::to_vec(&serde_json::json!({"position": 3})).unwrap();
        let local = ObjectRelationRepo::update(&target, &target_ctx, &local).unwrap();

        let mut commits = serialized_commits_from(&source);
        commits
            .last_mut()
            .unwrap()
            .object_payloads
            .push(collect_sync_state_payload(&source).unwrap());
        let result =
            SyncApplyRepo::apply_batch(&target, &target_ctx, &CommitBatch::new(commits, 0, true))
                .unwrap();
        assert_eq!(result.conflict_count, 1);
        assert_eq!(
            ObjectRelationRepo::get_by_id(&target, &relation_id)
                .unwrap()
                .unwrap()
                .head_commit_id,
            local.head_commit_id
        );
        let conflicts =
            ConflictRepo::list_by_object(&target, ConflictObjectType::ObjectRelation, &relation_id)
                .unwrap();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].object_type, ConflictObjectType::ObjectRelation);

        drop(source);
        drop(target);
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn audit_commit_correlation_roundtrips_and_rejects_tampering() {
        let source_path = temp_vault_path("audit-correlation-source");
        let target_path = temp_vault_path("audit-correlation-target");
        let mut source = VaultConnection::create(&source_path).unwrap();
        initialize_vault(
            &source,
            &VaultInitParams {
                device_id: "device-a".to_string(),
                ..Default::default()
            },
        )
        .unwrap();
        checkpoint(&source);
        std::fs::copy(&source_path, &target_path).unwrap();

        source.attach_keyring(
            Keyring::from_vault_key(&[11_u8; 32], b"sync-audit-correlation").unwrap(),
        );
        let source_ctx = CommitContext::new("device-a".to_string());
        let project = ProjectRepo::create(&source, &source_ctx, "P", None, None).unwrap();
        let session = VaultSession {
            session_id: "session-a".to_string(),
            unlock_method: UnlockMethodType::Password,
            created_at: "1970-01-01T00:16:40Z".to_string(),
            assurance: SessionAssurance::from_unlock_method(UnlockMethodType::Password, 1_000),
        };
        let device = DeviceContext {
            device_id: Some("device-a".to_string()),
            assurance: DeviceAssurance::Standard,
            secure_clipboard_available: true,
            screen_capture_protection_available: false,
            secure_temp_files_available: true,
        };
        TigaService::set_policy_override_authorized(
            &source,
            &source_ctx,
            TigaScope::Project {
                project_id: project.project_id,
            },
            TigaPolicyOverride {
                clipboard_allowed: Some(false),
                ..Default::default()
            },
            None,
            TigaAuthorizationContext {
                session: Some(&session),
                device: &device,
                now_unix_secs: 1_010,
            },
        )
        .unwrap();
        let source_event = TigaService::list_security_audit_events(&source, 10)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let audit_commit_id = source_event.commit_id.clone().unwrap();

        let mut commits = serialized_commits_from(&source);
        attach_state_payload_to_commit(&source, &mut commits, &audit_commit_id);
        let mut target = VaultConnection::open(&target_path).unwrap();
        target.attach_keyring(
            Keyring::from_vault_key(&[11_u8; 32], b"sync-audit-correlation").unwrap(),
        );
        let target_ctx = CommitContext::new("device-b".to_string());
        SyncApplyRepo::apply_batch(&target, &target_ctx, &CommitBatch::new(commits, 0, true))
            .unwrap();

        let target_event = TigaService::list_security_audit_events(&target, 10)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(target_event, source_event);

        let synced_row = collect_sync_state(&source)
            .unwrap()
            .security_audit_events
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let mut rewritten_correlation = synced_row.clone();
        rewritten_correlation.operation_id = Some("rewritten-operation".to_string());
        rewritten_correlation.integrity_tag = None;
        let correlation_error =
            tiga_apply::apply_security_audit_events(&target, &[rewritten_correlation]).unwrap_err();
        assert!(correlation_error
            .to_string()
            .contains("mismatched operation and commit"));

        let mut rewritten_evidence = synced_row;
        rewritten_evidence.policy_fingerprint.as_mut().unwrap()[0] ^= 1;
        let evidence_error =
            tiga_apply::apply_security_audit_events(&target, &[rewritten_evidence]).unwrap_err();
        assert!(evidence_error
            .to_string()
            .contains("integrity tag mismatch"));

        drop(source);
        drop(target);
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn divergent_entry_different_payload_fields_auto_merge() {
        let source_path = temp_vault_path("field-merge-source");
        let target_path = temp_vault_path("field-merge-target");
        let entry_id;

        {
            let source = VaultConnection::create(&source_path).unwrap();
            initialize_vault(
                &source,
                &VaultInitParams {
                    vault_id: Some("field-merge-vault".to_string()),
                    device_id: "device-a".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
            let source_ctx = CommitContext::new("device-a".to_string());
            let project = ProjectRepo::create(&source, &source_ctx, "P", None, None).unwrap();
            let entry = EntryRepo::create(
                &source,
                &source_ctx,
                &project.project_id,
                EntryType::Login,
                Some("Login"),
                &serde_json::json!({
                    "username": "alice",
                    "password": "old",
                    "url": "https://old.example"
                }),
            )
            .unwrap();
            entry_id = entry.entry_id.clone();
            checkpoint(&source);
        }
        std::fs::copy(&source_path, &target_path).unwrap();

        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        let source_ctx = CommitContext::new("device-a".to_string());
        let target_ctx = CommitContext::new("device-b".to_string());

        let incoming = update_entry_payload(
            &source,
            &source_ctx,
            &entry_id,
            serde_json::json!({
                "username": "alice",
                "password": "old",
                "url": "https://remote.example"
            }),
        );
        let _local = update_entry_payload(
            &target,
            &target_ctx,
            &entry_id,
            serde_json::json!({
                "username": "alice-local",
                "password": "old",
                "url": "https://old.example"
            }),
        );

        let mut commits = serialized_commits_from(&source);
        attach_state_payload_to_commit(&source, &mut commits, &incoming.head_commit_id);
        let result =
            SyncApplyRepo::apply_batch(&target, &target_ctx, &CommitBatch::new(commits, 0, true))
                .unwrap();

        assert_eq!(result.conflict_count, 0);
        assert!(ConflictRepo::list_unresolved(&target).unwrap().is_empty());
        let merged = entry_payload_json(&target, &entry_id);
        assert_eq!(merged["username"], "alice-local");
        assert_eq!(merged["password"], "old");
        assert_eq!(merged["url"], "https://remote.example");

        let merged_entry = EntryRepo::get_by_id(&target, &entry_id).unwrap().unwrap();
        let parent_count: i64 = target
            .inner()
            .query_row(
                "SELECT COUNT(*) FROM commit_parents WHERE commit_id = ?1",
                params![merged_entry.head_commit_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(parent_count, 2);
        let version_count: i64 = target
            .inner()
            .query_row(
                "SELECT COUNT(*) FROM object_versions
                 WHERE object_type = 'entry' AND object_id = ?1 AND commit_id = ?2",
                params![entry_id, merged_entry.head_commit_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version_count, 1);

        drop(source);
        drop(target);
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn divergent_entry_same_payload_field_creates_conflict() {
        let source_path = temp_vault_path("field-conflict-source");
        let target_path = temp_vault_path("field-conflict-target");
        let entry_id;

        {
            let source = VaultConnection::create(&source_path).unwrap();
            initialize_vault(
                &source,
                &VaultInitParams {
                    vault_id: Some("field-conflict-vault".to_string()),
                    device_id: "device-a".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
            let source_ctx = CommitContext::new("device-a".to_string());
            let project = ProjectRepo::create(&source, &source_ctx, "P", None, None).unwrap();
            let entry = EntryRepo::create(
                &source,
                &source_ctx,
                &project.project_id,
                EntryType::Login,
                Some("Login"),
                &serde_json::json!({
                    "username": "alice",
                    "password": "old",
                    "url": "https://old.example"
                }),
            )
            .unwrap();
            entry_id = entry.entry_id.clone();
            checkpoint(&source);
        }
        std::fs::copy(&source_path, &target_path).unwrap();

        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        let source_ctx = CommitContext::new("device-a".to_string());
        let target_ctx = CommitContext::new("device-b".to_string());

        let incoming = update_entry_payload(
            &source,
            &source_ctx,
            &entry_id,
            serde_json::json!({
                "username": "alice",
                "password": "remote-secret",
                "url": "https://old.example"
            }),
        );
        let _local = update_entry_payload(
            &target,
            &target_ctx,
            &entry_id,
            serde_json::json!({
                "username": "alice",
                "password": "local-secret",
                "url": "https://old.example"
            }),
        );

        let mut commits = serialized_commits_from(&source);
        attach_state_payload_to_commit(&source, &mut commits, &incoming.head_commit_id);
        let result =
            SyncApplyRepo::apply_batch(&target, &target_ctx, &CommitBatch::new(commits, 0, true))
                .unwrap();

        assert_eq!(result.conflict_count, 1);
        let conflicts = ConflictRepo::list_unresolved(&target).unwrap();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].object_id, entry_id);
        assert_eq!(conflicts[0].conflicting_fields, vec!["password"]);

        let local_after = entry_payload_json(&target, &entry_id);
        assert_eq!(local_after["password"], "local-secret");

        drop(source);
        drop(target);
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn divergent_project_different_fields_auto_merge() {
        let (source_path, target_path, project_id) =
            create_project_divergence("project-field-merge");
        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        let source_ctx = CommitContext::new("device-a".to_string());
        let target_ctx = CommitContext::new("device-b".to_string());

        let incoming = update_project_for_test(&source, &source_ctx, &project_id, |project| {
            project.icon_ref = Some("remote-icon".to_string());
        });
        let _local = update_project_for_test(&target, &target_ctx, &project_id, |project| {
            project.favorite = true;
        });

        let mut commits = serialized_commits_from(&source);
        attach_state_payload_to_commit(&source, &mut commits, &incoming.head_commit_id);
        let result =
            SyncApplyRepo::apply_batch(&target, &target_ctx, &CommitBatch::new(commits, 0, true))
                .unwrap();

        assert_eq!(result.conflict_count, 0);
        assert!(ConflictRepo::list_unresolved(&target).unwrap().is_empty());
        let merged = ProjectRepo::get_by_id(&target, &project_id)
            .unwrap()
            .unwrap();
        assert_eq!(merged.icon_ref.as_deref(), Some("remote-icon"));
        assert!(merged.favorite);

        let parent_count: i64 = target
            .inner()
            .query_row(
                "SELECT COUNT(*) FROM commit_parents WHERE commit_id = ?1",
                params![merged.head_commit_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(parent_count, 2);
        assert!(
            ObjectVersionRepo::get_project(&target, &project_id, &merged.head_commit_id)
                .unwrap()
                .is_some()
        );

        drop(source);
        drop(target);
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn divergent_project_same_field_creates_field_conflict() {
        let (source_path, target_path, project_id) =
            create_project_divergence("project-field-conflict");
        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        let source_ctx = CommitContext::new("device-a".to_string());
        let target_ctx = CommitContext::new("device-b".to_string());

        let incoming = update_project_for_test(&source, &source_ctx, &project_id, |project| {
            project.group_id = Some("remote".to_string());
        });
        let _local = update_project_for_test(&target, &target_ctx, &project_id, |project| {
            project.group_id = Some("local".to_string());
        });

        let mut commits = serialized_commits_from(&source);
        attach_state_payload_to_commit(&source, &mut commits, &incoming.head_commit_id);
        let result =
            SyncApplyRepo::apply_batch(&target, &target_ctx, &CommitBatch::new(commits, 0, true))
                .unwrap();

        assert_eq!(result.conflict_count, 1);
        let conflicts = ConflictRepo::list_unresolved(&target).unwrap();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].object_id, project_id);
        assert_eq!(conflicts[0].conflicting_fields, vec!["group_id"]);

        let local_after = ProjectRepo::get_by_id(&target, &project_id)
            .unwrap()
            .unwrap();
        assert_eq!(local_after.group_id.as_deref(), Some("local"));

        drop(source);
        drop(target);
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn divergent_attachment_metadata_and_remote_content_auto_merge() {
        let (source_path, target_path, attachment_id) =
            create_attachment_divergence("attachment-field-merge");
        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        let source_ctx = CommitContext::new("device-a".to_string());
        let target_ctx = CommitContext::new("device-b".to_string());

        AttachmentRepo::write_inline_content(
            &source,
            &source_ctx,
            &attachment_id,
            b"remote content",
        )
        .unwrap();
        let incoming = AttachmentRepo::get_by_id(&source, &attachment_id)
            .unwrap()
            .unwrap();
        let _local =
            AttachmentRepo::rename(&target, &target_ctx, &attachment_id, "local.txt", None)
                .unwrap();

        let mut commits = serialized_commits_from(&source);
        attach_state_payload_to_commit(&source, &mut commits, &incoming.head_commit_id);
        let result =
            SyncApplyRepo::apply_batch(&target, &target_ctx, &CommitBatch::new(commits, 0, true))
                .unwrap();

        assert_eq!(result.conflict_count, 0);
        assert!(ConflictRepo::list_unresolved(&target).unwrap().is_empty());
        let merged = AttachmentRepo::get_by_id(&target, &attachment_id)
            .unwrap()
            .unwrap();
        assert_eq!(merged.file_name_ct, b"local.txt");
        assert_eq!(
            AttachmentRepo::read_content(&target, &attachment_id).unwrap(),
            b"remote content"
        );
        assert!(
            ObjectVersionRepo::get_attachment(&target, &attachment_id, &merged.head_commit_id)
                .unwrap()
                .is_some()
        );

        drop(source);
        drop(target);
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn divergent_attachment_both_change_content_creates_conflict() {
        let (source_path, target_path, attachment_id) =
            create_attachment_divergence("attachment-content-conflict");
        let source = VaultConnection::open(&source_path).unwrap();
        let target = VaultConnection::open(&target_path).unwrap();
        let source_ctx = CommitContext::new("device-a".to_string());
        let target_ctx = CommitContext::new("device-b".to_string());

        AttachmentRepo::write_inline_content(
            &source,
            &source_ctx,
            &attachment_id,
            b"remote content",
        )
        .unwrap();
        let incoming = AttachmentRepo::get_by_id(&source, &attachment_id)
            .unwrap()
            .unwrap();
        AttachmentRepo::write_inline_content(
            &target,
            &target_ctx,
            &attachment_id,
            b"local content",
        )
        .unwrap();

        let mut commits = serialized_commits_from(&source);
        attach_state_payload_to_commit(&source, &mut commits, &incoming.head_commit_id);
        let result =
            SyncApplyRepo::apply_batch(&target, &target_ctx, &CommitBatch::new(commits, 0, true))
                .unwrap();

        assert_eq!(result.conflict_count, 1);
        let conflicts = ConflictRepo::list_unresolved(&target).unwrap();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].object_id, attachment_id);
        assert_eq!(conflicts[0].conflicting_fields, vec!["content_hash"]);
        assert_eq!(
            AttachmentRepo::read_content(&target, &attachment_id).unwrap(),
            b"local content"
        );

        drop(source);
        drop(target);
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn entry_conflict_resolve_local_wins_writes_resolution_commit() {
        let (source_path, target_path, entry_id) =
            create_divergent_password_conflict("resolve-local-wins");
        let target = VaultConnection::open(&target_path).unwrap();
        let target_ctx = CommitContext::new("device-b".to_string());
        let conflict = ConflictRepo::list_unresolved(&target).unwrap().remove(0);
        let before = EntryRepo::get_by_id(&target, &entry_id).unwrap().unwrap();

        let resolved = ConflictRepo::resolve_entry(
            &target,
            &target_ctx,
            &conflict.conflict_id,
            ConflictResolution::LocalWins,
        )
        .unwrap();

        assert_eq!(resolved.resolution, ConflictResolution::LocalWins);
        assert!(resolved.resolved_at.is_some());
        assert!(ConflictRepo::list_unresolved(&target).unwrap().is_empty());

        let after = EntryRepo::get_by_id(&target, &entry_id).unwrap().unwrap();
        assert_ne!(after.head_commit_id, before.head_commit_id);
        assert_eq!(
            entry_payload_json(&target, &entry_id)["password"],
            "local-secret"
        );

        let parents = SyncApplyRepo::parent_ids_for_commit(&target, &after.head_commit_id).unwrap();
        assert!(parents.contains(&before.head_commit_id));
        assert!(parents.contains(&conflict.incoming_commit_id));

        drop(target);
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn entry_conflict_resolve_incoming_wins_applies_incoming_snapshot() {
        let (source_path, target_path, entry_id) =
            create_divergent_password_conflict("resolve-incoming-wins");
        let target = VaultConnection::open(&target_path).unwrap();
        let target_ctx = CommitContext::new("device-b".to_string());
        let conflict = ConflictRepo::list_unresolved(&target).unwrap().remove(0);
        let before = EntryRepo::get_by_id(&target, &entry_id).unwrap().unwrap();

        let resolved = ConflictRepo::resolve_entry(
            &target,
            &target_ctx,
            &conflict.conflict_id,
            ConflictResolution::IncomingWins,
        )
        .unwrap();

        assert_eq!(resolved.resolution, ConflictResolution::IncomingWins);
        assert!(resolved.resolved_at.is_some());
        assert!(ConflictRepo::list_unresolved(&target).unwrap().is_empty());

        let after = EntryRepo::get_by_id(&target, &entry_id).unwrap().unwrap();
        assert_ne!(after.head_commit_id, before.head_commit_id);
        assert_eq!(
            entry_payload_json(&target, &entry_id)["password"],
            "remote-secret"
        );
        assert!(
            ObjectVersionRepo::get_entry(&target, &entry_id, &after.head_commit_id)
                .unwrap()
                .is_some()
        );

        let parents = SyncApplyRepo::parent_ids_for_commit(&target, &after.head_commit_id).unwrap();
        assert!(parents.contains(&before.head_commit_id));
        assert!(parents.contains(&conflict.incoming_commit_id));

        drop(target);
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn entry_conflict_resolve_custom_payload_writes_merge_commit() {
        let (source_path, target_path, entry_id) =
            create_divergent_password_conflict("resolve-custom-payload");
        let target = VaultConnection::open(&target_path).unwrap();
        let target_ctx = CommitContext::new("device-b".to_string());
        let conflict = ConflictRepo::list_unresolved(&target).unwrap().remove(0);
        let before = EntryRepo::get_by_id(&target, &entry_id).unwrap().unwrap();

        let resolved = ConflictRepo::resolve_entry_custom_payload(
            &target,
            &target_ctx,
            &conflict.conflict_id,
            &serde_json::json!({
                "username": "alice",
                "password": "merged-secret",
                "url": "https://old.example"
            }),
        )
        .unwrap();

        assert_eq!(resolved.resolution, ConflictResolution::Custom);
        assert!(resolved.resolved_at.is_some());
        assert!(ConflictRepo::list_unresolved(&target).unwrap().is_empty());

        let after = EntryRepo::get_by_id(&target, &entry_id).unwrap().unwrap();
        assert_ne!(after.head_commit_id, before.head_commit_id);
        assert_eq!(
            entry_payload_json(&target, &entry_id)["password"],
            "merged-secret"
        );
        assert!(
            ObjectVersionRepo::get_entry(&target, &entry_id, &after.head_commit_id)
                .unwrap()
                .is_some()
        );

        let parents = SyncApplyRepo::parent_ids_for_commit(&target, &after.head_commit_id).unwrap();
        assert!(parents.contains(&before.head_commit_id));
        assert!(parents.contains(&conflict.incoming_commit_id));

        drop(target);
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn remote_delete_local_modify_creates_conflict_without_losing_tombstone() {
        let (source_path, target_path, entry_id) =
            create_delete_modify_conflict("remote-delete-local-modify", true);
        let target = VaultConnection::open(&target_path).unwrap();

        let conflicts = ConflictRepo::list_unresolved(&target).unwrap();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].object_id, entry_id);
        assert_eq!(conflicts[0].conflicting_fields, vec!["deleted"]);

        let entry = EntryRepo::get_by_id(&target, &entry_id).unwrap().unwrap();
        assert!(!entry.deleted);
        assert_eq!(
            entry_payload_json(&target, &entry_id)["password"],
            "local-change"
        );

        let tombstone_count: i64 = target
            .inner()
            .query_row(
                "SELECT COUNT(*) FROM tombstones
                 WHERE target_object_type = 'entry' AND target_object_id = ?1",
                params![entry_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tombstone_count, 1);

        drop(target);
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn local_delete_remote_modify_creates_conflict_without_reviving_entry() {
        let (source_path, target_path, entry_id) =
            create_delete_modify_conflict("local-delete-remote-modify", false);
        let target = VaultConnection::open(&target_path).unwrap();

        let conflicts = ConflictRepo::list_unresolved(&target).unwrap();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].object_id, entry_id);
        assert_eq!(conflicts[0].conflicting_fields, vec!["deleted"]);

        let entry = EntryRepo::get_by_id(&target, &entry_id).unwrap().unwrap();
        assert!(entry.deleted);

        let tombstone_count: i64 = target
            .inner()
            .query_row(
                "SELECT COUNT(*) FROM tombstones
                 WHERE target_object_type = 'entry' AND target_object_id = ?1",
                params![entry_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tombstone_count, 1);

        drop(target);
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn resolved_conflict_sync_converges_delete_and_revival_tombstones() {
        for (label, remote_deletes, expected_deleted) in [
            ("resolved-revival", true, false),
            ("resolved-delete", false, true),
        ] {
            let (source_path, target_path, entry_id) =
                create_delete_modify_conflict(label, remote_deletes);
            let source = VaultConnection::open(&source_path).unwrap();
            let target = VaultConnection::open(&target_path).unwrap();
            let source_ctx = CommitContext::new("device-a".to_string());
            let target_ctx = CommitContext::new("device-b".to_string());
            let conflict = ConflictRepo::list_unresolved(&target).unwrap().remove(0);

            ConflictRepo::resolve_entry(
                &target,
                &target_ctx,
                &conflict.conflict_id,
                ConflictResolution::LocalWins,
            )
            .unwrap();
            let resolved = EntryRepo::get_by_id(&target, &entry_id).unwrap().unwrap();
            assert_eq!(resolved.deleted, expected_deleted);
            assert_eq!(
                entry_tombstone_count(&target, &entry_id),
                i64::from(expected_deleted)
            );
            assert!(ConflictRepo::list_unresolved(&target).unwrap().is_empty());

            let mut commits = serialized_commits_from(&target);
            attach_state_payload_to_commit(&target, &mut commits, &resolved.head_commit_id);
            let batch = CommitBatch::new(commits, 0, true);
            let result = SyncApplyRepo::apply_batch(&source, &source_ctx, &batch).unwrap();

            assert_eq!(result.conflict_count, 0);
            assert!(ConflictRepo::list_unresolved(&source).unwrap().is_empty());
            let synchronized = EntryRepo::get_by_id(&source, &entry_id).unwrap().unwrap();
            assert_eq!(synchronized.deleted, expected_deleted);
            assert_eq!(synchronized.head_commit_id, resolved.head_commit_id);
            assert_eq!(
                entry_tombstone_count(&source, &entry_id),
                i64::from(expected_deleted)
            );
            assert!(
                ObjectVersionRepo::get_entry(&source, &entry_id, &synchronized.head_commit_id)
                    .unwrap()
                    .is_some()
            );
            assert_eq!(
                SyncApplyRepo::current_branch_head(&source, None, "main")
                    .unwrap()
                    .as_deref(),
                Some(resolved.head_commit_id.as_str())
            );

            let repeated = SyncApplyRepo::apply_batch(&source, &source_ctx, &batch).unwrap();
            assert_eq!(repeated.conflict_count, 0);
            assert_eq!(
                EntryRepo::get_by_id(&source, &entry_id)
                    .unwrap()
                    .unwrap()
                    .head_commit_id,
                resolved.head_commit_id
            );
            assert_eq!(
                entry_tombstone_count(&source, &entry_id),
                i64::from(expected_deleted)
            );

            drop(source);
            drop(target);
            remove_vault_files(&source_path);
            remove_vault_files(&target_path);
        }
    }

    #[test]
    fn mutable_sync_apply_refreshes_keys_after_sequential_rotation() {
        let (source_path, target_path, base_project_id) =
            create_key_epoch_sync_pair("sequential-key-epoch");
        let mut source = VaultConnection::open(&source_path).unwrap();
        let mut target = VaultConnection::open(&target_path).unwrap();
        UnlockService::unlock_with_password(&mut source, "epoch sync password").unwrap();
        UnlockService::unlock_with_password(&mut target, "epoch sync password").unwrap();
        let source_ctx = CommitContext::new("device-a".to_string());
        let target_ctx = CommitContext::new("device-b".to_string());

        let rotation = rotate_epoch_for_sync(&mut source, &source_ctx, "device-a");
        let after =
            ProjectRepo::create(&source, &source_ctx, "After rotation", None, None).unwrap();
        let mut commits = serialized_commits_from(&source);
        attach_state_payload_to_commit(&source, &mut commits, &after.head_commit_id);

        let result = SyncApplyRepo::apply_batch_mut(
            &mut target,
            &target_ctx,
            &CommitBatch::new(commits, 0, true),
        )
        .unwrap();
        assert_eq!(result.conflict_count, 0);
        assert_eq!(
            target.active_key_epoch_id(),
            Some(rotation.active_epoch_id.as_str())
        );
        assert!(target
            .keyring_for_epoch(&rotation.previous_epoch_id)
            .is_some());
        assert!(target
            .keyring_for_epoch(&rotation.active_epoch_id)
            .is_some());
        assert_eq!(
            ProjectRepo::get_by_id(&target, &base_project_id)
                .unwrap()
                .unwrap()
                .title_ct,
            b"Base"
        );
        assert_eq!(
            ProjectRepo::get_by_id(&target, &after.project_id)
                .unwrap()
                .unwrap()
                .title_ct,
            b"After rotation"
        );

        drop(source);
        drop(target);
        remove_vault_files(&source_path);
        remove_vault_files(&target_path);
    }

    #[test]
    fn concurrent_rotations_converge_and_preserve_both_epoch_keys() {
        let (left_path, right_path, base_project_id) =
            create_key_epoch_sync_pair("concurrent-key-epoch");
        let mut left = VaultConnection::open(&left_path).unwrap();
        let mut right = VaultConnection::open(&right_path).unwrap();
        UnlockService::unlock_with_password(&mut left, "epoch sync password").unwrap();
        UnlockService::unlock_with_password(&mut right, "epoch sync password").unwrap();
        let left_ctx = CommitContext::new("device-a".to_string());
        let right_ctx = CommitContext::new("device-b".to_string());

        let left_rotation = rotate_epoch_for_sync(&mut left, &left_ctx, "device-a");
        let left_project = ProjectRepo::create(&left, &left_ctx, "Left epoch", None, None).unwrap();
        let right_rotation = rotate_epoch_for_sync(&mut right, &right_ctx, "device-b");
        let right_project =
            ProjectRepo::create(&right, &right_ctx, "Right epoch", None, None).unwrap();

        let mut left_commits = serialized_commits_from(&left);
        attach_state_payload_to_commit(&left, &mut left_commits, &left_project.head_commit_id);
        let mut right_commits = serialized_commits_from(&right);
        attach_state_payload_to_commit(&right, &mut right_commits, &right_project.head_commit_id);

        SyncApplyRepo::apply_batch_mut(
            &mut left,
            &left_ctx,
            &CommitBatch::new(right_commits, 0, true),
        )
        .unwrap();
        SyncApplyRepo::apply_batch_mut(
            &mut right,
            &right_ctx,
            &CommitBatch::new(left_commits, 0, true),
        )
        .unwrap();

        let expected_active = if (
            right_rotation.rotated_at.as_str(),
            right_rotation.active_epoch_id.as_str(),
        ) > (
            left_rotation.rotated_at.as_str(),
            left_rotation.active_epoch_id.as_str(),
        ) {
            right_rotation.active_epoch_id.as_str()
        } else {
            left_rotation.active_epoch_id.as_str()
        };
        assert_eq!(left.active_key_epoch_id(), Some(expected_active));
        assert_eq!(right.active_key_epoch_id(), Some(expected_active));
        for conn in [&left, &right] {
            assert!(conn
                .keyring_for_epoch(&left_rotation.active_epoch_id)
                .is_some());
            assert!(conn
                .keyring_for_epoch(&right_rotation.active_epoch_id)
                .is_some());
            let epoch_count: i64 = conn
                .inner()
                .query_row("SELECT COUNT(*) FROM key_epochs", [], |row| row.get(0))
                .unwrap();
            assert_eq!(epoch_count, 3);
            assert_eq!(
                ProjectRepo::get_by_id(conn, &base_project_id)
                    .unwrap()
                    .unwrap()
                    .title_ct,
                b"Base"
            );
            assert_eq!(
                ProjectRepo::get_by_id(conn, &left_project.project_id)
                    .unwrap()
                    .unwrap()
                    .title_ct,
                b"Left epoch"
            );
            assert_eq!(
                ProjectRepo::get_by_id(conn, &right_project.project_id)
                    .unwrap()
                    .unwrap()
                    .title_ct,
                b"Right epoch"
            );
        }

        drop(left);
        drop(right);
        remove_vault_files(&left_path);
        remove_vault_files(&right_path);
    }

    #[test]
    fn key_epoch_sync_rejects_immutable_unsigned_and_tampered_changes() {
        let (source_path, target_path, _) = create_key_epoch_sync_pair("rejected-key-epoch");
        let mut source = VaultConnection::open(&source_path).unwrap();
        let mut target = VaultConnection::open(&target_path).unwrap();
        UnlockService::unlock_with_password(&mut source, "epoch sync password").unwrap();
        UnlockService::unlock_with_password(&mut target, "epoch sync password").unwrap();
        let source_ctx = CommitContext::new("device-a".to_string());
        rotate_epoch_for_sync(&mut source, &source_ctx, "device-a");
        let incoming = collect_sync_state(&source)
            .unwrap()
            .key_epoch_state
            .unwrap();
        let original_active = target.active_key_epoch_id().unwrap().to_string();

        let immutable_error = key_epoch_apply::apply(
            &target,
            &incoming,
            key_epoch_apply::MergeMode::FastForward,
            false,
        )
        .unwrap_err();
        assert!(immutable_error.to_string().contains("mutable sync apply"));

        let mut unsigned = incoming.clone();
        unsigned.integrity_tag = None;
        let unsigned_error = key_epoch_apply::apply(
            &target,
            &unsigned,
            key_epoch_apply::MergeMode::FastForward,
            true,
        )
        .unwrap_err();
        assert!(unsigned_error.to_string().contains("integrity tag"));

        let mut tampered = incoming;
        tampered.integrity_tag.as_mut().unwrap()[0] ^= 1;
        let tampered_error = key_epoch_apply::apply(
            &target,
            &tampered,
            key_epoch_apply::MergeMode::FastForward,
            true,
        )
        .unwrap_err();
        assert!(tampered_error
            .to_string()
            .contains("integrity tag mismatch"));
        assert_eq!(target.active_key_epoch_id(), Some(original_active.as_str()));
        let database_active: String = target
            .inner()
            .query_row("SELECT active_key_epoch_id FROM vault_meta", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(database_active, original_active);

        drop(source);
        drop(target);
        remove_vault_files(&source_path);
        remove_vault_files(&target_path);
    }
}
