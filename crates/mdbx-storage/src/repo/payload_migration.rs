use std::collections::BTreeMap;

use mdbx_core::model::{
    payload_migration_digest, validate_payload_migration_outputs, ObjectTypeId,
    PayloadMigrationExecution, PayloadMigrationOutput, PayloadMigrationPlan,
    PayloadMigrationPlanItem, MAX_PAYLOAD_MIGRATION_ITEMS, MAX_PAYLOAD_MIGRATION_ITEM_BYTES,
    MAX_PAYLOAD_MIGRATION_TOTAL_BYTES,
};
use rusqlite::{params, OptionalExtension};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::connection::VaultConnection;
use crate::error::{StorageError, StorageResult};
use crate::repo::{
    BranchRepo, CollectionProfileRepo, CommitChange, CommitContext, CommitOperation, EntryRepo,
    OperationExecution,
};

#[derive(Debug, Clone)]
pub struct PayloadMigrationPlanRequest {
    pub collection_id: String,
    pub object_type_id: ObjectTypeId,
    pub source_schema_version: u32,
    pub target_schema_version: u32,
    pub max_items: usize,
    pub branch_id: Option<String>,
}

pub struct PayloadMigrationRepo;

impl PayloadMigrationRepo {
    pub fn create_plan(
        conn: &VaultConnection,
        request: PayloadMigrationPlanRequest,
    ) -> StorageResult<PayloadMigrationPlan> {
        validate_request(&request)?;
        conn.with_read_transaction(|| Self::create_plan_in_snapshot(conn, &request))
    }

    fn create_plan_in_snapshot(
        conn: &VaultConnection,
        request: &PayloadMigrationPlanRequest,
    ) -> StorageResult<PayloadMigrationPlan> {
        ensure_active_collection(conn, &request.collection_id)?;
        CollectionProfileRepo::ensure_object_write_allowed(
            conn,
            &request.collection_id,
            &request.object_type_id,
        )?;

        let branch = match request.branch_id.as_deref() {
            Some(branch_id) => BranchRepo::require_by_id(conn, branch_id)?,
            None => BranchRepo::resolve_unique_name(conn, "main")?,
        };
        let profile_digest = collection_profile_digest(conn, &request.collection_id)?;
        let total_matching = EntryRepo::count_for_payload_migration(
            conn,
            &request.collection_id,
            &request.object_type_id,
            request.source_schema_version,
        )?;
        let candidates = EntryRepo::list_for_payload_migration(
            conn,
            &request.collection_id,
            &request.object_type_id,
            request.source_schema_version,
            request.max_items,
        )?;

        let mut total_source_bytes = 0usize;
        let mut items = Vec::with_capacity(candidates.len());
        for entry in candidates {
            if entry.payload_ct.len() > MAX_PAYLOAD_MIGRATION_ITEM_BYTES {
                return Err(StorageError::ConstraintViolation(format!(
                    "object {} payload exceeds the {} byte migration item limit",
                    entry.entry_id, MAX_PAYLOAD_MIGRATION_ITEM_BYTES
                )));
            }
            let next_total = total_source_bytes
                .checked_add(entry.payload_ct.len())
                .ok_or_else(|| {
                    StorageError::ConstraintViolation(
                        "payload migration source byte count overflowed".to_string(),
                    )
                })?;
            if next_total > MAX_PAYLOAD_MIGRATION_TOTAL_BYTES {
                break;
            }
            total_source_bytes = next_total;
            items.push(PayloadMigrationPlanItem {
                object_id: entry.entry_id,
                object_head_commit_id: entry.head_commit_id,
                source_payload_digest: payload_migration_digest(&entry.payload_ct),
                source_payload: entry.payload_ct,
            });
        }
        if items.is_empty() {
            return Err(StorageError::NotFound(format!(
                "active objects in collection {} with type {} and payload schema version {}",
                request.collection_id, request.object_type_id, request.source_schema_version
            )));
        }

        let plan = PayloadMigrationPlan {
            plan_id: Uuid::new_v4().to_string(),
            collection_id: request.collection_id.clone(),
            object_type_id: request.object_type_id.clone(),
            source_schema_version: request.source_schema_version,
            target_schema_version: request.target_schema_version,
            branch_id: branch.branch_id,
            branch_name: branch.branch_name,
            branch_head_commit_id: branch.head_commit_id,
            collection_profile_digest: profile_digest,
            remaining_count: total_matching.saturating_sub(items.len() as u64),
            total_source_bytes: total_source_bytes as u64,
            items,
        };
        plan.validate().map_err(StorageError::Validation)?;
        Ok(plan)
    }

    pub fn execute(
        conn: &VaultConnection,
        ctx: &CommitContext,
        plan: &PayloadMigrationPlan,
        outputs: &[PayloadMigrationOutput],
    ) -> StorageResult<PayloadMigrationExecution> {
        validate_payload_migration_outputs(plan, outputs).map_err(StorageError::Validation)?;
        let intent_hash = migration_intent_hash(plan, outputs)?;
        let changed_objects = plan
            .items
            .iter()
            .map(|item| CommitChange {
                object_type: "entry".to_string(),
                object_id: item.object_id.clone(),
                action: "migrate-payload-schema".to_string(),
                fields: vec!["payload".to_string(), "payload_schema_version".to_string()],
            })
            .collect();
        let operation = CommitOperation::new(
            plan.plan_id.clone(),
            "payload-schema-migration",
            plan.branch_name.clone(),
            "change",
            "entry",
            changed_objects,
        )
        .with_branch_id(plan.branch_id.clone())
        .with_intent_hash(intent_hash)
        .with_message(format!(
            "Migrate {} payload schema {} to {}",
            plan.object_type_id, plan.source_schema_version, plan.target_schema_version
        ));

        let outputs_by_id = outputs
            .iter()
            .map(|output| (output.object_id.as_str(), output))
            .collect::<BTreeMap<_, _>>();
        let migrated_count = u32::try_from(plan.items.len()).map_err(|error| {
            StorageError::Validation(format!("migration item count is invalid: {error}"))
        })?;
        match ctx.run_operation(conn, operation, |operation_ctx| {
            validate_plan_bindings(conn, plan)?;

            let mut entries = Vec::with_capacity(plan.items.len());
            for item in &plan.items {
                let entry = EntryRepo::get_by_id(conn, &item.object_id)?
                    .ok_or_else(|| StorageError::NotFound(item.object_id.clone()))?;
                validate_entry_binding(plan, item, &entry)?;
                entries.push(entry);
            }

            for mut entry in entries {
                let output = outputs_by_id.get(entry.entry_id.as_str()).ok_or_else(|| {
                    StorageError::Validation(format!(
                        "missing migration output for object {}",
                        entry.entry_id
                    ))
                })?;
                entry.payload_ct.clone_from(&output.target_payload);
                entry.payload_schema_version = plan.target_schema_version;
                EntryRepo::update(conn, operation_ctx, &entry)?;
            }
            Ok(())
        })? {
            OperationExecution::Applied { commit_id, .. } => Ok(PayloadMigrationExecution {
                commit_id,
                migrated_count,
                already_committed: false,
            }),
            OperationExecution::AlreadyCommitted { commit_id } => Ok(PayloadMigrationExecution {
                commit_id,
                migrated_count,
                already_committed: true,
            }),
        }
    }
}

fn validate_request(request: &PayloadMigrationPlanRequest) -> StorageResult<()> {
    if request.collection_id.trim().is_empty() {
        return Err(StorageError::Validation(
            "payload migration requires a collection ID".to_string(),
        ));
    }
    request
        .object_type_id
        .validate()
        .map_err(StorageError::Validation)?;
    if request.source_schema_version == 0 || request.target_schema_version == 0 {
        return Err(StorageError::Validation(
            "payload schema versions must be greater than zero".to_string(),
        ));
    }
    if request.target_schema_version <= request.source_schema_version {
        return Err(StorageError::Validation(
            "target payload schema version must advance the source version".to_string(),
        ));
    }
    if request.max_items == 0 || request.max_items > MAX_PAYLOAD_MIGRATION_ITEMS {
        return Err(StorageError::Validation(format!(
            "payload migration max_items must be between 1 and {MAX_PAYLOAD_MIGRATION_ITEMS}"
        )));
    }
    if request
        .branch_id
        .as_deref()
        .is_some_and(|branch_id| branch_id.trim().is_empty())
    {
        return Err(StorageError::Validation(
            "payload migration branch ID must not be empty".to_string(),
        ));
    }
    Ok(())
}

fn validate_plan_bindings(
    conn: &VaultConnection,
    plan: &PayloadMigrationPlan,
) -> StorageResult<()> {
    plan.validate().map_err(StorageError::Validation)?;
    ensure_active_collection(conn, &plan.collection_id)?;
    CollectionProfileRepo::ensure_object_write_allowed(
        conn,
        &plan.collection_id,
        &plan.object_type_id,
    )?;
    let branch = BranchRepo::require_by_id(conn, &plan.branch_id)?;
    if branch.branch_name != plan.branch_name || branch.head_commit_id != plan.branch_head_commit_id
    {
        return Err(StorageError::ConstraintViolation(format!(
            "payload migration plan {} is stale because branch {} changed",
            plan.plan_id, plan.branch_id
        )));
    }
    if collection_profile_digest(conn, &plan.collection_id)? != plan.collection_profile_digest {
        return Err(StorageError::ConstraintViolation(format!(
            "payload migration plan {} is stale because collection {} profile changed",
            plan.plan_id, plan.collection_id
        )));
    }
    Ok(())
}

fn validate_entry_binding(
    plan: &PayloadMigrationPlan,
    item: &PayloadMigrationPlanItem,
    entry: &mdbx_core::model::Entry,
) -> StorageResult<()> {
    let matches = !entry.deleted
        && entry.project_id == plan.collection_id
        && entry.entry_type == plan.object_type_id
        && entry.payload_schema_version == plan.source_schema_version
        && entry.head_commit_id == item.object_head_commit_id
        && payload_migration_digest(&entry.payload_ct) == item.source_payload_digest;
    if !matches {
        return Err(StorageError::ConstraintViolation(format!(
            "payload migration plan {} is stale for object {}",
            plan.plan_id, item.object_id
        )));
    }
    Ok(())
}

fn ensure_active_collection(conn: &VaultConnection, collection_id: &str) -> StorageResult<()> {
    let active = conn
        .inner()
        .query_row(
            "SELECT deleted = 0 FROM projects WHERE project_id = ?1",
            params![collection_id],
            |row| row.get::<_, bool>(0),
        )
        .optional()?;
    match active {
        Some(true) => Ok(()),
        Some(false) => Err(StorageError::ConstraintViolation(format!(
            "collection {collection_id} is deleted"
        ))),
        None => Err(StorageError::NotFound(collection_id.to_string())),
    }
}

fn collection_profile_digest(
    conn: &VaultConnection,
    collection_id: &str,
) -> StorageResult<Option<Vec<u8>>> {
    let Some(profile) = CollectionProfileRepo::get_by_collection_id(conn, collection_id)? else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(&profile)
        .map_err(|error| StorageError::SchemaCreation(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(b"mdbx-collection-profile-migration-binding-v1");
    hasher.update((encoded.len() as u64).to_le_bytes());
    hasher.update(encoded);
    Ok(Some(hasher.finalize().to_vec()))
}

fn migration_intent_hash(
    plan: &PayloadMigrationPlan,
    outputs: &[PayloadMigrationOutput],
) -> StorageResult<Vec<u8>> {
    let mut canonical_outputs = outputs.to_vec();
    canonical_outputs.sort_by(|left, right| left.object_id.cmp(&right.object_id));
    let encoded = serde_json::to_vec(&(plan, canonical_outputs))
        .map_err(|error| StorageError::SchemaCreation(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(b"mdbx-payload-migration-intent-v1");
    hasher.update((encoded.len() as u64).to_le_bytes());
    hasher.update(encoded);
    Ok(hasher.finalize().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdbx_core::model::{CollectionTypeId, ExtensionCapabilityId};
    use serde_json::json;

    use crate::init::{initialize_vault, VaultInitParams};
    use crate::repo::{CollectionProfileSpec, CommitHistoryRepo, ProjectRepo};

    fn setup() -> (VaultConnection, CommitContext, String, ObjectTypeId) {
        let mut conn = VaultConnection::open_in_memory().unwrap();
        initialize_vault(
            &conn,
            &VaultInitParams {
                device_id: "device-a".to_string(),
                ..Default::default()
            },
        )
        .unwrap();
        let ctx = CommitContext::new("device-a".to_string());
        let collection = ProjectRepo::create(&conn, &ctx, "Mail", None, None).unwrap();
        let object_type = ObjectTypeId::custom("com.monica.mail.message").unwrap();
        let capability = ExtensionCapabilityId::new("com.monica.mail.payload-v2").unwrap();
        conn.set_extension_capabilities([capability.clone()]);
        CollectionProfileRepo::set(
            &conn,
            &ctx,
            CollectionProfileSpec {
                collection_id: collection.project_id.clone(),
                collection_type_id: CollectionTypeId::new("com.monica.mail").unwrap(),
                payload: b"profile".to_vec(),
                payload_schema_version: 1,
                allowed_object_type_ids: vec![object_type.clone()],
                required_capability_ids: vec![capability],
            },
        )
        .unwrap();
        for index in 0..2 {
            EntryRepo::create_with_payload_schema_version(
                &conn,
                &ctx,
                &collection.project_id,
                object_type.clone(),
                Some(&format!("Message {index}")),
                &json!({"version": 1, "index": index}),
                1,
            )
            .unwrap();
        }
        (conn, ctx, collection.project_id, object_type)
    }

    fn plan(
        conn: &VaultConnection,
        collection_id: &str,
        object_type_id: ObjectTypeId,
        max_items: usize,
    ) -> PayloadMigrationPlan {
        PayloadMigrationRepo::create_plan(
            conn,
            PayloadMigrationPlanRequest {
                collection_id: collection_id.to_string(),
                object_type_id,
                source_schema_version: 1,
                target_schema_version: 2,
                max_items,
                branch_id: None,
            },
        )
        .unwrap()
    }

    fn outputs(plan: &PayloadMigrationPlan) -> Vec<PayloadMigrationOutput> {
        plan.items
            .iter()
            .map(|item| PayloadMigrationOutput {
                object_id: item.object_id.clone(),
                target_payload: json!({"version": 2, "migrated": item.object_id})
                    .to_string()
                    .into_bytes(),
            })
            .collect()
    }

    #[test]
    fn bounded_plan_reports_remaining_objects() {
        let (conn, _ctx, collection_id, object_type) = setup();
        let plan = plan(&conn, &collection_id, object_type, 1);

        assert_eq!(plan.items.len(), 1);
        assert_eq!(plan.remaining_count, 1);
        assert_eq!(
            plan.total_source_bytes,
            plan.items[0].source_payload.len() as u64
        );
        plan.validate().unwrap();
    }

    #[test]
    fn batch_migration_uses_one_commit_and_is_idempotent() {
        let (conn, ctx, collection_id, object_type) = setup();
        let plan = plan(&conn, &collection_id, object_type.clone(), 2);
        let outputs = outputs(&plan);

        let applied = PayloadMigrationRepo::execute(&conn, &ctx, &plan, &outputs).unwrap();
        assert_eq!(applied.migrated_count, 2);
        assert!(!applied.already_committed);
        for item in &plan.items {
            let entry = EntryRepo::get_by_id(&conn, &item.object_id)
                .unwrap()
                .unwrap();
            assert_eq!(entry.payload_schema_version, 2);
            assert_eq!(entry.head_commit_id, applied.commit_id);
        }
        let history = CommitHistoryRepo::get(&conn, &applied.commit_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            history.operation_kind.as_deref(),
            Some("payload-schema-migration")
        );
        assert_eq!(history.changes.len(), 2);
        assert!(history.changes.iter().all(|change| {
            change.action == "migrate-payload-schema"
                && change.fields == ["payload", "payload_schema_version"]
        }));

        let repeated = PayloadMigrationRepo::execute(&conn, &ctx, &plan, &outputs).unwrap();
        assert!(repeated.already_committed);
        assert_eq!(repeated.commit_id, applied.commit_id);
        assert!(PayloadMigrationRepo::create_plan(
            &conn,
            PayloadMigrationPlanRequest {
                collection_id,
                object_type_id: object_type,
                source_schema_version: 1,
                target_schema_version: 2,
                max_items: 2,
                branch_id: None,
            }
        )
        .is_err());
    }

    #[test]
    fn stale_plan_rolls_back_every_object() {
        let (conn, ctx, collection_id, object_type) = setup();
        let plan = plan(&conn, &collection_id, object_type, 2);
        let mut changed = EntryRepo::get_by_id(&conn, &plan.items[0].object_id)
            .unwrap()
            .unwrap();
        changed.payload_ct = b"concurrent-change".to_vec();
        EntryRepo::update(&conn, &ctx, &changed).unwrap();

        assert!(PayloadMigrationRepo::execute(&conn, &ctx, &plan, &outputs(&plan)).is_err());
        let untouched = EntryRepo::get_by_id(&conn, &plan.items[1].object_id)
            .unwrap()
            .unwrap();
        assert_eq!(untouched.payload_schema_version, 1);
    }

    #[test]
    fn missing_adapter_capability_rejects_plan_and_execution() {
        let (mut conn, ctx, collection_id, object_type) = setup();
        let plan = plan(&conn, &collection_id, object_type.clone(), 2);
        conn.set_extension_capabilities(Vec::<ExtensionCapabilityId>::new());

        assert!(matches!(
            PayloadMigrationRepo::create_plan(
                &conn,
                PayloadMigrationPlanRequest {
                    collection_id,
                    object_type_id: object_type,
                    source_schema_version: 1,
                    target_schema_version: 2,
                    max_items: 2,
                    branch_id: None,
                }
            ),
            Err(StorageError::MissingExtensionCapabilities { .. })
        ));
        assert!(matches!(
            PayloadMigrationRepo::execute(&conn, &ctx, &plan, &outputs(&plan)),
            Err(StorageError::MissingExtensionCapabilities { .. })
        ));
    }
}
