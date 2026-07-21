use mdbx_core::model::{
    CollectionProfile, CollectionTypeId, ExtensionCapabilityId, PayloadMigrationOutput,
};
use mdbx_storage::repo::{
    CollectionProfileRepo, CollectionProfileSpec, CommitContext, PayloadMigrationPlanRequest,
    PayloadMigrationRepo,
};

use super::{
    parse_object_type_id, MdbxCollectionProfile, MdbxFfiError, MdbxPayloadMigrationExecution,
    MdbxPayloadMigrationOutput, MdbxPayloadMigrationPlan, MdbxVault,
};

#[uniffi::export]
impl MdbxVault {
    pub fn set_extension_capabilities(
        &self,
        capability_ids: Vec<String>,
    ) -> Result<(), MdbxFfiError> {
        let capabilities = capability_ids
            .iter()
            .map(|capability_id| parse_extension_capability_id(capability_id))
            .collect::<Result<Vec<_>, _>>()?;
        let mut conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        conn.set_extension_capabilities(capabilities);
        Ok(())
    }

    pub fn get_collection_profile(
        &self,
        collection_id: String,
    ) -> Result<Option<MdbxCollectionProfile>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(
            CollectionProfileRepo::get_by_collection_id(&conn, &collection_id)?
                .map(collection_profile_from_core),
        )
    }

    pub fn set_collection_profile(
        &self,
        collection_id: String,
        collection_type_id: String,
        payload: Vec<u8>,
        payload_schema_version: u32,
        allowed_object_type_ids: Vec<String>,
        required_capability_ids: Vec<String>,
    ) -> Result<MdbxCollectionProfile, MdbxFfiError> {
        let allowed_object_type_ids = allowed_object_type_ids
            .iter()
            .map(|object_type_id| parse_object_type_id(object_type_id))
            .collect::<Result<Vec<_>, _>>()?;
        let required_capability_ids = required_capability_ids
            .iter()
            .map(|capability_id| parse_extension_capability_id(capability_id))
            .collect::<Result<Vec<_>, _>>()?;
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let ctx = CommitContext::new(self.device_id.clone());
        let profile = CollectionProfileRepo::set(
            &conn,
            &ctx,
            CollectionProfileSpec {
                collection_id,
                collection_type_id: parse_collection_type_id(&collection_type_id)?,
                payload,
                payload_schema_version,
                allowed_object_type_ids,
                required_capability_ids,
            },
        )?;
        Ok(collection_profile_from_core(profile))
    }

    /// Build a bounded Adapter payload migration plan. The returned payloads
    /// are decrypted bytes; the Adapter owns their interpretation and
    /// conversion, while storage rechecks every binding during execution.
    pub fn create_payload_migration_plan(
        &self,
        collection_id: String,
        object_type_id: String,
        source_schema_version: u32,
        target_schema_version: u32,
        max_items: u32,
        branch_id: Option<String>,
    ) -> Result<MdbxPayloadMigrationPlan, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(PayloadMigrationRepo::create_plan(
            &conn,
            PayloadMigrationPlanRequest {
                collection_id,
                object_type_id: parse_object_type_id(&object_type_id)?,
                source_schema_version,
                target_schema_version,
                max_items: max_items as usize,
                branch_id,
            },
        )?
        .into())
    }

    /// Apply Adapter-produced payloads as one idempotent user operation.
    pub fn execute_payload_migration(
        &self,
        plan: MdbxPayloadMigrationPlan,
        outputs: Vec<MdbxPayloadMigrationOutput>,
    ) -> Result<MdbxPayloadMigrationExecution, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let plan = plan.into_core()?;
        let outputs = outputs
            .into_iter()
            .map(|output| PayloadMigrationOutput {
                object_id: output.object_id,
                target_payload: output.target_payload,
            })
            .collect::<Vec<_>>();
        let ctx = CommitContext::new(self.device_id.clone());
        Ok(PayloadMigrationRepo::execute(&conn, &ctx, &plan, &outputs)?.into())
    }
}

fn parse_collection_type_id(collection_type_id: &str) -> Result<CollectionTypeId, MdbxFfiError> {
    collection_type_id
        .parse()
        .map_err(|_| MdbxFfiError::InvalidCollectionTypeId {
            collection_type_id: collection_type_id.to_string(),
        })
}

fn parse_extension_capability_id(
    capability_id: &str,
) -> Result<ExtensionCapabilityId, MdbxFfiError> {
    capability_id
        .parse()
        .map_err(|_| MdbxFfiError::InvalidExtensionCapabilityId {
            capability_id: capability_id.to_string(),
        })
}

fn collection_profile_from_core(profile: CollectionProfile) -> MdbxCollectionProfile {
    MdbxCollectionProfile {
        collection_id: profile.collection_id,
        collection_type_id: profile.collection_type_id.to_string(),
        payload: profile.payload_ct,
        payload_schema_version: profile.payload_schema_version,
        allowed_object_type_ids: profile
            .allowed_object_type_ids
            .into_iter()
            .map(|object_type| object_type.to_string())
            .collect(),
        required_capability_ids: profile
            .required_capability_ids
            .into_iter()
            .map(|capability| capability.to_string())
            .collect(),
        created_at: profile.created_at,
        updated_at: profile.updated_at,
        created_by_device_id: profile.created_by_device_id,
        updated_by_device_id: profile.updated_by_device_id,
    }
}
