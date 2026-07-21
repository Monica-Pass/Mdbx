use mdbx_storage::error::StorageError;
use mdbx_storage::repo::{
    CommitContext, EntryRepo, ObjectLabelAssignmentCreateRequest, ObjectLabelAssignmentRepo,
    ObjectLabelCreateRequest, ObjectLabelRepo, ObjectRelationCreateRequest, ObjectRelationRepo,
    ObjectSummaryRepo, ProjectRepo,
};

use super::{
    entry_for_project, entry_record_from_entry, object_label_assignment_record,
    object_label_record, object_record_from_entry, object_relation_record,
    object_summary_from_core, parse_entry_type, parse_object_type_id, parse_optional_entry_type,
    parse_optional_object_type_id, parse_payload_json, parse_relation_kind, EntryRecord,
    MdbxFfiError, MdbxObjectLabelAssignmentRecord, MdbxObjectLabelRecord, MdbxObjectRecord,
    MdbxObjectRelationRecord, MdbxObjectSummaryPage, MdbxVault, ProjectRecord,
};

#[uniffi::export]
impl MdbxVault {
    pub fn create_project(&self, title: String) -> Result<ProjectRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let ctx = CommitContext::new(self.device_id.clone());
        let project = ProjectRepo::create(&conn, &ctx, &title, None, None)?;
        Ok(ProjectRecord {
            project_id: project.project_id,
            title: String::from_utf8_lossy(&project.title_ct).to_string(),
        })
    }

    pub fn create_entry(
        &self,
        project_id: String,
        entry_type: String,
        title: String,
        payload_json: String,
    ) -> Result<EntryRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let ctx = CommitContext::new(self.device_id.clone());
        let payload = parse_payload_json(&payload_json)?;
        let entry = EntryRepo::create(
            &conn,
            &ctx,
            &project_id,
            parse_entry_type(&entry_type)?,
            Some(&title),
            &payload,
        )?;
        entry_record_from_entry(&entry)
    }

    pub fn create_object(
        &self,
        collection_id: String,
        object_type_id: String,
        title: String,
        payload_json: String,
        payload_schema_version: u32,
    ) -> Result<MdbxObjectRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let ctx = CommitContext::new(self.device_id.clone());
        let payload = parse_payload_json(&payload_json)?;
        let object = EntryRepo::create_with_payload_schema_version(
            &conn,
            &ctx,
            &collection_id,
            parse_object_type_id(&object_type_id)?,
            Some(&title),
            &payload,
            payload_schema_version,
        )?;
        object_record_from_entry(&object)
    }

    pub fn get_object(
        &self,
        collection_id: String,
        object_id: String,
    ) -> Result<Option<MdbxObjectRecord>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let Some(object) = EntryRepo::get_by_id(&conn, &object_id)? else {
            return Ok(None);
        };
        if object.project_id != collection_id {
            return Ok(None);
        }
        Ok(Some(object_record_from_entry(&object)?))
    }

    pub fn list_objects(
        &self,
        collection_id: String,
        object_type_id: Option<String>,
    ) -> Result<Vec<MdbxObjectRecord>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let object_type_id = parse_optional_object_type_id(object_type_id)?;
        let objects = match object_type_id {
            Some(object_type_id) => {
                EntryRepo::list_by_project_and_type(&conn, &collection_id, object_type_id)?
            }
            None => EntryRepo::list_by_project(&conn, &collection_id)?,
        };
        objects.iter().map(object_record_from_entry).collect()
    }

    pub fn list_object_summaries(
        &self,
        collection_id: String,
        object_type_id: Option<String>,
        page_size: u32,
        cursor: Option<String>,
    ) -> Result<MdbxObjectSummaryPage, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let object_type_id = parse_optional_object_type_id(object_type_id)?;
        let page = ObjectSummaryRepo::list(
            &conn,
            &collection_id,
            object_type_id.as_ref(),
            page_size as usize,
            cursor.as_deref(),
        )?;
        Ok(MdbxObjectSummaryPage {
            items: page
                .items
                .into_iter()
                .map(object_summary_from_core)
                .collect(),
            next_cursor: page.next_cursor,
        })
    }

    pub fn update_object(
        &self,
        collection_id: String,
        object_id: String,
        object_type_id: String,
        title: String,
        payload_json: String,
        payload_schema_version: u32,
    ) -> Result<MdbxObjectRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let expected_type = parse_object_type_id(&object_type_id)?;
        let mut object = entry_for_project(&conn, &collection_id, &object_id)?;
        if object.deleted {
            return Err(StorageError::ConstraintViolation(format!(
                "object {} is deleted",
                object_id
            ))
            .into());
        }
        if object.entry_type != expected_type {
            return Err(StorageError::ConstraintViolation(format!(
                "object {} does not have type {}",
                object_id, object_type_id
            ))
            .into());
        }

        object.title_ct = Some(title.into_bytes());
        object.payload_ct = serde_json::to_vec(&parse_payload_json(&payload_json)?)?;
        object.payload_schema_version = payload_schema_version;

        let ctx = CommitContext::new(self.device_id.clone());
        let updated = EntryRepo::update(&conn, &ctx, &object)?;
        object_record_from_entry(&updated)
    }

    pub fn create_object_relation(
        &self,
        source_object_id: String,
        target_object_id: String,
        relation_kind: String,
        payload_json: String,
        payload_schema_version: u32,
    ) -> Result<MdbxObjectRelationRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let ctx = CommitContext::new(self.device_id.clone());
        let relation = ObjectRelationRepo::create(
            &conn,
            &ctx,
            ObjectRelationCreateRequest::new(
                source_object_id,
                target_object_id,
                parse_relation_kind(&relation_kind)?,
                parse_payload_json(&payload_json)?,
            )
            .with_payload_schema_version(payload_schema_version),
        )?;
        object_relation_record(&relation)
    }

    pub fn get_object_relation(
        &self,
        relation_id: String,
    ) -> Result<Option<MdbxObjectRelationRecord>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        ObjectRelationRepo::get_by_id(&conn, &relation_id)?
            .as_ref()
            .map(object_relation_record)
            .transpose()
    }

    pub fn list_object_relations_from(
        &self,
        source_object_id: String,
        relation_kind: Option<String>,
    ) -> Result<Vec<MdbxObjectRelationRecord>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let kind = relation_kind
            .as_deref()
            .map(parse_relation_kind)
            .transpose()?;
        ObjectRelationRepo::list_from_object(&conn, &source_object_id, kind.as_ref())?
            .iter()
            .map(object_relation_record)
            .collect()
    }

    pub fn list_object_relations_to(
        &self,
        target_object_id: String,
        relation_kind: Option<String>,
    ) -> Result<Vec<MdbxObjectRelationRecord>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let kind = relation_kind
            .as_deref()
            .map(parse_relation_kind)
            .transpose()?;
        ObjectRelationRepo::list_to_object(&conn, &target_object_id, kind.as_ref())?
            .iter()
            .map(object_relation_record)
            .collect()
    }

    pub fn update_object_relation(
        &self,
        relation_id: String,
        relation_kind: String,
        payload_json: String,
        payload_schema_version: u32,
    ) -> Result<MdbxObjectRelationRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let mut relation = ObjectRelationRepo::get_by_id(&conn, &relation_id)?
            .ok_or_else(|| StorageError::NotFound(relation_id.clone()))?;
        relation.relation_kind = parse_relation_kind(&relation_kind)?;
        relation.payload_ct = serde_json::to_vec(&parse_payload_json(&payload_json)?)?;
        relation.payload_schema_version = payload_schema_version;
        let ctx = CommitContext::new(self.device_id.clone());
        object_relation_record(&ObjectRelationRepo::update(&conn, &ctx, &relation)?)
    }

    pub fn delete_object_relation(&self, relation_id: String) -> Result<(), MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        ObjectRelationRepo::soft_delete(
            &conn,
            &CommitContext::new(self.device_id.clone()),
            &relation_id,
        )?;
        Ok(())
    }

    pub fn create_object_label(
        &self,
        collection_id: String,
        name: String,
        payload_json: String,
        payload_schema_version: u32,
    ) -> Result<MdbxObjectLabelRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let label = ObjectLabelRepo::create(
            &conn,
            &CommitContext::new(self.device_id.clone()),
            ObjectLabelCreateRequest::new(collection_id, name, parse_payload_json(&payload_json)?)
                .with_payload_schema_version(payload_schema_version),
        )?;
        object_label_record(&label)
    }

    pub fn list_object_labels(
        &self,
        collection_id: String,
    ) -> Result<Vec<MdbxObjectLabelRecord>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        ObjectLabelRepo::list_by_collection(&conn, &collection_id)?
            .iter()
            .map(object_label_record)
            .collect()
    }

    pub fn update_object_label(
        &self,
        label_id: String,
        name: String,
        payload_json: String,
        payload_schema_version: u32,
    ) -> Result<MdbxObjectLabelRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let mut label = ObjectLabelRepo::get_by_id(&conn, &label_id)?
            .ok_or_else(|| StorageError::NotFound(label_id.clone()))?;
        label.name_ct = name.into_bytes();
        label.payload_ct = serde_json::to_vec(&parse_payload_json(&payload_json)?)?;
        label.payload_schema_version = payload_schema_version;
        object_label_record(&ObjectLabelRepo::update(
            &conn,
            &CommitContext::new(self.device_id.clone()),
            &label,
        )?)
    }

    pub fn delete_object_label(&self, label_id: String) -> Result<(), MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        ObjectLabelRepo::soft_delete(
            &conn,
            &CommitContext::new(self.device_id.clone()),
            &label_id,
        )?;
        Ok(())
    }

    pub fn assign_object_label(
        &self,
        object_id: String,
        label_id: String,
    ) -> Result<MdbxObjectLabelAssignmentRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(object_label_assignment_record(
            &ObjectLabelAssignmentRepo::create(
                &conn,
                &CommitContext::new(self.device_id.clone()),
                ObjectLabelAssignmentCreateRequest::new(object_id, label_id),
            )?,
        ))
    }

    pub fn list_object_label_assignments(
        &self,
        object_id: String,
    ) -> Result<Vec<MdbxObjectLabelAssignmentRecord>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(
            ObjectLabelAssignmentRepo::list_by_object(&conn, &object_id)?
                .iter()
                .map(object_label_assignment_record)
                .collect(),
        )
    }

    pub fn remove_object_label_assignment(
        &self,
        assignment_id: String,
    ) -> Result<(), MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        ObjectLabelAssignmentRepo::soft_delete(
            &conn,
            &CommitContext::new(self.device_id.clone()),
            &assignment_id,
        )?;
        Ok(())
    }

    pub fn list_entries(
        &self,
        project_id: String,
        entry_type: Option<String>,
    ) -> Result<Vec<EntryRecord>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let entry_type = parse_optional_entry_type(entry_type)?;
        let entries = match entry_type {
            Some(entry_type) => {
                EntryRepo::list_by_project_and_type(&conn, &project_id, entry_type)?
            }
            None => EntryRepo::list_by_project(&conn, &project_id)?,
        };
        entries.iter().map(entry_record_from_entry).collect()
    }

    pub fn list_deleted_entries(
        &self,
        project_id: String,
        entry_type: Option<String>,
    ) -> Result<Vec<EntryRecord>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let entry_type = parse_optional_entry_type(entry_type)?;
        let entries = match entry_type {
            Some(entry_type) => {
                EntryRepo::list_deleted_by_project_and_type(&conn, &project_id, entry_type)?
            }
            None => EntryRepo::list_deleted_by_project(&conn, &project_id)?,
        };
        entries.iter().map(entry_record_from_entry).collect()
    }

    pub fn update_entry(
        &self,
        project_id: String,
        entry_id: String,
        entry_type: String,
        title: String,
        payload_json: String,
    ) -> Result<EntryRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let expected_type = parse_entry_type(&entry_type)?;
        let mut entry = entry_for_project(&conn, &project_id, &entry_id)?;
        if entry.deleted {
            return Err(StorageError::ConstraintViolation(format!(
                "entry {} is deleted",
                entry_id
            ))
            .into());
        }
        if entry.entry_type != expected_type {
            return Err(StorageError::ConstraintViolation(format!(
                "entry {} is not a {} entry",
                entry_id, entry_type
            ))
            .into());
        }

        entry.title_ct = Some(title.into_bytes());
        entry.payload_ct = serde_json::to_vec(&parse_payload_json(&payload_json)?)?;

        let ctx = CommitContext::new(self.device_id.clone());
        let updated = EntryRepo::update(&conn, &ctx, &entry)?;
        entry_record_from_entry(&updated)
    }

    pub fn delete_entry(&self, project_id: String, entry_id: String) -> Result<(), MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let entry = entry_for_project(&conn, &project_id, &entry_id)?;
        if entry.deleted {
            return Err(StorageError::ConstraintViolation(format!(
                "entry {} is already deleted",
                entry_id
            ))
            .into());
        }

        let ctx = CommitContext::new(self.device_id.clone());
        EntryRepo::soft_delete(&conn, &ctx, &entry_id)?;
        Ok(())
    }

    pub fn restore_entry(
        &self,
        project_id: String,
        entry_id: String,
    ) -> Result<EntryRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let entry = entry_for_project(&conn, &project_id, &entry_id)?;
        if !entry.deleted {
            return Err(StorageError::ConstraintViolation(format!(
                "entry {} is not deleted",
                entry_id
            ))
            .into());
        }

        let ctx = CommitContext::new(self.device_id.clone());
        let restored = EntryRepo::restore(&conn, &ctx, &entry_id)?;
        entry_record_from_entry(&restored)
    }

    pub fn move_entry(
        &self,
        project_id: String,
        entry_id: String,
        target_project_id: String,
    ) -> Result<EntryRecord, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let entry = entry_for_project(&conn, &project_id, &entry_id)?;
        if entry.deleted {
            return Err(StorageError::ConstraintViolation(format!(
                "entry {} is deleted",
                entry_id
            ))
            .into());
        }

        let ctx = CommitContext::new(self.device_id.clone());
        let moved = EntryRepo::move_to_project(&conn, &ctx, &entry_id, &target_project_id)?;
        entry_record_from_entry(&moved)
    }
}
