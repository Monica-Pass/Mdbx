use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::blob_lifecycle::{
    collect_external_blob_references, collect_provider_inventory, BlobLifecycleLimits,
    ExternalBlobReferenceInventory, MAX_BLOB_LIFECYCLE_ITEMS,
};
use crate::blob_store::{
    validate_blob_id, EncryptedBlobMetadata, ManageableEncryptedBlobStore, MAX_BLOB_PAGE_SIZE,
};
use crate::connection::VaultConnection;
use crate::error::{StorageError, StorageResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobReplicaPageRequest {
    pub cursor: Option<String>,
    pub checkpoint: Option<String>,
    pub page_size: usize,
    pub limits: BlobLifecycleLimits,
}

impl BlobReplicaPageRequest {
    pub fn new(
        cursor: Option<String>,
        checkpoint: Option<String>,
        page_size: usize,
        limits: BlobLifecycleLimits,
    ) -> StorageResult<Self> {
        limits.validate()?;
        if !(1..=MAX_BLOB_PAGE_SIZE).contains(&page_size) {
            return Err(StorageError::Validation(format!(
                "Blob replica page size must be between 1 and {MAX_BLOB_PAGE_SIZE}"
            )));
        }
        if let Some(cursor) = cursor.as_deref() {
            validate_blob_id(cursor)?;
            if checkpoint.is_none() {
                return Err(StorageError::Validation(
                    "Blob replica cursor requires a plan checkpoint".to_string(),
                ));
            }
        }
        if let Some(checkpoint) = checkpoint.as_deref() {
            validate_blob_id(checkpoint).map_err(|_| {
                StorageError::Validation(
                    "Blob replica checkpoint must be a SHA-256 hex digest".to_string(),
                )
            })?;
        }
        Ok(Self {
            cursor,
            checkpoint,
            page_size,
            limits,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlobReplicaState {
    TransferRequired,
    SourceMissing,
    SourceSizeInvalid,
    DestinationConflict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobReplicaItem {
    pub blob_id: String,
    pub declared_max_bytes: u64,
    pub source_size: Option<u64>,
    pub destination_size: Option<u64>,
    pub state: BlobReplicaState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobReplicaPage {
    pub plan_token: String,
    pub source_namespace_id: String,
    pub destination_namespace_id: String,
    pub raw_reference_count: usize,
    pub unique_reference_count: usize,
    pub items: Vec<BlobReplicaItem>,
    pub next_cursor: Option<String>,
}

pub struct BlobReplicaService;

impl BlobReplicaService {
    pub fn page(
        conn: &VaultConnection,
        source: &dyn ManageableEncryptedBlobStore,
        destination: &dyn ManageableEncryptedBlobStore,
        request: BlobReplicaPageRequest,
    ) -> StorageResult<BlobReplicaPage> {
        request.limits.validate()?;
        if conn.keyring().is_none() {
            return Err(StorageError::Validation(
                "Blob replica planning requires an unlocked encrypted vault".to_string(),
            ));
        }
        let source_namespace_id = validate_namespace(source.namespace_id()?)?;
        let destination_namespace_id = validate_namespace(destination.namespace_id()?)?;
        if source_namespace_id == destination_namespace_id {
            return Err(StorageError::Validation(
                "Blob replica source and destination namespaces must differ".to_string(),
            ));
        }
        let references = collect_external_blob_references(conn, request.limits)?;
        let source_inventory = collect_provider_inventory(source, request.limits)?;
        let destination_inventory = collect_provider_inventory(destination, request.limits)?;
        let vault_id = vault_id(conn)?;
        let plan_token = compute_plan_token(
            &vault_id,
            &source_namespace_id,
            &destination_namespace_id,
            &references,
            &source_inventory,
            &destination_inventory,
        );
        if let Some(expected) = request.checkpoint.as_deref() {
            if expected != plan_token {
                return Err(StorageError::ConstraintViolation(
                    "Blob replica plan changed; create a new checkpoint".to_string(),
                ));
            }
        }

        let mut actionable = Vec::new();
        for (blob_id, maximum_bytes) in &references.blobs {
            let source_blob = source_inventory.get(blob_id);
            let destination_blob = destination_inventory.get(blob_id);
            let declared_max_bytes = u64::try_from(*maximum_bytes).map_err(|_| {
                StorageError::Validation("Blob reference size exceeds SQLite range".to_string())
            })?;
            let item = match source_blob {
                None => BlobReplicaItem {
                    blob_id: blob_id.clone(),
                    declared_max_bytes,
                    source_size: None,
                    destination_size: destination_blob.map(|blob| blob.stored_size),
                    state: BlobReplicaState::SourceMissing,
                },
                Some(source_blob)
                    if source_blob.stored_size == 0
                        || source_blob.stored_size > declared_max_bytes =>
                {
                    BlobReplicaItem {
                        blob_id: blob_id.clone(),
                        declared_max_bytes,
                        source_size: Some(source_blob.stored_size),
                        destination_size: destination_blob.map(|blob| blob.stored_size),
                        state: BlobReplicaState::SourceSizeInvalid,
                    }
                }
                Some(source_blob)
                    if destination_blob
                        .is_some_and(|blob| blob.stored_size != source_blob.stored_size) =>
                {
                    BlobReplicaItem {
                        blob_id: blob_id.clone(),
                        declared_max_bytes,
                        source_size: Some(source_blob.stored_size),
                        destination_size: destination_blob.map(|blob| blob.stored_size),
                        state: BlobReplicaState::DestinationConflict,
                    }
                }
                Some(_) if destination_blob.is_some() => continue,
                Some(source_blob) => BlobReplicaItem {
                    blob_id: blob_id.clone(),
                    declared_max_bytes,
                    source_size: Some(source_blob.stored_size),
                    destination_size: None,
                    state: BlobReplicaState::TransferRequired,
                },
            };
            if actionable.len() >= MAX_BLOB_LIFECYCLE_ITEMS {
                return Err(StorageError::Validation(format!(
                    "Blob replica action count exceeds the limit of {MAX_BLOB_LIFECYCLE_ITEMS}"
                )));
            }
            actionable.push(item);
        }

        let mut page_items = Vec::with_capacity(request.page_size.saturating_add(1));
        for item in actionable.into_iter().filter(|item| {
            request
                .cursor
                .as_deref()
                .is_none_or(|cursor| item.blob_id.as_str() > cursor)
        }) {
            page_items.push(item);
            if page_items.len() > request.page_size {
                break;
            }
        }
        let next_cursor = if page_items.len() > request.page_size {
            page_items.truncate(request.page_size);
            page_items.last().map(|item| item.blob_id.clone())
        } else {
            None
        };
        Ok(BlobReplicaPage {
            plan_token,
            source_namespace_id,
            destination_namespace_id,
            raw_reference_count: references.raw_reference_count,
            unique_reference_count: references.blobs.len(),
            items: page_items,
            next_cursor,
        })
    }
}

fn validate_namespace(namespace_id: String) -> StorageResult<String> {
    if namespace_id.is_empty() || namespace_id.len() > 4096 {
        return Err(StorageError::BlobStore(
            "Blob Provider namespace ID must contain 1 to 4096 bytes".to_string(),
        ));
    }
    Ok(namespace_id)
}

fn vault_id(conn: &VaultConnection) -> StorageResult<String> {
    conn.inner()
        .query_row("SELECT vault_id FROM vault_meta LIMIT 1", [], |row| {
            row.get(0)
        })
        .map_err(StorageError::from)
}

fn compute_plan_token(
    vault_id: &str,
    source_namespace_id: &str,
    destination_namespace_id: &str,
    references: &ExternalBlobReferenceInventory,
    source: &BTreeMap<String, EncryptedBlobMetadata>,
    destination: &BTreeMap<String, EncryptedBlobMetadata>,
) -> String {
    let mut hasher = Sha256::new();
    hash_part(&mut hasher, b"mdbx-blob-replica-plan-v1");
    hash_part(&mut hasher, vault_id.as_bytes());
    hash_part(&mut hasher, source_namespace_id.as_bytes());
    hash_part(&mut hasher, destination_namespace_id.as_bytes());
    hash_part(
        &mut hasher,
        &(references.raw_reference_count as u64).to_le_bytes(),
    );
    for (blob_id, maximum_bytes) in &references.blobs {
        hash_part(&mut hasher, b"reference");
        hash_part(&mut hasher, blob_id.as_bytes());
        hash_part(&mut hasher, &(*maximum_bytes as u64).to_le_bytes());
    }
    hash_inventory(&mut hasher, b"source", source);
    hash_inventory(&mut hasher, b"destination", destination);
    format!("{:x}", hasher.finalize())
}

fn hash_inventory(
    hasher: &mut Sha256,
    label: &[u8],
    inventory: &BTreeMap<String, EncryptedBlobMetadata>,
) {
    hash_part(hasher, label);
    for blob in inventory.values() {
        hash_part(hasher, blob.blob_id.as_bytes());
        hash_part(hasher, &blob.stored_size.to_le_bytes());
        hash_part(hasher, &blob.modified_at_unix_secs.to_le_bytes());
    }
}

fn hash_part(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}

#[cfg(all(test, feature = "filesystem-blob-store"))]
mod tests {
    use super::*;
    use std::io::Cursor;

    use crate::blob_store::{compute_blob_id, EncryptedBlobStore, FileSystemBlobStore};
    use crate::connection::VaultConnection;
    use crate::init::{initialize_vault, VaultInitParams};
    use crate::repo::{
        AttachmentRepo, AttachmentWriteOptions, CommitContext, ProjectRepo, SnapshotRepo,
    };

    fn setup() -> (VaultConnection, CommitContext, String) {
        let mut conn = VaultConnection::open_in_memory().unwrap();
        initialize_vault(
            &conn,
            &VaultInitParams {
                device_id: "replica-test-device".to_string(),
                ..VaultInitParams::default()
            },
        )
        .unwrap();
        conn.attach_keyring(
            mdbx_crypto::keyring::Keyring::from_vault_key(&[23_u8; 32], b"blob-replica-tests")
                .unwrap(),
        );
        let context = CommitContext::new("replica-test-device".to_string());
        let project = ProjectRepo::create(&conn, &context, "Replica", None, None).unwrap();
        (conn, context, project.project_id)
    }

    fn add_external(
        conn: &VaultConnection,
        context: &CommitContext,
        project_id: &str,
        store: &FileSystemBlobStore,
    ) -> String {
        let attachment = AttachmentRepo::add(
            conn,
            context,
            project_id,
            None,
            "replica.bin",
            None,
            "",
            100,
        )
        .unwrap();
        AttachmentRepo::write_external_content_from_reader_with_options(
            conn,
            context,
            &attachment.attachment_id,
            &mut Cursor::new(vec![5_u8; 100]),
            AttachmentWriteOptions::exact(50, 100),
            store,
        )
        .unwrap();
        attachment.attachment_id
    }

    fn request(
        page_size: usize,
        cursor: Option<String>,
        checkpoint: Option<String>,
    ) -> BlobReplicaPageRequest {
        BlobReplicaPageRequest::new(
            cursor,
            checkpoint,
            page_size,
            BlobLifecycleLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn replica_pages_report_missing_and_conflicting_reference_bodies() {
        let (conn, context, project_id) = setup();
        let source_dir = tempfile::tempdir().unwrap();
        let destination_dir = tempfile::tempdir().unwrap();
        let source = FileSystemBlobStore::new(source_dir.path().join("source.blobs"));
        let destination =
            FileSystemBlobStore::new(destination_dir.path().join("destination.blobs"));
        add_external(&conn, &context, &project_id, &source);
        let source_page = source.list(None, 10).unwrap();
        assert_eq!(source_page.blobs.len(), 2);
        let conflict_id = source_page.blobs[0].blob_id.clone();
        let missing_id = source_page.blobs[1].blob_id.clone();
        let conflict_bytes = vec![9_u8; 3];
        let conflict_path = destination.blob_path(&conflict_id).unwrap();
        std::fs::create_dir_all(conflict_path.parent().unwrap()).unwrap();
        std::fs::write(conflict_path, conflict_bytes).unwrap();

        let page = BlobReplicaService::page(&conn, &source, &destination, request(10, None, None))
            .unwrap();
        assert_eq!(page.raw_reference_count, 2);
        assert_eq!(page.unique_reference_count, 2);
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].blob_id, conflict_id);
        assert_eq!(page.items[0].state, BlobReplicaState::DestinationConflict);
        assert_eq!(page.items[1].blob_id, missing_id);
        assert_eq!(page.items[1].state, BlobReplicaState::TransferRequired);
    }

    #[test]
    fn retained_snapshot_references_report_missing_and_invalid_sources() {
        let (conn, context, project_id) = setup();
        let source_dir = tempfile::tempdir().unwrap();
        let destination_dir = tempfile::tempdir().unwrap();
        let source = FileSystemBlobStore::new(source_dir.path().join("source.blobs"));
        let destination =
            FileSystemBlobStore::new(destination_dir.path().join("destination.blobs"));
        let attachment_id = add_external(&conn, &context, &project_id, &source);
        SnapshotRepo::create_snapshot(&conn, &context).unwrap();
        AttachmentRepo::write_inline_content(&conn, &context, &attachment_id, b"replacement")
            .unwrap();
        let source_page = source.list(None, 10).unwrap();
        let missing_id = source_page.blobs[0].blob_id.clone();
        let invalid_id = source_page.blobs[1].blob_id.clone();
        source.delete(&missing_id).unwrap();
        std::fs::write(
            source.blob_path(&invalid_id).unwrap(),
            vec![0_u8; 1024 * 1024],
        )
        .unwrap();

        let page = BlobReplicaService::page(&conn, &source, &destination, request(10, None, None))
            .unwrap();
        assert_eq!(page.raw_reference_count, 2);
        assert_eq!(page.unique_reference_count, 2);
        assert_eq!(page.items[0].blob_id, missing_id);
        assert_eq!(page.items[0].state, BlobReplicaState::SourceMissing);
        assert_eq!(page.items[1].blob_id, invalid_id);
        assert_eq!(page.items[1].state, BlobReplicaState::SourceSizeInvalid);
    }

    #[test]
    fn replica_plan_is_stable_paginated_and_rejects_provider_changes() {
        let (conn, context, project_id) = setup();
        let source_dir = tempfile::tempdir().unwrap();
        let destination_dir = tempfile::tempdir().unwrap();
        let source = FileSystemBlobStore::new(source_dir.path().join("source.blobs"));
        let destination =
            FileSystemBlobStore::new(destination_dir.path().join("destination.blobs"));
        add_external(&conn, &context, &project_id, &source);
        let first =
            BlobReplicaService::page(&conn, &source, &destination, request(1, None, None)).unwrap();
        assert_eq!(first.items.len(), 1);
        let next = first.next_cursor.clone().unwrap();
        let second = BlobReplicaService::page(
            &conn,
            &source,
            &destination,
            request(1, Some(next.clone()), Some(first.plan_token.clone())),
        )
        .unwrap();
        assert_eq!(second.items.len(), 1);
        assert!(second.next_cursor.is_none());
        assert_eq!(second.plan_token, first.plan_token);

        let extra = b"provider mutation";
        let extra_id = compute_blob_id(extra);
        source.put(&extra_id, extra).unwrap();
        let error = BlobReplicaService::page(
            &conn,
            &source,
            &destination,
            request(1, Some(next), Some(first.plan_token)),
        )
        .unwrap_err();
        assert!(matches!(error, StorageError::ConstraintViolation(_)));
    }

    #[test]
    fn replica_request_rejects_unbounded_or_unanchored_pages() {
        assert!(
            BlobReplicaPageRequest::new(None, None, 0, BlobLifecycleLimits::default(),).is_err()
        );
        assert!(BlobReplicaPageRequest::new(
            Some(compute_blob_id(b"cursor")),
            None,
            1,
            BlobLifecycleLimits::default(),
        )
        .is_err());
    }
}
