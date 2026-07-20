use std::collections::BTreeMap;

use mdbx_sync::{
    BlobChunkRequest, BlobChunkResponse, BlobManifestEntry, BlobManifestEntryState,
    BlobManifestPageRequest, BlobManifestPageResponse, MAX_BLOB_TOTAL_SIZE,
};
use sha2::{Digest, Sha256};

use crate::blob_lifecycle::{
    collect_external_blob_references, collect_provider_inventory, BlobLifecycleLimits,
    ExternalBlobReferenceInventory,
};
use crate::blob_store::{
    validate_blob_id, EncryptedBlobMetadata, EncryptedBlobTransferStore,
    ManageableEncryptedBlobStore,
};
use crate::connection::VaultConnection;
use crate::error::{StorageError, StorageResult};

/// A source Provider capable of serving both its bounded inventory and
/// ciphertext ranges. The trait stays transport-neutral and is implementable
/// by filesystem, memory, or application-owned Providers.
pub trait BlobSyncSourceStore: ManageableEncryptedBlobStore + EncryptedBlobTransferStore {}

impl<T> BlobSyncSourceStore for T where T: ManageableEncryptedBlobStore + EncryptedBlobTransferStore {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobSyncSourceLimits {
    pub lifecycle: BlobLifecycleLimits,
    pub max_blob_bytes: u64,
}

impl Default for BlobSyncSourceLimits {
    fn default() -> Self {
        Self {
            lifecycle: BlobLifecycleLimits::default(),
            max_blob_bytes: MAX_BLOB_TOTAL_SIZE,
        }
    }
}

impl BlobSyncSourceLimits {
    fn validate(self) -> StorageResult<()> {
        self.lifecycle.validate()?;
        if !(1..=MAX_BLOB_TOTAL_SIZE).contains(&self.max_blob_bytes) {
            return Err(StorageError::Validation(format!(
                "Blob sync source size limit must be between 1 and {MAX_BLOB_TOTAL_SIZE}"
            )));
        }
        Ok(())
    }
}

pub struct BlobSyncSourceAdapter;

impl BlobSyncSourceAdapter {
    /// Publish a stable page of referenced source Blobs. The checkpoint binds
    /// the vault references and Provider inventory, so a later page cannot
    /// silently mix two source states.
    pub fn manifest_page<S>(
        conn: &VaultConnection,
        source: &S,
        request: BlobManifestPageRequest,
        limits: BlobSyncSourceLimits,
    ) -> StorageResult<BlobManifestPageResponse>
    where
        S: BlobSyncSourceStore + ?Sized,
    {
        limits.validate()?;
        request
            .validate()
            .map_err(|error| StorageError::Validation(error.to_string()))?;
        if conn.keyring().is_none() {
            return Err(StorageError::Validation(
                "Blob sync manifest requires an unlocked encrypted vault".to_string(),
            ));
        }
        let namespace_id = EncryptedBlobTransferStore::namespace_id(source)?;
        validate_namespace(&namespace_id)?;
        if namespace_id != request.namespace_id {
            return Err(StorageError::ConstraintViolation(
                "Blob sync request namespace does not match the source Provider".to_string(),
            ));
        }

        let references = collect_external_blob_references(conn, limits.lifecycle)?;
        let provider = collect_provider_inventory(source, limits.lifecycle)?;
        let checkpoint = source_checkpoint(conn, &namespace_id, &references, &provider)?;
        if request
            .checkpoint
            .as_deref()
            .is_some_and(|value| value != checkpoint)
        {
            return Err(StorageError::ConstraintViolation(
                "Blob sync source manifest changed; create a new checkpoint".to_string(),
            ));
        }
        if request.cursor.is_some() && request.checkpoint.is_none() {
            return Err(StorageError::Validation(
                "Blob sync manifest cursor requires a checkpoint".to_string(),
            ));
        }

        let cursor = request.cursor.as_deref();
        if let Some(cursor) = cursor {
            validate_blob_id(cursor).map_err(|_| {
                StorageError::Validation("Blob sync manifest cursor must be a Blob ID".to_string())
            })?;
        }

        let page_size = usize::from(request.page_size);
        let mut items = Vec::with_capacity(page_size.saturating_add(1));
        for (blob_id, declared_max_bytes) in &references.blobs {
            if cursor.is_some_and(|cursor| blob_id.as_str() <= cursor) {
                continue;
            }
            items.push(manifest_entry(
                blob_id,
                *declared_max_bytes as u64,
                provider.get(blob_id),
                limits.max_blob_bytes,
            ));
            if items.len() > page_size {
                break;
            }
        }
        let next_cursor = if items.len() > page_size {
            items.truncate(page_size);
            items.last().map(|item| item.blob_id.clone())
        } else {
            None
        };
        BlobManifestPageResponse::new(namespace_id, checkpoint, items, next_cursor)
            .map_err(|error| StorageError::Validation(error.to_string()))
    }

    /// Serve one ciphertext range after rechecking the source inventory size.
    /// This prevents a source Provider mutation between manifest and chunk
    /// requests from being mistaken for a valid range.
    pub fn chunk<S>(
        source: &S,
        request: BlobChunkRequest,
        limits: BlobSyncSourceLimits,
    ) -> StorageResult<BlobChunkResponse>
    where
        S: BlobSyncSourceStore + ?Sized,
    {
        limits.validate()?;
        request
            .validate()
            .map_err(|error| StorageError::Validation(error.to_string()))?;
        let namespace_id = EncryptedBlobTransferStore::namespace_id(source)?;
        validate_namespace(&namespace_id)?;
        if namespace_id != request.namespace_id {
            return Err(StorageError::ConstraintViolation(
                "Blob chunk request namespace does not match the source Provider".to_string(),
            ));
        }
        let inventory = collect_provider_inventory(source, limits.lifecycle)?;
        let metadata = inventory.get(&request.blob_id).ok_or_else(|| {
            StorageError::NotFound(format!("source Blob {} is missing", request.blob_id))
        })?;
        if metadata.stored_size != request.total_size
            || metadata.stored_size > limits.max_blob_bytes
        {
            return Err(StorageError::ConstraintViolation(
                "source Blob size no longer matches the manifest".to_string(),
            ));
        }
        let max_bytes = usize::try_from(request.max_bytes).map_err(|_| {
            StorageError::Validation("Blob chunk size cannot be represented locally".to_string())
        })?;
        let ciphertext = EncryptedBlobTransferStore::read_chunk(
            source,
            &request.blob_id,
            request.offset,
            max_bytes,
        )?;
        if ciphertext.is_empty() {
            return Err(StorageError::ConstraintViolation(
                "source Provider returned an empty Blob chunk before completion".to_string(),
            ));
        }
        let end = request
            .offset
            .checked_add(ciphertext.len() as u64)
            .ok_or_else(|| StorageError::Validation("Blob chunk offset overflow".to_string()))?;
        if end > request.total_size {
            return Err(StorageError::ConstraintViolation(
                "source Provider returned bytes beyond the manifest size".to_string(),
            ));
        }
        BlobChunkResponse::new(
            namespace_id,
            request.blob_id,
            request.total_size,
            request.offset,
            ciphertext,
            end == request.total_size,
        )
        .map_err(|error| StorageError::Validation(error.to_string()))
    }
}

fn manifest_entry(
    blob_id: &str,
    declared_max_bytes: u64,
    metadata: Option<&EncryptedBlobMetadata>,
    max_blob_bytes: u64,
) -> BlobManifestEntry {
    match metadata {
        None => BlobManifestEntry {
            blob_id: blob_id.to_string(),
            total_size: None,
            state: BlobManifestEntryState::SourceMissing,
        },
        Some(metadata)
            if metadata.stored_size == 0
                || metadata.stored_size > declared_max_bytes
                || metadata.stored_size > max_blob_bytes
                || metadata.stored_size > MAX_BLOB_TOTAL_SIZE =>
        {
            BlobManifestEntry {
                blob_id: blob_id.to_string(),
                total_size: (metadata.stored_size <= MAX_BLOB_TOTAL_SIZE)
                    .then_some(metadata.stored_size),
                state: BlobManifestEntryState::SourceSizeInvalid,
            }
        }
        Some(metadata) => BlobManifestEntry {
            blob_id: blob_id.to_string(),
            total_size: Some(metadata.stored_size),
            state: BlobManifestEntryState::Available,
        },
    }
}

fn source_checkpoint(
    conn: &VaultConnection,
    namespace_id: &str,
    references: &ExternalBlobReferenceInventory,
    provider: &BTreeMap<String, EncryptedBlobMetadata>,
) -> StorageResult<String> {
    let vault_id =
        conn.inner()
            .query_row("SELECT vault_id FROM vault_meta LIMIT 1", [], |row| {
                row.get::<_, String>(0)
            })?;
    let mut hasher = Sha256::new();
    hash_part(&mut hasher, b"mdbx-blob-sync-source-manifest-v1");
    hash_part(&mut hasher, vault_id.as_bytes());
    hash_part(&mut hasher, namespace_id.as_bytes());
    hash_part(
        &mut hasher,
        &(references.raw_reference_count as u64).to_le_bytes(),
    );
    for (blob_id, declared_size) in &references.blobs {
        hash_part(&mut hasher, blob_id.as_bytes());
        hash_part(&mut hasher, &(*declared_size as u64).to_le_bytes());
    }
    for metadata in provider.values() {
        hash_part(&mut hasher, metadata.blob_id.as_bytes());
        hash_part(&mut hasher, &metadata.stored_size.to_le_bytes());
        hash_part(&mut hasher, &metadata.modified_at_unix_secs.to_le_bytes());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn hash_part(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn validate_namespace(namespace_id: &str) -> StorageResult<()> {
    if namespace_id.is_empty() || namespace_id.len() > 4096 {
        return Err(StorageError::Validation(
            "Blob sync Provider namespace must contain 1 to 4096 bytes".to_string(),
        ));
    }
    Ok(())
}

#[cfg(all(test, feature = "filesystem-blob-store"))]
mod tests {
    use super::*;
    use std::io::Cursor;

    use mdbx_crypto::keyring::Keyring;
    use mdbx_sync::MAX_BLOB_ID_BYTES;

    use crate::blob_store::{EncryptedBlobStore, FileSystemBlobStore};
    use crate::connection::VaultConnection;
    use crate::init::{initialize_vault, VaultInitParams};
    use crate::repo::{AttachmentRepo, AttachmentWriteOptions, CommitContext, ProjectRepo};

    fn setup() -> (VaultConnection, CommitContext, String) {
        let mut conn = VaultConnection::open_in_memory().unwrap();
        initialize_vault(
            &conn,
            &VaultInitParams {
                device_id: "blob-sync-source-test".to_string(),
                ..VaultInitParams::default()
            },
        )
        .unwrap();
        conn.attach_keyring(
            Keyring::from_vault_key(&[71_u8; 32], b"blob-sync-source-tests").unwrap(),
        );
        let context = CommitContext::new("blob-sync-source-test".to_string());
        let project = ProjectRepo::create(&conn, &context, "Sync", None, None).unwrap();
        (conn, context, project.project_id)
    }

    fn add_external(
        conn: &VaultConnection,
        context: &CommitContext,
        project_id: &str,
        store: &FileSystemBlobStore,
    ) -> Vec<u8> {
        let attachment =
            AttachmentRepo::add(conn, context, project_id, None, "sync.bin", None, "", 12).unwrap();
        let bytes = b"source bytes".to_vec();
        AttachmentRepo::write_external_content_from_reader_with_options(
            conn,
            context,
            &attachment.attachment_id,
            &mut Cursor::new(bytes.clone()),
            AttachmentWriteOptions::exact(4, bytes.len() as u64),
            store,
        )
        .unwrap();
        bytes
    }

    #[test]
    fn source_manifest_pages_are_stable_and_source_chunks_are_bounded() {
        let (conn, context, project_id) = setup();
        let dir = tempfile::tempdir().unwrap();
        let source = FileSystemBlobStore::new(dir.path().join("source.blobs"));
        add_external(&conn, &context, &project_id, &source);
        let provider = collect_provider_inventory(&source, BlobLifecycleLimits::default()).unwrap();
        assert_eq!(provider.len(), 3);
        let namespace = EncryptedBlobTransferStore::namespace_id(&source).unwrap();
        let first_request = BlobManifestPageRequest::new(namespace.clone(), None, None, 1).unwrap();
        let first = BlobSyncSourceAdapter::manifest_page(
            &conn,
            &source,
            first_request,
            BlobSyncSourceLimits::default(),
        )
        .unwrap();
        assert_eq!(first.items.len(), 1);
        assert!(first.next_cursor.is_some());
        assert_eq!(first.items[0].blob_id.len(), MAX_BLOB_ID_BYTES);
        assert_eq!(first.items[0].state, BlobManifestEntryState::Available);
        let second_request = BlobManifestPageRequest::new(
            namespace.clone(),
            Some(first.checkpoint.clone()),
            first.next_cursor.clone(),
            1,
        )
        .unwrap();
        let second = BlobSyncSourceAdapter::manifest_page(
            &conn,
            &source,
            second_request,
            BlobSyncSourceLimits::default(),
        )
        .unwrap();
        assert_eq!(second.items.len(), 1);
        assert_ne!(first.items[0].blob_id, second.items[0].blob_id);

        let item = &first.items[0];
        let total_size = item.total_size.unwrap();
        let expected =
            EncryptedBlobTransferStore::read_chunk(&source, &item.blob_id, 0, 4).unwrap();
        let chunk_request =
            BlobChunkRequest::new(namespace, item.blob_id.clone(), total_size, 0, 4).unwrap();
        let chunk =
            BlobSyncSourceAdapter::chunk(&source, chunk_request, BlobSyncSourceLimits::default())
                .unwrap();
        assert_eq!(chunk.ciphertext, expected);
        assert_eq!(chunk.is_last, total_size <= 4);
    }

    #[test]
    fn source_rejects_stale_manifests_and_changed_sizes() {
        let (conn, context, project_id) = setup();
        let dir = tempfile::tempdir().unwrap();
        let source = FileSystemBlobStore::new(dir.path().join("source.blobs"));
        add_external(&conn, &context, &project_id, &source);
        let namespace = EncryptedBlobTransferStore::namespace_id(&source).unwrap();
        let first = BlobSyncSourceAdapter::manifest_page(
            &conn,
            &source,
            BlobManifestPageRequest::new(namespace.clone(), None, None, 1).unwrap(),
            BlobSyncSourceLimits::default(),
        )
        .unwrap();
        source.put(&"f".repeat(64), b"different").unwrap_err();
        let extra = b"unreferenced";
        source
            .put(&crate::blob_store::compute_blob_id(extra), extra)
            .unwrap();
        let stale =
            BlobManifestPageRequest::new(namespace, Some(first.checkpoint), first.next_cursor, 1)
                .unwrap();
        assert!(BlobSyncSourceAdapter::manifest_page(
            &conn,
            &source,
            stale,
            BlobSyncSourceLimits::default()
        )
        .is_err());
    }
}
