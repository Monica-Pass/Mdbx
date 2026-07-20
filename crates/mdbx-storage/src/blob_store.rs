use sha2::{Digest, Sha256};

use crate::error::{StorageError, StorageResult};

pub const MAX_BLOB_PAGE_SIZE: usize = 1_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedBlobMetadata {
    pub blob_id: String,
    pub stored_size: u64,
    pub modified_at_unix_secs: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedBlobPage {
    pub blobs: Vec<EncryptedBlobMetadata>,
    pub next_cursor: Option<String>,
}

/// Stores opaque, authenticated ciphertext outside the MDBX database file.
///
/// Implementations receive encrypted bytes only. Blob identifiers are the
/// lowercase SHA-256 digest of those exact bytes, making every object
/// immutable and independently verifiable.
pub trait EncryptedBlobStore: Send + Sync {
    fn put(&self, blob_id: &str, encrypted_blob: &[u8]) -> StorageResult<()>;

    /// Reads at most `max_bytes` bytes and verifies the returned object.
    fn get(&self, blob_id: &str, max_bytes: usize) -> StorageResult<Vec<u8>>;
}

/// Adds bounded inventory and deletion operations for maintenance clients.
///
/// This is an additive extension so write/read-only custom Providers remain
/// source-compatible. Deletion must be idempotent and return `false` when the
/// object is already absent.
pub trait ManageableEncryptedBlobStore: EncryptedBlobStore {
    fn namespace_id(&self) -> StorageResult<String>;

    fn list(&self, cursor: Option<&str>, limit: usize) -> StorageResult<EncryptedBlobPage>;

    fn delete(&self, blob_id: &str) -> StorageResult<bool>;
}

pub fn validate_blob_id(blob_id: &str) -> StorageResult<()> {
    if blob_id.len() != 64
        || !blob_id
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(StorageError::BlobStore(
            "blob ID must be a 64-character lowercase SHA-256 hex digest".to_string(),
        ));
    }
    Ok(())
}

pub fn compute_blob_id(encrypted_blob: &[u8]) -> String {
    format!("{:x}", Sha256::digest(encrypted_blob))
}

#[cfg(feature = "filesystem-blob-store")]
mod filesystem {
    use std::ffi::OsStr;
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};

    use tempfile::NamedTempFile;

    use super::{
        compute_blob_id, validate_blob_id, EncryptedBlobMetadata, EncryptedBlobPage,
        EncryptedBlobStore, ManageableEncryptedBlobStore, MAX_BLOB_PAGE_SIZE,
    };
    use crate::error::{StorageError, StorageResult};

    /// Content-addressed encrypted blob store rooted at a caller-owned directory.
    ///
    /// Objects are placed under two digest-prefix directories. Callers cannot
    /// supply path components because only validated SHA-256 identifiers are
    /// accepted.
    #[derive(Debug, Clone)]
    pub struct FileSystemBlobStore {
        root: PathBuf,
    }

    impl FileSystemBlobStore {
        const MAX_PREFIX_DIRECTORY_ENTRIES: usize = 65_536;

        pub fn new(root: impl Into<PathBuf>) -> Self {
            Self { root: root.into() }
        }

        pub fn root(&self) -> &Path {
            &self.root
        }

        pub fn blob_path(&self, blob_id: &str) -> StorageResult<PathBuf> {
            validate_blob_id(blob_id)?;
            Ok(self
                .root
                .join(&blob_id[..2])
                .join(&blob_id[2..4])
                .join(blob_id))
        }

        fn prepare_parent(&self, blob_id: &str) -> StorageResult<PathBuf> {
            let path = self.blob_path(blob_id)?;
            let parent = path.parent().ok_or_else(|| {
                StorageError::BlobStore("blob path has no parent directory".to_string())
            })?;
            fs::create_dir_all(parent)?;
            for directory in [
                self.root.as_path(),
                parent.parent().unwrap_or(parent),
                parent,
            ] {
                let metadata = fs::symlink_metadata(directory)?;
                if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                    return Err(StorageError::BlobStore(format!(
                        "blob directory is not a regular directory: {}",
                        directory.display()
                    )));
                }
            }
            Ok(path)
        }

        fn read_verified(&self, blob_id: &str, max_bytes: usize) -> StorageResult<Vec<u8>> {
            let path = self.blob_path(blob_id)?;
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    StorageError::BlobStore(format!("blob {blob_id} is missing"))
                } else {
                    StorageError::Io(error)
                }
            })?;
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(StorageError::BlobStore(format!(
                    "blob {blob_id} is not a regular file"
                )));
            }
            if metadata.len() > max_bytes as u64 {
                return Err(StorageError::BlobStore(format!(
                    "blob {blob_id} exceeds the {max_bytes}-byte read limit"
                )));
            }

            let file = File::open(&path)?;
            let read_limit = max_bytes.checked_add(1).unwrap_or(max_bytes) as u64;
            let mut limited = file.take(read_limit);
            let mut encrypted_blob = Vec::new();
            encrypted_blob
                .try_reserve_exact(metadata.len() as usize)
                .map_err(|error| {
                    StorageError::BlobStore(format!("cannot allocate blob read buffer: {error}"))
                })?;
            limited.read_to_end(&mut encrypted_blob)?;
            if encrypted_blob.len() > max_bytes {
                return Err(StorageError::BlobStore(format!(
                    "blob {blob_id} grew beyond the {max_bytes}-byte read limit"
                )));
            }
            if compute_blob_id(&encrypted_blob) != blob_id {
                return Err(StorageError::BlobStore(format!(
                    "blob {blob_id} failed SHA-256 verification"
                )));
            }
            Ok(encrypted_blob)
        }

        fn validate_root_for_listing(&self) -> StorageResult<bool> {
            match fs::symlink_metadata(&self.root) {
                Ok(metadata) => {
                    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                        return Err(StorageError::BlobStore(format!(
                            "blob root is not a regular directory: {}",
                            self.root.display()
                        )));
                    }
                    Ok(true)
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(StorageError::Io(error)),
            }
        }

        fn sorted_directory_entries(
            directory: &Path,
            maximum_entries: usize,
        ) -> StorageResult<Vec<fs::DirEntry>> {
            let mut entries = Vec::new();
            for entry in fs::read_dir(directory)? {
                if entries.len() >= maximum_entries {
                    return Err(StorageError::BlobStore(format!(
                        "blob directory exceeds the {maximum_entries}-entry maintenance limit: {}",
                        directory.display()
                    )));
                }
                entries.push(entry?);
            }
            entries.sort_by_key(|entry| entry.file_name());
            Ok(entries)
        }

        fn validate_prefix_directory(entry: &fs::DirEntry) -> StorageResult<String> {
            let name = entry.file_name().into_string().map_err(|_| {
                StorageError::BlobStore("blob prefix directory name is not UTF-8".to_string())
            })?;
            if name.len() != 2
                || !name
                    .as_bytes()
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                return Err(StorageError::BlobStore(format!(
                    "invalid blob prefix directory: {name}"
                )));
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err(StorageError::BlobStore(format!(
                    "blob prefix is not a regular directory: {}",
                    entry.path().display()
                )));
            }
            Ok(name)
        }

        fn metadata_for_inventory(
            first_prefix: &str,
            second_prefix: &str,
            entry: &fs::DirEntry,
        ) -> StorageResult<EncryptedBlobMetadata> {
            let blob_id = entry
                .file_name()
                .into_string()
                .map_err(|_| StorageError::BlobStore("blob file name is not UTF-8".to_string()))?;
            validate_blob_id(&blob_id)?;
            if !blob_id.starts_with(first_prefix) || blob_id.get(2..4) != Some(second_prefix) {
                return Err(StorageError::BlobStore(format!(
                    "blob {blob_id} is stored below the wrong prefix directory"
                )));
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(StorageError::BlobStore(format!(
                    "blob inventory entry is not a regular file: {}",
                    entry.path().display()
                )));
            }
            let modified_at_unix_secs = metadata
                .modified()?
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .try_into()
                .unwrap_or(i64::MAX);
            Ok(EncryptedBlobMetadata {
                blob_id,
                stored_size: metadata.len(),
                modified_at_unix_secs,
            })
        }
    }

    impl EncryptedBlobStore for FileSystemBlobStore {
        fn put(&self, blob_id: &str, encrypted_blob: &[u8]) -> StorageResult<()> {
            validate_blob_id(blob_id)?;
            if compute_blob_id(encrypted_blob) != blob_id {
                return Err(StorageError::BlobStore(format!(
                    "blob {blob_id} does not match supplied ciphertext"
                )));
            }
            let path = self.prepare_parent(blob_id)?;
            if path.exists() {
                self.read_verified(blob_id, encrypted_blob.len())?;
                return Ok(());
            }

            let parent = path.parent().ok_or_else(|| {
                StorageError::BlobStore("blob path has no parent directory".to_string())
            })?;
            let mut temporary = NamedTempFile::new_in(parent)?;
            temporary.as_file_mut().write_all(encrypted_blob)?;
            temporary.as_file_mut().sync_all()?;
            match temporary.persist_noclobber(&path) {
                Ok(_) => Ok(()),
                Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                    self.read_verified(blob_id, encrypted_blob.len())?;
                    Ok(())
                }
                Err(error) => Err(StorageError::Io(error.error)),
            }
        }

        fn get(&self, blob_id: &str, max_bytes: usize) -> StorageResult<Vec<u8>> {
            self.read_verified(blob_id, max_bytes)
        }
    }

    impl ManageableEncryptedBlobStore for FileSystemBlobStore {
        fn namespace_id(&self) -> StorageResult<String> {
            let root = if self.root.is_absolute() {
                self.root.clone()
            } else {
                std::env::current_dir()?.join(&self.root)
            };
            Ok(format!("filesystem:{}", root.to_string_lossy()))
        }

        fn list(&self, cursor: Option<&str>, limit: usize) -> StorageResult<EncryptedBlobPage> {
            if !(1..=MAX_BLOB_PAGE_SIZE).contains(&limit) {
                return Err(StorageError::Validation(format!(
                    "blob page size must be between 1 and {MAX_BLOB_PAGE_SIZE}"
                )));
            }
            if let Some(cursor) = cursor {
                validate_blob_id(cursor)?;
            }
            if !self.validate_root_for_listing()? {
                return Ok(EncryptedBlobPage {
                    blobs: Vec::new(),
                    next_cursor: None,
                });
            }

            let mut blobs = Vec::with_capacity(limit.saturating_add(1));
            let cursor_first = cursor.map(|cursor| &cursor[..2]);
            let cursor_second = cursor.map(|cursor| &cursor[2..4]);
            'inventory: for first in Self::sorted_directory_entries(&self.root, 256)? {
                let first_prefix = Self::validate_prefix_directory(&first)?;
                if cursor_first.is_some_and(|cursor| first_prefix.as_str() < cursor) {
                    continue;
                }
                for second in Self::sorted_directory_entries(&first.path(), 256)? {
                    let second_prefix = Self::validate_prefix_directory(&second)?;
                    if cursor_first == Some(first_prefix.as_str())
                        && cursor_second.is_some_and(|cursor| second_prefix.as_str() < cursor)
                    {
                        continue;
                    }
                    for entry in Self::sorted_directory_entries(
                        &second.path(),
                        Self::MAX_PREFIX_DIRECTORY_ENTRIES,
                    )? {
                        let metadata =
                            Self::metadata_for_inventory(&first_prefix, &second_prefix, &entry)?;
                        if cursor.is_some_and(|cursor| metadata.blob_id.as_str() <= cursor) {
                            continue;
                        }
                        blobs.push(metadata);
                        if blobs.len() > limit {
                            break 'inventory;
                        }
                    }
                }
            }

            let next_cursor = if blobs.len() > limit {
                blobs.truncate(limit);
                blobs.last().map(|blob| blob.blob_id.clone())
            } else {
                None
            };
            Ok(EncryptedBlobPage { blobs, next_cursor })
        }

        fn delete(&self, blob_id: &str) -> StorageResult<bool> {
            let path = self.blob_path(blob_id)?;
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                Err(error) => return Err(StorageError::Io(error)),
            };
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(StorageError::BlobStore(format!(
                    "blob {blob_id} is not a regular file"
                )));
            }
            fs::remove_file(&path)?;
            if let Some(second) = path.parent() {
                let _ = fs::remove_dir(second);
                if let Some(first) = second.parent() {
                    if first.as_os_str() != OsStr::new("") && first != self.root {
                        let _ = fs::remove_dir(first);
                    }
                }
            }
            Ok(true)
        }
    }
}

#[cfg(feature = "filesystem-blob-store")]
pub use filesystem::FileSystemBlobStore;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_ids_reject_path_syntax_and_noncanonical_hex() {
        for invalid in [
            "../secret",
            "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3",
            "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
            "abcd",
        ] {
            assert!(validate_blob_id(invalid).is_err());
        }
    }

    #[cfg(feature = "filesystem-blob-store")]
    #[test]
    fn filesystem_blob_store_roundtrips_and_verifies_ciphertext() {
        let directory = tempfile::tempdir().unwrap();
        let store = FileSystemBlobStore::new(directory.path());
        let encrypted = b"opaque authenticated ciphertext";
        let blob_id = compute_blob_id(encrypted);

        store.put(&blob_id, encrypted).unwrap();
        store.put(&blob_id, encrypted).unwrap();

        assert_eq!(store.get(&blob_id, encrypted.len()).unwrap(), encrypted);
        assert_eq!(
            store.blob_path(&blob_id).unwrap().components().count(),
            directory.path().components().count() + 3
        );
    }

    #[cfg(feature = "filesystem-blob-store")]
    #[test]
    fn filesystem_blob_store_rejects_wrong_id_corruption_and_oversize() {
        let directory = tempfile::tempdir().unwrap();
        let store = FileSystemBlobStore::new(directory.path());
        let encrypted = b"ciphertext";
        let blob_id = compute_blob_id(encrypted);
        let wrong_id = compute_blob_id(b"different");

        assert!(store.put(&wrong_id, encrypted).is_err());
        store.put(&blob_id, encrypted).unwrap();
        assert!(store.get(&blob_id, encrypted.len() - 1).is_err());
        std::fs::write(store.blob_path(&blob_id).unwrap(), b"corrupt").unwrap();
        assert!(store.get(&blob_id, encrypted.len()).is_err());
    }

    #[cfg(feature = "filesystem-blob-store")]
    #[test]
    fn filesystem_blob_inventory_is_bounded_paginated_and_deletable() {
        let directory = tempfile::tempdir().unwrap();
        let store = FileSystemBlobStore::new(directory.path());
        let mut expected = Vec::new();
        for encrypted in [b"third".as_slice(), b"first", b"second"] {
            let blob_id = compute_blob_id(encrypted);
            store.put(&blob_id, encrypted).unwrap();
            expected.push(blob_id);
        }
        expected.sort();

        let first = store.list(None, 2).unwrap();
        assert_eq!(
            first
                .blobs
                .iter()
                .map(|blob| blob.blob_id.clone())
                .collect::<Vec<_>>(),
            expected[..2]
        );
        assert_eq!(first.next_cursor.as_deref(), Some(expected[1].as_str()));
        let second = store.list(first.next_cursor.as_deref(), 2).unwrap();
        assert_eq!(second.blobs.len(), 1);
        assert_eq!(second.blobs[0].blob_id, expected[2]);
        assert!(second.next_cursor.is_none());

        assert!(store.delete(&expected[1]).unwrap());
        assert!(!store.delete(&expected[1]).unwrap());
        let remaining = store.list(None, 10).unwrap();
        assert_eq!(remaining.blobs.len(), 2);
    }

    #[cfg(feature = "filesystem-blob-store")]
    #[test]
    fn filesystem_blob_inventory_rejects_invalid_limits_cursors_and_entries() {
        let directory = tempfile::tempdir().unwrap();
        let store = FileSystemBlobStore::new(directory.path());
        assert!(store.list(None, 0).is_err());
        assert!(store.list(Some("../cursor"), 1).is_err());

        std::fs::create_dir_all(directory.path()).unwrap();
        std::fs::write(directory.path().join("unexpected"), b"data").unwrap();
        assert!(store.list(None, 10).is_err());
    }
}
