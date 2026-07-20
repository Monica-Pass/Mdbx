use sha2::{Digest, Sha256};

use crate::error::{StorageError, StorageResult};

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
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};

    use tempfile::NamedTempFile;

    use super::{compute_blob_id, validate_blob_id, EncryptedBlobStore};
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
}
