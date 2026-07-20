use mdbx_core::tiga::AuthorizationDecision;
use mdbx_crypto::error::CryptoError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),

    #[error("schema creation failed: {0}")]
    SchemaCreation(String),

    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("constraint violation: {0}")]
    ConstraintViolation(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("encrypted blob store error: {0}")]
    BlobStore(String),

    #[error("attachment {attachment_id} requires an encrypted blob store")]
    EncryptedBlobStoreRequired { attachment_id: String },

    #[error("Tiga authorization did not allow the operation: {0:?}")]
    Authorization(AuthorizationDecision),

    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
}

pub type StorageResult<T> = Result<T, StorageError>;
