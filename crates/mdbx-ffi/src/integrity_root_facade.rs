use std::path::Path;

use mdbx_storage::integrity_root::{
    IntegrityRootService, IntegrityRootState, IntegrityRootStatus, IntegrityRootVerification,
};

use super::{MdbxFfiError, MdbxVault};

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MdbxIntegrityRootState {
    Disabled,
    Pending,
    Building,
    Established,
    Stale,
}

impl From<IntegrityRootState> for MdbxIntegrityRootState {
    fn from(value: IntegrityRootState) -> Self {
        match value {
            IntegrityRootState::Disabled => Self::Disabled,
            IntegrityRootState::Pending => Self::Pending,
            IntegrityRootState::Building => Self::Building,
            IntegrityRootState::Established => Self::Established,
            IntegrityRootState::Stale => Self::Stale,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxIntegrityRootStatus {
    pub profile: Option<String>,
    pub state: MdbxIntegrityRootState,
    pub authenticated: bool,
    pub generation: u64,
    pub leaf_count: u64,
    pub root_hash: Option<Vec<u8>>,
    pub latest_commit_sequence: u64,
    pub latest_delta_sequence: u64,
}

impl From<IntegrityRootStatus> for MdbxIntegrityRootStatus {
    fn from(value: IntegrityRootStatus) -> Self {
        Self {
            profile: value.profile,
            state: value.state.into(),
            authenticated: value.authenticated,
            generation: value.generation,
            leaf_count: value.leaf_count,
            root_hash: value.root_hash.map(Vec::from),
            latest_commit_sequence: value.latest_commit_seq,
            latest_delta_sequence: value.latest_delta_seq,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxIntegrityRootVerification {
    pub profile: String,
    pub generation: u64,
    pub leaf_count: u64,
    pub root_hash: Vec<u8>,
    pub latest_commit_sequence: u64,
    pub latest_delta_sequence: u64,
}

impl From<IntegrityRootVerification> for MdbxIntegrityRootVerification {
    fn from(value: IntegrityRootVerification) -> Self {
        Self {
            profile: value.profile,
            generation: value.generation,
            leaf_count: value.leaf_count,
            root_hash: value.root_hash.to_vec(),
            latest_commit_sequence: value.latest_commit_seq,
            latest_delta_sequence: value.latest_delta_seq,
        }
    }
}

/// Reads integrity-root metadata without unlocking, migrating, or opening the
/// vault for writing. `authenticated` is always false on this path.
#[uniffi::export]
pub fn inspect_vault_integrity_root(path: String) -> Result<MdbxIntegrityRootStatus, MdbxFfiError> {
    Ok(IntegrityRootService::status_path(Path::new(&path))?.into())
}

#[uniffi::export]
impl MdbxVault {
    pub fn integrity_root_status(&self) -> Result<MdbxIntegrityRootStatus, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(IntegrityRootService::status(&conn)?.into())
    }

    pub fn enable_integrity_root(&self) -> Result<MdbxIntegrityRootStatus, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(IntegrityRootService::enable(&conn)?.into())
    }

    pub fn verify_integrity_root(&self) -> Result<MdbxIntegrityRootVerification, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(IntegrityRootService::verify(&conn)?.into())
    }

    pub fn rebuild_integrity_root(&self) -> Result<MdbxIntegrityRootStatus, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(IntegrityRootService::rebuild(&conn)?.into())
    }
}
