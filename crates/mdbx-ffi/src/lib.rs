//! Generic UniFFI boundary for MDBX vault clients.
//!
//! This crate intentionally exposes vault, project, and generic entry
//! operations only. Product-specific payloads belong in each client.

use std::path::Path;
use std::sync::{Arc, Mutex};

use mdbx_core::model::EntryType;
use mdbx_core::tiga::TigaMode;
use mdbx_storage::connection::VaultConnection;
use mdbx_storage::error::{StorageError, StorageResult};
use mdbx_storage::init::{initialize_vault, VaultInitParams};
use mdbx_storage::repo::{CommitContext, EntryRepo, ProjectRepo};
use mdbx_storage::unlock::UnlockService;
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MdbxFfiError {
    #[error("storage error: {message}")]
    Storage { message: String },
    #[error("serialization error: {message}")]
    Serialization { message: String },
    #[error("invalid entry type: {entry_type}")]
    InvalidEntryType { entry_type: String },
    #[error("vault lock poisoned")]
    LockPoisoned,
}

impl From<StorageError> for MdbxFfiError {
    fn from(value: StorageError) -> Self {
        MdbxFfiError::Storage {
            message: value.to_string(),
        }
    }
}

impl From<serde_json::Error> for MdbxFfiError {
    fn from(value: serde_json::Error) -> Self {
        MdbxFfiError::Serialization {
            message: value.to_string(),
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct VaultInfo {
    pub vault_id: String,
    pub device_id: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ProjectRecord {
    pub project_id: String,
    pub title: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct EntryRecord {
    pub entry_id: String,
    pub project_id: String,
    pub entry_type: String,
    pub title: String,
    pub payload_json: String,
    pub deleted: bool,
}

#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum MdbxTigaMode {
    Sky,
    Multi,
    Power,
}

impl From<MdbxTigaMode> for TigaMode {
    fn from(value: MdbxTigaMode) -> Self {
        match value {
            MdbxTigaMode::Sky => TigaMode::Sky,
            MdbxTigaMode::Multi => TigaMode::Multi,
            MdbxTigaMode::Power => TigaMode::Power,
        }
    }
}

#[derive(uniffi::Object)]
pub struct MdbxVault {
    conn: Mutex<VaultConnection>,
    device_id: String,
    vault_id: String,
}

#[uniffi::export]
impl MdbxVault {
    pub fn info(&self) -> VaultInfo {
        VaultInfo {
            vault_id: self.vault_id.clone(),
            device_id: self.device_id.clone(),
        }
    }

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

    pub fn setup_local_security_key_unlock(
        &self,
        key_material: Vec<u8>,
    ) -> Result<(), MdbxFfiError> {
        let mut conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let key_material = Zeroizing::new(key_material);
        UnlockService::setup_security_key(&mut conn, key_material.as_slice())?;
        Ok(())
    }

    pub fn reset_master_password(&self, new_password: String) -> Result<(), MdbxFfiError> {
        self.reset_master_password_with_tiga_mode(new_password, MdbxTigaMode::Multi)
    }

    pub fn reset_master_password_with_tiga_mode(
        &self,
        new_password: String,
        mode: MdbxTigaMode,
    ) -> Result<(), MdbxFfiError> {
        let mut conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let new_password = Zeroizing::new(new_password);
        UnlockService::reset_password_with_mode(&mut conn, new_password.as_str(), mode.into())?;
        Ok(())
    }
}

#[uniffi::export]
pub fn create_vault(
    path: String,
    password: String,
    device_id: String,
) -> Result<Arc<MdbxVault>, MdbxFfiError> {
    create_vault_with_tiga_mode(path, password, device_id, MdbxTigaMode::Multi)
}

#[uniffi::export]
pub fn create_vault_with_tiga_mode(
    path: String,
    password: String,
    device_id: String,
    mode: MdbxTigaMode,
) -> Result<Arc<MdbxVault>, MdbxFfiError> {
    let mut conn = VaultConnection::create(Path::new(&path))?;
    let mode: TigaMode = mode.into();
    let init = initialize_vault(
        &conn,
        &VaultInitParams {
            default_tiga_mode: mode.to_string(),
            device_id: device_id.clone(),
            ..Default::default()
        },
    )?;
    let password = Zeroizing::new(password);
    UnlockService::setup_password_with_mode(&mut conn, password.as_str(), mode)?;
    Ok(Arc::new(MdbxVault {
        conn: Mutex::new(conn),
        device_id,
        vault_id: init.vault_id,
    }))
}

#[uniffi::export]
pub fn open_vault(
    path: String,
    password: String,
    device_id: String,
) -> Result<Arc<MdbxVault>, MdbxFfiError> {
    let mut conn = VaultConnection::open(Path::new(&path))?;
    let password = Zeroizing::new(password);
    UnlockService::unlock_with_password(&mut conn, password.as_str())?;
    let vault_id = read_vault_id(&conn)?;
    Ok(Arc::new(MdbxVault {
        conn: Mutex::new(conn),
        device_id,
        vault_id,
    }))
}

#[uniffi::export]
pub fn open_vault_with_security_key(
    path: String,
    key_material: Vec<u8>,
    device_id: String,
) -> Result<Arc<MdbxVault>, MdbxFfiError> {
    let mut conn = VaultConnection::open(Path::new(&path))?;
    let key_material = Zeroizing::new(key_material);
    UnlockService::unlock_with_security_key(&mut conn, key_material.as_slice())?;
    let vault_id = read_vault_id(&conn)?;
    Ok(Arc::new(MdbxVault {
        conn: Mutex::new(conn),
        device_id,
        vault_id,
    }))
}

fn read_vault_id(conn: &VaultConnection) -> Result<String, MdbxFfiError> {
    conn.inner()
        .query_row("SELECT vault_id FROM vault_meta LIMIT 1", [], |row| {
            row.get::<_, String>(0)
        })
        .map_err(StorageError::from)
        .map_err(MdbxFfiError::from)
}

fn entry_for_project(
    conn: &VaultConnection,
    project_id: &str,
    entry_id: &str,
) -> StorageResult<mdbx_core::model::Entry> {
    let entry = EntryRepo::get_by_id(conn, entry_id)?
        .ok_or_else(|| StorageError::NotFound(entry_id.to_string()))?;
    if entry.project_id != project_id {
        return Err(StorageError::ConstraintViolation(format!(
            "entry {} does not belong to project {}",
            entry_id, project_id
        )));
    }
    Ok(entry)
}

fn parse_entry_type(entry_type: &str) -> Result<EntryType, MdbxFfiError> {
    entry_type
        .parse()
        .map_err(|_| MdbxFfiError::InvalidEntryType {
            entry_type: entry_type.to_string(),
        })
}

fn parse_optional_entry_type(
    entry_type: Option<String>,
) -> Result<Option<EntryType>, MdbxFfiError> {
    entry_type.as_deref().map(parse_entry_type).transpose()
}

fn parse_payload_json(payload_json: &str) -> Result<serde_json::Value, MdbxFfiError> {
    serde_json::from_str(payload_json).map_err(MdbxFfiError::from)
}

fn entry_record_from_entry(entry: &mdbx_core::model::Entry) -> Result<EntryRecord, MdbxFfiError> {
    let payload: serde_json::Value = serde_json::from_slice(&entry.payload_ct)?;
    Ok(EntryRecord {
        entry_id: entry.entry_id.clone(),
        project_id: entry.project_id.clone(),
        entry_type: entry.entry_type.to_string(),
        title: entry
            .title_ct
            .as_deref()
            .map(String::from_utf8_lossy)
            .map(|s| s.to_string())
            .unwrap_or_default(),
        payload_json: serde_json::to_string(&payload)?,
        deleted: entry.deleted,
    })
}
