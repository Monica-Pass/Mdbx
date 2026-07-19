use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use rusqlite::backup::{Backup, StepResult};
use rusqlite::{Connection, OpenFlags};
use tempfile::NamedTempFile;

use crate::connection::VaultConnection;
use crate::error::{StorageError, StorageResult};
use crate::migration::{inspect_migration, CURRENT_SCHEMA_VERSION, FORMAT_V2};

const BACKUP_PAGES_PER_STEP: i32 = 128;
const BACKUP_RETRY_PAUSE: Duration = Duration::from_millis(10);
const BACKUP_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultBackupInfo {
    pub vault_id: String,
    pub format_version: String,
    pub schema_version: u32,
    pub file_size_bytes: u64,
}

pub struct BackupService;

impl BackupService {
    /// Create a transactionally consistent, self-contained copy of a live vault.
    ///
    /// The destination and its SQLite sidecars must not already exist. The copy
    /// is verified before it is published and is never allowed to replace an
    /// existing file.
    pub fn create_portable_copy(
        source: &VaultConnection,
        destination: &Path,
    ) -> StorageResult<VaultBackupInfo> {
        let destination = absolute_destination(destination)?;
        reject_source_destination_alias(source.inner(), &destination)?;
        ensure_destination_absent(&destination)?;

        let source_vault_id = read_vault_id(source.inner())?;
        let parent = destination.parent().ok_or_else(|| {
            StorageError::Validation("backup destination must have a parent directory".to_string())
        })?;
        let temporary = NamedTempFile::new_in(parent)?;
        let temporary_path = temporary.path().to_path_buf();
        let _sidecar_cleanup = TemporarySidecarCleanup::new(&temporary_path);

        let mut target =
            Connection::open_with_flags(&temporary_path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        target.execute_batch("PRAGMA busy_timeout=5000;")?;
        copy_online(source.inner(), &mut target)?;

        let journal_mode: String =
            target.query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("delete") {
            return Err(StorageError::Validation(format!(
                "portable backup retained unsupported journal mode: {journal_mode}"
            )));
        }

        let integrity: String = target.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
        if integrity != "ok" {
            return Err(StorageError::Validation(format!(
                "portable backup integrity check failed: {integrity}"
            )));
        }

        let migration = inspect_migration(&target)?;
        if !migration.initialized
            || migration.unknown_critical_extensions
            || migration.requires_upgrade
            || migration.format_version.as_deref() != Some(FORMAT_V2)
            || migration.schema_version != Some(CURRENT_SCHEMA_VERSION)
        {
            return Err(StorageError::Validation(
                "portable backup does not contain current MDBX2 metadata".to_string(),
            ));
        }

        let target_vault_id = read_vault_id(&target)?;
        if target_vault_id != source_vault_id {
            return Err(StorageError::Validation(
                "portable backup vault identity does not match the source".to_string(),
            ));
        }

        drop(target);
        ensure_sidecars_absent(&temporary_path)?;
        temporary.as_file().sync_all()?;
        let file_size_bytes = temporary.as_file().metadata()?.len();

        ensure_destination_absent(&destination)?;
        temporary
            .persist_noclobber(&destination)
            .map_err(|error| StorageError::Io(error.error))?;

        Ok(VaultBackupInfo {
            vault_id: source_vault_id,
            format_version: FORMAT_V2.to_string(),
            schema_version: CURRENT_SCHEMA_VERSION,
            file_size_bytes,
        })
    }
}

fn copy_online(source: &Connection, target: &mut Connection) -> StorageResult<()> {
    let backup = Backup::new(source, target)?;
    let deadline = Instant::now() + BACKUP_DEADLINE;

    loop {
        if Instant::now() >= deadline {
            return Err(StorageError::Validation(
                "portable backup exceeded its completion deadline".to_string(),
            ));
        }
        match backup.step(BACKUP_PAGES_PER_STEP)? {
            StepResult::Done => return Ok(()),
            StepResult::More => thread::yield_now(),
            StepResult::Busy | StepResult::Locked => {
                thread::sleep(BACKUP_RETRY_PAUSE);
            }
            _ => {
                return Err(StorageError::Validation(
                    "portable backup returned an unknown SQLite step result".to_string(),
                ))
            }
        }
    }
}

fn read_vault_id(connection: &Connection) -> StorageResult<String> {
    connection
        .query_row("SELECT vault_id FROM vault_meta LIMIT 1", [], |row| {
            row.get(0)
        })
        .map_err(StorageError::Database)
}

fn reject_source_destination_alias(source: &Connection, destination: &Path) -> StorageResult<()> {
    let source_path: String = source.query_row(
        "SELECT file FROM pragma_database_list WHERE name = 'main'",
        [],
        |row| row.get(0),
    )?;
    if !source_path.is_empty() {
        let source_path = fs::canonicalize(source_path)?;
        if source_path == destination {
            return Err(StorageError::Validation(
                "backup destination must differ from the source vault".to_string(),
            ));
        }
    }
    Ok(())
}

fn absolute_destination(destination: &Path) -> StorageResult<PathBuf> {
    let file_name = destination.file_name().ok_or_else(|| {
        StorageError::Validation("backup destination must name a file".to_string())
    })?;
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(fs::canonicalize(parent)?.join(file_name))
}

fn ensure_destination_absent(destination: &Path) -> StorageResult<()> {
    ensure_path_absent(destination)?;
    ensure_sidecars_absent(destination)
}

fn ensure_sidecars_absent(path: &Path) -> StorageResult<()> {
    for suffix in ["-wal", "-shm"] {
        ensure_path_absent(&sqlite_sidecar_path(path, suffix))?;
    }
    Ok(())
}

fn ensure_path_absent(path: &Path) -> StorageResult<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(StorageError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "backup destination artifact already exists: {}",
                path.display()
            ),
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(StorageError::Io(error)),
    }
}

fn sqlite_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

struct TemporarySidecarCleanup {
    path: PathBuf,
}

impl TemporarySidecarCleanup {
    fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
        }
    }
}

impl Drop for TemporarySidecarCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(sqlite_sidecar_path(&self.path, "-wal"));
        let _ = fs::remove_file(sqlite_sidecar_path(&self.path, "-shm"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::PendingVaultCreation;
    use crate::init::{initialize_vault, VaultInitParams};
    use crate::repo::{CommitContext, ProjectRepo};

    fn create_source(directory: &Path) -> (PathBuf, VaultConnection, String) {
        let path = directory.join("source.mdbx");
        let creation = PendingVaultCreation::begin(&path).unwrap();
        let initialized =
            initialize_vault(creation.connection(), &VaultInitParams::default()).unwrap();
        (path, creation.commit(), initialized.vault_id)
    }

    #[test]
    fn backup_includes_committed_wal_pages_and_reopens_without_sidecars() {
        let directory = tempfile::tempdir().unwrap();
        let (source_path, source, vault_id) = create_source(directory.path());
        let context = CommitContext::new("backup-device".to_string());
        let project =
            ProjectRepo::create(&source, &context, "Latest WAL project", None, None).unwrap();
        let source_wal = sqlite_sidecar_path(&source_path, "-wal");
        assert!(source_wal.metadata().unwrap().len() > 0);

        let destination = directory.path().join("portable.mdbx");
        let info = BackupService::create_portable_copy(&source, &destination).unwrap();

        assert_eq!(info.vault_id, vault_id);
        assert_eq!(info.format_version, FORMAT_V2);
        assert_eq!(info.schema_version, CURRENT_SCHEMA_VERSION);
        assert!(info.file_size_bytes > 0);
        assert!(destination.exists());
        assert!(!sqlite_sidecar_path(&destination, "-wal").exists());
        assert!(!sqlite_sidecar_path(&destination, "-shm").exists());

        let reopened = VaultConnection::open(&destination).unwrap();
        let restored = ProjectRepo::get_by_id(&reopened, &project.project_id)
            .unwrap()
            .unwrap();
        assert_eq!(restored.title_ct, b"Latest WAL project");
    }

    #[test]
    fn backup_preserves_an_existing_destination_file() {
        let directory = tempfile::tempdir().unwrap();
        let (_, source, _) = create_source(directory.path());
        let destination = directory.path().join("existing.mdbx");
        fs::write(&destination, b"preserve existing backup").unwrap();

        let error = BackupService::create_portable_copy(&source, &destination)
            .err()
            .unwrap();

        assert!(matches!(error, StorageError::Io(_)));
        assert_eq!(fs::read(destination).unwrap(), b"preserve existing backup");
    }

    #[test]
    fn backup_preserves_existing_destination_sidecars() {
        let directory = tempfile::tempdir().unwrap();
        let (_, source, _) = create_source(directory.path());
        let destination = directory.path().join("sidecars.mdbx");
        let wal = sqlite_sidecar_path(&destination, "-wal");
        let shm = sqlite_sidecar_path(&destination, "-shm");
        fs::write(&wal, b"preserve wal").unwrap();
        fs::write(&shm, b"preserve shm").unwrap();

        let error = BackupService::create_portable_copy(&source, &destination)
            .err()
            .unwrap();

        assert!(matches!(error, StorageError::Io(_)));
        assert!(!destination.exists());
        assert_eq!(fs::read(wal).unwrap(), b"preserve wal");
        assert_eq!(fs::read(shm).unwrap(), b"preserve shm");
    }

    #[test]
    fn backup_rejects_the_source_path() {
        let directory = tempfile::tempdir().unwrap();
        let (source_path, source, _) = create_source(directory.path());

        let error = BackupService::create_portable_copy(&source, &source_path)
            .err()
            .unwrap();

        assert!(matches!(error, StorageError::Validation(_)));
        assert!(source_path.exists());
    }

    #[test]
    fn failed_backup_removes_temporary_database_and_sidecars() {
        let directory = tempfile::tempdir().unwrap();
        let (_, source, _) = create_source(directory.path());
        source
            .inner()
            .execute("UPDATE vault_meta SET format_version = 'MDBX-FUTURE'", [])
            .unwrap();
        let before = directory_entries(directory.path());
        let destination = directory.path().join("invalid.mdbx");

        let error = BackupService::create_portable_copy(&source, &destination)
            .err()
            .unwrap();

        assert!(matches!(error, StorageError::Validation(_)));
        assert_eq!(directory_entries(directory.path()), before);
        assert!(!destination.exists());
    }

    fn directory_entries(directory: &Path) -> Vec<String> {
        let mut entries = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        entries.sort();
        entries
    }
}
