use rusqlite::Connection;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

use mdbx_core::model::VaultSession;
use mdbx_crypto::keyring::Keyring;

use crate::error::{StorageError, StorageResult};
use crate::schema;

/// 打开的 vault 数据库连接。
///
/// 在打开时自动设置必要的 PRAGMA：
/// - WAL 模式（增量写入友好）
/// - foreign_keys 强制
/// - secure_delete 启用
/// - busy_timeout 5 秒
///
/// 解锁后可附加 Keyring 以启用字段级加密。
pub struct VaultConnection {
    pub(crate) conn: Connection,
    pub(crate) keyring: Option<Keyring>,
    pub(crate) active_session: Option<VaultSession>,
}

/// A newly reserved vault file that is removed unless creation is committed.
///
/// Production callers keep this guard alive while initializing metadata and
/// configuring the first unlock method. Any early return drops the connection
/// before removing the database and its SQLite sidecars.
pub struct PendingVaultCreation {
    path: PathBuf,
    connection: Option<VaultConnection>,
    committed: bool,
}

impl PendingVaultCreation {
    pub fn begin(path: &Path) -> StorageResult<Self> {
        Ok(Self {
            path: path.to_path_buf(),
            connection: Some(VaultConnection::create(path)?),
            committed: false,
        })
    }

    pub fn connection(&self) -> &VaultConnection {
        self.connection
            .as_ref()
            .expect("pending vault connection must exist before commit")
    }

    pub fn connection_mut(&mut self) -> &mut VaultConnection {
        self.connection
            .as_mut()
            .expect("pending vault connection must exist before commit")
    }

    pub fn commit(mut self) -> VaultConnection {
        self.committed = true;
        self.connection
            .take()
            .expect("pending vault connection must exist before commit")
    }
}

impl Drop for PendingVaultCreation {
    fn drop(&mut self) {
        self.connection.take();
        if !self.committed {
            remove_vault_files(&self.path);
        }
    }
}

impl VaultConnection {
    /// 打开已有的 `.mdbx` 文件。
    pub fn open(path: &Path) -> StorageResult<Self> {
        let conn = Connection::open(path)?;
        Self::apply_pragmas(&conn)?;
        Self::cleanup_legacy_persistent_fts(&conn)?;
        crate::migration::upgrade_to_latest(&conn)?;
        Ok(Self {
            conn,
            keyring: None,
            active_session: None,
        })
    }

    /// 创建新的 `.mdbx` 文件。
    ///
    /// 文件路径必须尚不存在。生产入口应通过 `PendingVaultCreation`
    /// 完成初始化与首个解锁方法配置，使后续步骤失败时可以清理新文件。
    pub fn create(path: &Path) -> StorageResult<Self> {
        ensure_sidecars_absent(path)?;
        OpenOptions::new().write(true).create_new(true).open(path)?;

        let result = (|| {
            let conn = Connection::open(path)?;
            Self::apply_pragmas(&conn)?;
            schema::create_all_tables(&conn)?;
            Self::cleanup_legacy_persistent_fts(&conn)?;
            Ok(Self {
                conn,
                keyring: None,
                active_session: None,
            })
        })();
        if result.is_err() {
            remove_vault_files(path);
        }
        result
    }

    /// 打开内存数据库（用于测试）。
    pub fn open_in_memory() -> StorageResult<Self> {
        let conn = Connection::open_in_memory()?;
        Self::apply_pragmas(&conn)?;
        schema::create_all_tables(&conn)?;
        Self::cleanup_legacy_persistent_fts(&conn)?;
        Ok(Self {
            conn,
            keyring: None,
            active_session: None,
        })
    }

    fn apply_pragmas(conn: &Connection) -> StorageResult<()> {
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;
             PRAGMA secure_delete=ON;
             PRAGMA busy_timeout=5000;",
        )
        .map_err(StorageError::Database)
    }

    fn cleanup_legacy_persistent_fts(conn: &Connection) -> StorageResult<()> {
        conn.execute_batch("DROP TABLE IF EXISTS main.project_titles_fts;")
            .map_err(StorageError::Database)
    }

    /// 获取内部 rusqlite 连接的引用。
    pub fn inner(&self) -> &Connection {
        &self.conn
    }

    /// Run a storage mutation atomically.
    ///
    /// This uses a manual transaction because repositories share an immutable
    /// connection handle. If the caller is already inside a transaction, the
    /// closure is executed in that existing transaction.
    pub(crate) fn with_immediate_transaction<T>(
        &self,
        f: impl FnOnce() -> StorageResult<T>,
    ) -> StorageResult<T> {
        if !self.conn.is_autocommit() {
            return f();
        }

        self.conn
            .execute_batch("BEGIN IMMEDIATE TRANSACTION;")
            .map_err(StorageError::Database)?;

        match f() {
            Ok(value) => {
                if let Err(e) = self.conn.execute_batch("COMMIT;") {
                    let _ = self.conn.execute_batch("ROLLBACK;");
                    Err(StorageError::Database(e))
                } else {
                    Ok(value)
                }
            }
            Err(err) => {
                let _ = self.conn.execute_batch("ROLLBACK;");
                Err(err)
            }
        }
    }

    pub(crate) fn with_immediate_transaction_mut<T>(
        &mut self,
        f: impl FnOnce(&mut Self) -> StorageResult<T>,
    ) -> StorageResult<T> {
        if !self.conn.is_autocommit() {
            return f(self);
        }

        self.conn
            .execute_batch("BEGIN IMMEDIATE TRANSACTION;")
            .map_err(StorageError::Database)?;
        match f(self) {
            Ok(value) => {
                if let Err(error) = self.conn.execute_batch("COMMIT;") {
                    let _ = self.conn.execute_batch("ROLLBACK;");
                    Err(StorageError::Database(error))
                } else {
                    Ok(value)
                }
            }
            Err(error) => {
                let _ = self.conn.execute_batch("ROLLBACK;");
                Err(error)
            }
        }
    }

    /// 附加密钥环，启用字段级加密。
    ///
    /// 在解锁成功后调用。此后所有 `_ct` 字段在写入时加密、读取时解密。
    pub fn attach_keyring(&mut self, keyring: Keyring) {
        self.keyring = Some(keyring);
    }

    pub fn attach_session(&mut self, session: VaultSession) {
        self.active_session = Some(session);
    }

    pub fn active_session(&self) -> Option<&VaultSession> {
        self.active_session.as_ref()
    }

    pub(crate) fn touch_active_session(&mut self, now_unix_secs: i64) {
        if let Some(session) = self.active_session.as_mut() {
            session.assurance = session.assurance.touched(now_unix_secs);
        }
    }

    pub fn clear_session(&mut self) {
        self.active_session = None;
        self.keyring = None;
    }

    /// 获取密钥环的引用（存在时）。
    pub fn keyring(&self) -> Option<&Keyring> {
        self.keyring.as_ref()
    }

    /// 当前连接是否已启用加密。
    pub fn is_encrypted(&self) -> bool {
        self.keyring.is_some()
    }
}

fn sqlite_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn ensure_sidecars_absent(path: &Path) -> StorageResult<()> {
    for suffix in ["-wal", "-shm"] {
        let sidecar = sqlite_sidecar_path(path, suffix);
        match fs::symlink_metadata(&sidecar) {
            Ok(_) => {
                return Err(StorageError::Io(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("SQLite sidecar already exists: {}", sidecar.display()),
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(StorageError::Io(error)),
        }
    }
    Ok(())
}

fn remove_vault_files(path: &Path) {
    let _ = fs::remove_file(sqlite_sidecar_path(path, "-wal"));
    let _ = fs::remove_file(sqlite_sidecar_path(path, "-shm"));
    let _ = fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::{initialize_vault, VaultInitParams};
    use uuid::Uuid;

    fn temp_db_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("mdbx-{label}-{}.db", Uuid::new_v4()))
    }

    fn create_legacy_fts_db(path: &Path) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE VIRTUAL TABLE main.project_titles_fts USING fts5(
                project_id UNINDEXED,
                title,
                tokenize='unicode61 remove_diacritics 2'
             );
             INSERT INTO main.project_titles_fts (project_id, title)
             VALUES ('project-1', 'plaintext legacy title');",
        )
        .unwrap();
    }

    fn persistent_fts_exists(conn: &Connection) -> bool {
        conn.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'project_titles_fts'
             )",
            [],
            |row| row.get::<_, bool>(0),
        )
        .unwrap()
    }

    #[test]
    fn open_removes_legacy_persistent_fts() {
        let path = temp_db_path("open-legacy-fts");
        create_legacy_fts_db(&path);

        let conn = VaultConnection::open(&path).unwrap();
        assert!(!persistent_fts_exists(conn.inner()));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn create_rejects_existing_legacy_fts_database_without_modifying_it() {
        let path = temp_db_path("create-legacy-fts");
        create_legacy_fts_db(&path);

        let error = VaultConnection::create(&path).err().unwrap();
        let existing = Connection::open(&path).unwrap();

        assert!(matches!(error, StorageError::Io(_)));
        assert!(persistent_fts_exists(&existing));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn open_in_memory_does_not_create_persistent_fts() {
        let conn = VaultConnection::open_in_memory().unwrap();
        assert!(!persistent_fts_exists(conn.inner()));
    }

    #[test]
    fn create_rejects_existing_file_without_modifying_it() {
        let path = temp_db_path("existing-file");
        let original = b"existing non-mdbx data";
        fs::write(&path, original).unwrap();

        let error = VaultConnection::create(&path).err().unwrap();

        assert!(matches!(error, StorageError::Io(_)));
        assert_eq!(fs::read(&path).unwrap(), original);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn create_rejects_preexisting_sidecars_without_modifying_them() {
        let path = temp_db_path("existing-sidecars");
        let wal = sqlite_sidecar_path(&path, "-wal");
        let shm = sqlite_sidecar_path(&path, "-shm");
        fs::write(&wal, b"existing wal data").unwrap();
        fs::write(&shm, b"existing shm data").unwrap();

        let error = VaultConnection::create(&path).err().unwrap();

        assert!(matches!(error, StorageError::Io(_)));
        assert!(!path.exists());
        assert_eq!(fs::read(&wal).unwrap(), b"existing wal data");
        assert_eq!(fs::read(&shm).unwrap(), b"existing shm data");
        let _ = fs::remove_file(wal);
        let _ = fs::remove_file(shm);
    }

    #[test]
    fn abandoned_pending_creation_removes_database_and_sidecars() {
        let path = temp_db_path("abandoned-creation");
        {
            let creation = PendingVaultCreation::begin(&path).unwrap();
            initialize_vault(creation.connection(), &VaultInitParams::default()).unwrap();
            assert!(path.exists());
        }

        assert!(!path.exists());
        assert!(!sqlite_sidecar_path(&path, "-wal").exists());
        assert!(!sqlite_sidecar_path(&path, "-shm").exists());
    }

    #[test]
    fn committed_pending_creation_remains_reopenable() {
        let path = temp_db_path("committed-creation");
        let mut creation = PendingVaultCreation::begin(&path).unwrap();
        let initialized =
            initialize_vault(creation.connection(), &VaultInitParams::default()).unwrap();
        creation
            .connection_mut()
            .inner()
            .execute_batch("PRAGMA wal_checkpoint(PASSIVE);")
            .unwrap();
        let connection = creation.commit();
        drop(connection);

        let reopened = VaultConnection::open(&path).unwrap();
        let vault_id: String = reopened
            .inner()
            .query_row("SELECT vault_id FROM vault_meta", [], |row| row.get(0))
            .unwrap();

        assert_eq!(vault_id, initialized.vault_id);
        drop(reopened);
        remove_vault_files(&path);
    }
}
