use rusqlite::Connection;
use std::path::Path;

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
}

impl VaultConnection {
    /// 打开已有的 `.mdbx` 文件。
    pub fn open(path: &Path) -> StorageResult<Self> {
        let conn = Connection::open(path)?;
        Self::apply_pragmas(&conn)?;
        Self::cleanup_legacy_persistent_fts(&conn)?;
        Ok(Self {
            conn,
            keyring: None,
        })
    }

    /// 创建新的 `.mdbx` 文件。
    pub fn create(path: &Path) -> StorageResult<Self> {
        let conn = Connection::open(path)?;
        Self::apply_pragmas(&conn)?;
        schema::create_all_tables(&conn)?;
        Self::cleanup_legacy_persistent_fts(&conn)?;
        Ok(Self {
            conn,
            keyring: None,
        })
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
        })
    }

    fn apply_pragmas(conn: &Connection) -> StorageResult<()> {
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;
             PRAGMA secure_delete=ON;
             PRAGMA busy_timeout=5000;",
        )
        .map_err(|e| StorageError::Database(e))
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

    /// 附加密钥环，启用字段级加密。
    ///
    /// 在解锁成功后调用。此后所有 `_ct` 字段在写入时加密、读取时解密。
    pub fn attach_keyring(&mut self, keyring: Keyring) {
        self.keyring = Some(keyring);
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

#[cfg(test)]
mod tests {
    use super::*;
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
    fn create_removes_legacy_persistent_fts_from_existing_file() {
        let path = temp_db_path("create-legacy-fts");
        create_legacy_fts_db(&path);

        let conn = VaultConnection::create(&path).unwrap();
        assert!(!persistent_fts_exists(conn.inner()));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn open_in_memory_does_not_create_persistent_fts() {
        let conn = VaultConnection::open_in_memory().unwrap();
        assert!(!persistent_fts_exists(conn.inner()));
    }
}
