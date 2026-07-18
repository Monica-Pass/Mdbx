pub mod v1;
pub mod v2;

use rusqlite::Connection;

use crate::error::StorageResult;

/// 当前 schema 版本号。
pub const SCHEMA_VERSION: u32 = 3;

/// 创建全部表与索引。
pub fn create_all_tables(conn: &Connection) -> StorageResult<()> {
    v1::create_all_tables(conn)?;
    v2::create_extensions(conn)
}
