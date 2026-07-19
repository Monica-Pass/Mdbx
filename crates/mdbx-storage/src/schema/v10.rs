use rusqlite::{Connection, OptionalExtension};

use crate::error::{StorageError, StorageResult};

const ATTACHMENT_SCOPE_MARKER: &str = "'attachment'";

pub fn create_extensions(conn: &Connection) -> StorageResult<()> {
    let exception_sql = table_sql(conn, "tiga_policy_exceptions")?;
    let override_sql = table_sql(conn, "tiga_policy_overrides")?;
    if exception_sql.contains(ATTACHMENT_SCOPE_MARKER)
        && override_sql.contains(ATTACHMENT_SCOPE_MARKER)
    {
        return Ok(());
    }

    conn.execute_batch(
        "CREATE TABLE tiga_policy_exceptions_v10 (
            exception_id           TEXT PRIMARY KEY NOT NULL,
            target_scope           TEXT NOT NULL CHECK (target_scope IN ('vault', 'project', 'entry', 'attachment')),
            target_id              TEXT NOT NULL,
            approved_override_json TEXT NOT NULL,
            reason                 TEXT NOT NULL CHECK (length(trim(reason)) > 0),
            expires_at_unix_secs   INTEGER,
            created_at             TEXT NOT NULL,
            created_by_session_id  TEXT,
            revoked_at             TEXT,
            integrity_tag          BLOB
        );
        INSERT INTO tiga_policy_exceptions_v10
            (exception_id, target_scope, target_id, approved_override_json,
             reason, expires_at_unix_secs, created_at, created_by_session_id,
             revoked_at, integrity_tag)
        SELECT exception_id, target_scope, target_id, approved_override_json,
               reason, expires_at_unix_secs, created_at, created_by_session_id,
               revoked_at, integrity_tag
        FROM tiga_policy_exceptions;

        CREATE TABLE tiga_policy_overrides_v10 (
            scope_type           TEXT NOT NULL CHECK (scope_type IN ('vault', 'project', 'entry', 'attachment')),
            scope_id             TEXT NOT NULL,
            policy_json          TEXT NOT NULL,
            exception_id         TEXT,
            updated_at           TEXT NOT NULL,
            updated_by_device_id TEXT NOT NULL,
            integrity_tag        BLOB,
            PRIMARY KEY (scope_type, scope_id),
            FOREIGN KEY (exception_id) REFERENCES tiga_policy_exceptions_v10(exception_id)
        );
        INSERT INTO tiga_policy_overrides_v10
            (scope_type, scope_id, policy_json, exception_id, updated_at,
             updated_by_device_id, integrity_tag)
        SELECT scope_type, scope_id, policy_json, exception_id, updated_at,
               updated_by_device_id, integrity_tag
        FROM tiga_policy_overrides;

        DROP TABLE tiga_policy_overrides;
        DROP TABLE tiga_policy_exceptions;
        ALTER TABLE tiga_policy_exceptions_v10 RENAME TO tiga_policy_exceptions;
        ALTER TABLE tiga_policy_overrides_v10 RENAME TO tiga_policy_overrides;
        CREATE INDEX idx_tiga_exceptions_target
            ON tiga_policy_exceptions (target_scope, target_id, revoked_at);",
    )
    .map_err(StorageError::Database)
}

fn table_sql(conn: &Connection, table: &str) -> StorageResult<String> {
    conn.query_row(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [table],
        |row| row.get(0),
    )
    .optional()
    .map_err(StorageError::Database)?
    .ok_or_else(|| StorageError::Validation(format!("missing required table {table}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema;

    #[test]
    fn schema_10_accepts_attachment_tiga_scopes() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        schema::create_all_tables(&conn).unwrap();
        conn.execute(
            "INSERT INTO tiga_policy_exceptions
                (exception_id, target_scope, target_id, approved_override_json,
                 reason, created_at)
             VALUES ('e1', 'attachment', 'a1', '{}', 'test', '2026-07-20T00:00:00Z')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO tiga_policy_overrides
                (scope_type, scope_id, policy_json, exception_id, updated_at,
                 updated_by_device_id)
             VALUES ('attachment', 'a1', '{}', 'e1', '2026-07-20T00:00:00Z', 'd1')",
            [],
        )
        .unwrap();
    }

    #[test]
    fn schema_10_rebuild_preserves_existing_policy_rows_and_foreign_keys() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE tiga_policy_exceptions (
                exception_id TEXT PRIMARY KEY NOT NULL,
                target_scope TEXT NOT NULL CHECK (target_scope IN ('vault', 'project', 'entry')),
                target_id TEXT NOT NULL,
                approved_override_json TEXT NOT NULL,
                reason TEXT NOT NULL CHECK (length(trim(reason)) > 0),
                expires_at_unix_secs INTEGER,
                created_at TEXT NOT NULL,
                created_by_session_id TEXT,
                revoked_at TEXT,
                integrity_tag BLOB
             );
             CREATE TABLE tiga_policy_overrides (
                scope_type TEXT NOT NULL CHECK (scope_type IN ('vault', 'project', 'entry')),
                scope_id TEXT NOT NULL,
                policy_json TEXT NOT NULL,
                exception_id TEXT,
                updated_at TEXT NOT NULL,
                updated_by_device_id TEXT NOT NULL,
                integrity_tag BLOB,
                PRIMARY KEY (scope_type, scope_id),
                FOREIGN KEY (exception_id) REFERENCES tiga_policy_exceptions(exception_id)
             );
             CREATE INDEX idx_tiga_exceptions_target
                ON tiga_policy_exceptions (target_scope, target_id, revoked_at);
             INSERT INTO tiga_policy_exceptions
                (exception_id, target_scope, target_id, approved_override_json,
                 reason, created_at)
             VALUES ('legacy-exception', 'project', 'p1', '{}', 'legacy',
                     '2026-07-19T00:00:00Z');
             INSERT INTO tiga_policy_overrides
                (scope_type, scope_id, policy_json, exception_id, updated_at,
                 updated_by_device_id)
             VALUES ('project', 'p1', '{}', 'legacy-exception',
                     '2026-07-19T00:00:00Z', 'd1');",
        )
        .unwrap();

        create_extensions(&conn).unwrap();

        let preserved: (String, String) = conn
            .query_row(
                "SELECT e.target_scope, o.scope_type
                 FROM tiga_policy_exceptions e
                 JOIN tiga_policy_overrides o ON o.exception_id = e.exception_id
                 WHERE e.exception_id = 'legacy-exception'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(preserved, ("project".to_string(), "project".to_string()));
        let foreign_key_target: String = conn
            .query_row(
                "PRAGMA foreign_key_list(tiga_policy_overrides)",
                [],
                |row| row.get(2),
            )
            .unwrap();
        assert_eq!(foreign_key_target, "tiga_policy_exceptions");
        let foreign_key_errors: i64 = conn
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(foreign_key_errors, 0);

        conn.execute(
            "INSERT INTO tiga_policy_overrides
                (scope_type, scope_id, policy_json, updated_at, updated_by_device_id)
             VALUES ('attachment', 'a1', '{}', '2026-07-20T00:00:00Z', 'd1')",
            [],
        )
        .unwrap();
    }
}
