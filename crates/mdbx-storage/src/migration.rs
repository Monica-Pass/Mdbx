use std::collections::HashMap;

use mdbx_core::model::{KdfParams, UnlockMethodType};
use mdbx_core::tiga::{TigaMode, TigaPolicyOverride, TIGA_POLICY_VERSION};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use std::path::Path;

use crate::error::{StorageError, StorageResult};
use crate::schema::v2;

pub const FORMAT_V1: &str = "MDBX-1";
pub const FORMAT_V1_DRAFT: &str = "MDBX-1-DRAFT";
pub const FORMAT_V2: &str = "MDBX-2";
pub const CURRENT_SCHEMA_VERSION: u32 = 5;
pub const MIGRATION_V1_TO_V2: &str = "mdbx-1-to-mdbx-2";
pub const MIGRATION_TIGA2_POLICY: &str = "mdbx-2-tiga-policy-v2";
pub const MIGRATION_COMMIT2: &str = "mdbx-2-operation-commits-v1";
pub const MIGRATION_TIGA_AUDIT_CORRELATION: &str = "mdbx-2-tiga-audit-correlation-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatInfo {
    pub format_version: String,
    pub schema_version: u32,
    pub min_reader_version: String,
    pub min_writer_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationInfo {
    pub initialized: bool,
    pub format_version: Option<String>,
    pub schema_version: Option<u32>,
    pub min_reader_version: Option<String>,
    pub min_writer_version: Option<String>,
    pub requires_upgrade: bool,
    pub unknown_critical_extensions: bool,
    pub target_format_version: String,
    pub target_schema_version: u32,
}

/// Inspect a vault without changing it. This is the client-facing planning
/// step for backup, consent, progress, and remediation UI.
pub fn inspect_migration(conn: &Connection) -> StorageResult<MigrationInfo> {
    if !table_exists(conn, "vault_meta")? {
        return Ok(MigrationInfo {
            initialized: false,
            format_version: None,
            schema_version: None,
            min_reader_version: None,
            min_writer_version: None,
            requires_upgrade: false,
            unknown_critical_extensions: false,
            target_format_version: FORMAT_V2.to_string(),
            target_schema_version: CURRENT_SCHEMA_VERSION,
        });
    }

    let meta: Option<(String, String)> = conn
        .query_row(
            "SELECT format_version, critical_extensions FROM vault_meta LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(StorageError::Database)?;
    let Some((format_version, critical_extensions)) = meta else {
        return Ok(MigrationInfo {
            initialized: false,
            format_version: None,
            schema_version: None,
            min_reader_version: None,
            min_writer_version: None,
            requires_upgrade: false,
            unknown_critical_extensions: false,
            target_format_version: FORMAT_V2.to_string(),
            target_schema_version: CURRENT_SCHEMA_VERSION,
        });
    };

    let schema_version = if v2::column_exists(conn, "vault_meta", "schema_version")? {
        conn.query_row("SELECT schema_version FROM vault_meta LIMIT 1", [], |row| {
            row.get::<_, i64>(0)
        })
        .optional()?
        .map(|value| value as u32)
    } else {
        Some(1)
    };
    let min_reader_version = optional_meta_text(conn, "min_reader_version")?;
    let min_writer_version = optional_meta_text(conn, "min_writer_version")?;
    let requires_upgrade = match format_version.as_str() {
        FORMAT_V1 | FORMAT_V1_DRAFT => true,
        FORMAT_V2 => schema_version.unwrap_or(1) < CURRENT_SCHEMA_VERSION,
        other => {
            return Err(StorageError::Validation(format!(
                "unsupported MDBX format version: {other}"
            )))
        }
    };

    Ok(MigrationInfo {
        initialized: true,
        format_version: Some(format_version),
        schema_version,
        min_reader_version,
        min_writer_version,
        requires_upgrade,
        unknown_critical_extensions: has_unknown_critical_extensions(&critical_extensions),
        target_format_version: FORMAT_V2.to_string(),
        target_schema_version: CURRENT_SCHEMA_VERSION,
    })
}

/// Inspect a vault file using a read-only SQLite handle.
pub fn inspect_migration_path(path: &Path) -> StorageResult<MigrationInfo> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(StorageError::Database)?;
    inspect_migration(&conn)
}

/// Explicitly upgrade a vault file through the storage-core migration path.
/// The existing `VaultConnection::open` path remains an automatic-upgrade
/// compatibility path; clients that need consent and backup orchestration can
/// call this function after `inspect_migration_path`.
pub fn upgrade_path(path: &Path) -> StorageResult<Option<FormatInfo>> {
    let conn = Connection::open(path).map_err(StorageError::Database)?;
    upgrade_to_latest(&conn)
}

fn optional_meta_text(conn: &Connection, column: &str) -> StorageResult<Option<String>> {
    if !v2::column_exists(conn, "vault_meta", column)? {
        return Ok(None);
    }
    conn.query_row(
        &format!("SELECT {column} FROM vault_meta LIMIT 1"),
        [],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(StorageError::Database)
}

/// Upgrade an initialized vault to the latest supported generation.
///
/// The format marker is updated last inside one SQLite transaction. An empty
/// database is left untouched so `VaultConnection::create` can initialize it.
pub fn upgrade_to_latest(conn: &Connection) -> StorageResult<Option<FormatInfo>> {
    if !table_exists(conn, "vault_meta")? {
        return Ok(None);
    }

    let meta: Option<(String, String)> = conn
        .query_row(
            "SELECT format_version, critical_extensions FROM vault_meta LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(StorageError::Database)?;
    let Some((format_version, critical_extensions)) = meta else {
        return Ok(None);
    };

    reject_unknown_critical_extensions(&critical_extensions)?;

    match format_version.as_str() {
        FORMAT_V1 | FORMAT_V1_DRAFT => migrate_v1_to_v2(conn, &format_version)?,
        FORMAT_V2 => upgrade_mdbx2_schema(conn)?,
        other => {
            return Err(StorageError::Validation(format!(
                "unsupported MDBX format version: {other}"
            )))
        }
    }

    read_format_info(conn).map(Some)
}

pub fn read_format_info(conn: &Connection) -> StorageResult<FormatInfo> {
    validate_v2_schema(conn)?;
    conn.query_row(
        "SELECT format_version, schema_version, min_reader_version, min_writer_version
         FROM vault_meta LIMIT 1",
        [],
        |row| {
            Ok(FormatInfo {
                format_version: row.get(0)?,
                schema_version: row.get::<_, i64>(1)? as u32,
                min_reader_version: row.get(2)?,
                min_writer_version: row.get(3)?,
            })
        },
    )
    .map_err(StorageError::Database)
}

fn migrate_v1_to_v2(conn: &Connection, from_format: &str) -> StorageResult<()> {
    conn.execute_batch("BEGIN IMMEDIATE TRANSACTION;")
        .map_err(StorageError::Database)?;

    let result = (|| -> StorageResult<()> {
        v2::add_column_if_missing(
            conn,
            "vault_meta",
            "schema_version",
            "INTEGER NOT NULL DEFAULT 1",
        )?;
        v2::add_column_if_missing(
            conn,
            "vault_meta",
            "min_reader_version",
            "TEXT NOT NULL DEFAULT 'MDBX-1'",
        )?;
        v2::add_column_if_missing(
            conn,
            "vault_meta",
            "min_writer_version",
            "TEXT NOT NULL DEFAULT 'MDBX-1'",
        )?;
        conn.execute_batch(v2::SCHEMA_MIGRATIONS_DDL)
            .map_err(StorageError::Database)?;
        v2::create_extensions(conn)?;

        let now = chrono::Utc::now().to_rfc3339();
        let remediation_required = migrate_tiga1_policy(conn, &now)?;
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations
             (migration_id, from_format, to_format, applied_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![MIGRATION_V1_TO_V2, from_format, FORMAT_V2, now],
        )
        .map_err(StorageError::Database)?;

        // The generation marker is deliberately the final mutation.
        conn.execute(
            "UPDATE vault_meta SET format_version = ?1, schema_version = ?2,
             min_reader_version = ?3, min_writer_version = ?4, updated_at = ?5,
             tiga_policy_version = ?6, tiga_compliance_status = ?7",
            params![
                FORMAT_V2,
                CURRENT_SCHEMA_VERSION,
                FORMAT_V1,
                FORMAT_V2,
                now,
                TIGA_POLICY_VERSION,
                if remediation_required {
                    "remediation-required"
                } else {
                    "compliant"
                }
            ],
        )
        .map_err(StorageError::Database)?;
        Ok(())
    })();

    match result {
        Ok(()) => conn
            .execute_batch("COMMIT;")
            .map_err(StorageError::Database),
        Err(err) => {
            let _ = conn.execute_batch("ROLLBACK;");
            Err(err)
        }
    }
}

fn upgrade_mdbx2_schema(conn: &Connection) -> StorageResult<()> {
    let schema_version = if v2::column_exists(conn, "vault_meta", "schema_version")? {
        conn.query_row("SELECT schema_version FROM vault_meta LIMIT 1", [], |row| {
            row.get::<_, i64>(0)
        })
        .optional()?
        .unwrap_or(1) as u32
    } else {
        1
    };
    if schema_version >= CURRENT_SCHEMA_VERSION {
        return validate_v2_schema(conn);
    }

    conn.execute_batch("BEGIN IMMEDIATE TRANSACTION;")?;
    let result = (|| -> StorageResult<()> {
        v2::create_extensions(conn)?;
        let now = chrono::Utc::now().to_rfc3339();
        let remediation_required = migrate_tiga1_policy(conn, &now)?;
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations
                (migration_id, from_format, to_format, applied_at)
             VALUES (?1, ?2, ?2, ?3)",
            params![MIGRATION_TIGA2_POLICY, FORMAT_V2, now],
        )?;
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations
                (migration_id, from_format, to_format, applied_at)
             VALUES (?1, ?2, ?2, ?3)",
            params![MIGRATION_COMMIT2, FORMAT_V2, now],
        )?;
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations
                (migration_id, from_format, to_format, applied_at)
             VALUES (?1, ?2, ?2, ?3)",
            params![MIGRATION_TIGA_AUDIT_CORRELATION, FORMAT_V2, now],
        )?;
        conn.execute(
            "UPDATE vault_meta SET schema_version = ?1, tiga_policy_version = ?2,
             tiga_compliance_status = ?3, min_writer_version = ?4, updated_at = ?5",
            params![
                CURRENT_SCHEMA_VERSION,
                TIGA_POLICY_VERSION,
                if remediation_required {
                    "remediation-required"
                } else {
                    "compliant"
                },
                FORMAT_V2,
                now,
            ],
        )?;
        Ok(())
    })();

    match result {
        Ok(()) => conn
            .execute_batch("COMMIT;")
            .map_err(StorageError::Database),
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK;");
            Err(error)
        }
    }?;
    validate_v2_schema(conn)
}

fn migrate_tiga1_policy(conn: &Connection, now: &str) -> StorageResult<bool> {
    let default_mode_string: String =
        conn.query_row("SELECT default_tiga_mode FROM vault_meta", [], |row| {
            row.get(0)
        })?;
    let default_mode: TigaMode = default_mode_string
        .parse()
        .map_err(|error| StorageError::Validation(format!("invalid legacy Tiga mode: {error}")))?;
    let mut remediation_required = !legacy_unlock_configuration_complies(conn, default_mode)?;

    let mut project_modes = HashMap::<String, TigaMode>::new();
    let mut project_stmt = conn.prepare(
        "SELECT project_id, tiga_mode_override FROM projects WHERE tiga_mode_override IS NOT NULL",
    )?;
    let project_rows = project_stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in project_rows {
        let (project_id, mode_string) = row?;
        let mode: TigaMode = mode_string.parse().map_err(|error| {
            StorageError::Validation(format!(
                "invalid legacy project Tiga mode for {project_id}: {error}"
            ))
        })?;
        project_modes.insert(project_id.clone(), mode);
        if mode < default_mode {
            insert_legacy_policy_exception(
                conn,
                "project",
                &project_id,
                &TigaPolicyOverride::for_resource_profile(mode),
                now,
            )?;
            remediation_required = true;
        }
    }

    let mut entry_stmt = conn.prepare(
        "SELECT entry_id, project_id, tiga_mode_override
         FROM entries WHERE tiga_mode_override IS NOT NULL",
    )?;
    let entry_rows = entry_stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    for row in entry_rows {
        let (entry_id, project_id, mode_string) = row?;
        let mode: TigaMode = mode_string.parse().map_err(|error| {
            StorageError::Validation(format!(
                "invalid legacy entry Tiga mode for {entry_id}: {error}"
            ))
        })?;
        let parent_mode = project_modes
            .get(&project_id)
            .copied()
            .unwrap_or(default_mode);
        if mode < parent_mode {
            insert_legacy_policy_exception(
                conn,
                "entry",
                &entry_id,
                &TigaPolicyOverride::for_resource_profile(mode),
                now,
            )?;
            remediation_required = true;
        }
    }

    Ok(remediation_required)
}

fn insert_legacy_policy_exception(
    conn: &Connection,
    scope: &str,
    scope_id: &str,
    policy_override: &TigaPolicyOverride,
    now: &str,
) -> StorageResult<()> {
    let json = serde_json::to_string(policy_override)
        .map_err(|error| StorageError::Validation(error.to_string()))?;
    conn.execute(
        "INSERT OR IGNORE INTO tiga_policy_exceptions
            (exception_id, target_scope, target_id, approved_override_json, reason,
             expires_at_unix_secs, created_at, created_by_session_id, revoked_at,
             integrity_tag)
         VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, NULL, NULL, NULL)",
        params![
            format!("mdbx1-tiga-{scope}-{scope_id}"),
            scope,
            scope_id,
            json,
            "preserved automatically from a weaker MDBX1 Tiga override",
            now,
        ],
    )?;
    Ok(())
}

fn legacy_unlock_configuration_complies(conn: &Connection, mode: TigaMode) -> StorageResult<bool> {
    let mut stmt = conn.prepare("SELECT method_type, kdf_params_ct FROM unlock_methods")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    let mut method_count = 0_u32;
    let mut has_portable = false;
    let mut has_strong_combined = false;
    for row in rows {
        method_count += 1;
        let (method_type, kdf_params) = row?;
        let Ok(method_type) = UnlockMethodType::parse(&method_type) else {
            return Ok(false);
        };
        has_portable |= method_type.is_portable();
        if method_type.is_combined_password_security_key() {
            has_strong_combined |= KdfParams::from_json_bytes(&kdf_params)
                .map(|params| params.infer_tiga_mode() >= mode)
                .unwrap_or(false);
        }
    }
    if method_count == 0 {
        return Ok(false);
    }
    Ok(match mode {
        TigaMode::Power => has_strong_combined && !has_portable,
        TigaMode::Multi | TigaMode::Sky => has_portable,
    })
}

fn validate_v2_schema(conn: &Connection) -> StorageResult<()> {
    for column in [
        "schema_version",
        "min_reader_version",
        "min_writer_version",
        "tiga_policy_version",
        "tiga_compliance_status",
    ] {
        if !v2::column_exists(conn, "vault_meta", column)? {
            return Err(StorageError::Validation(format!(
                "MDBX-2 vault is missing required vault_meta column {column}"
            )));
        }
    }
    if !table_exists(conn, "schema_migrations")? {
        return Err(StorageError::Validation(
            "MDBX-2 vault is missing schema_migrations".to_string(),
        ));
    }
    for table in [
        "tiga_policy_overrides",
        "tiga_policy_exceptions",
        "security_audit_events",
        "commit_operations",
        "commit_device_sequences",
    ] {
        if !table_exists(conn, table)? {
            return Err(StorageError::Validation(format!(
                "MDBX-2 vault is missing required table {table}"
            )));
        }
    }
    for column in [
        "operation_id",
        "commit_id",
        "policy_version",
        "policy_fingerprint",
    ] {
        if !v2::column_exists(conn, "security_audit_events", column)? {
            return Err(StorageError::Validation(format!(
                "MDBX-2 vault is missing required security_audit_events column {column}"
            )));
        }
    }
    let (schema_version, policy_version): (i64, i64) = conn.query_row(
        "SELECT schema_version, tiga_policy_version FROM vault_meta",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if schema_version != i64::from(CURRENT_SCHEMA_VERSION) {
        return Err(StorageError::Validation(format!(
            "unsupported MDBX-2 schema version {schema_version}; expected {CURRENT_SCHEMA_VERSION}"
        )));
    }
    if policy_version != i64::from(TIGA_POLICY_VERSION) {
        return Err(StorageError::Validation(format!(
            "unsupported Tiga policy version {policy_version}; expected {TIGA_POLICY_VERSION}"
        )));
    }
    Ok(())
}

fn reject_unknown_critical_extensions(value: &str) -> StorageResult<()> {
    if !has_unknown_critical_extensions(value) {
        return Ok(());
    }

    Err(StorageError::Validation(format!(
        "vault requires unsupported critical extensions: {}",
        value.trim()
    )))
}

fn has_unknown_critical_extensions(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty() && trimmed != "[]"
}

fn table_exists(conn: &Connection, table: &str) -> StorageResult<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        params![table],
        |row| row.get(0),
    )
    .map_err(StorageError::Database)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::VaultConnection;
    use crate::schema;

    fn v1_database() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::schema::v1::create_all_tables(&conn).unwrap();
        conn.execute(
            "INSERT INTO vault_meta (vault_id, format_version, created_at, updated_at,
             default_tiga_mode, active_key_epoch_id, compat_flags, critical_extensions)
             VALUES ('vault-1', 'MDBX-1', '2026-01-01T00:00:00Z',
             '2026-01-01T00:00:00Z', 'multi', 'epoch-1', '', '')",
            [],
        )
        .unwrap();
        conn
    }

    fn insert_legacy_password(conn: &Connection) -> Vec<u8> {
        let params = KdfParams::for_password().to_json_bytes();
        conn.execute(
            "INSERT INTO unlock_methods
                (method_id, method_type, kdf_profile_id, kdf_params_ct,
                 wrapped_vault_key_ct, created_at, updated_at)
             VALUES ('password-1', 'password', 'legacy', ?1, X'01020304',
                     '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            params![params],
        )
        .unwrap();
        params
    }

    #[test]
    fn upgrades_v1_to_mdbx2_and_preserves_identity() {
        let conn = v1_database();
        let info = upgrade_to_latest(&conn).unwrap().unwrap();
        assert_eq!(info.format_version, FORMAT_V2);
        assert_eq!(info.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(info.min_reader_version, FORMAT_V1);
        assert_eq!(info.min_writer_version, FORMAT_V2);

        let vault_id: String = conn
            .query_row("SELECT vault_id FROM vault_meta", [], |row| row.get(0))
            .unwrap();
        assert_eq!(vault_id, "vault-1");
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
        let policy_state: (i64, String) = conn
            .query_row(
                "SELECT tiga_policy_version, tiga_compliance_status FROM vault_meta",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(policy_state.0, i64::from(TIGA_POLICY_VERSION));
        assert_eq!(policy_state.1, "remediation-required");
    }

    #[test]
    fn upgrade_is_idempotent() {
        let conn = v1_database();
        upgrade_to_latest(&conn).unwrap();
        let first = read_format_info(&conn).unwrap();
        upgrade_to_latest(&conn).unwrap();
        let second = read_format_info(&conn).unwrap();
        assert_eq!(first, second);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn draft_v1_is_supported() {
        let conn = v1_database();
        conn.execute(
            "UPDATE vault_meta SET format_version = ?1",
            params![FORMAT_V1_DRAFT],
        )
        .unwrap();
        assert_eq!(
            upgrade_to_latest(&conn).unwrap().unwrap().format_version,
            FORMAT_V2
        );
    }

    #[test]
    fn unknown_critical_extensions_are_rejected_before_upgrade() {
        let conn = v1_database();
        conn.execute(
            "UPDATE vault_meta SET critical_extensions = 'future-secret-index'",
            [],
        )
        .unwrap();
        let err = upgrade_to_latest(&conn).unwrap_err();
        assert!(err.to_string().contains("unsupported critical extensions"));
        let version: String = conn
            .query_row("SELECT format_version FROM vault_meta", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, FORMAT_V1);
        assert!(!v2::column_exists(&conn, "vault_meta", "schema_version").unwrap());
    }

    #[test]
    fn migration_inspection_is_read_only_and_reports_legacy_upgrade() {
        let conn = v1_database();
        let info = inspect_migration(&conn).unwrap();
        assert!(info.initialized);
        assert_eq!(info.format_version.as_deref(), Some(FORMAT_V1));
        assert_eq!(info.schema_version, Some(1));
        assert!(info.requires_upgrade);
        assert!(!info.unknown_critical_extensions);

        let format: String = conn
            .query_row("SELECT format_version FROM vault_meta", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(format, FORMAT_V1);
    }

    #[test]
    fn current_migration_inspection_reports_no_upgrade() {
        let conn = VaultConnection::open_in_memory().unwrap();
        crate::init::initialize_vault(&conn, &crate::init::VaultInitParams::default()).unwrap();
        let info = inspect_migration(conn.inner()).unwrap();
        assert!(info.initialized);
        assert_eq!(info.format_version.as_deref(), Some(FORMAT_V2));
        assert_eq!(info.schema_version, Some(CURRENT_SCHEMA_VERSION));
        assert!(!info.requires_upgrade);
    }

    #[test]
    fn migration_inspection_flags_unknown_critical_extensions_without_writing() {
        let conn = v1_database();
        conn.execute(
            "UPDATE vault_meta SET critical_extensions = 'future-extension'",
            [],
        )
        .unwrap();
        let info = inspect_migration(&conn).unwrap();
        assert!(info.unknown_critical_extensions);
        assert!(info.requires_upgrade);
        let error = upgrade_to_latest(&conn).unwrap_err();
        assert!(error.to_string().contains("critical extensions"));
        let format: String = conn
            .query_row("SELECT format_version FROM vault_meta", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(format, FORMAT_V1);
    }

    #[test]
    fn new_schema_is_mdbx2_ready() {
        let conn = Connection::open_in_memory().unwrap();
        schema::create_all_tables(&conn).unwrap();
        assert!(v2::column_exists(&conn, "vault_meta", "schema_version").unwrap());
        assert!(table_exists(&conn, "schema_migrations").unwrap());
        assert!(v2::column_exists(&conn, "vault_meta", "tiga_policy_version").unwrap());
        assert!(table_exists(&conn, "tiga_policy_overrides").unwrap());
        assert!(table_exists(&conn, "tiga_policy_exceptions").unwrap());
        assert!(table_exists(&conn, "security_audit_events").unwrap());
        assert!(v2::column_exists(&conn, "security_audit_events", "operation_id").unwrap());
        assert!(v2::column_exists(&conn, "security_audit_events", "commit_id").unwrap());
        assert!(v2::column_exists(&conn, "security_audit_events", "policy_version").unwrap());
        assert!(v2::column_exists(&conn, "security_audit_events", "policy_fingerprint").unwrap());
        assert!(table_exists(&conn, "commit_operations").unwrap());
        assert!(table_exists(&conn, "commit_device_sequences").unwrap());
    }

    #[test]
    fn early_mdbx2_schema_is_upgraded_in_place_to_tiga2() {
        let conn = v1_database();
        v2::add_column_if_missing(
            &conn,
            "vault_meta",
            "schema_version",
            "INTEGER NOT NULL DEFAULT 2",
        )
        .unwrap();
        v2::add_column_if_missing(
            &conn,
            "vault_meta",
            "min_reader_version",
            "TEXT NOT NULL DEFAULT 'MDBX-1'",
        )
        .unwrap();
        v2::add_column_if_missing(
            &conn,
            "vault_meta",
            "min_writer_version",
            "TEXT NOT NULL DEFAULT 'MDBX-2'",
        )
        .unwrap();
        conn.execute_batch(v2::SCHEMA_MIGRATIONS_DDL).unwrap();
        conn.execute(
            "UPDATE vault_meta SET format_version = 'MDBX-2', schema_version = 2",
            [],
        )
        .unwrap();

        let info = upgrade_to_latest(&conn).unwrap().unwrap();
        assert_eq!(info.schema_version, CURRENT_SCHEMA_VERSION);
        assert!(table_exists(&conn, "tiga_policy_overrides").unwrap());
        assert!(table_exists(&conn, "commit_operations").unwrap());
        assert!(table_exists(&conn, "commit_device_sequences").unwrap());
        let migration_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE migration_id = ?1",
                params![MIGRATION_TIGA2_POLICY],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(migration_count, 1);
        let commit2_migration_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE migration_id = ?1",
                params![MIGRATION_COMMIT2],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(commit2_migration_count, 1);
        let audit_correlation_migration_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE migration_id = ?1",
                params![MIGRATION_TIGA_AUDIT_CORRELATION],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(audit_correlation_migration_count, 1);
    }

    #[test]
    fn schema4_audit_rows_gain_nullable_correlation_fields() {
        let conn = v1_database();
        v2::add_column_if_missing(
            &conn,
            "vault_meta",
            "schema_version",
            "INTEGER NOT NULL DEFAULT 4",
        )
        .unwrap();
        v2::add_column_if_missing(
            &conn,
            "vault_meta",
            "min_reader_version",
            "TEXT NOT NULL DEFAULT 'MDBX-1'",
        )
        .unwrap();
        v2::add_column_if_missing(
            &conn,
            "vault_meta",
            "min_writer_version",
            "TEXT NOT NULL DEFAULT 'MDBX-2'",
        )
        .unwrap();
        conn.execute_batch(
            "CREATE TABLE security_audit_events (
                event_id TEXT PRIMARY KEY NOT NULL,
                occurred_at TEXT NOT NULL,
                operation TEXT NOT NULL,
                outcome TEXT NOT NULL,
                scope_type TEXT NOT NULL,
                scope_id TEXT NOT NULL,
                session_id TEXT,
                device_id TEXT,
                reason_codes_json TEXT NOT NULL,
                constraints_json TEXT NOT NULL,
                exception_id TEXT,
                integrity_tag BLOB
             );
             INSERT INTO security_audit_events
                (event_id, occurred_at, operation, outcome, scope_type, scope_id,
                 reason_codes_json, constraints_json)
             VALUES ('legacy-event', '2026-01-01T00:00:00Z', 'copy-secret', 'allow',
                     'vault', '', '[]', '[]');",
        )
        .unwrap();
        conn.execute(
            "UPDATE vault_meta SET format_version = 'MDBX-2', schema_version = 4",
            [],
        )
        .unwrap();

        let info = upgrade_to_latest(&conn).unwrap().unwrap();
        assert_eq!(info.schema_version, CURRENT_SCHEMA_VERSION);
        let correlation: (Option<String>, Option<String>, Option<i64>, Option<Vec<u8>>) = conn
            .query_row(
                "SELECT operation_id, commit_id, policy_version, policy_fingerprint
                 FROM security_audit_events WHERE event_id = 'legacy-event'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(correlation, (None, None, None, None));
    }

    #[test]
    fn legacy_weaker_overrides_are_preserved_as_remediation_exceptions() {
        let conn = v1_database();
        conn.execute(
            "INSERT INTO projects
                (project_id, title_ct, tiga_mode_override, object_clock, head_commit_id,
                 created_at, updated_at, created_by_device_id, updated_by_device_id)
             VALUES ('project-1', X'70', 'sky', '{}', 'commit-1',
                     '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'd1', 'd1')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO entries
                (entry_id, project_id, entry_type, payload_ct, tiga_mode_override,
                 object_clock, head_commit_id, created_at, updated_at,
                 created_by_device_id, updated_by_device_id)
             VALUES ('entry-1', 'project-1', 'login', X'7B7D', 'power', '{}',
                     'commit-1', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z',
                     'd1', 'd1')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO projects
                (project_id, title_ct, tiga_mode_override, object_clock, head_commit_id,
                 created_at, updated_at, created_by_device_id, updated_by_device_id)
             VALUES ('project-2', X'70', 'power', '{}', 'commit-2',
                     '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'd1', 'd1')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO entries
                (entry_id, project_id, entry_type, payload_ct, tiga_mode_override,
                 object_clock, head_commit_id, created_at, updated_at,
                 created_by_device_id, updated_by_device_id)
             VALUES ('entry-2', 'project-2', 'login', X'7B7D', 'sky', '{}',
                     'commit-2', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z',
                     'd1', 'd1')",
            [],
        )
        .unwrap();

        upgrade_to_latest(&conn).unwrap();
        let project_mode: String = conn
            .query_row(
                "SELECT tiga_mode_override FROM projects WHERE project_id = 'project-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(project_mode, "sky");
        let exception_json: String = conn
            .query_row(
                "SELECT approved_override_json FROM tiga_policy_exceptions
                 WHERE target_scope = 'project' AND target_id = 'project-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let policy_override: TigaPolicyOverride = serde_json::from_str(&exception_json).unwrap();
        assert_eq!(policy_override.profile, Some(TigaMode::Sky));
        let entry_exception_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM tiga_policy_exceptions
                 WHERE target_scope = 'entry' AND target_id = 'entry-2'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(entry_exception_count, 1);
        let status: String = conn
            .query_row("SELECT tiga_compliance_status FROM vault_meta", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(status, "remediation-required");
    }

    #[test]
    fn migration_preserves_unlock_wrappers_and_marks_compliant_legacy_multi() {
        let conn = v1_database();
        let original_params = insert_legacy_password(&conn);
        upgrade_to_latest(&conn).unwrap();
        let (params_after, wrapped_after, status): (Vec<u8>, Vec<u8>, String) = conn
            .query_row(
                "SELECT u.kdf_params_ct, u.wrapped_vault_key_ct, v.tiga_compliance_status
                 FROM unlock_methods u CROSS JOIN vault_meta v
                 WHERE u.method_id = 'password-1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(params_after, original_params);
        assert_eq!(wrapped_after, vec![1, 2, 3, 4]);
        assert_eq!(status, "compliant");
    }

    #[test]
    fn invalid_legacy_tiga_mode_rolls_back_the_entire_upgrade() {
        let conn = v1_database();
        conn.execute(
            "UPDATE vault_meta SET default_tiga_mode = 'unknown-mode'",
            [],
        )
        .unwrap();
        assert!(upgrade_to_latest(&conn).is_err());
        let format: String = conn
            .query_row("SELECT format_version FROM vault_meta", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(format, FORMAT_V1);
        assert!(!v2::column_exists(&conn, "vault_meta", "tiga_policy_version").unwrap());
        assert!(!table_exists(&conn, "tiga_policy_exceptions").unwrap());
    }

    #[test]
    fn opening_a_v1_file_automatically_upgrades_it() {
        let path =
            std::env::temp_dir().join(format!("mdbx-v1-upgrade-{}.mdbx", uuid::Uuid::new_v4()));
        {
            let conn = Connection::open(&path).unwrap();
            crate::schema::v1::create_all_tables(&conn).unwrap();
            conn.execute(
                "INSERT INTO vault_meta (vault_id, format_version, created_at, updated_at,
                 default_tiga_mode, active_key_epoch_id, compat_flags, critical_extensions)
                 VALUES ('disk-vault', 'MDBX-1', '2026-01-01T00:00:00Z',
                 '2026-01-01T00:00:00Z', 'multi', 'epoch-1', '', '')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO projects (project_id, title_ct, object_clock, head_commit_id,
                 created_at, updated_at, created_by_device_id, updated_by_device_id)
                 VALUES ('project-1', X'7469746C65', '{}', 'commit-1',
                 '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'device-1', 'device-1')",
                [],
            )
            .unwrap();
        }

        let vault = VaultConnection::open(&path).unwrap();
        assert_eq!(
            read_format_info(vault.inner()).unwrap().format_version,
            FORMAT_V2
        );
        let title: Vec<u8> = vault
            .inner()
            .query_row(
                "SELECT title_ct FROM projects WHERE project_id = 'project-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(title, b"title");
        drop(vault);

        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{}", path.display(), suffix));
        }
    }
}
