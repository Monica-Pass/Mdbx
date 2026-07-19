use std::fs;
use std::path::{Path, PathBuf};

use mdbx_ffi::{
    create_vault, create_vault_with_tiga_mode, inspect_vault_migration, open_vault,
    open_vault_with_password_security_key, open_vault_with_security_key, upgrade_vault,
    MdbxAuthorizationConstraintKind, MdbxAuthorizationOutcome, MdbxAuthorizationReason,
    MdbxDeviceAssurance, MdbxDeviceContext, MdbxPolicyCompliance, MdbxTigaMode, MdbxTigaOperation,
    MdbxTigaScope, MdbxTigaScopeType, MdbxUnlockMethodType, MdbxWriteCommand,
};
use uuid::Uuid;

struct TempVaultPath {
    path: PathBuf,
    path_string: String,
}

impl TempVaultPath {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("mdbx-ffi-{}-{}.mdbx", label, Uuid::new_v4()));
        let path_string = path.to_string_lossy().to_string();
        Self { path, path_string }
    }

    fn as_path_string(&self) -> String {
        self.path_string.clone()
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempVaultPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_file(sqlite_sidecar_path(&self.path, "-shm"));
        let _ = fs::remove_file(sqlite_sidecar_path(&self.path, "-wal"));
    }
}

fn temp_vault_path(label: &str) -> TempVaultPath {
    TempVaultPath::new(label)
}

fn vault_scope() -> MdbxTigaScope {
    MdbxTigaScope {
        scope_type: MdbxTigaScopeType::Vault,
        scope_id: None,
    }
}

fn standard_device() -> MdbxDeviceContext {
    MdbxDeviceContext {
        assurance: MdbxDeviceAssurance::Standard,
        secure_clipboard_available: false,
        screen_capture_protection_available: false,
        secure_temp_files_available: true,
    }
}

fn trusted_device() -> MdbxDeviceContext {
    MdbxDeviceContext {
        assurance: MdbxDeviceAssurance::TrustedHardware,
        secure_clipboard_available: true,
        screen_capture_protection_available: true,
        secure_temp_files_available: true,
    }
}

fn count_rows(path: &Path, table: &str) -> i64 {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .unwrap()
}

fn sqlite_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[test]
fn create_failure_removes_database_and_sidecars() {
    let vault_path = temp_vault_path("create-failure-cleanup");

    let result = create_vault(
        vault_path.as_path_string(),
        String::new(),
        "ffi-create-failure-device".to_string(),
    );

    assert!(result.is_err());
    assert!(!vault_path.path().exists());
    assert!(!sqlite_sidecar_path(vault_path.path(), "-wal").exists());
    assert!(!sqlite_sidecar_path(vault_path.path(), "-shm").exists());
}

#[test]
fn create_rejects_existing_vault_and_preserves_contents() {
    let vault_path = temp_vault_path("create-existing-preserved");
    let path = vault_path.as_path_string();
    let password = "existing vault password 12345!";
    let vault = create_vault(
        path.clone(),
        password.to_string(),
        "ffi-existing-device".to_string(),
    )
    .unwrap();
    let project = vault.create_project("Preserved".to_string()).unwrap();
    drop(vault);

    assert!(create_vault(
        path.clone(),
        "replacement password 12345!".to_string(),
        "ffi-replacement-device".to_string(),
    )
    .is_err());
    let reopened = open_vault(
        path,
        password.to_string(),
        "ffi-existing-device".to_string(),
    )
    .unwrap();
    let entry = reopened
        .create_entry(
            project.project_id.clone(),
            "note".to_string(),
            "Preservation Check".to_string(),
            r#"{"body":"original vault remains writable"}"#.to_string(),
        )
        .unwrap();

    assert_eq!(entry.project_id, project.project_id);
}

#[test]
fn open_and_upgrade_missing_paths_do_not_create_files() {
    let open_path = temp_vault_path("open-missing");
    assert!(open_vault(
        open_path.as_path_string(),
        "unused password 12345!".to_string(),
        "ffi-open-missing-device".to_string(),
    )
    .is_err());
    assert!(!open_path.path().exists());

    let upgrade_path = temp_vault_path("upgrade-missing");
    assert!(upgrade_vault(upgrade_path.as_path_string()).is_err());
    assert!(!upgrade_path.path().exists());
}

#[test]
fn open_and_upgrade_reject_non_mdbx_sqlite_without_modification() {
    let vault_path = temp_vault_path("open-non-mdbx");
    {
        let conn = rusqlite::Connection::open(vault_path.path()).unwrap();
        conn.execute_batch(
            "CREATE TABLE unrelated_data (value TEXT NOT NULL);
             INSERT INTO unrelated_data VALUES ('preserve-me');",
        )
        .unwrap();
    }
    let before = fs::read(vault_path.path()).unwrap();

    assert!(open_vault(
        vault_path.as_path_string(),
        "unused password 12345!".to_string(),
        "ffi-open-non-mdbx-device".to_string(),
    )
    .is_err());
    assert_eq!(fs::read(vault_path.path()).unwrap(), before);
    assert!(upgrade_vault(vault_path.as_path_string()).is_err());
    assert_eq!(fs::read(vault_path.path()).unwrap(), before);
}

#[test]
fn write_operation_coalesces_commands_and_retries_idempotently() {
    let vault_path = temp_vault_path("write-operation");
    let vault = create_vault(
        vault_path.as_path_string(),
        "operation password 12345!".to_string(),
        "ffi-operation-device".to_string(),
    )
    .unwrap();
    let project_id = Uuid::new_v4().to_string();
    let entry_id = Uuid::new_v4().to_string();
    let commands = vec![
        MdbxWriteCommand::CreateProject {
            project_id: project_id.clone(),
            title: "Operation Project".to_string(),
        },
        MdbxWriteCommand::CreateEntry {
            entry_id: entry_id.clone(),
            project_id: project_id.clone(),
            entry_type: "login".to_string(),
            title: "Operation Entry".to_string(),
            payload_json: r#"{"username":"alice","password":"secret"}"#.to_string(),
        },
    ];
    let before = count_rows(vault_path.path(), "commits");

    let first = vault
        .execute_write_operation(
            "ffi-operation-1".to_string(),
            "create-project-with-entry".to_string(),
            commands.clone(),
        )
        .unwrap();
    assert!(!first.already_committed);
    assert_eq!(first.project_ids, vec![project_id.clone()]);
    assert_eq!(first.entry_ids, vec![entry_id.clone()]);
    assert_eq!(count_rows(vault_path.path(), "commits"), before + 1);

    let db = rusqlite::Connection::open(vault_path.path()).unwrap();
    let (project_head, entry_head): (String, String) = db
        .query_row(
            "SELECT p.head_commit_id, e.head_commit_id
             FROM projects p JOIN entries e ON e.project_id = p.project_id
             WHERE p.project_id = ?1 AND e.entry_id = ?2",
            rusqlite::params![project_id, entry_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(project_head, first.commit_id);
    assert_eq!(entry_head, first.commit_id);
    drop(db);

    let retry = vault
        .execute_write_operation(
            "ffi-operation-1".to_string(),
            "create-project-with-entry".to_string(),
            commands.clone(),
        )
        .unwrap();
    assert!(retry.already_committed);
    assert_eq!(retry.commit_id, first.commit_id);
    assert_eq!(count_rows(vault_path.path(), "commits"), before + 1);

    let mut changed_commands = commands;
    if let MdbxWriteCommand::CreateProject { title, .. } = &mut changed_commands[0] {
        *title = "Different Intent".to_string();
    }
    assert!(vault
        .execute_write_operation(
            "ffi-operation-1".to_string(),
            "create-project-with-entry".to_string(),
            changed_commands,
        )
        .is_err());
}

#[test]
fn write_operation_rolls_back_every_command_on_failure() {
    let vault_path = temp_vault_path("write-operation-rollback");
    let vault = create_vault(
        vault_path.as_path_string(),
        "rollback password 12345!".to_string(),
        "ffi-operation-device".to_string(),
    )
    .unwrap();
    let project_id = Uuid::new_v4().to_string();
    let entry_id = Uuid::new_v4().to_string();
    let missing_project_id = Uuid::new_v4().to_string();
    let before = count_rows(vault_path.path(), "commits");

    let result = vault.execute_write_operation(
        "ffi-operation-rollback".to_string(),
        "failing-batch".to_string(),
        vec![
            MdbxWriteCommand::CreateProject {
                project_id: project_id.clone(),
                title: "Rolled Back".to_string(),
            },
            MdbxWriteCommand::CreateEntry {
                entry_id,
                project_id: missing_project_id,
                entry_type: "note".to_string(),
                title: "Fails".to_string(),
                payload_json: r#"{"body":"failure"}"#.to_string(),
            },
        ],
    );
    assert!(result.is_err());

    let db = rusqlite::Connection::open(vault_path.path()).unwrap();
    let project_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM projects WHERE project_id = ?1",
            rusqlite::params![project_id],
            |row| row.get(0),
        )
        .unwrap();
    let operation_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM commit_operations WHERE operation_id = 'ffi-operation-rollback'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(project_count, 0);
    assert_eq!(operation_count, 0);
    assert_eq!(count_rows(vault_path.path(), "commits"), before);
}

#[test]
fn branch_history_pages_include_stable_identity_and_legacy_records() {
    let vault_path = temp_vault_path("commit-history");
    let vault = create_vault(
        vault_path.as_path_string(),
        "history password 12345!".to_string(),
        "ffi-history-device".to_string(),
    )
    .unwrap();
    let branches = vault.list_branches().unwrap();
    assert_eq!(branches.len(), 1);
    assert_eq!(branches[0].branch_name, "main");
    let main_branch_id = branches[0].branch_id.clone();
    let before = count_rows(vault_path.path(), "commits");
    assert!(vault
        .execute_write_operation_on_branch(
            "missing-branch-id".to_string(),
            "history-missing-branch".to_string(),
            "create-project".to_string(),
            vec![MdbxWriteCommand::CreateProject {
                project_id: Uuid::new_v4().to_string(),
                title: "Missing Branch".to_string(),
            }],
        )
        .is_err());
    assert_eq!(count_rows(vault_path.path(), "commits"), before);
    assert_eq!(count_rows(vault_path.path(), "commit_operations"), 0);

    let project_id = Uuid::new_v4().to_string();
    let execution = vault
        .execute_write_operation_on_branch(
            main_branch_id.clone(),
            "history-typed-summary".to_string(),
            "create-project".to_string(),
            vec![MdbxWriteCommand::CreateProject {
                project_id: project_id.clone(),
                title: "History Project".to_string(),
            }],
        )
        .unwrap();

    let first = vault.list_commit_history(1, None).unwrap();
    assert_eq!(first.items.len(), 1);
    assert!(first.items[0].operation_id.is_some());
    assert_eq!(first.items[0].changes[0].object_id, project_id);
    assert_eq!(first.items[0].changes[0].action, "create");
    assert_eq!(first.items[0].changes[0].fields, vec!["title"]);
    let detail = vault
        .get_commit_history(first.items[0].commit_id.clone())
        .unwrap()
        .unwrap();
    assert_eq!(detail.commit_id, first.items[0].commit_id);

    let first_v2 = vault.list_commit_history_v2(1, None).unwrap();
    assert_eq!(first_v2.items.len(), 1);
    assert_eq!(
        first_v2.items[0].branch_id.as_deref(),
        Some(main_branch_id.as_str())
    );
    assert_eq!(first_v2.items[0].item.commit_id, execution.commit_id);
    let detail_v2 = vault
        .get_commit_history_v2(first_v2.items[0].item.commit_id.clone())
        .unwrap()
        .unwrap();
    assert_eq!(
        detail_v2.branch_id.as_deref(),
        Some(main_branch_id.as_str())
    );
    assert_eq!(detail_v2.item.commit_id, execution.commit_id);

    let second = vault.list_commit_history(1, first.next_cursor).unwrap();
    assert_eq!(second.items.len(), 1);
    assert!(second.items[0].legacy);
    assert!(second.items[0].operation_id.is_none());
    assert!(vault
        .get_commit_history("missing-commit".to_string())
        .unwrap()
        .is_none());
}

#[test]
fn creates_reopens_and_preserves_generic_entries() {
    let vault_path = temp_vault_path("roundtrip");
    let path = vault_path.as_path_string();
    let password = "中文 password 12345!";
    let device_id = "ffi-test-device";

    let vault = create_vault(path.clone(), password.to_string(), device_id.to_string()).unwrap();
    let project = vault.create_project("Personal".to_string()).unwrap();

    let payloads = [
        (
            "login",
            "GitHub Login",
            r#"{"kind":"password","username":"alice","password":"secret","favorite":false}"#,
        ),
        (
            "note",
            "Recovery Codes",
            r#"{"kind":"note","body":"code-1\ncode-2","favorite":true}"#,
        ),
        (
            "totp",
            "GitHub TOTP",
            r#"{"kind":"totp","secret":"JBSWY3DPEHPK3PXP","period":30,"digits":6}"#,
        ),
        (
            "card",
            "Everyday Visa",
            r#"{"kind":"card","cardholderName":"Alice","number":"4111111111111111"}"#,
        ),
        (
            "identity",
            "Passport",
            r#"{"kind":"identity","documentType":"passport","fullName":"Alice Example"}"#,
        ),
    ];

    for (entry_type, title, payload_json) in payloads {
        let created = vault
            .create_entry(
                project.project_id.clone(),
                entry_type.to_string(),
                title.to_string(),
                payload_json.to_string(),
            )
            .unwrap();
        assert_eq!(created.entry_type, entry_type);
        assert_eq!(created.title, title);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&created.payload_json).unwrap(),
            serde_json::from_str::<serde_json::Value>(payload_json).unwrap()
        );
    }
    drop(vault);

    let reopened = open_vault(path.clone(), password.to_string(), device_id.to_string()).unwrap();
    let all_entries = reopened
        .list_entries(project.project_id.clone(), None)
        .unwrap();
    assert_eq!(all_entries.len(), 5);

    let login_entries = reopened
        .list_entries(project.project_id.clone(), Some("login".to_string()))
        .unwrap();
    assert_eq!(login_entries.len(), 1);
    assert_eq!(login_entries[0].entry_type, "login");
    assert_eq!(login_entries[0].title, "GitHub Login");

    let invalid_payload = reopened.create_entry(
        project.project_id.clone(),
        "login".to_string(),
        "Broken".to_string(),
        "{not json".to_string(),
    );
    assert!(invalid_payload.is_err());
}

#[test]
fn updates_deletes_restores_and_moves_generic_entry() {
    let vault_path = temp_vault_path("mutation");
    let path = vault_path.as_path_string();
    let password = "中文 password 12345!";
    let device_id = "ffi-test-device";

    let vault = create_vault(path.clone(), password.to_string(), device_id.to_string()).unwrap();
    let source = vault.create_project("Source".to_string()).unwrap();
    let target = vault.create_project("Target".to_string()).unwrap();
    let created = vault
        .create_entry(
            source.project_id.clone(),
            "login".to_string(),
            "Original".to_string(),
            r#"{"kind":"password","username":"alice","favorite":false}"#.to_string(),
        )
        .unwrap();

    let updated = vault
        .update_entry(
            source.project_id.clone(),
            created.entry_id.clone(),
            "login".to_string(),
            "Updated".to_string(),
            r#"{"kind":"password","username":"alice@example.com","favorite":true}"#.to_string(),
        )
        .unwrap();
    assert_eq!(updated.entry_id, created.entry_id);
    assert_eq!(updated.title, "Updated");
    assert_eq!(updated.entry_type, "login");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&updated.payload_json).unwrap()["favorite"],
        true
    );

    vault
        .delete_entry(source.project_id.clone(), created.entry_id.clone())
        .unwrap();
    assert!(vault
        .list_entries(source.project_id.clone(), Some("login".to_string()))
        .unwrap()
        .is_empty());
    let deleted = vault
        .list_deleted_entries(source.project_id.clone(), Some("login".to_string()))
        .unwrap();
    assert_eq!(deleted.len(), 1);
    assert!(deleted[0].deleted);

    let restored = vault
        .restore_entry(source.project_id.clone(), created.entry_id.clone())
        .unwrap();
    assert!(!restored.deleted);

    let moved = vault
        .move_entry(
            source.project_id.clone(),
            created.entry_id.clone(),
            target.project_id.clone(),
        )
        .unwrap();
    assert_eq!(moved.project_id, target.project_id);
    assert_eq!(moved.entry_id, created.entry_id);
}

#[test]
fn opens_with_security_key_material() {
    let vault_path = temp_vault_path("security-key");
    let path = vault_path.as_path_string();
    let password = "中文 password 12345!";
    let device_id = "ffi-test-device";
    let key_material = b"local-security-key-material".to_vec();

    let vault = create_vault(path.clone(), password.to_string(), device_id.to_string()).unwrap();
    let project = vault.create_project("Personal".to_string()).unwrap();
    vault
        .setup_local_security_key_unlock(key_material.clone())
        .unwrap();
    drop(vault);

    let reopened =
        open_vault_with_security_key(path.clone(), key_material, device_id.to_string()).unwrap();
    let info = reopened.info();
    assert_eq!(info.device_id, device_id);
    reopened
        .create_entry(
            project.project_id,
            "note".to_string(),
            "Unlocked".to_string(),
            r#"{"kind":"note","body":"opened with security key"}"#.to_string(),
        )
        .unwrap();
}

#[test]
fn resets_master_password_for_unlocked_vault() {
    let vault_path = temp_vault_path("reset-password");
    let path = vault_path.as_path_string();
    let old_password = "中文 password 12345!";
    let new_password = "new 中文 password 67890!";
    let device_id = "ffi-test-device";

    let vault = create_vault(
        path.clone(),
        old_password.to_string(),
        device_id.to_string(),
    )
    .unwrap();
    vault
        .reset_master_password(new_password.to_string())
        .unwrap();
    drop(vault);

    assert!(open_vault(
        path.clone(),
        old_password.to_string(),
        device_id.to_string()
    )
    .is_err());
    let reopened = open_vault(
        path.clone(),
        new_password.to_string(),
        device_id.to_string(),
    )
    .unwrap();
    assert_eq!(reopened.info().device_id, device_id);
}

#[test]
fn creates_vault_with_explicit_tiga_mode() {
    let vault_path = temp_vault_path("tiga-mode");
    let path = vault_path.as_path_string();
    let password = "中文 password 12345!";
    let device_id = "ffi-test-device";

    let vault = create_vault_with_tiga_mode(
        path.clone(),
        password.to_string(),
        device_id.to_string(),
        MdbxTigaMode::Sky,
    )
    .unwrap();
    assert_eq!(vault.info().device_id, device_id);
    drop(vault);

    let conn = rusqlite::Connection::open(vault_path.path()).unwrap();
    let mode: String = conn
        .query_row(
            "SELECT default_tiga_mode FROM vault_meta LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(mode, "sky");
}

#[test]
fn clients_can_inspect_and_explicitly_upgrade_legacy_vault() {
    let vault_path = temp_vault_path("migration-plan");
    {
        let conn = rusqlite::Connection::open(vault_path.path()).unwrap();
        mdbx_storage::schema::v1::create_all_tables(&conn).unwrap();
        conn.execute(
            "INSERT INTO vault_meta (vault_id, format_version, created_at, updated_at,
             default_tiga_mode, active_key_epoch_id, compat_flags, critical_extensions)
             VALUES ('ffi-legacy-vault', 'MDBX-1', '2026-01-01T00:00:00Z',
             '2026-01-01T00:00:00Z', 'multi', 'epoch-1', '', '')",
            [],
        )
        .unwrap();
    }

    let plan = inspect_vault_migration(vault_path.as_path_string()).unwrap();
    assert!(plan.initialized);
    assert_eq!(plan.format_version.as_deref(), Some("MDBX-1"));
    assert_eq!(plan.schema_version, Some(1));
    assert!(plan.requires_upgrade);
    assert!(!plan.unknown_critical_extensions);

    let upgraded = upgrade_vault(vault_path.as_path_string()).unwrap();
    assert_eq!(upgraded.format_version.as_deref(), Some("MDBX-2"));
    assert_eq!(upgraded.schema_version, Some(6));
    assert!(!upgraded.requires_upgrade);

    let stored_format: String = rusqlite::Connection::open(vault_path.path())
        .unwrap()
        .query_row("SELECT format_version FROM vault_meta", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(stored_format, "MDBX-2");
}

#[test]
fn exposes_tiga_policy_typed_authorization_and_exact_exceptions() {
    let vault_path = temp_vault_path("tiga-runtime");
    let vault = create_vault(
        vault_path.as_path_string(),
        "中文 password 12345!".to_string(),
        "ffi-policy-device".to_string(),
    )
    .unwrap();

    let policy = vault.resolve_tiga_policy(vault_scope()).unwrap();
    assert_eq!(policy.profile, MdbxTigaMode::Multi);
    assert_eq!(policy.compliance, MdbxPolicyCompliance::Compliant);
    assert_eq!(policy.idle_timeout_secs, 600);
    assert!(policy.security_key_recommended);

    let before = vault.active_session_info().unwrap().unwrap();
    let copy = vault
        .authorize_tiga_operation(
            vault_scope(),
            MdbxTigaOperation::CopySecret,
            standard_device(),
        )
        .unwrap();
    assert_eq!(copy.outcome, MdbxAuthorizationOutcome::AllowWithConstraints);
    assert!(copy.constraints.iter().any(|constraint| {
        constraint.kind == MdbxAuthorizationConstraintKind::ClearClipboardAfterSeconds
            && constraint.seconds == Some(30)
    }));
    let after = vault.active_session_info().unwrap().unwrap();
    assert_eq!(
        after.authenticated_at_unix_secs,
        before.authenticated_at_unix_secs
    );
    assert!(after.last_activity_at_unix_secs >= before.last_activity_at_unix_secs);

    let denied = vault
        .authorize_tiga_operation(
            vault_scope(),
            MdbxTigaOperation::RevealSecret,
            MdbxDeviceContext {
                assurance: MdbxDeviceAssurance::Unknown,
                secure_clipboard_available: false,
                screen_capture_protection_available: false,
                secure_temp_files_available: false,
            },
        )
        .unwrap();
    assert_eq!(denied.outcome, MdbxAuthorizationOutcome::Deny);
    assert!(denied
        .reasons
        .contains(&MdbxAuthorizationReason::DeviceAssuranceInsufficient));

    let weakened = vault
        .set_tiga_profile(
            MdbxTigaMode::Sky,
            Some("portable recovery required for travel".to_string()),
            None,
            standard_device(),
        )
        .unwrap();
    assert_eq!(weakened.profile, MdbxTigaMode::Sky);
    assert_eq!(weakened.compliance, MdbxPolicyCompliance::Exception);
    assert!(weakened.exception_id.is_some());

    let audit = vault.list_security_audit_events(20).unwrap();
    assert!(audit
        .iter()
        .any(|event| event.operation == MdbxTigaOperation::CopySecret));
    assert!(audit
        .iter()
        .any(|event| event.operation == MdbxTigaOperation::ChangeSecurityPolicy));
    let audit_v2 = vault.list_security_audit_events_v2(20).unwrap();
    let policy_change = audit_v2
        .iter()
        .find(|event| event.operation == MdbxTigaOperation::ChangeSecurityPolicy)
        .unwrap();
    assert!(policy_change.operation_id.is_some());
    assert!(policy_change.commit_id.is_some());
    assert_eq!(policy_change.policy_version, Some(2));
    assert_eq!(
        policy_change.policy_fingerprint.as_deref().map(<[u8]>::len),
        Some(32)
    );
    let copy_v2 = audit_v2
        .iter()
        .find(|event| event.operation == MdbxTigaOperation::CopySecret)
        .unwrap();
    assert!(copy_v2.commit_id.is_none());
    assert_eq!(copy_v2.policy_version, Some(2));
}

#[test]
fn power_vault_can_complete_combined_factor_remediation_through_ffi() {
    let vault_path = temp_vault_path("power-remediation");
    let path = vault_path.as_path_string();
    let password = "power 中文 password 12345!";
    let key_material = b"power-security-key-material".to_vec();
    let device_id = "ffi-power-device";

    let vault = create_vault_with_tiga_mode(
        path.clone(),
        password.to_string(),
        device_id.to_string(),
        MdbxTigaMode::Power,
    )
    .unwrap();
    assert_eq!(
        vault.resolve_tiga_policy(vault_scope()).unwrap().compliance,
        MdbxPolicyCompliance::RemediationRequired
    );
    let password_method = vault
        .list_unlock_methods()
        .unwrap()
        .into_iter()
        .find(|method| method.method_type == MdbxUnlockMethodType::Password)
        .unwrap();

    vault
        .setup_password_security_key_unlock(
            password.to_string(),
            key_material.clone(),
            standard_device(),
        )
        .unwrap();
    vault
        .remove_unlock_method(password_method.method_id, standard_device())
        .unwrap();
    let assessment = vault.assess_tiga_unlock_policy().unwrap();
    assert!(assessment.satisfies_policy);
    assert_eq!(assessment.configured_methods.len(), 1);
    assert_eq!(
        assessment.configured_methods[0],
        MdbxUnlockMethodType::PasswordSecurityKey
    );
    drop(vault);

    let reopened = open_vault_with_password_security_key(
        path,
        password.to_string(),
        key_material,
        device_id.to_string(),
    )
    .unwrap();
    assert_eq!(
        reopened
            .active_session_info()
            .unwrap()
            .unwrap()
            .unlock_method,
        MdbxUnlockMethodType::PasswordSecurityKey
    );
    assert_eq!(
        reopened
            .resolve_tiga_policy(vault_scope())
            .unwrap()
            .compliance,
        MdbxPolicyCompliance::Compliant
    );
    let reveal = reopened
        .authorize_tiga_operation(
            vault_scope(),
            MdbxTigaOperation::RevealSecret,
            trusted_device(),
        )
        .unwrap();
    assert_eq!(
        reveal.outcome,
        MdbxAuthorizationOutcome::AllowWithConstraints
    );
    assert!(reveal.constraints.iter().any(|constraint| {
        constraint.kind == MdbxAuthorizationConstraintKind::PreventScreenCapture
    }));
    let export = reopened
        .authorize_tiga_operation(
            vault_scope(),
            MdbxTigaOperation::ExportData,
            trusted_device(),
        )
        .unwrap();
    assert_eq!(export.outcome, MdbxAuthorizationOutcome::Deny);
    assert!(export
        .reasons
        .contains(&MdbxAuthorizationReason::OperationDisabled));
}
