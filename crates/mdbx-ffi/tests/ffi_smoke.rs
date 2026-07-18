use std::fs;
use std::path::{Path, PathBuf};

use mdbx_ffi::{
    create_vault, create_vault_with_tiga_mode, open_vault, open_vault_with_password_security_key,
    open_vault_with_security_key, MdbxAuthorizationConstraintKind, MdbxAuthorizationOutcome,
    MdbxAuthorizationReason, MdbxDeviceAssurance, MdbxDeviceContext, MdbxPolicyCompliance,
    MdbxTigaMode, MdbxTigaOperation, MdbxTigaScope, MdbxTigaScopeType, MdbxUnlockMethodType,
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
        let _ = fs::remove_file(self.path.with_extension("mdbx-shm"));
        let _ = fs::remove_file(self.path.with_extension("mdbx-wal"));
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
