use std::fs;
use std::path::{Path, PathBuf};

use mdbx_ffi::{
    create_vault, create_vault_with_tiga_mode, open_vault, open_vault_with_security_key,
    MdbxTigaMode,
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

#[test]
fn creates_reopens_and_preserves_generic_entries() {
    let vault_path = temp_vault_path("roundtrip");
    let path = vault_path.as_path_string();
    let password = "中文 password 12345!";
    let device_id = "ffi-test-device";

    let vault = create_vault(path.clone(), password.to_string(), device_id.to_string()).unwrap();
    let project = vault.create_project("Personal".to_string()).unwrap();
    assert!(!project.deleted);

    let projects = vault.list_projects(false).unwrap();
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0].project_id, project.project_id);

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
fn creates_reads_renames_and_deletes_attachment_content() {
    let vault_path = temp_vault_path("attachment");
    let path = vault_path.as_path_string();
    let password = "涓枃 password 12345!";
    let device_id = "ffi-test-device";

    let vault = create_vault(path.clone(), password.to_string(), device_id.to_string()).unwrap();
    let project = vault.create_project("Personal".to_string()).unwrap();
    let entry = vault
        .create_entry(
            project.project_id.clone(),
            "login".to_string(),
            "GitHub".to_string(),
            r#"{"kind":"password","username":"alice"}"#.to_string(),
        )
        .unwrap();

    let attachment = vault
        .create_attachment_metadata(
            project.project_id.clone(),
            Some(entry.entry_id.clone()),
            "recovery.txt".to_string(),
            Some("text/plain".to_string()),
            "".to_string(),
            0,
        )
        .unwrap();
    assert_eq!(attachment.file_name, "recovery.txt");
    assert_eq!(attachment.media_type.as_deref(), Some("text/plain"));
    assert_eq!(
        attachment.entry_id.as_deref(),
        Some(entry.entry_id.as_str())
    );

    let content = b"one\ntwo\nthree".to_vec();
    let written = vault
        .write_attachment_inline_content(attachment.attachment_id.clone(), content.clone())
        .unwrap();
    assert_eq!(written.storage_mode, "embedded-inline");
    assert_eq!(written.stored_size, content.len() as u64);
    assert_eq!(written.chunk_count, 1);

    let read = vault
        .read_attachment_content(attachment.attachment_id.clone())
        .unwrap();
    assert_eq!(read, content);

    let by_entry = vault
        .list_attachments_by_entry(entry.entry_id.clone())
        .unwrap();
    assert_eq!(by_entry.len(), 1);
    assert_eq!(by_entry[0].attachment_id, attachment.attachment_id);

    let renamed = vault
        .rename_attachment(
            attachment.attachment_id.clone(),
            "codes.txt".to_string(),
            Some("text/markdown".to_string()),
        )
        .unwrap();
    assert_eq!(renamed.file_name, "codes.txt");
    assert_eq!(renamed.media_type.as_deref(), Some("text/markdown"));

    vault.delete_attachment(attachment.attachment_id).unwrap();
    assert!(vault
        .list_attachments_by_project(project.project_id)
        .unwrap()
        .is_empty());
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

    let type_changed = vault
        .update_entry(
            source.project_id.clone(),
            created.entry_id.clone(),
            "ssh-key".to_string(),
            "SSH Key".to_string(),
            r#"{"kind":"password","username":"alice","sshKeyData":"private-key-material"}"#
                .to_string(),
        )
        .unwrap();
    assert_eq!(type_changed.entry_id, created.entry_id);
    assert_eq!(type_changed.title, "SSH Key");
    assert_eq!(type_changed.entry_type, "ssh-key");
    assert!(vault
        .list_entries(source.project_id.clone(), Some("login".to_string()))
        .unwrap()
        .is_empty());
    assert_eq!(
        vault
            .list_entries(source.project_id.clone(), Some("ssh-key".to_string()))
            .unwrap()
            .len(),
        1
    );

    vault
        .delete_entry(source.project_id.clone(), created.entry_id.clone())
        .unwrap();
    assert!(vault
        .list_entries(source.project_id.clone(), Some("ssh-key".to_string()))
        .unwrap()
        .is_empty());
    let deleted = vault
        .list_deleted_entries(source.project_id.clone(), Some("ssh-key".to_string()))
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
