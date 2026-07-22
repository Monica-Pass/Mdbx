use super::*;
use std::io::Write;

use mdbx_core::model::ConflictObjectType;
use mdbx_storage::init::{initialize_vault, VaultInitParams};
use mdbx_storage::repo::{
    AttachmentRepo, CommitContext, ConflictRepo, ObjectLabelAssignmentRepo, ObjectLabelRepo,
    ObjectRelationCreateRequest, ObjectRelationRepo, ProjectRepo, TombstoneRepo,
};
use mdbx_storage::unlock::UnlockService;
use sha2::{Digest, Sha256};

fn ffi_test_vault() -> MdbxVault {
    let mut conn = VaultConnection::open_in_memory().unwrap();
    let init = initialize_vault(&conn, &VaultInitParams::default()).unwrap();
    UnlockService::setup_password_with_mode(&mut conn, "attachment-password", TigaMode::Multi)
        .unwrap();
    MdbxVault {
        conn: Mutex::new(conn),
        device_id: "ffi-attachment-device".to_string(),
        vault_id: init.vault_id,
    }
}

fn ffi_test_count(vault: &MdbxVault, table: &str) -> i64 {
    let conn = vault.conn.lock().unwrap();
    conn.inner()
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

#[test]
fn build_capability_manifest_is_available_without_a_vault() {
    let manifest = mdbx_build_capability_manifest();
    assert_eq!(manifest.profile, "mdbx-build-capabilities-v1");
    assert_eq!(manifest.engine_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(manifest.storage_profile, "mdbx-storage-capabilities-v1");
    assert_eq!(manifest.sync_profile, "mdbx-sync-capabilities-v1");
    assert_eq!(manifest.sync_protocol_version, mdbx_sync::PROTOCOL_VERSION);
    assert!(manifest
        .enabled_storage_capability_ids
        .contains(&"mdbx.storage.mdbx1-compatibility".to_string()));
    assert!(manifest
        .enabled_sync_capability_ids
        .contains(&mdbx_sync::CAPABILITY_AUTHENTICATED_STATE_ROOT_V1.to_string()));

    // Cargo may unify dependency features in workspace builds. The manifest
    // must report the resulting binary and partition each optional ID once.
    for capability in [
        "mdbx.storage.benchmarks",
        "mdbx.storage.derived-search-index",
        "mdbx.storage.filesystem-blob-store",
        "mdbx.storage.kdbx-json-export",
        "mdbx.storage.kdbx-json-import",
    ] {
        let enabled = manifest
            .enabled_storage_capability_ids
            .contains(&capability.to_string());
        let disabled = manifest
            .disabled_optional_storage_capability_ids
            .contains(&capability.to_string());
        assert_ne!(enabled, disabled, "optional capability {capability}");
    }
    let zstd = mdbx_sync::CAPABILITY_ZSTD_BUNDLE_V1.to_string();
    assert_ne!(
        manifest.enabled_sync_capability_ids.contains(&zstd),
        manifest
            .disabled_optional_sync_capability_ids
            .contains(&zstd)
    );
}

#[test]
fn integrity_root_ffi_exposes_metadata_only_status_and_locked_inspection() {
    let path =
        std::env::temp_dir().join(format!("mdbx-ffi-integrity-root-{}.mdbx", Uuid::new_v4()));
    let path_string = path.to_string_lossy().into_owned();
    let vault = create_vault(
        path_string.clone(),
        "integrity-root-password".to_string(),
        "ffi-integrity-root-device".to_string(),
    )
    .unwrap();

    let disabled = vault.integrity_root_status().unwrap();
    assert_eq!(disabled.state, MdbxIntegrityRootState::Disabled);
    assert!(!disabled.authenticated);
    assert!(disabled.root_hash.is_none());

    let enabled = vault.enable_integrity_root().unwrap();
    assert_eq!(enabled.state, MdbxIntegrityRootState::Established);
    assert!(enabled.authenticated);
    assert_eq!(enabled.root_hash.as_ref().map(Vec::len), Some(32));
    let verified = vault.verify_integrity_root().unwrap();
    assert_eq!(verified.profile, "mdbx-authenticated-state-root-v1");
    assert_eq!(verified.root_hash.len(), 32);

    let rebuilt = vault.rebuild_integrity_root().unwrap();
    assert!(rebuilt.generation > enabled.generation);
    drop(vault);

    let locked = inspect_vault_integrity_root(path_string.clone()).unwrap();
    assert_eq!(locked.state, MdbxIntegrityRootState::Established);
    assert!(!locked.authenticated);
    assert_eq!(locked.root_hash.as_ref().map(Vec::len), Some(32));

    let reopened = open_vault(
        path_string,
        "integrity-root-password".to_string(),
        "ffi-integrity-root-device".to_string(),
    )
    .unwrap();
    assert!(reopened.integrity_root_status().unwrap().authenticated);
    drop(reopened);
    for suffix in ["", "-wal", "-shm"] {
        let candidate = std::path::PathBuf::from(format!("{}{}", path.display(), suffix));
        let _ = std::fs::remove_file(candidate);
    }
}

#[test]
fn integrity_root_checkpoint_ffi_authenticates_negotiates_and_roundtrips_wire() {
    let vault = ffi_test_vault();
    vault.enable_integrity_root().unwrap();
    let first = vault.create_integrity_root_checkpoint().unwrap();
    let verified = vault
        .verify_integrity_root_checkpoint(first.clone())
        .unwrap();
    assert_eq!(verified.root_hash, first.root_hash);

    vault
        .create_project("checkpoint advance".to_string())
        .unwrap();
    let advanced = vault.create_integrity_root_checkpoint().unwrap();
    assert_eq!(
        vault
            .compare_integrity_root_checkpoints(first.clone(), advanced.clone())
            .unwrap(),
        MdbxIntegrityRootCheckpointRelation::Advanced
    );
    assert!(vault
        .compare_integrity_root_checkpoints(advanced.clone(), first.clone())
        .is_err());

    let initiator =
        create_integrity_root_sync_session("root-initiator".to_string(), first.clone()).unwrap();
    let responder =
        create_integrity_root_sync_session("root-responder".to_string(), advanced.clone()).unwrap();
    let hello = initiator.hello().unwrap();
    assert_eq!(hello.authenticated_state_root, Some(first.clone()));

    let sender =
        create_sync_wire_session("root-wire".to_string(), default_sync_wire_payload_bytes())
            .unwrap();
    let receiver =
        create_sync_wire_session("root-wire".to_string(), default_sync_wire_payload_bytes())
            .unwrap();
    let bytes = sender
        .encode_integrity_root_hello(hello.clone(), None)
        .unwrap();
    let decoded = receiver.accept_integrity_root_hello(bytes).unwrap();
    assert_eq!(decoded.hello, hello);
    receiver.acknowledge_inbound(decoded.sequence).unwrap();

    let ack = responder.accept_hello(decoded.hello).unwrap();
    let ack_bytes = receiver
        .encode_integrity_root_hello_ack(ack, Some(decoded.sequence))
        .unwrap();
    let decoded_ack = sender.accept_integrity_root_hello_ack(ack_bytes).unwrap();
    assert_eq!(decoded_ack.in_reply_to, Some(decoded.sequence));
    sender.acknowledge_inbound(decoded_ack.sequence).unwrap();
    initiator.accept_hello_ack(decoded_ack.hello).unwrap();
    assert!(initiator.integrity_root_is_negotiated().unwrap());
    assert!(responder.integrity_root_is_negotiated().unwrap());
    assert_eq!(
        initiator.remote_integrity_root_checkpoint().unwrap(),
        Some(advanced.clone())
    );
    assert_eq!(
        responder.remote_integrity_root_checkpoint().unwrap(),
        Some(first.clone())
    );

    let mut tampered = advanced;
    tampered.authentication_tag[0] ^= 1;
    assert!(vault.verify_integrity_root_checkpoint(tampered).is_err());
}

#[test]
fn rollback_anchor_ffi_roundtrips_opaque_tokens_and_reports_advancement() {
    let vault = ffi_test_vault();
    let token = vault.create_rollback_anchor().unwrap();
    let equal = vault.verify_rollback_anchor(token.clone()).unwrap();
    assert!(!equal.advanced);
    assert_eq!(
        equal.anchored_commit_inventory_seq,
        equal.current_commit_inventory_seq
    );

    vault.create_project("After anchor".to_string()).unwrap();
    let advanced = vault.verify_rollback_anchor(token.clone()).unwrap();
    assert!(advanced.advanced);
    assert!(advanced.current_commit_inventory_seq > advanced.anchored_commit_inventory_seq);

    let mut tampered = token.clone();
    tampered[12] ^= 1;
    assert!(vault.verify_rollback_anchor(tampered).is_err());

    let foreign = ffi_test_vault();
    assert!(foreign.verify_rollback_anchor(token).is_err());
}

#[test]
fn content_manifest_ffi_roundtrips_and_rejects_stale_state() {
    let vault = ffi_test_vault();
    let token = vault.create_content_manifest().unwrap();
    let equal = vault.verify_content_manifest(token.clone()).unwrap();
    assert!(equal.table_count > 0);
    assert!(equal.row_count > 0);

    vault
        .create_project("Manifest FFI change".to_string())
        .unwrap();
    assert!(vault.verify_content_manifest(token).is_err());
    let replacement = vault.create_content_manifest().unwrap();
    assert!(vault.verify_content_manifest(replacement).is_ok());
}

#[test]
fn ffi_wire_session_roundtrips_blob_messages_and_sequences() {
    let limit = default_sync_wire_payload_bytes();
    let sender = create_sync_wire_session("wire-session".to_string(), limit).unwrap();
    let receiver = create_sync_wire_session("wire-session".to_string(), limit).unwrap();
    let blob_id = "a".repeat(64);
    let request = MdbxBlobChunkRequest {
        namespace_id: "source".to_string(),
        blob_id: blob_id.clone(),
        total_size: 8,
        offset: 0,
        max_bytes: 4,
    };
    let bytes = sender
        .encode_blob_chunk_request(request.clone(), None)
        .unwrap();
    let decoded = receiver.accept_blob_chunk_request(bytes.clone()).unwrap();
    assert_eq!(decoded.sequence, 1);
    assert_eq!(decoded.request, request);
    assert_eq!(receiver.pending_inbound_sequence().unwrap(), Some(1));
    receiver.acknowledge_inbound(1).unwrap();
    assert!(receiver.accept_blob_chunk_request(bytes).is_err());

    let response = MdbxBlobChunkResponse {
        namespace_id: "source".to_string(),
        blob_id,
        total_size: 8,
        offset: 0,
        ciphertext: vec![1, 2, 3, 4],
        is_last: false,
    };
    let response_bytes = sender
        .encode_blob_chunk_response(response.clone(), Some(decoded.sequence))
        .unwrap();
    let decoded_response = receiver.accept_blob_chunk_response(response_bytes).unwrap();
    assert_eq!(decoded_response.sequence, 2);
    assert_eq!(decoded_response.in_reply_to, Some(1));
    assert_eq!(decoded_response.response, response);
}

#[test]
fn ffi_wire_session_restores_sequence_state_and_rejects_wrong_types() {
    let limit = default_sync_wire_payload_bytes();
    let sender = create_sync_wire_session("wire-session".to_string(), limit).unwrap();
    let receiver = create_sync_wire_session("wire-session".to_string(), limit).unwrap();
    let hello = MdbxSyncHello {
        device_id: "device-a".to_string(),
        protocol_version: 2,
        heads: Vec::new(),
        known_commit_ids: Vec::new(),
        capabilities: Vec::new(),
    };
    let hello_bytes = sender.encode_hello(hello.clone(), None).unwrap();
    let decoded = receiver.accept_hello(hello_bytes).unwrap();
    assert_eq!(decoded.hello, hello);
    receiver.acknowledge_inbound(decoded.sequence).unwrap();
    let resume = receiver.resume().unwrap();
    let encoded_resume = serde_json::to_vec(&resume).unwrap();
    let restored: MdbxSyncWireResume = serde_json::from_slice(&encoded_resume).unwrap();
    let restarted = create_sync_wire_session("wire-session".to_string(), limit).unwrap();
    restarted.restore_resume(restored).unwrap();
    assert_eq!(restarted.resume().unwrap().next_inbound_sequence, 2);

    let response = MdbxBlobChunkResponse {
        namespace_id: "source".to_string(),
        blob_id: "b".repeat(64),
        total_size: 4,
        offset: 0,
        ciphertext: vec![8, 9, 10, 11],
        is_last: true,
    };
    let response_bytes = sender
        .encode_blob_chunk_response(response, Some(decoded.sequence))
        .unwrap();
    assert!(restarted.accept_blob_chunk_request(response_bytes).is_err());
    assert_eq!(restarted.pending_inbound_sequence().unwrap(), None);
}

#[test]
fn ffi_blob_sync_session_negotiates_and_advances_only_after_ack() {
    let local = create_blob_sync_session("ffi-local".to_string()).unwrap();
    let remote = create_blob_sync_session("ffi-remote".to_string()).unwrap();
    local
        .begin_blob_sync("source-namespace".to_string())
        .unwrap();
    let hello = local.hello().unwrap();
    assert_eq!(hello.capabilities.len(), 3);
    let ack = remote.accept_hello(hello).unwrap();
    local.accept_hello_ack(ack).unwrap();
    assert!(local.blob_replication_is_negotiated().unwrap());
    assert_eq!(
        local.blob_sync_phase().unwrap(),
        MdbxBlobSyncPhase::Manifest
    );

    let blob_id = "a".repeat(64);
    local.blob_manifest_request(8).unwrap();
    let manifest = MdbxBlobManifestPageResponse {
        namespace_id: "source-namespace".to_string(),
        checkpoint: "checkpoint".to_string(),
        items: vec![MdbxBlobManifestEntry {
            blob_id: blob_id.clone(),
            total_size: Some(8),
            state: MdbxBlobManifestEntryState::Available,
        }],
        next_cursor: None,
    };
    local
        .validate_blob_manifest_response(manifest.clone())
        .unwrap();
    assert!(local
        .blob_resume()
        .unwrap()
        .unwrap()
        .manifest_checkpoint
        .is_none());

    let first_request = local.blob_chunk_request(blob_id.clone(), 8, 4).unwrap();
    let first = MdbxBlobChunkResponse {
        namespace_id: "source-namespace".to_string(),
        blob_id: blob_id.clone(),
        total_size: 8,
        offset: first_request.offset,
        ciphertext: vec![1, 2, 3, 4],
        is_last: false,
    };
    local.validate_blob_chunk_response(first.clone()).unwrap();
    assert_eq!(local.blob_resume().unwrap().unwrap().next_durable_offset, 0);
    local.acknowledge_blob_chunk(first).unwrap();
    assert_eq!(local.blob_resume().unwrap().unwrap().next_durable_offset, 4);

    let second_request = local.blob_chunk_request(blob_id.clone(), 8, 4).unwrap();
    let second = MdbxBlobChunkResponse {
        namespace_id: "source-namespace".to_string(),
        blob_id,
        total_size: 8,
        offset: second_request.offset,
        ciphertext: vec![5, 6, 7, 8],
        is_last: true,
    };
    local.acknowledge_blob_chunk(second).unwrap();
    local.acknowledge_blob_manifest_page(manifest).unwrap();
    assert_eq!(
        local.blob_sync_phase().unwrap(),
        MdbxBlobSyncPhase::Complete
    );
}

#[test]
fn ffi_blob_sync_session_restores_resume_and_rejects_partial_negotiation() {
    let local = create_blob_sync_session("ffi-local".to_string()).unwrap();
    let remote = create_blob_sync_session("ffi-remote".to_string()).unwrap();
    local
        .begin_blob_sync("source-namespace".to_string())
        .unwrap();
    let hello = local.hello().unwrap();
    let mut ack = remote.accept_hello(hello).unwrap();
    ack.capabilities.pop();
    local.accept_hello_ack(ack).unwrap();
    assert!(!local.blob_replication_is_negotiated().unwrap());
    assert!(matches!(
        local.blob_manifest_request(1),
        Err(MdbxFfiError::SyncProtocol { .. })
    ));

    let restored = MdbxBlobSyncResume {
        namespace_id: "source-namespace".to_string(),
        manifest_checkpoint: Some("checkpoint".to_string()),
        manifest_cursor: None,
        current_blob_id: Some("b".repeat(64)),
        total_size: 8,
        next_durable_offset: 4,
        manifest_complete: false,
    };
    let resumed = create_blob_sync_session("ffi-resumed".to_string()).unwrap();
    let peer = create_blob_sync_session("ffi-peer".to_string()).unwrap();
    resumed
        .begin_blob_sync("source-namespace".to_string())
        .unwrap();
    let hello = resumed.hello().unwrap();
    let ack = peer.accept_hello(hello).unwrap();
    resumed.accept_hello_ack(ack).unwrap();
    resumed.restore_blob_sync(restored.clone()).unwrap();
    assert_eq!(resumed.blob_resume().unwrap().unwrap(), restored);
}

#[test]
fn attachment_tiga_scope_roundtrips_through_ffi_types() {
    let core = MdbxTigaScope {
        scope_type: MdbxTigaScopeType::Attachment,
        scope_id: Some("attachment-1".to_string()),
    }
    .into_core()
    .unwrap();
    assert_eq!(
        core,
        TigaScope::Attachment {
            attachment_id: "attachment-1".to_string()
        }
    );
    assert_eq!(
        scope_from_core(core),
        MdbxTigaScope {
            scope_type: MdbxTigaScopeType::Attachment,
            scope_id: Some("attachment-1".to_string())
        }
    );
}

#[test]
fn attachment_facade_roundtrips_and_coalesces_content_commits() {
    let vault = ffi_test_vault();
    let project = vault.create_project("Steam".to_string()).unwrap();
    let attachment_id = Uuid::new_v4().to_string();
    let operation_id = Uuid::new_v4().to_string();
    let limits = MdbxAttachmentContentLimits {
        chunk_size: 3,
        max_plaintext_bytes: 64,
    };
    let commits_before = ffi_test_count(&vault, "commits");

    let created = vault
        .create_attachment_with_content(
            operation_id.clone(),
            MdbxAttachmentCreateRequest {
                attachment_id: attachment_id.clone(),
                project_id: project.project_id.clone(),
                entry_id: None,
                file_name: "account.maFile".to_string(),
                media_type: Some("application/json".to_string()),
            },
            b"mafile".to_vec(),
            limits,
        )
        .unwrap();
    assert!(!created.already_committed);
    assert_eq!(created.attachment.attachment_id, attachment_id);
    assert_eq!(created.attachment.chunk_count, 2);
    assert_eq!(ffi_test_count(&vault, "commits"), commits_before + 1);
    assert_eq!(
        vault
            .read_attachment_content(attachment_id.clone(), 64)
            .unwrap(),
        b"mafile"
    );

    let retried = vault
        .create_attachment_with_content(
            operation_id.clone(),
            MdbxAttachmentCreateRequest {
                attachment_id: attachment_id.clone(),
                project_id: project.project_id.clone(),
                entry_id: None,
                file_name: "account.maFile".to_string(),
                media_type: Some("application/json".to_string()),
            },
            b"mafile".to_vec(),
            limits,
        )
        .unwrap();
    assert!(retried.already_committed);
    assert_eq!(retried.commit_id, created.commit_id);
    assert!(vault
        .create_attachment_with_content(
            operation_id,
            MdbxAttachmentCreateRequest {
                attachment_id: attachment_id.clone(),
                project_id: project.project_id.clone(),
                entry_id: None,
                file_name: "account.maFile".to_string(),
                media_type: Some("application/json".to_string()),
            },
            b"different".to_vec(),
            limits,
        )
        .is_err());
    assert_eq!(ffi_test_count(&vault, "commits"), commits_before + 1);

    let original_hash = created.attachment.content_hash;
    let replaced = vault
        .replace_attachment_content(
            Uuid::new_v4().to_string(),
            attachment_id.clone(),
            b"mail-body".to_vec(),
            limits,
        )
        .unwrap();
    assert_ne!(replaced.attachment.content_hash, original_hash);
    let renamed = vault
        .rename_attachment(
            attachment_id.clone(),
            "message.eml".to_string(),
            Some("message/rfc822".to_string()),
        )
        .unwrap();
    assert_eq!(renamed.content_hash, replaced.attachment.content_hash);
    assert_eq!(renamed.file_name, "message.eml");
    assert_eq!(
        vault
            .list_attachments(project.project_id, None)
            .unwrap()
            .len(),
        1
    );

    vault.delete_attachment(attachment_id.clone()).unwrap();
    assert!(
        vault
            .get_attachment(attachment_id.clone())
            .unwrap()
            .unwrap()
            .deleted
    );
    assert!(vault
        .list_deleted_attachments()
        .unwrap()
        .iter()
        .any(|attachment| attachment.attachment_id == attachment_id));
}

#[test]
fn attachment_batch_is_atomic_idempotent_and_mixes_content_metadata() {
    let vault = ffi_test_vault();
    let project = vault.create_project("Mail".to_string()).unwrap();
    let first_id = Uuid::new_v4().to_string();
    let second_id = Uuid::new_v4().to_string();
    let operation_id = Uuid::new_v4().to_string();
    let limits = MdbxAttachmentBatchLimits {
        max_commands: 4,
        max_plaintext_bytes_per_command: 64,
        max_plaintext_bytes: 64,
        chunk_size: 3,
    };
    let commands = vec![
        MdbxAttachmentBatchCommand::Create {
            attachment_id: first_id.clone(),
            project_id: project.project_id.clone(),
            entry_id: None,
            file_name: "first.bin".to_string(),
            media_type: Some("application/octet-stream".to_string()),
            content: b"first-content".to_vec(),
        },
        MdbxAttachmentBatchCommand::Create {
            attachment_id: second_id.clone(),
            project_id: project.project_id,
            entry_id: None,
            file_name: "second.bin".to_string(),
            media_type: None,
            content: b"second-content".to_vec(),
        },
        MdbxAttachmentBatchCommand::Rename {
            attachment_id: first_id.clone(),
            file_name: "renamed.bin".to_string(),
            media_type: Some("application/custom".to_string()),
        },
        MdbxAttachmentBatchCommand::Replace {
            attachment_id: second_id.clone(),
            content: b"replacement".to_vec(),
        },
    ];
    let commits_before = ffi_test_count(&vault, "commits");
    let first = vault
        .execute_attachment_batch_with_limits(operation_id.clone(), commands.clone(), limits)
        .unwrap();
    assert!(!first.already_committed);
    assert_eq!(first.attachments.len(), 2);
    assert_eq!(first.attachments[0].attachment_id, first_id);
    assert_eq!(first.attachments[0].file_name, "renamed.bin");
    assert_eq!(first.attachments[1].attachment_id, second_id);
    assert_eq!(first.attachments[1].original_size, 14);
    assert_eq!(first.attachments[1].stored_size, 11);
    assert_eq!(ffi_test_count(&vault, "commits"), commits_before + 1);
    assert_eq!(
        vault
            .read_attachment_content(first.attachments[0].attachment_id.clone(), 64)
            .unwrap(),
        b"first-content"
    );
    assert_eq!(
        vault
            .read_attachment_content(first.attachments[1].attachment_id.clone(), 64)
            .unwrap(),
        b"replacement"
    );

    let retry = vault
        .execute_attachment_batch_with_limits(operation_id.clone(), commands.clone(), limits)
        .unwrap();
    assert!(retry.already_committed);
    assert_eq!(retry.commit_id, first.commit_id);
    assert_eq!(ffi_test_count(&vault, "commits"), commits_before + 1);

    let mut changed_commands = commands;
    if let MdbxAttachmentBatchCommand::Replace { content, .. } = &mut changed_commands[3] {
        *content = b"different-content".to_vec();
    }
    assert!(vault
        .execute_attachment_batch_with_limits(operation_id, changed_commands, limits,)
        .unwrap_err()
        .to_string()
        .contains("reused for a different operation"));

    let deleted = vault
        .execute_attachment_batch_with_limits(
            Uuid::new_v4().to_string(),
            vec![
                MdbxAttachmentBatchCommand::Delete {
                    attachment_id: first.attachments[0].attachment_id.clone(),
                },
                MdbxAttachmentBatchCommand::Replace {
                    attachment_id: first.attachments[1].attachment_id.clone(),
                    content: b"final".to_vec(),
                },
            ],
            limits,
        )
        .unwrap();
    assert_eq!(ffi_test_count(&vault, "commits"), commits_before + 2);
    assert!(deleted.attachments[0].deleted);
    assert_eq!(
        vault
            .read_attachment_content(first.attachments[1].attachment_id.clone(), 64)
            .unwrap(),
        b"final"
    );
    {
        let conn = vault.conn.lock().unwrap();
        conn.inner()
            .execute(
                "UPDATE attachment_chunks SET chunk_ct = zeroblob(length(chunk_ct))
                     WHERE attachment_id = ?1 AND chunk_index = 0",
                [&first.attachments[1].attachment_id],
            )
            .unwrap();
    }
    assert!(!vault
        .verify_attachment_integrity(first.attachments[1].attachment_id.clone())
        .unwrap());
    assert!(vault
        .read_attachment_content(first.attachments[1].attachment_id.clone(), 64)
        .is_err());
}

#[test]
fn attachment_batch_rejects_partial_failures_bounds_and_missing_capability() {
    let vault = ffi_test_vault();
    let project = vault.create_project("Mail".to_string()).unwrap();
    let commits_before = ffi_test_count(&vault, "commits");
    let attachments_before = ffi_test_count(&vault, "attachments");
    assert!(vault
        .execute_attachment_batch(
            Uuid::new_v4().to_string(),
            vec![
                MdbxAttachmentBatchCommand::Create {
                    attachment_id: Uuid::new_v4().to_string(),
                    project_id: project.project_id.clone(),
                    entry_id: None,
                    file_name: "rolled-back.bin".to_string(),
                    media_type: None,
                    content: b"content".to_vec(),
                },
                MdbxAttachmentBatchCommand::Delete {
                    attachment_id: Uuid::new_v4().to_string(),
                },
            ],
        )
        .is_err());
    assert_eq!(ffi_test_count(&vault, "commits"), commits_before);
    assert_eq!(ffi_test_count(&vault, "attachments"), attachments_before);

    let small_limits = MdbxAttachmentBatchLimits {
        max_commands: 2,
        max_plaintext_bytes_per_command: 4,
        max_plaintext_bytes: 8,
        chunk_size: 2,
    };
    assert!(vault
        .execute_attachment_batch_with_limits(
            Uuid::new_v4().to_string(),
            vec![MdbxAttachmentBatchCommand::Create {
                attachment_id: Uuid::new_v4().to_string(),
                project_id: project.project_id.clone(),
                entry_id: None,
                file_name: "oversized.bin".to_string(),
                media_type: None,
                content: b"12345".to_vec(),
            }],
            small_limits,
        )
        .unwrap_err()
        .to_string()
        .contains("command plaintext bytes"));
    assert_eq!(ffi_test_count(&vault, "commits"), commits_before);

    vault
        .set_extension_capabilities(vec!["com.monica.mail.store".to_string()])
        .unwrap();
    vault
        .set_collection_profile(
            project.project_id.clone(),
            "com.monica.mail".to_string(),
            b"profile".to_vec(),
            1,
            vec!["com.monica.mail.message".to_string()],
            vec!["com.monica.mail.store".to_string()],
        )
        .unwrap();
    vault.set_extension_capabilities(Vec::new()).unwrap();
    let commits_before_capability_failure = ffi_test_count(&vault, "commits");
    assert!(vault
        .execute_attachment_batch(
            Uuid::new_v4().to_string(),
            vec![MdbxAttachmentBatchCommand::Create {
                attachment_id: Uuid::new_v4().to_string(),
                project_id: project.project_id,
                entry_id: None,
                file_name: "blocked.bin".to_string(),
                media_type: None,
                content: b"content".to_vec(),
            }],
        )
        .is_err());
    assert_eq!(
        ffi_test_count(&vault, "commits"),
        commits_before_capability_failure
    );
    assert_eq!(ffi_test_count(&vault, "attachments"), attachments_before);
}

#[test]
fn attachment_facade_rejects_oversized_content_without_side_effects() {
    let vault = ffi_test_vault();
    let project = vault.create_project("Mail".to_string()).unwrap();
    let commits_before = ffi_test_count(&vault, "commits");
    let attachments_before = ffi_test_count(&vault, "attachments");
    let result = vault.create_attachment_with_content(
        Uuid::new_v4().to_string(),
        MdbxAttachmentCreateRequest {
            attachment_id: Uuid::new_v4().to_string(),
            project_id: project.project_id,
            entry_id: None,
            file_name: "large.eml".to_string(),
            media_type: Some("message/rfc822".to_string()),
        },
        vec![0; 5],
        MdbxAttachmentContentLimits {
            chunk_size: 2,
            max_plaintext_bytes: 4,
        },
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("attachment plaintext bytes"));
    assert_eq!(ffi_test_count(&vault, "commits"), commits_before);
    assert_eq!(ffi_test_count(&vault, "attachments"), attachments_before);
}

#[test]
fn attachment_facade_enforces_stream_limits_and_detects_tampering() {
    let vault = ffi_test_vault();
    let project = vault.create_project("Mail".to_string()).unwrap();
    let attachment_id = Uuid::new_v4().to_string();
    vault
        .create_attachment_with_content(
            Uuid::new_v4().to_string(),
            MdbxAttachmentCreateRequest {
                attachment_id: attachment_id.clone(),
                project_id: project.project_id,
                entry_id: None,
                file_name: "message.eml".to_string(),
                media_type: None,
            },
            b"123456".to_vec(),
            MdbxAttachmentContentLimits {
                chunk_size: 3,
                max_plaintext_bytes: 64,
            },
        )
        .unwrap();
    {
        let conn = vault.conn.lock().unwrap();
        conn.inner()
            .execute(
                "UPDATE attachments SET stored_size = 1 WHERE attachment_id = ?1",
                [&attachment_id],
            )
            .unwrap();
    }
    let limit_error = vault
        .read_attachment_content(attachment_id.clone(), 4)
        .unwrap_err();
    assert!(
        limit_error
            .to_string()
            .contains("attachment stored size mismatch"),
        "unexpected error: {limit_error}"
    );
    let mut limited = LimitedAttachmentContentWriter::new(4);
    limited.write_all(b"123").unwrap();
    assert!(limited.write_all(b"456").is_err());
    assert_eq!(limited.bytes, b"123");
    {
        let conn = vault.conn.lock().unwrap();
        conn.inner()
            .execute(
                "UPDATE attachments SET stored_size = 6 WHERE attachment_id = ?1",
                [&attachment_id],
            )
            .unwrap();
        conn.inner()
            .execute(
                "UPDATE attachment_chunks SET chunk_ct = zeroblob(length(chunk_ct))
                     WHERE attachment_id = ?1 AND chunk_index = 0",
                [&attachment_id],
            )
            .unwrap();
    }
    assert!(vault
        .read_attachment_content(attachment_id.clone(), 64)
        .is_err());
    assert!(!vault.verify_attachment_integrity(attachment_id).unwrap());
}

#[test]
fn attachment_facade_honors_collection_capability_trimming() {
    let vault = ffi_test_vault();
    let project = vault.create_project("Mail".to_string()).unwrap();
    vault
        .set_extension_capabilities(vec!["com.monica.mail.store".to_string()])
        .unwrap();
    vault
        .set_collection_profile(
            project.project_id.clone(),
            "com.monica.mail".to_string(),
            b"profile".to_vec(),
            1,
            vec!["com.monica.mail.message".to_string()],
            vec!["com.monica.mail.store".to_string()],
        )
        .unwrap();
    vault.set_extension_capabilities(Vec::new()).unwrap();
    let commits_before = ffi_test_count(&vault, "commits");

    assert!(vault
        .create_attachment_with_content(
            Uuid::new_v4().to_string(),
            MdbxAttachmentCreateRequest {
                attachment_id: Uuid::new_v4().to_string(),
                project_id: project.project_id,
                entry_id: None,
                file_name: "blocked.eml".to_string(),
                media_type: None,
            },
            b"content".to_vec(),
            default_attachment_content_limits(),
        )
        .is_err());
    assert_eq!(ffi_test_count(&vault, "commits"), commits_before);
    assert_eq!(ffi_test_count(&vault, "attachments"), 0);
}

#[test]
fn collection_profile_facade_registers_capabilities_and_guards_object_types() {
    let conn = VaultConnection::open_in_memory().unwrap();
    initialize_vault(&conn, &VaultInitParams::default()).unwrap();
    let vault = MdbxVault {
        conn: Mutex::new(conn),
        device_id: "ffi-profile-device".to_string(),
        vault_id: "ffi-profile-vault".to_string(),
    };
    let collection = vault.create_project("Mail".to_string()).unwrap();
    vault
        .set_extension_capabilities(vec!["com.monica.mail.store".to_string()])
        .unwrap();
    let profile = vault
        .set_collection_profile(
            collection.project_id.clone(),
            "com.monica.mail".to_string(),
            b"opaque-profile".to_vec(),
            1,
            vec!["com.monica.mail.message".to_string()],
            vec!["com.monica.mail.store".to_string()],
        )
        .unwrap();
    assert_eq!(profile.collection_type_id, "com.monica.mail");
    assert_eq!(
        vault
            .get_collection_profile(collection.project_id.clone())
            .unwrap()
            .unwrap()
            .payload,
        b"opaque-profile"
    );

    vault
        .create_object(
            collection.project_id.clone(),
            "com.monica.mail.message".to_string(),
            "Message".to_string(),
            r#"{"body":"hello"}"#.to_string(),
            1,
        )
        .unwrap();
    assert!(vault
        .create_object(
            collection.project_id,
            "login".to_string(),
            "Login".to_string(),
            "{}".to_string(),
            1,
        )
        .is_err());
}

#[test]
fn payload_migration_facade_exposes_adapter_bytes_and_one_commit_result() {
    let conn = VaultConnection::open_in_memory().unwrap();
    initialize_vault(&conn, &VaultInitParams::default()).unwrap();
    let vault = MdbxVault {
        conn: Mutex::new(conn),
        device_id: "ffi-migration-device".to_string(),
        vault_id: "ffi-migration-vault".to_string(),
    };
    let collection = vault.create_project("Mail".to_string()).unwrap();
    vault
        .set_extension_capabilities(vec!["com.monica.mail.payload-v2".to_string()])
        .unwrap();
    vault
        .set_collection_profile(
            collection.project_id.clone(),
            "com.monica.mail".to_string(),
            b"profile".to_vec(),
            1,
            vec!["com.monica.mail.message".to_string()],
            vec!["com.monica.mail.payload-v2".to_string()],
        )
        .unwrap();
    let object = vault
        .create_object(
            collection.project_id.clone(),
            "com.monica.mail.message".to_string(),
            "Message".to_string(),
            r#"{"version":1}"#.to_string(),
            1,
        )
        .unwrap();

    let plan = vault
        .create_payload_migration_plan(
            collection.project_id.clone(),
            "com.monica.mail.message".to_string(),
            1,
            2,
            16,
            None,
        )
        .unwrap();
    assert_eq!(plan.items.len(), 1);
    assert_eq!(plan.items[0].object_id, object.object_id);
    assert_eq!(plan.items[0].source_payload, br#"{"version":1}"#);

    let result = vault
        .execute_payload_migration(
            plan,
            vec![MdbxPayloadMigrationOutput {
                object_id: object.object_id.clone(),
                target_payload: br#"{"version":2}"#.to_vec(),
            }],
        )
        .unwrap();
    assert_eq!(result.migrated_count, 1);
    assert!(!result.already_committed);
    let migrated = vault
        .get_object(collection.project_id, object.object_id)
        .unwrap()
        .unwrap();
    assert_eq!(migrated.payload_schema_version, 2);
    assert_eq!(migrated.payload_json, r#"{"version":2}"#);
}

#[test]
fn conflict_facade_lists_and_resolves_generic_metadata() {
    let conn = VaultConnection::open_in_memory().unwrap();
    initialize_vault(&conn, &VaultInitParams::default()).unwrap();
    let ctx = CommitContext::new("ffi-conflict-device".to_string());
    let project = ProjectRepo::create(&conn, &ctx, "Mail", None, None).unwrap();
    let first = EntryRepo::create(
        &conn,
        &ctx,
        &project.project_id,
        EntryType::custom("com.monica.mail.message").unwrap(),
        Some("First"),
        &serde_json::json!({"body":"first"}),
    )
    .unwrap();
    let second = EntryRepo::create(
        &conn,
        &ctx,
        &project.project_id,
        EntryType::custom("com.monica.mail.message").unwrap(),
        Some("Second"),
        &serde_json::json!({"body":"second"}),
    )
    .unwrap();
    let relation = ObjectRelationRepo::create(
        &conn,
        &ctx,
        ObjectRelationCreateRequest::new(
            &first.entry_id,
            &second.entry_id,
            RelationKindId::new("com.monica.mail.reply-to").unwrap(),
            serde_json::json!({"position":1}),
        ),
    )
    .unwrap();
    let current = mdbx_storage::repo::ObjectVersionRepo::current_object_relation_row(
        &conn,
        &relation.relation_id,
    )
    .unwrap();
    let incoming_commit = ctx
        .create_commit(
            &conn,
            "change",
            "object-relation",
            std::slice::from_ref(&relation.relation_id),
            std::slice::from_ref(&current.head_commit_id),
        )
        .unwrap();
    let mut incoming = current.clone();
    incoming.payload_ct = serde_json::to_vec(&serde_json::json!({"position":2})).unwrap();
    incoming.head_commit_id = incoming_commit.clone();
    mdbx_storage::repo::ObjectVersionRepo::record_object_relation_row(
        &conn,
        &incoming_commit,
        &incoming,
    )
    .unwrap();
    let conflict = ConflictRepo::create(
        &conn,
        &ctx,
        ConflictObjectType::ObjectRelation,
        &relation.relation_id,
        &current.head_commit_id,
        &current.head_commit_id,
        &incoming_commit,
        &["payload_ct".to_string()],
    )
    .unwrap();
    let vault = MdbxVault {
        conn: Mutex::new(conn),
        device_id: "ffi-conflict-device".to_string(),
        vault_id: "ffi-conflict-vault".to_string(),
    };

    let listed = vault.list_unresolved_conflicts().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].object_type, "object-relation");
    let resolved = vault
        .resolve_conflict(conflict.conflict_id, MdbxConflictChoice::IncomingWins)
        .unwrap();
    assert_eq!(resolved.resolution, "incoming-wins");
    assert!(vault.list_unresolved_conflicts().unwrap().is_empty());
    let conn = vault.conn.lock().unwrap();
    let stored = ObjectRelationRepo::get_by_id(&conn, &relation.relation_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&stored.payload_ct).unwrap(),
        serde_json::json!({"position":2})
    );
}

#[test]
fn conflict_facade_applies_typed_project_and_attachment_custom_merges() {
    let conn = VaultConnection::open_in_memory().unwrap();
    initialize_vault(&conn, &VaultInitParams::default()).unwrap();
    let ctx = CommitContext::new("ffi-custom-conflict-device".to_string());
    let project = ProjectRepo::create(&conn, &ctx, "Local", None, None).unwrap();
    let project_row =
        mdbx_storage::repo::ObjectVersionRepo::current_project_row(&conn, &project.project_id)
            .unwrap();
    let project_incoming_commit = ctx
        .create_commit(
            &conn,
            "change",
            "project",
            std::slice::from_ref(&project.project_id),
            std::slice::from_ref(&project_row.head_commit_id),
        )
        .unwrap();
    let mut incoming_project = project_row.clone();
    incoming_project.title_ct = b"Incoming".to_vec();
    incoming_project.head_commit_id = project_incoming_commit.clone();
    mdbx_storage::repo::ObjectVersionRepo::record_project_row(
        &conn,
        &project_incoming_commit,
        &incoming_project,
    )
    .unwrap();
    let project_conflict = ConflictRepo::create(
        &conn,
        &ctx,
        ConflictObjectType::Project,
        &project.project_id,
        &project_row.head_commit_id,
        &project_row.head_commit_id,
        &project_incoming_commit,
        &["title_ct".to_string()],
    )
    .unwrap();

    let content_hash = "a".repeat(64);
    let attachment = AttachmentRepo::add(
        &conn,
        &ctx,
        &project.project_id,
        None,
        "local.mafile",
        Some("application/json"),
        &content_hash,
        256,
    )
    .unwrap();
    let attachment_row = mdbx_storage::repo::ObjectVersionRepo::current_attachment_row(
        &conn,
        &attachment.attachment_id,
    )
    .unwrap();
    let attachment_incoming_commit = ctx
        .create_commit(
            &conn,
            "change",
            "attachment",
            std::slice::from_ref(&attachment.attachment_id),
            std::slice::from_ref(&attachment_row.head_commit_id),
        )
        .unwrap();
    let mut incoming_attachment = attachment_row.clone();
    incoming_attachment.file_name_ct = b"incoming.mafile".to_vec();
    incoming_attachment.head_commit_id = attachment_incoming_commit.clone();
    mdbx_storage::repo::ObjectVersionRepo::record_attachment_row(
        &conn,
        &attachment_incoming_commit,
        &incoming_attachment,
    )
    .unwrap();
    let attachment_conflict = ConflictRepo::create(
        &conn,
        &ctx,
        ConflictObjectType::Attachment,
        &attachment.attachment_id,
        &attachment_row.head_commit_id,
        &attachment_row.head_commit_id,
        &attachment_incoming_commit,
        &["file_name_ct".to_string()],
    )
    .unwrap();
    let vault = MdbxVault {
        conn: Mutex::new(conn),
        device_id: "ffi-custom-conflict-device".to_string(),
        vault_id: "ffi-custom-conflict-vault".to_string(),
    };

    assert!(vault
        .resolve_project_conflict_custom(
            attachment_conflict.conflict_id.clone(),
            MdbxProjectConflictMerge {
                title: "Wrong type".to_string(),
                summary: None,
                group_id: None,
                icon_ref: None,
                favorite: false,
                archived: false,
                deleted: false,
            },
        )
        .is_err());

    let resolved_project = vault
        .resolve_project_conflict_custom(
            project_conflict.conflict_id,
            MdbxProjectConflictMerge {
                title: "Merged".to_string(),
                summary: Some("Selected summary".to_string()),
                group_id: Some("accounts".to_string()),
                icon_ref: Some("steam".to_string()),
                favorite: true,
                archived: false,
                deleted: false,
            },
        )
        .unwrap();
    let resolved_attachment = vault
        .resolve_attachment_conflict_custom(
            attachment_conflict.conflict_id,
            MdbxAttachmentConflictMerge {
                project_id: project.project_id.clone(),
                entry_id: None,
                file_name: "merged.mafile".to_string(),
                media_type: Some("application/vnd.monica.mafile+json".to_string()),
                deleted: false,
            },
        )
        .unwrap();

    assert_eq!(resolved_project.resolution, "custom");
    assert_eq!(resolved_attachment.resolution, "custom");
    assert!(vault.list_unresolved_conflicts().unwrap().is_empty());
    let conn = vault.conn.lock().unwrap();
    let stored_project = ProjectRepo::get_by_id(&conn, &project.project_id)
        .unwrap()
        .unwrap();
    let stored_attachment = AttachmentRepo::get_by_id(&conn, &attachment.attachment_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored_project.title_ct, b"Merged");
    assert_eq!(
        stored_project.summary_ct.as_deref(),
        Some(b"Selected summary".as_slice())
    );
    assert!(stored_project.favorite);
    assert_eq!(stored_attachment.file_name_ct, b"merged.mafile");
    assert_eq!(stored_attachment.content_hash, content_hash);
    assert_eq!(stored_attachment.original_size, 256);
}

#[test]
fn health_check_returns_structured_tombstone_issues() {
    let conn = VaultConnection::open_in_memory().unwrap();
    initialize_vault(&conn, &VaultInitParams::default()).unwrap();
    let ctx = CommitContext::new("ffi-health-device".to_string());
    let project = ProjectRepo::create(&conn, &ctx, "Health", None, None).unwrap();
    let vault = MdbxVault {
        conn: Mutex::new(conn),
        device_id: "ffi-health-device".to_string(),
        vault_id: "ffi-health-vault".to_string(),
    };

    let clean = vault.health_check().unwrap();
    assert!(clean.healthy);

    {
        let conn = vault.conn.lock().unwrap();
        ProjectRepo::soft_delete(&conn, &ctx, &project.project_id).unwrap();
        conn.inner()
            .execute(
                "DELETE FROM tombstones
                     WHERE target_object_type = 'project' AND target_object_id = ?1",
                rusqlite::params![project.project_id],
            )
            .unwrap();
    }

    let unhealthy = vault.health_check().unwrap();
    assert!(!unhealthy.healthy);
    assert!(unhealthy.issues.iter().any(|issue| {
        issue.severity == MdbxHealthIssueSeverity::Error
            && issue.category == "tombstones"
            && issue.description.contains(&project.project_id)
            && issue.description.contains("deleted without")
    }));
}

#[test]
fn tombstone_purge_eligibility_is_available_to_native_clients() {
    let conn = VaultConnection::open_in_memory().unwrap();
    initialize_vault(
        &conn,
        &VaultInitParams {
            device_id: "ffi-purge-device".to_string(),
            ..VaultInitParams::default()
        },
    )
    .unwrap();
    let ctx = CommitContext::new("ffi-purge-device".to_string());
    let project = ProjectRepo::create(&conn, &ctx, "Purge", None, None).unwrap();
    ProjectRepo::soft_delete(&conn, &ctx, &project.project_id).unwrap();
    let tombstone = TombstoneRepo::find_by_target(&conn, &project.project_id)
        .unwrap()
        .unwrap();
    let vault = MdbxVault {
        conn: Mutex::new(conn),
        device_id: "ffi-purge-device".to_string(),
        vault_id: "ffi-purge-vault".to_string(),
    };

    let result = vault
        .evaluate_tombstone_purge_eligibility(
            tombstone.tombstone_id,
            "2030-01-01T00:00:00Z".to_string(),
        )
        .unwrap();
    assert!(!result.eligible);
    assert_eq!(result.blockers.len(), 1);
    assert_eq!(result.blockers[0].code, "retention-not-scheduled");
}

#[test]
fn bounded_write_operation_limits_and_streaming_intent_hash_are_stable() {
    let limits = default_write_operation_limits();
    assert_eq!(limits.max_commands, 256);
    assert_eq!(limits.max_payload_bytes_per_command, 1024 * 1024);
    assert_eq!(limits.max_payload_bytes, 8 * 1024 * 1024);
    assert_eq!(limits.max_intent_bytes, 16 * 1024 * 1024);

    let commands = vec![MdbxWriteCommand::CreateProject {
        project_id: Uuid::new_v4().to_string(),
        title: "Mail".to_string(),
    }];
    let encoded = serde_json::to_vec(&commands).unwrap();
    assert_eq!(
        hash_write_operation_intent(&commands, encoded.len()).unwrap(),
        Sha256::digest(&encoded).to_vec()
    );
    assert!(hash_write_operation_intent(&commands, encoded.len() - 1)
        .unwrap_err()
        .to_string()
        .contains("serialized intent bytes"));

    let invalid = MdbxWriteOperationLimits {
        max_commands: HARD_MAX_WRITE_COMMANDS as u64 + 1,
        ..limits
    };
    assert!(invalid.into_internal().is_err());
}

#[test]
fn bounded_write_operation_rejects_without_database_side_effects() {
    let conn = VaultConnection::open_in_memory().unwrap();
    initialize_vault(&conn, &VaultInitParams::default()).unwrap();
    let initial_commits: i64 = conn
        .inner()
        .query_row("SELECT COUNT(*) FROM commits", [], |row| row.get(0))
        .unwrap();
    let initial_projects: i64 = conn
        .inner()
        .query_row("SELECT COUNT(*) FROM projects", [], |row| row.get(0))
        .unwrap();
    let initial_head: String = conn
        .inner()
        .query_row(
            "SELECT head_commit_id FROM branches WHERE branch_name = 'main'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let vault = MdbxVault {
        conn: Mutex::new(conn),
        device_id: "ffi-bounded-write-device".to_string(),
        vault_id: "ffi-bounded-write-vault".to_string(),
    };

    let too_many = (0..=DEFAULT_MAX_WRITE_COMMANDS)
        .map(|index| MdbxWriteCommand::CreateProject {
            project_id: Uuid::new_v4().to_string(),
            title: format!("Collection {index}"),
        })
        .collect();
    assert!(vault
        .execute_write_operation(
            Uuid::new_v4().to_string(),
            "bulk-import".to_string(),
            too_many,
        )
        .unwrap_err()
        .to_string()
        .contains("write operation commands"));

    let oversized_payload = format!(
        "\"{}\"",
        "x".repeat(DEFAULT_MAX_WRITE_PAYLOAD_BYTES_PER_COMMAND)
    );
    assert!(vault
        .execute_write_operation(
            Uuid::new_v4().to_string(),
            "mail-import".to_string(),
            vec![MdbxWriteCommand::CreateEntry {
                entry_id: Uuid::new_v4().to_string(),
                project_id: Uuid::new_v4().to_string(),
                entry_type: "com.monica.mail.message".to_string(),
                title: "Oversized".to_string(),
                payload_json: oversized_payload,
            }],
        )
        .unwrap_err()
        .to_string()
        .contains("command payload bytes"));

    let small_limits = MdbxWriteOperationLimits {
        max_commands: 2,
        max_payload_bytes_per_command: 16,
        max_payload_bytes: 16,
        max_intent_bytes: 4096,
    };
    let payload = r#"{"body":"1234"}"#.to_string();
    assert!(vault
        .execute_write_operation_with_limits(
            Uuid::new_v4().to_string(),
            "mail-import".to_string(),
            vec![
                MdbxWriteCommand::CreateEntry {
                    entry_id: Uuid::new_v4().to_string(),
                    project_id: Uuid::new_v4().to_string(),
                    entry_type: "com.monica.mail.message".to_string(),
                    title: "First".to_string(),
                    payload_json: payload.clone(),
                },
                MdbxWriteCommand::CreateEntry {
                    entry_id: Uuid::new_v4().to_string(),
                    project_id: Uuid::new_v4().to_string(),
                    entry_type: "com.monica.mail.message".to_string(),
                    title: "Second".to_string(),
                    payload_json: payload,
                },
            ],
            small_limits,
        )
        .unwrap_err()
        .to_string()
        .contains("write operation payload bytes"));

    let conn = vault.conn.lock().unwrap();
    assert_eq!(
        conn.inner()
            .query_row("SELECT COUNT(*) FROM commits", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        initial_commits
    );
    assert_eq!(
        conn.inner()
            .query_row("SELECT COUNT(*) FROM projects", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        initial_projects
    );
    assert_eq!(
        conn.inner()
            .query_row(
                "SELECT head_commit_id FROM branches WHERE branch_name = 'main'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        initial_head
    );
}

#[test]
fn write_operation_is_atomic_single_commit_and_idempotent_across_limit_apis() {
    let conn = VaultConnection::open_in_memory().unwrap();
    initialize_vault(&conn, &VaultInitParams::default()).unwrap();
    let initial_commits: i64 = conn
        .inner()
        .query_row("SELECT COUNT(*) FROM commits", [], |row| row.get(0))
        .unwrap();
    let vault = MdbxVault {
        conn: Mutex::new(conn),
        device_id: "ffi-write-device".to_string(),
        vault_id: "ffi-write-vault".to_string(),
    };
    let operation_id = Uuid::new_v4().to_string();
    let project_id = Uuid::new_v4().to_string();
    let entry_id = Uuid::new_v4().to_string();
    let commands = vec![
        MdbxWriteCommand::CreateProject {
            project_id: project_id.clone(),
            title: "Mail".to_string(),
        },
        MdbxWriteCommand::CreateEntry {
            entry_id: entry_id.clone(),
            project_id: project_id.clone(),
            entry_type: "com.monica.mail.message".to_string(),
            title: "Message".to_string(),
            payload_json: r#"{"body":"encrypted by storage"}"#.to_string(),
        },
    ];
    let explicit_limits = MdbxWriteOperationLimits {
        max_commands: 2,
        max_payload_bytes_per_command: 1024,
        max_payload_bytes: 1024,
        max_intent_bytes: 4096,
    };

    let first = vault
        .execute_write_operation_with_limits(
            operation_id.clone(),
            "mail-import".to_string(),
            commands.clone(),
            explicit_limits,
        )
        .unwrap();
    assert!(!first.already_committed);
    assert_eq!(first.project_ids, vec![project_id.clone()]);
    assert_eq!(first.entry_ids, vec![entry_id.clone()]);

    let retry = vault
        .execute_write_operation(
            operation_id.clone(),
            "mail-import".to_string(),
            commands.clone(),
        )
        .unwrap();
    assert!(retry.already_committed);
    assert_eq!(retry.commit_id, first.commit_id);

    let changed_commands = vec![commands[0].clone()];
    assert!(vault
        .execute_write_operation(operation_id, "mail-import".to_string(), changed_commands,)
        .unwrap_err()
        .to_string()
        .contains("reused for a different operation"));

    let failed_project_id = Uuid::new_v4().to_string();
    let missing_project_id = Uuid::new_v4().to_string();
    assert!(vault
        .execute_write_operation(
            Uuid::new_v4().to_string(),
            "mail-import".to_string(),
            vec![
                MdbxWriteCommand::CreateProject {
                    project_id: failed_project_id.clone(),
                    title: "Rolled back".to_string(),
                },
                MdbxWriteCommand::CreateEntry {
                    entry_id: Uuid::new_v4().to_string(),
                    project_id: missing_project_id,
                    entry_type: "com.monica.mail.message".to_string(),
                    title: "Failure".to_string(),
                    payload_json: "{}".to_string(),
                },
            ],
        )
        .is_err());

    let conn = vault.conn.lock().unwrap();
    assert_eq!(
        conn.inner()
            .query_row("SELECT COUNT(*) FROM commits", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        initial_commits + 1
    );
    assert_eq!(
        conn.inner()
            .query_row(
                "SELECT COUNT(*) FROM projects WHERE project_id = ?1",
                rusqlite::params![failed_project_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    let stored_entry = EntryRepo::get_by_id(&conn, &entry_id).unwrap().unwrap();
    assert_eq!(stored_entry.head_commit_id, first.commit_id);
}

#[test]
fn generic_metadata_write_operation_is_atomic_idempotent_and_lifecycle_complete() {
    let vault = ffi_test_vault();
    let operation_id = Uuid::new_v4().to_string();
    let project_id = Uuid::new_v4().to_string();
    let first_entry_id = Uuid::new_v4().to_string();
    let second_entry_id = Uuid::new_v4().to_string();
    let relation_id = Uuid::new_v4().to_string();
    let label_id = Uuid::new_v4().to_string();
    let assignment_id = Uuid::new_v4().to_string();
    let commits_before = ffi_test_count(&vault, "commits");
    let commands = vec![
        MdbxWriteCommand::CreateProject {
            project_id: project_id.clone(),
            title: "Mail".to_string(),
        },
        MdbxWriteCommand::CreateEntry {
            entry_id: first_entry_id.clone(),
            project_id: project_id.clone(),
            entry_type: "com.monica.mail.message".to_string(),
            title: "First".to_string(),
            payload_json: r#"{"body":"first"}"#.to_string(),
        },
        MdbxWriteCommand::CreateEntry {
            entry_id: second_entry_id.clone(),
            project_id: project_id.clone(),
            entry_type: "com.monica.mail.message".to_string(),
            title: "Second".to_string(),
            payload_json: r#"{"body":"second"}"#.to_string(),
        },
        MdbxWriteCommand::CreateObjectRelation {
            relation_id: relation_id.clone(),
            source_object_id: first_entry_id.clone(),
            target_object_id: second_entry_id.clone(),
            relation_kind: "com.monica.mail.reply-to".to_string(),
            payload_json: r#"{"position":1}"#.to_string(),
            payload_schema_version: 1,
        },
        MdbxWriteCommand::CreateObjectLabel {
            label_id: label_id.clone(),
            collection_id: project_id.clone(),
            name: "Important".to_string(),
            payload_json: r#"{"color":"red"}"#.to_string(),
            payload_schema_version: 1,
        },
        MdbxWriteCommand::AssignObjectLabel {
            assignment_id: assignment_id.clone(),
            object_id: first_entry_id.clone(),
            label_id: label_id.clone(),
        },
    ];

    let created = vault
        .execute_write_operation(
            operation_id.clone(),
            "mail-thread-import".to_string(),
            commands.clone(),
        )
        .unwrap();
    assert!(!created.already_committed);
    assert_eq!(created.project_ids, vec![project_id.clone()]);
    assert_eq!(
        created.entry_ids,
        vec![first_entry_id.clone(), second_entry_id.clone()]
    );
    assert_eq!(created.relation_ids, vec![relation_id.clone()]);
    assert_eq!(created.label_ids, vec![label_id.clone()]);
    assert_eq!(created.label_assignment_ids, vec![assignment_id.clone()]);
    assert_eq!(ffi_test_count(&vault, "commits"), commits_before + 1);
    {
        let conn = vault.conn.lock().unwrap();
        assert_eq!(
            ObjectRelationRepo::get_by_id(&conn, &relation_id)
                .unwrap()
                .unwrap()
                .head_commit_id,
            created.commit_id
        );
        assert_eq!(
            ObjectLabelRepo::get_by_id(&conn, &label_id)
                .unwrap()
                .unwrap()
                .head_commit_id,
            created.commit_id
        );
        assert_eq!(
            ObjectLabelAssignmentRepo::get_by_id(&conn, &assignment_id)
                .unwrap()
                .unwrap()
                .head_commit_id,
            created.commit_id
        );
    }

    let retry = vault
        .execute_write_operation(
            operation_id.clone(),
            "mail-thread-import".to_string(),
            commands.clone(),
        )
        .unwrap();
    assert!(retry.already_committed);
    assert_eq!(retry.commit_id, created.commit_id);
    let mut changed_commands = commands.clone();
    if let MdbxWriteCommand::CreateObjectRelation { payload_json, .. } = &mut changed_commands[3] {
        *payload_json = r#"{"position":2}"#.to_string();
    }
    assert!(vault
        .execute_write_operation(
            operation_id,
            "mail-thread-import".to_string(),
            changed_commands,
        )
        .unwrap_err()
        .to_string()
        .contains("reused for a different operation"));

    let updated = vault
        .execute_write_operation(
            Uuid::new_v4().to_string(),
            "mail-thread-update".to_string(),
            vec![
                MdbxWriteCommand::UpdateObjectRelation {
                    relation_id: relation_id.clone(),
                    relation_kind: "com.monica.mail.thread-member".to_string(),
                    payload_json: r#"{"position":2}"#.to_string(),
                    payload_schema_version: 2,
                },
                MdbxWriteCommand::UpdateObjectLabel {
                    label_id: label_id.clone(),
                    name: "Priority".to_string(),
                    payload_json: r#"{"color":"orange"}"#.to_string(),
                    payload_schema_version: 2,
                },
            ],
        )
        .unwrap();
    assert_eq!(updated.relation_ids, vec![relation_id.clone()]);
    assert_eq!(updated.label_ids, vec![label_id.clone()]);
    assert_eq!(ffi_test_count(&vault, "commits"), commits_before + 2);

    let deleted = vault
        .execute_write_operation(
            Uuid::new_v4().to_string(),
            "mail-thread-delete".to_string(),
            vec![
                MdbxWriteCommand::RemoveObjectLabelAssignment {
                    assignment_id: assignment_id.clone(),
                },
                MdbxWriteCommand::DeleteObjectLabel {
                    label_id: label_id.clone(),
                },
                MdbxWriteCommand::DeleteObjectRelation {
                    relation_id: relation_id.clone(),
                },
            ],
        )
        .unwrap();
    assert_eq!(deleted.relation_ids, vec![relation_id.clone()]);
    assert_eq!(deleted.label_ids, vec![label_id.clone()]);
    assert_eq!(deleted.label_assignment_ids, vec![assignment_id.clone()]);
    assert_eq!(ffi_test_count(&vault, "commits"), commits_before + 3);
    let conn = vault.conn.lock().unwrap();
    assert!(
        ObjectRelationRepo::get_by_id(&conn, &relation_id)
            .unwrap()
            .unwrap()
            .deleted
    );
    assert!(
        ObjectLabelRepo::get_by_id(&conn, &label_id)
            .unwrap()
            .unwrap()
            .deleted
    );
    assert!(
        ObjectLabelAssignmentRepo::get_by_id(&conn, &assignment_id)
            .unwrap()
            .unwrap()
            .deleted
    );
}

#[test]
fn generic_metadata_write_operation_rolls_back_and_enforces_bounds() {
    let vault = ffi_test_vault();
    let project = vault.create_project("Mail".to_string()).unwrap();
    let first = vault
        .create_object(
            project.project_id.clone(),
            "com.monica.mail.message".to_string(),
            "First".to_string(),
            "{}".to_string(),
            1,
        )
        .unwrap();
    let second = vault
        .create_object(
            project.project_id.clone(),
            "com.monica.mail.message".to_string(),
            "Second".to_string(),
            "{}".to_string(),
            1,
        )
        .unwrap();
    let rolled_back_label_id = Uuid::new_v4().to_string();
    let commits_before = ffi_test_count(&vault, "commits");

    assert!(vault
        .execute_write_operation(
            Uuid::new_v4().to_string(),
            "mail-label-import".to_string(),
            vec![
                MdbxWriteCommand::CreateObjectLabel {
                    label_id: rolled_back_label_id.clone(),
                    collection_id: project.project_id.clone(),
                    name: "Rolled back".to_string(),
                    payload_json: "{}".to_string(),
                    payload_schema_version: 1,
                },
                MdbxWriteCommand::AssignObjectLabel {
                    assignment_id: Uuid::new_v4().to_string(),
                    object_id: Uuid::new_v4().to_string(),
                    label_id: rolled_back_label_id.clone(),
                },
            ],
        )
        .is_err());
    assert_eq!(ffi_test_count(&vault, "commits"), commits_before);
    assert_eq!(ffi_test_count(&vault, "object_labels"), 0);

    let limits = MdbxWriteOperationLimits {
        max_commands: 1,
        max_payload_bytes_per_command: 8,
        max_payload_bytes: 8,
        max_intent_bytes: 4096,
    };
    assert!(vault
        .execute_write_operation_with_limits(
            Uuid::new_v4().to_string(),
            "mail-relation-import".to_string(),
            vec![MdbxWriteCommand::CreateObjectRelation {
                relation_id: Uuid::new_v4().to_string(),
                source_object_id: first.object_id.clone(),
                target_object_id: second.object_id.clone(),
                relation_kind: "com.monica.mail.reply-to".to_string(),
                payload_json: r#"{"position":1}"#.to_string(),
                payload_schema_version: 1,
            }],
            limits,
        )
        .unwrap_err()
        .to_string()
        .contains("command payload bytes"));
    assert_eq!(ffi_test_count(&vault, "commits"), commits_before);
    assert_eq!(ffi_test_count(&vault, "object_relations"), 0);

    vault
        .set_extension_capabilities(vec!["com.monica.mail.store".to_string()])
        .unwrap();
    vault
        .set_collection_profile(
            project.project_id.clone(),
            "com.monica.mail".to_string(),
            b"profile".to_vec(),
            1,
            vec!["com.monica.mail.message".to_string()],
            vec!["com.monica.mail.store".to_string()],
        )
        .unwrap();
    vault.set_extension_capabilities(Vec::new()).unwrap();
    let commits_before_capability_failure = ffi_test_count(&vault, "commits");
    assert!(vault
        .execute_write_operation(
            Uuid::new_v4().to_string(),
            "mail-relation-import".to_string(),
            vec![MdbxWriteCommand::CreateObjectRelation {
                relation_id: Uuid::new_v4().to_string(),
                source_object_id: first.object_id,
                target_object_id: second.object_id,
                relation_kind: "com.monica.mail.reply-to".to_string(),
                payload_json: "{}".to_string(),
                payload_schema_version: 1,
            }],
        )
        .is_err());
    assert_eq!(
        ffi_test_count(&vault, "commits"),
        commits_before_capability_failure
    );
    assert_eq!(ffi_test_count(&vault, "object_relations"), 0);
}

#[test]
fn composite_write_operation_creates_parent_and_attachment_in_one_commit() {
    let vault = ffi_test_vault();
    let project_id = Uuid::new_v4().to_string();
    let entry_id = Uuid::new_v4().to_string();
    let attachment_id = Uuid::new_v4().to_string();
    let operation_id = Uuid::new_v4().to_string();
    let mut limits = default_composite_write_operation_limits();
    limits.write_limits.max_commands = 2;
    limits.write_limits.max_payload_bytes_per_command = 1024;
    limits.write_limits.max_payload_bytes = 1024;
    limits.write_limits.max_intent_bytes = 4096;
    limits.attachment_limits.max_commands = 1;
    limits.attachment_limits.max_plaintext_bytes_per_command = 64;
    limits.attachment_limits.max_plaintext_bytes = 64;
    limits.attachment_limits.chunk_size = 3;
    let generic_commands = vec![
        MdbxWriteCommand::CreateProject {
            project_id: project_id.clone(),
            title: "Mail".to_string(),
        },
        MdbxWriteCommand::CreateEntry {
            entry_id: entry_id.clone(),
            project_id: project_id.clone(),
            entry_type: "com.monica.mail.message".to_string(),
            title: "Message".to_string(),
            payload_json: r#"{"body":"hello"}"#.to_string(),
        },
    ];
    let attachment_commands = vec![MdbxAttachmentBatchCommand::Create {
        attachment_id: attachment_id.clone(),
        project_id: project_id.clone(),
        entry_id: Some(entry_id.clone()),
        file_name: "message.eml".to_string(),
        media_type: Some("message/rfc822".to_string()),
        content: b"mail body".to_vec(),
    }];
    let commits_before = ffi_test_count(&vault, "commits");
    let first = vault
        .execute_composite_write_operation_with_limits(
            operation_id.clone(),
            "mail-import".to_string(),
            generic_commands.clone(),
            attachment_commands.clone(),
            limits,
        )
        .unwrap();
    assert!(!first.operation.already_committed);
    assert_eq!(first.operation.project_ids, vec![project_id.clone()]);
    assert_eq!(first.operation.entry_ids, vec![entry_id.clone()]);
    assert_eq!(first.attachments.len(), 1);
    assert_eq!(first.attachments[0].attachment_id, attachment_id);
    assert_eq!(ffi_test_count(&vault, "commits"), commits_before + 1);
    {
        let conn = vault.conn.lock().unwrap();
        let project = ProjectRepo::get_by_id(&conn, &project_id).unwrap().unwrap();
        let entry = EntryRepo::get_by_id(&conn, &entry_id).unwrap().unwrap();
        let attachment = AttachmentRepo::get_by_id(&conn, &attachment_id)
            .unwrap()
            .unwrap();
        assert_eq!(project.head_commit_id, first.operation.commit_id);
        assert_eq!(entry.head_commit_id, first.operation.commit_id);
        assert_eq!(attachment.head_commit_id, first.operation.commit_id);
    }
    assert_eq!(
        vault
            .read_attachment_content(attachment_id.clone(), 64)
            .unwrap(),
        b"mail body"
    );

    let retry = vault
        .execute_composite_write_operation_with_limits(
            operation_id.clone(),
            "mail-import".to_string(),
            generic_commands.clone(),
            attachment_commands.clone(),
            limits,
        )
        .unwrap();
    assert!(retry.operation.already_committed);
    assert_eq!(retry.operation.commit_id, first.operation.commit_id);
    assert_eq!(ffi_test_count(&vault, "commits"), commits_before + 1);

    let changed_attachment_commands = vec![MdbxAttachmentBatchCommand::Create {
        attachment_id,
        project_id: project_id.clone(),
        entry_id: Some(entry_id.clone()),
        file_name: "message.eml".to_string(),
        media_type: Some("message/rfc822".to_string()),
        content: b"changed body".to_vec(),
    }];
    assert!(vault
        .execute_composite_write_operation_with_limits(
            operation_id,
            "mail-import".to_string(),
            generic_commands,
            changed_attachment_commands,
            limits,
        )
        .unwrap_err()
        .to_string()
        .contains("reused for a different operation"));

    let failed_project_id = Uuid::new_v4().to_string();
    let failed_entry_id = Uuid::new_v4().to_string();
    let failed_attachment_id = Uuid::new_v4().to_string();
    assert!(vault
        .execute_composite_write_operation(
            Uuid::new_v4().to_string(),
            "mail-import".to_string(),
            vec![
                MdbxWriteCommand::CreateProject {
                    project_id: failed_project_id.clone(),
                    title: "Rolled back".to_string(),
                },
                MdbxWriteCommand::CreateEntry {
                    entry_id: failed_entry_id.clone(),
                    project_id: failed_project_id.clone(),
                    entry_type: "com.monica.mail.message".to_string(),
                    title: "Failure".to_string(),
                    payload_json: "{}".to_string(),
                },
            ],
            vec![MdbxAttachmentBatchCommand::Create {
                attachment_id: failed_attachment_id.clone(),
                project_id: failed_project_id.clone(),
                entry_id: Some(Uuid::new_v4().to_string()),
                file_name: "failure.eml".to_string(),
                media_type: None,
                content: b"failure".to_vec(),
            }],
        )
        .is_err());
    assert_eq!(ffi_test_count(&vault, "commits"), commits_before + 1);
    {
        let conn = vault.conn.lock().unwrap();
        assert!(ProjectRepo::get_by_id(&conn, &failed_project_id)
            .unwrap()
            .is_none());
        assert!(EntryRepo::get_by_id(&conn, &failed_entry_id)
            .unwrap()
            .is_none());
        assert!(AttachmentRepo::get_by_id(&conn, &failed_attachment_id)
            .unwrap()
            .is_none());
    }

    let bounded_project_id = Uuid::new_v4().to_string();
    let bounded_entry_id = Uuid::new_v4().to_string();
    let mut bounded_limits = default_composite_write_operation_limits();
    bounded_limits.write_limits.max_commands = 2;
    bounded_limits.write_limits.max_payload_bytes_per_command = 1024;
    bounded_limits.write_limits.max_payload_bytes = 1024;
    bounded_limits.write_limits.max_intent_bytes = 4096;
    bounded_limits.attachment_limits.max_commands = 1;
    bounded_limits
        .attachment_limits
        .max_plaintext_bytes_per_command = 4;
    bounded_limits.attachment_limits.max_plaintext_bytes = 4;
    bounded_limits.attachment_limits.chunk_size = 2;
    assert!(vault
        .execute_composite_write_operation_with_limits(
            Uuid::new_v4().to_string(),
            "mail-import".to_string(),
            vec![
                MdbxWriteCommand::CreateProject {
                    project_id: bounded_project_id.clone(),
                    title: "Bounded".to_string(),
                },
                MdbxWriteCommand::CreateEntry {
                    entry_id: bounded_entry_id.clone(),
                    project_id: bounded_project_id.clone(),
                    entry_type: "com.monica.mail.message".to_string(),
                    title: "Bounded".to_string(),
                    payload_json: "{}".to_string(),
                },
            ],
            vec![MdbxAttachmentBatchCommand::Create {
                attachment_id: Uuid::new_v4().to_string(),
                project_id: bounded_project_id.clone(),
                entry_id: Some(bounded_entry_id),
                file_name: "oversized.eml".to_string(),
                media_type: None,
                content: b"12345".to_vec(),
            }],
            bounded_limits,
        )
        .unwrap_err()
        .to_string()
        .contains("command plaintext bytes"));
    assert_eq!(ffi_test_count(&vault, "commits"), commits_before + 1);
    let conn = vault.conn.lock().unwrap();
    assert!(ProjectRepo::get_by_id(&conn, &bounded_project_id)
        .unwrap()
        .is_none());
}

#[test]
fn every_write_command_has_a_typed_change_summary() {
    let commands = vec![
        MdbxWriteCommand::CreateProject {
            project_id: "project".to_string(),
            title: "Project".to_string(),
        },
        MdbxWriteCommand::CreateEntry {
            entry_id: "created".to_string(),
            project_id: "project".to_string(),
            entry_type: "login".to_string(),
            title: "Created".to_string(),
            payload_json: "{}".to_string(),
        },
        MdbxWriteCommand::UpdateEntry {
            entry_id: "updated".to_string(),
            project_id: "project".to_string(),
            entry_type: "login".to_string(),
            title: "Updated".to_string(),
            payload_json: "{}".to_string(),
        },
        MdbxWriteCommand::DeleteEntry {
            entry_id: "deleted".to_string(),
            project_id: "project".to_string(),
        },
        MdbxWriteCommand::RestoreEntry {
            entry_id: "restored".to_string(),
            project_id: "project".to_string(),
        },
        MdbxWriteCommand::MoveEntry {
            entry_id: "moved".to_string(),
            project_id: "project".to_string(),
            target_project_id: "target".to_string(),
        },
        MdbxWriteCommand::CreateObjectRelation {
            relation_id: "relation-created".to_string(),
            source_object_id: "source".to_string(),
            target_object_id: "target".to_string(),
            relation_kind: "com.monica.test.relation".to_string(),
            payload_json: "{}".to_string(),
            payload_schema_version: 1,
        },
        MdbxWriteCommand::UpdateObjectRelation {
            relation_id: "relation-updated".to_string(),
            relation_kind: "com.monica.test.relation".to_string(),
            payload_json: "{}".to_string(),
            payload_schema_version: 2,
        },
        MdbxWriteCommand::DeleteObjectRelation {
            relation_id: "relation-deleted".to_string(),
        },
        MdbxWriteCommand::CreateObjectLabel {
            label_id: "label-created".to_string(),
            collection_id: "project".to_string(),
            name: "Created".to_string(),
            payload_json: "{}".to_string(),
            payload_schema_version: 1,
        },
        MdbxWriteCommand::UpdateObjectLabel {
            label_id: "label-updated".to_string(),
            name: "Updated".to_string(),
            payload_json: "{}".to_string(),
            payload_schema_version: 2,
        },
        MdbxWriteCommand::DeleteObjectLabel {
            label_id: "label-deleted".to_string(),
        },
        MdbxWriteCommand::AssignObjectLabel {
            assignment_id: "assignment-created".to_string(),
            object_id: "created".to_string(),
            label_id: "label-created".to_string(),
        },
        MdbxWriteCommand::RemoveObjectLabelAssignment {
            assignment_id: "assignment-deleted".to_string(),
        },
    ];

    let changes = write_operation_changes(&commands);
    let actions = changes
        .iter()
        .map(|change| change.action.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        actions,
        vec![
            "create", "create", "update", "delete", "restore", "move", "create", "update",
            "delete", "create", "update", "delete", "create", "delete"
        ]
    );
    assert_eq!(changes[0].fields, vec!["title"]);
    assert_eq!(
        changes[1].fields,
        vec!["project_id", "entry_type", "title", "payload"]
    );
    assert_eq!(changes[2].fields, vec!["title", "payload"]);
    assert_eq!(changes[3].fields, vec!["deleted"]);
    assert_eq!(changes[4].fields, vec!["deleted"]);
    assert_eq!(changes[5].fields, vec!["project_id"]);
    assert_eq!(
        changes[6].fields,
        vec![
            "source_object_id",
            "target_object_id",
            "relation_kind",
            "payload",
            "payload_schema_version"
        ]
    );
    assert_eq!(
        changes[7].fields,
        vec!["relation_kind", "payload", "payload_schema_version"]
    );
    assert_eq!(changes[8].fields, vec!["deleted"]);
    assert_eq!(
        changes[9].fields,
        vec!["collection_id", "name", "payload", "payload_schema_version"]
    );
    assert_eq!(
        changes[10].fields,
        vec!["name", "payload", "payload_schema_version"]
    );
    assert_eq!(changes[11].fields, vec!["deleted"]);
    assert_eq!(changes[12].fields, vec!["object_id", "label_id"]);
    assert_eq!(changes[13].fields, vec!["deleted"]);
}
