# MDBX FFI

Language: [简体中文](README.zh-CN.md) | [English](README.md)

`mdbx-ffi` is the generic UniFFI boundary for non-Rust MDBX clients. It exposes the safe storage/repository facade for vault creation, unlock, projects, and generic entries, while keeping product-specific payload semantics in each client.

This crate is intentionally not a low-level SQLite API. If a client needs tags, attachments, sync, conflicts, snapshots, or diagnostics through FFI, add explicit facade methods here with tests instead of writing MDBX tables directly from the client.

## Current Scope

The exported boundary covers:

- create a vault with password unlock, defaulting to `Multi` Tiga mode
- create a vault with explicit `Sky`, `Multi`, or `Power` Tiga mode
- open a vault with password unlock
- inspect migration requirements without changing the vault and explicitly invoke the storage-core upgrade
- create a read-only pre-migration portable backup from a vault path
- create a verified, no-clobber, single-file portable backup from an open vault
- configure local security-key-material unlock on an already unlocked vault
- open a vault with local security-key material
- reset the master password on an already unlocked vault
- inspect the complete effective Tiga2 runtime policy at vault, project, or entry scope
- authorize sensitive operations with typed outcomes, reasons, and client constraints
- supply real device assurance and platform-protection capabilities
- inspect active-session activity, unlock-policy compliance, and security audit events
- apply an exact audited exception when explicitly weakening a vault profile
- configure and open password + security-key combined unlock methods
- list and remove unlock methods through authorized storage APIs
- rotate the data-key epoch through Tiga authorization and return the old epoch, new active epoch, rotation commit, and timestamp
- create projects
- register extension capabilities actually present in the client and read or set Collection Profiles
- create, list, update, soft-delete, restore, and move generic entries
- create, query, update, and delete generic relations, labels, and label assignments
- list unresolved conflicts and resolve project, entry, attachment, relation, label, and assignment conflicts with local-wins or incoming-wins
- apply validated custom payload or generic metadata conflict resolutions

The boundary does not currently expose:

- project listing or project update/delete flows
- nested folder-specific operations beyond project containers
- tags
- attachments and attachment content
- sync bundle/apply operations
- snapshots
- diagnostics and maintenance data

Treat unsupported features as missing facade methods, not permission to bypass the storage layer.

## Data Model

### Records

`VaultInfo` contains:

- `vault_id`: stable vault identifier read from `vault_meta`
- `device_id`: caller-supplied device identifier used for commit context

`MdbxBackupInfo` contains:

- `vault_id`: source and backup identity
- `format_version`: verified MDBX format generation
- `schema_version`: verified schema version
- `file_size_bytes`: published backup size

`ProjectRecord` contains:

- `project_id`
- `title`

`MdbxCollectionProfile` contains the Collection's namespaced type, versioned binary encrypted configuration, allowed ObjectTypeIds, required ExtensionCapabilityIds, and creation/update device metadata.

Call `set_extension_capabilities` before mutating a profiled Collection and declare only Adapter capabilities actually present in the current process. The declaration is not persisted and grants no key access. `set_collection_profile` establishes or advances a Profile; its CollectionTypeId is immutable. When required capabilities are absent, user-visible Project, ObjectRecord, Relation, Label, Assignment, Attachment, and conflict-resolution mutations return a storage error. Opaque reads, synchronization, and recovery remain available.

`EntryRecord` contains:

- `entry_id`
- `project_id`
- `entry_type`
- `title`
- `payload_json`
- `deleted`

`MdbxKeyEpochRotationResult` contains:

- `previous_epoch_id`: the active epoch before rotation
- `active_epoch_id`: the epoch used for subsequent field writes
- `commit_id`: the `key-rotation` / `key-epoch` commit
- `rotated_at`: the UTC rotation time

### Tiga2 Runtime Boundary

`MdbxDeviceContext` carries the device evidence used for each authorization decision. Clients must report actual platform capabilities and must not claim `TrustedHardware`, secure clipboard, screen-capture protection, or secure temporary files unless those protections are active for the operation.

Call `resolve_tiga_policy` to obtain the complete effective policy for a vault, project, or entry. Call `authorize_tiga_operation` immediately before a client-owned sensitive action. Only `Allow` and `AllowWithConstraints` permit the action. Every returned constraint must be enforced by the client; a confirmation dialog does not override `RequireFreshAuthentication`, `RequireAdditionalFactor`, or `Deny`.

Successful connection-backed authorization renews the session idle timestamp without changing the original authentication timestamp or absolute lifetime. `active_session_info`, `assess_tiga_unlock_policy`, and `list_security_audit_events` expose the state needed for client security UI without exposing credential or key material.

`set_tiga_profile` requires a non-empty reason when weakening the current baseline. The storage core creates and persists an exact scope-bound policy exception. Strengthening the profile clears an active vault-level weakening override.

Power remediation is available through `setup_password_security_key_unlock`, `list_unlock_methods`, and `remove_unlock_method`. After removing weaker standalone fallbacks, reopen with `open_vault_with_password_security_key` so the active session carries both factors.

Use `inspect_vault_migration` before opening when the client needs upgrade consent, backup, or progress UI. After consent, call `upgrade_vault`; the deterministic field conversion remains entirely inside `mdbx-storage`. The ordinary `open_vault` functions retain automatic upgrade for compatibility-oriented callers.

For client-controlled migration, call top-level `create_portable_backup(source_path, destination)` after `inspect_vault_migration` and before `upgrade_vault`. It opens the source read-only, requires no unlock credentials, retains MDBX1 or MDBX2 metadata, includes committed WAL pages, and leaves the persistent source database and WAL bytes unchanged.

Call `MdbxVault.create_backup(destination)` for an already open vault. Both interfaces verify integrity and MDBX identity and publish one file without replacing an existing destination, `-wal`, or `-shm` artifact. The backup retains the source unlock methods and reopens with the same credentials. It is separate from a vault-internal snapshot and a sync bundle; clients must not copy only the SQLite main file while WAL is active.

### Key Epoch Rotation

Call `MdbxVault.rotate_key_epoch(device)` with an active unlock session and truthful device capabilities. In one transaction, storage generates a random 32-byte epoch key, wraps it, retires the previous active epoch, activates the new epoch, creates the rotation commit, and correlates the Tiga audit event with that commit. Authorization denial or transaction failure leaves the active epoch and rotation-commit count unchanged.

After success, distribute the returned `commit_id` and its authenticated sync state to other replicas before allowing fields written under the new epoch to leave the device. Receivers should use the mutable verified-unlocked storage apply entry so active and retired wrappers are authenticated and the connection keyring is refreshed before return. Concurrent rotations retain both epochs and deterministically converge on one active epoch.

Rotation is not an ordinary idempotent operation API. If a network response is unknown, query commit history or security audit correlation before requesting another rotation. A deliberate second call is a new security-administration action and creates another epoch and commit.

### Entry Types

`entry_type` is a string parsed by `mdbx-core::model::EntryType`. Current accepted values are:

- `login`
- `note`
- `totp`
- `card`
- `identity`

Invalid values return `MdbxFfiError::InvalidEntryType`.

### Paginated Object Summaries

Use `list_object_summaries` for collection and search-result screens. It returns a bounded page containing object identity, type, title, payload schema version, head commit, and update time without reading or decrypting `payload_json`.

The opaque `next_cursor` is bound to the requested collection and optional object type. Reusing it with different filters returns an error. Page sizes must be between 1 and 200. Existing `list_objects` and `list_entries` remain available when a caller intentionally needs complete payloads.

### Payload JSON

`payload_json` must be a valid JSON string. The FFI layer validates that it parses as JSON and stores the parsed value through the storage repository APIs.

MDBX deliberately keeps the FFI entry payload generic. Clients own their product payload schema and should use explicit version/kind fields when they need stable interpretation. A typical login payload can look like:

```json
{
  "kind": "password",
  "schemaVersion": 1,
  "username": "alice@example.com",
  "password": "secret",
  "url": "https://example.com",
  "favorite": false
}
```

When an entry is returned, `payload_json` is serialized back from the stored JSON value. Do not depend on original whitespace or object key ordering being preserved.

## Error Behavior

All exported functions return `Result<_, MdbxFfiError>`.

- `Storage { message }`: storage, unlock, constraint, or repository failure
- `Serialization { message }`: invalid JSON input or invalid stored JSON
- `InvalidEntryType { entry_type }`: unknown entry type string
- `InvalidCollectionTypeId { collection_type_id }`: invalid or non-namespaced Collection type
- `InvalidExtensionCapabilityId { capability_id }`: invalid extension capability identifier
- `LockPoisoned`: the internal vault mutex was poisoned

Common constraint errors include updating a deleted entry, deleting an already deleted entry, restoring an active entry, moving a deleted entry, or using an entry ID that does not belong to the supplied project ID.

## Rust Usage Example

The Rust tests exercise the same facade that UniFFI exports:

```rust
use mdbx_ffi::{create_vault, open_vault, MdbxFfiError};

fn main() -> Result<(), MdbxFfiError> {
    let path = "/tmp/example.mdbx".to_string();
    let password = "correct horse battery staple".to_string();
    let device_id = "desktop-1".to_string();

    let vault = create_vault(path.clone(), password.clone(), device_id.clone())?;
    let project = vault.create_project("Personal".to_string())?;

    let entry = vault.create_entry(
        project.project_id.clone(),
        "login".to_string(),
        "Example".to_string(),
        r#"{"kind":"password","schemaVersion":1,"username":"alice"}"#.to_string(),
    )?;

    let entries = vault.list_entries(project.project_id.clone(), Some("login".to_string()))?;
    assert_eq!(entries[0].entry_id, entry.entry_id);

    drop(vault);
    let reopened = open_vault(path, password, device_id)?;
    assert!(!reopened.info().vault_id.is_empty());
    Ok(())
}
```

## Generating Bindings

Install the UniFFI CLI that matches the crate dependency:

```sh
cargo install uniffi --version 0.31.1 --locked --features cli
```

Build the dynamic library:

```sh
cargo build -p mdbx-ffi
```

Generate Swift bindings from the dynamic library:

```sh
uniffi-bindgen-swift --swift-sources target/debug/libmdbx_ffi.dylib ./generated
uniffi-bindgen-swift --headers target/debug/libmdbx_ffi.dylib ./generated
```

On Linux the dynamic library is `target/debug/libmdbx_ffi.so`; on Windows it is `target/debug/mdbx_ffi.dll`. Platform packaging still needs the matching static or dynamic library to be shipped with the generated bindings.

## iOS Notes

The Monica iOS workspace keeps helper scripts outside this repository. The expected packaging flow is:

- build `mdbx-ffi` for device and simulator targets
- generate Swift, header, and modulemap files with `uniffi-bindgen-swift`
- package the static libraries and generated header as an XCFramework
- include the generated Swift source and XCFramework from the Swift package or app target

Generated bindings should be treated as build artifacts. Regenerate them from this crate instead of editing generated Swift or headers by hand.

## Extending The FFI Boundary

When adding a new cross-language capability:

1. Add typed UniFFI records/enums that match client needs without leaking raw storage rows.
2. Implement the method by calling `mdbx-storage` repository/service APIs.
3. Preserve commit, object-version, tombstone, branch-head, device-head, key-epoch, conflict, snapshot, and sync-state invariants.
4. Add or update `crates/mdbx-ffi/tests/ffi_smoke.rs` to cover the exported behavior.
5. Run at least `cargo test -p mdbx-ffi`; run full `cargo test` when touching shared storage behavior.

Do not expose methods that let clients write `commits`, `commit_parents`, `object_versions`, `tombstones`, `snapshots`, `key_epochs`, `conflicts`, `device_heads`, `branches`, or `project_tags` directly.

## Verification

Run the FFI test suite from the repository root:

```sh
cargo test -p mdbx-ffi
```

The smoke tests verify vault create/open, entry round trips, update/delete/restore/move flows, security-key-material unlock, master-password reset, full Tiga2 policy and authorization mapping, exact exceptions, and Power combined-factor remediation.
