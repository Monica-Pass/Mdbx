# MDBX FFI

Language: [简体中文](README.zh-CN.md) | [English](README.md)

`mdbx-ffi` is the generic UniFFI boundary for non-Rust MDBX clients. It exposes the safe storage/repository facade for vault creation, unlock, projects, and generic entries, while keeping product-specific payload semantics in each client.

This crate is intentionally not a low-level SQLite API. If a client needs tags, attachments, sync, conflicts, snapshots, or diagnostics through FFI, add explicit facade methods here with tests instead of writing MDBX tables directly from the client.

## Current Scope

The exported boundary covers:

- create a vault with password unlock, defaulting to `Multi` Tiga mode
- create a vault with explicit `Sky`, `Multi`, or `Power` Tiga mode
- open a vault with password unlock
- configure local security-key-material unlock on an already unlocked vault
- open a vault with local security-key material
- reset the master password on an already unlocked vault
- create projects
- create, list, update, soft-delete, restore, and move generic entries

The boundary does not currently expose:

- project listing or project update/delete flows
- nested folder-specific operations beyond project containers
- tags
- attachments and attachment content
- sync bundle/apply operations
- snapshots
- conflicts and conflict resolution
- diagnostics and maintenance data

Treat unsupported features as missing facade methods, not permission to bypass the storage layer.

## Data Model

### Records

`VaultInfo` contains:

- `vault_id`: stable vault identifier read from `vault_meta`
- `device_id`: caller-supplied device identifier used for commit context

`ProjectRecord` contains:

- `project_id`
- `title`

`EntryRecord` contains:

- `entry_id`
- `project_id`
- `entry_type`
- `title`
- `payload_json`
- `deleted`

### Entry Types

`entry_type` is a string parsed by `mdbx-core::model::EntryType`. Current accepted values are:

- `login`
- `note`
- `totp`
- `card`
- `identity`

Invalid values return `MdbxFfiError::InvalidEntryType`.

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

The smoke tests verify vault create/open, entry round trips, update/delete/restore/move flows, security-key-material unlock, master-password reset, and explicit Tiga mode creation.
