# MDBX

Language: [简体中文](README.md) | [English](README.en.md)

This directory contains the Rust workspace and implementation notes for Monica MDBX.

MDBX is Monica's local-first encrypted vault format. It is designed around stable long-term storage, Git-like logical history, sync conflict handling, native attachments, snapshots, and Tiga security modes.

For the normative format documents, see `docs/`.

The MDBX rule is **4ever And 4ever**: old vaults must remain readable, compatibility paths must be preserved whenever possible, and data safety comes before convenience.

## Workspace Layout

- `crates/mdbx-core`
  - Core domain types.
- `crates/mdbx-crypto`
  - Encryption, KDF, and key material handling.
- `crates/mdbx-sync`
  - Sync payload and object payload model.
- `crates/mdbx-storage`
  - SQLite schema, vault initialization, repositories, search, snapshots, conflicts, recovery, and sync state.
- `crates/mdbx-ffi`
  - Generic UniFFI boundary exposing vault, project, and generic entry operations; client-specific payload semantics remain owned by each client.
- `crates/mdbx-cli`
  - CLI entry point for local testing and development.
- crate-local `tests/`
  - Compatibility, crypto-vector, concurrency, and recovery scenarios live beside the crates they validate.

## Documents In This Directory

- `CLIENT_INTEGRATION_GUIDE.md`
  - English guide for implementing MDBX support in another client.
- `CLIENT_INTEGRATION_GUIDE.zh-CN.md`
  - Chinese guide for implementing MDBX support in another client.
- `crates/mdbx-ffi/README.md` / `crates/mdbx-ffi/README.zh-CN.md`
  - UniFFI boundary reference for non-Rust clients.
- `android/README.md` / `android/README.zh-CN.md`
  - Current Monica for Android MDBX 1.0 integration structure, working-copy model, Room indexes, and future FFI migration notes.

## Specification Documents

Read the spec set in `docs/` before changing storage behavior:

- `docs/README.md` / `docs/README.zh-CN.md`
- `docs/01-product-spec.md`
- `docs/02-storage-sync-spec.md`
- `docs/03-security-spec.md`
- `docs/06-sqlite-schema-v1.zh-CN.md`

The `docs/` directory defines the format and product constraints. The Rust workspace implements those constraints and documents practical integration.

## Client Support Levels

MDBX support should be labeled honestly:

- **Read-only support**
  - Open and unlock a vault.
  - Display folders, entries, and attachment metadata.
  - Do not write tables, commits, tombstones, snapshots, or conflicts.
- **Basic read/write support**
  - Create and edit entries and folders.
  - Preserve commits, object versions, tombstones, snapshots, branch heads, and device heads.
- **Sync support**
  - Merge commit DAGs, preserve tombstones, detect conflicts, and apply sync state safely.
- **Full Monica-compatible support**
  - Provide the required management screens, diagnostics, snapshot structure preview, field-level history, and folder-aware move/copy/create flows.

See `CLIENT_INTEGRATION_GUIDE.md` for the complete checklist.

## Required User-Facing Management Screens

A full user-facing client should include:

- MDBX format-management home
- database detail page
- folder / structure management
- move / copy target picker
- conflict management
- commit history
- snapshots
- snapshot structure preview
- diagnostics / maintenance
- unlock and security

The format-management entry should always land on the MDBX management home. It should not automatically enter the last opened vault detail page.

Normal users should not see raw developer tools such as sync bundle import/export, benchmarks, or low-level chunk debugging. Keep those behind developer mode.

## Development Commands

From this directory:

```powershell
cargo test
```

Run the CLI during local development:

```powershell
cargo run -p mdbx-cli -- --help
```

The current `mdbx-cli` is a development and validation entry point for this Rust workspace. It covers:

- `init` / `unlock`
- basic project, entry, and attachment CRUD
- `snapshot create/list/restore`
- `sync bundle/apply`
- `health`
- `benchmark`
- `import-kdbx-json` / `export-kdbx-json`

Note: `import-kdbx-json` / `export-kdbx-json` use a KDBX interoperability JSON intermediate representation. They are not full binary `.kdbx` parsing or writing. Once a vault has unlock methods configured, normal CLI operations must pass `--unlock-password` or `--unlock-pin`; otherwise the command is rejected so production writes do not silently fall back to the legacy plaintext compatibility path.

The current CLI does not yet implement real FIDO/WebAuthn/security-key interaction, production session tokens, or audit policy. Security-key support in storage core is a key-material abstraction with policy tests, not an end-to-end hardware-key client.

`mdbx-ffi` provides a generic UniFFI boundary for non-Rust clients that need MDBX core read/write operations. It is not a low-level SQL escape hatch around the storage/repository rules; new cross-client capabilities should extend the FFI facade instead of writing tables directly.

For exported methods, JSON payload rules, binding generation, iOS packaging notes, and extension rules, see `crates/mdbx-ffi/README.md`.

Key capabilities currently verified in the Rust storage core:

- Snapshots include and restore active `attachment_chunks`; older metadata-only snapshots remain compatible.
- Entry, project, and attachment rows are recorded in `object_versions` for divergent three-way merge.
- Different-field concurrent entry/project changes write a two-parent merge commit; same-field changes create unresolved conflicts.
- Attachment metadata can merge at field level; concurrent content replacement keeps the local content and records a `content_hash` conflict.
- Entry, project, and attachment conflict resolution now has repository write-back APIs. Resolving a conflict writes a merge commit, updates the object head, records an object version, and then marks the conflict resolved. Attachment incoming-wins never fabricates remote content when the bytes are not locally available.
- High-risk user-visible project, entry, and attachment mutations are wrapped in atomic transactions so commits, object rows, heads, and object versions succeed or roll back together.
- `project_tags` are included in sync state. New payloads carry the complete tag set for each project, while old payloads that lack the tag field do not clear local tags. User-visible tag changes should use tracked tag APIs; temporary session search indexes do not enter history.
- Initial key epochs use a random `mdbx-init-marker-v1` marker; configuring or changing an unlock method binds `mdbx-active-key-epoch-v1` active epoch wrapping. Full key rotation / retirement remains future work.

## Implementation Rules

Do not bypass repository/storage APIs from client code unless you are changing the storage layer itself.

Compatibility and recovery are implementation requirements, not polish. New encryption envelopes, tables, indexes, unlock methods, and Tiga policies must keep old vault readability unless a critical security issue requires a deliberate migration.

Client code should not directly write:

- `commits`
- `commit_parents`
- `object_versions`
- `tombstones`
- `snapshots`
- `key_epochs`
- `conflicts`
- `device_heads`
- `branches`
- `project_tags`

Batch user operations should normally produce one user-level commit, not one commit per object.

Android and other clients should use repository/storage APIs for entry/project/attachment CRUD, tracked tag changes, and conflict resolution. Do not only update `conflicts.resolution`, and do not edit `project_tags` directly while skipping commits and sync state.

For the current Monica for Android integration reference, see `android/README.md`.

## Compatibility Checklist

Before claiming full support, a client should verify:

- Monica-created MDBX vaults open correctly.
- Nested folders can be created and selected as targets.
- Batch move/copy/delete creates coalesced commits.
- Tombstones prevent deleted objects from reappearing.
- Two clients show the same item count for the same vault.
- Conflicts are detected and displayed.
- Snapshots can be created and reverted with confirmation.
- Diagnostics expose sync, health, history, tombstone, attachment, and dangling-head status.
