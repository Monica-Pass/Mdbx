# MDBX2 Compatibility and Migration Specification

Version: `MDBX-2`

MDBX2 is the second MDBX format generation. It preserves the **4ever And 4ever** rule through ordered, additive, and transactional migration.

## Compatibility Contract

- MDBX2 implementations MUST read and upgrade `MDBX-1` and `MDBX-1-DRAFT` vaults.
- Migration MUST preserve stable IDs, ciphertext, commit history, object versions, tombstones, snapshots, key epochs, and attachment content.
- A failed migration MUST leave the original format marker and data unchanged.
- Schema migration MUST NOT implicitly rotate keys or re-encrypt the entire vault.
- Unknown formats or critical extensions MUST prevent writable open.

MDBX2 guarantees that the new reader understands the previous generation. Already released old binaries cannot safely write arbitrary future semantics; upgraded vaults therefore declare `min_writer_version = MDBX-2`.

## MDBX2 Metadata

An upgraded vault records:

```text
format_version     = MDBX-2
schema_version     = 4
min_reader_version = MDBX-1
min_writer_version = MDBX-2
tiga_policy_version = 2
```

`schema_migrations` records each ordered migration exactly once.

## Automatic Upgrade

On writable open, MDBX2 reads format metadata, rejects unsupported critical extensions, starts an immediate transaction, applies additive schema changes, records the migration, validates the result, and updates `format_version` last. Reopening an upgraded vault is idempotent.

Tiga1 profiles are mapped to Tiga policy version 2 in the same transaction. Existing weaker project or entry profiles become deterministic remediation exceptions. An unlock configuration that does not yet satisfy the new profile is marked `remediation-required`; migration never rewrites KDF parameters or wrapped vault-key bytes and does not deny access solely because remediation is pending.

Early MDBX2 vaults with schema versions 2 or 3 upgrade in place to schema version 4 without changing the `MDBX-2` format marker. Schema 4 adds operation-level commit metadata and atomic per-device sequence state while retaining the original `commits` table and DAG as the MDBX1-compatible projection.

Future generations MUST migrate sequentially. For example, MDBX3 opening MDBX-1 executes `MDBX-1 -> MDBX-2 -> MDBX-3`.

## MDBX2 Consistency Changes

- Snapshot creation and restore are atomic.
- Restore recreates the exact active set while retaining post-snapshot rows as tombstoned history.
- Restored objects receive one causal restore head and object-version records.
- New snapshots include project tags and attachment chunks without clearing fields absent from legacy snapshots.
- Tiga mutations atomically update commits, rows, heads, and object versions.
- Tiga2 policy state, scoped overrides, exact exceptions, and typed audit events are synchronized. Concurrent policy conflicts merge toward the stricter value.
- Commit2 adds idempotent operation IDs, typed change summaries, branch-aware heads, merged vector clocks, and atomic device sequence allocation without rewriting historical commits.
- Sync protocol and offline bundles use version 2 for operation metadata; MDBX2 readers still convert version 1 bundles with no operation metadata.
- CLI bundle application delegates to `mdbx-storage::SyncApplyRepo`; the duplicate CLI SQL apply engine was removed.

## Client/Core Boundary

Clients own upgrade prompts, backup placement, progress UI, platform capability evidence, and remediation interactions. The storage core owns format detection, deterministic conversion, transactions, rollback, idempotence, and validation. Clients must not reimplement the MDBX1-to-MDBX2 field mapping.

### Client-Controlled Migration APIs

The compatibility path `VaultConnection::open` continues to upgrade automatically so simple callers remain generation-compatible. A client that needs consent, backup, and progress orchestration should first call the read-only `mdbx_storage::migration::inspect_migration_path` (or the UniFFI `inspect_vault_migration` function). The result reports the current format/schema, minimum reader/writer generations, whether an upgrade is required, and whether critical extensions are unknown.

After the client has obtained consent and completed its backup workflow, it can call `mdbx_storage::migration::upgrade_path` (or UniFFI `upgrade_vault`). The same storage-core transactional migrator performs the conversion. Clients own prompts and progress, never a second MDBX1 field-mapping implementation. Unknown critical extensions may be inspected and shown in read-only UI, but explicit upgrade still refuses to write.

### Client Operation Write API

Mobile and desktop clients should submit multi-step edits through the UniFFI `MdbxVault::execute_write_operation` method. The boundary accepts a finite typed command set for project creation and entry create, update, delete, restore, and move operations; it never exposes SQL.

Every create command carries a client-generated stable UUID. The client reuses the same `operation_id` and complete command list for the initial call and retries. Storage executes the command list as one transaction and one commit. A completed operation retry returns the commit ID and the object IDs from the request without running mutations again. Reusing an operation ID with different command content is rejected, and failure of any command rolls back the entire batch.

The existing single-mutation FFI methods remain available as the MDBX1-compatible projection and simple-call entry points. A client action that must appear as one history node should use the operation API.

### Commit History Read API

Clients page through history with `MdbxVault::list_commit_history` using the returned keyset cursor and fetch one detail with `get_commit_history`. Results include operation metadata, branch, parents, typed change summaries, and a compatibility flag; MDBX1 commits without operation metadata remain visible through a compatibility summary. Clients must treat the storage-returned cursor as opaque and must not recreate pagination with offsets.
