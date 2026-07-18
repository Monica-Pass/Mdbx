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
schema_version     = 3
min_reader_version = MDBX-1
min_writer_version = MDBX-2
tiga_policy_version = 2
```

`schema_migrations` records each ordered migration exactly once.

## Automatic Upgrade

On writable open, MDBX2 reads format metadata, rejects unsupported critical extensions, starts an immediate transaction, applies additive schema changes, records the migration, validates the result, and updates `format_version` last. Reopening an upgraded vault is idempotent.

Tiga1 profiles are mapped to Tiga policy version 2 in the same transaction. Existing weaker project or entry profiles become deterministic remediation exceptions. An unlock configuration that does not yet satisfy the new profile is marked `remediation-required`; migration never rewrites KDF parameters or wrapped vault-key bytes and does not deny access solely because remediation is pending.

Early MDBX2 vaults with schema version 2 upgrade in place to schema version 3 without changing the `MDBX-2` format marker.

Future generations MUST migrate sequentially. For example, MDBX3 opening MDBX-1 executes `MDBX-1 -> MDBX-2 -> MDBX-3`.

## MDBX2 Consistency Changes

- Snapshot creation and restore are atomic.
- Restore recreates the exact active set while retaining post-snapshot rows as tombstoned history.
- Restored objects receive one causal restore head and object-version records.
- New snapshots include project tags and attachment chunks without clearing fields absent from legacy snapshots.
- Tiga mutations atomically update commits, rows, heads, and object versions.
- Tiga2 policy state, scoped overrides, exact exceptions, and typed audit events are synchronized. Concurrent policy conflicts merge toward the stricter value.
- CLI bundle application delegates to `mdbx-storage::SyncApplyRepo`; the duplicate CLI SQL apply engine was removed.

## Client/Core Boundary

Clients own upgrade prompts, backup placement, progress UI, platform capability evidence, and remediation interactions. The storage core owns format detection, deterministic conversion, transactions, rollback, idempotence, and validation. Clients must not reimplement the MDBX1-to-MDBX2 field mapping.

### Client-Controlled Migration APIs

The compatibility path `VaultConnection::open` continues to upgrade automatically so simple callers remain generation-compatible. A client that needs consent, backup, and progress orchestration should first call the read-only `mdbx_storage::migration::inspect_migration_path` (or the UniFFI `inspect_vault_migration` function). The result reports the current format/schema, minimum reader/writer generations, whether an upgrade is required, and whether critical extensions are unknown.

After the client has obtained consent and completed its backup workflow, it can call `mdbx_storage::migration::upgrade_path` (or UniFFI `upgrade_vault`). The same storage-core transactional migrator performs the conversion. Clients own prompts and progress, never a second MDBX1 field-mapping implementation. Unknown critical extensions may be inspected and shown in read-only UI, but explicit upgrade still refuses to write.
