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
schema_version     = 15
min_reader_version = MDBX-1
min_writer_version = MDBX-2
tiga_policy_version = 2
```

`schema_migrations` records each ordered migration exactly once.

## Automatic Upgrade

On writable open, MDBX2 reads format metadata, rejects unsupported critical extensions, starts an immediate transaction, applies additive schema changes, records the migration, validates the result, and updates `format_version` last. Reopening an upgraded vault is idempotent.

Tiga1 profiles are mapped to Tiga policy version 2 in the same transaction. Existing weaker project or entry profiles become deterministic remediation exceptions. An unlock configuration that does not yet satisfy the new profile is marked `remediation-required`; migration never rewrites KDF parameters or wrapped vault-key bytes and does not deny access solely because remediation is pending.

Early MDBX2 vaults with schema versions 2 or 3 upgrade in place to schema version 4 without changing the `MDBX-2` format marker. Schema 4 adds operation-level commit metadata and atomic per-device sequence state while retaining the original `commits` table and DAG as the MDBX1-compatible projection. Schema 4 vaults then upgrade additively to schema 5, which adds nullable Tiga audit correlation and policy-evidence fields. Existing audit rows remain valid with null values. Schema 5 vaults upgrade additively to schema 6, which adds a nullable `commit_operations.branch_id` and its lookup index. Existing operation rows retain a null branch ID because their V1 request hashes and integrity tags authenticate only `branch_name`.

Schemas 6 through 11 continue as ordered additive migrations. Schema 7 adds generic relations, labels, and assignments; schema 8 adds tombstone delete proof and device acknowledgements; schema 9 adds permanent purge receipts; schema 10 adds Attachment Tiga scopes; schema 11 adds one-to-one Collection Profiles. These migrations preserve the physical `projects` and `entries` tables and the legacy public interfaces.

Schema 10's policy-table rebuild also carries forward bounded, additive columns that are not known to the current reader when their definitions are nullable or have safe literal defaults. Unsupported definitions fail the transaction before the old tables are replaced, so a non-critical field is never silently discarded.

Schema 12 adds a local stable commit inventory whose migration preserves commit identity and backfills parent-before-child order. Schema 13 adds the state-delta batch inventory, its normalized commit associations, bounded versioned envelope rules, and a bootstrap floor fixed at the migration commit watermark. Schema 14 adds transaction-local logical mutation capture for every synchronized core state family. Before each outer write transaction commits, MDBX deduplicates those keys, materializes a bounded state body, and stores either a commit-associated or auxiliary batch atomically with the domain rows. Bootstrap mutations generated while creating or upgrading a vault are discarded in the same transaction because their state is covered by the floor. Historical deltas are not invented during migration; checkpoints before the floor continue to require bounded complete-state bootstrap.

Schema 15 adds `sync_state_extensions` for bounded unknown top-level complete-state fields. Apply upserts only keys present in the incoming state, in the same transaction as the commit and domain rows. A missing key never means deletion, so an older peer cannot erase a future extension merely by omitting it. Collection restores stored values in key order, and migration plus current-schema validation enforce 256 fields, 128-byte keys, a 64 KiB aggregate budget, and the existing nesting-depth limit.

The storage core treats each extension value as opaque JSON: it validates, stores, and forwards the value but does not interpret or decrypt it. Opaque does not mean automatically encrypted. Non-secret capability or version metadata may use ordinary JSON; any value containing passwords, mail content, tokens, or other sensitive material MUST be an authenticated ciphertext envelope produced before it enters the unknown extension. This contract lets a locked older reader preserve future sensitive state without creating plaintext itself.

The storage apply path recognizes authenticated `mdbx-storage/state-delta-v1` object payloads. A commit-associated envelope must be carried by its final associated commit, every referenced commit must be available, and the commit, sparse state rows, device heads, authorized deletions, received batch, and capture cleanup succeed or roll back together. Fast-forward, divergent, and late-payload repair paths share this boundary. Bundle v4 and its compressed v6 representation, plus their authenticated v8/v10 envelopes, apply commit-associated and auxiliary batches in one outer transaction, so a failed tail batch rolls back the complete segment without creating user-visible commits. These additions do not change the `projects`, `entries`, commit DAG, sync-state v1-v2, or bundle v1-v6 formats.

The CLI uses bounded complete state for bootstrap and bundle v4 after a paired commit/delta checkpoint. A partial v4/v6/v8/v10 transfer stores its transfer ID, next segment index, and previous logical payload digest in the checkpoint file; authentication and compression do not change that logical SHA-256 identity. Legacy checkpoint JSON without resume fields remains readable. The transport-neutral synchronization client selects v4 semantics only when both peers advertise commit paging, delta paging, bundle v4, and resume; paging-capable Hello messages omit the legacy complete commit-ID vector. Zstd is negotiated separately through `bundle-zstd-v1`. Keyed transport authentication is independently negotiated through `authenticated-bundle-v1`; it is intentionally not a fifth incremental requirement. Old or partially capable peers therefore retain bounded complete-state and v1-v6 fallback behavior.

Authenticated complete/incremental envelopes use versions 7/8, while their zstd representations use versions 9/10. Their existing logical payload SHA-256 trailer is followed by HMAC-SHA-256 keyed with the vault integrity subkey. The tag binds a versioned domain, magic, version, the bounded 20-byte header area, and the logical payload digest. The key is never stored in or transported with the bundle. This proves that the envelope was produced by a holder of the shared vault key and binds its metadata; it does not identify a particular device, encrypt the transport, replace inner field/delta encryption, or make a bundle safe to disclose. CLI export remains legacy v3/v4 by default, writes v5/v6 only with `--compression zstd`, and selects v7-v10 only with explicit `--authenticated`. CLI apply supplies the opened vault key automatically and continues to read v1-v6.

The implemented `IncrementalIntegrityRoot` profile is additive and intentionally
separate from the bundle capability. It keeps schema 16 unchanged and creates
its metadata, leaf, and sparse-node tables only after explicit verified-unlocked
opt-in. Establishment records `authenticated-state-root-v1` as a critical
extension, so a pre-profile MDBX2 writer rejects the vault before writable open.
The root updates in the same outer transaction as sync-delta capture. Without
that opt-in, current and legacy vault behavior is unchanged. The O(vault-size)
content manifest remains the exact schema checkpoint; external Provider bytes
and unregistered physical extension tables are not silently claimed by the
incremental root.

Protocol-v2 root exchange is additive: Hello and HelloAck omit the checkpoint
unless `authenticated-state-root-v1` is configured and both peers provide a
bounded checkpoint. Legacy JSON remains unchanged, and the capability is not
added to the four mandatory incremental-sync capabilities. Storage, not the
transport parser, authenticates the checkpoint under the vault integrity key
and checks per-peer monotonic generation and inventory anchors. Clients retain
the last verified remote value outside the vault; local and remote root hashes
are not required to match because inventory order can differ across replicas.

Future generations MUST migrate sequentially. For example, MDBX3 opening MDBX-1 executes `MDBX-1 -> MDBX-2 -> MDBX-3`.

### Release Golden Vault and Old Reader Boundary

The repository freezes both `crates/mdbx-storage/test-data/mdbx1-release-1.0.mdbx` and `mdbx1-draft-golden.mdbx`. The release fixture was generated by the historical `MDBX1.0` tag at commit `1a43fa9e8e87eebf6d0e1b84543c3291d0b25142`; the DRAFT fixture was derived by that same historical reader changing only `vault_meta.format_version` before checkpointing. Each manifest records the immutable SHA-256, test-only unlock credential, and stable project, entry, attachment, and snapshot IDs.

The shared migration regression runs against both exact byte sequences, verifies that inspection is read-only, upgrades schema 1 to the current schema, unlocks with the original MDBX1 credential, and compares the legacy commit and object-version identities before and after. It also verifies project metadata, entry payload, project tags, inline attachment bytes, snapshot identity, and repeated-upgrade idempotence.

As an additional release-binary observation, the `MDBX1.0` CLI successfully listed the project and entry from a copy already upgraded by the current reader. This demonstrates that the MDBX1 physical projection remains readable. It does not make the old binary a safe MDBX2 writer: old code does not enforce `min_writer_version`, cannot preserve future semantics, and MUST NOT be used for writes once the vault declares `min_writer_version = MDBX-2`.

## MDBX2 Consistency Changes

- Snapshot creation and restore are atomic.
- Restore recreates the exact active set while retaining post-snapshot rows as tombstoned history.
- Restored objects receive one causal restore head and object-version records.
- New snapshots include project tags and attachment chunks without clearing fields absent from legacy snapshots.
- Verified-unlocked snapshots use the `MDBXSN2` payload profile and a versioned
  HMAC descriptor that binds their base commit and row metadata. Existing
  64-hex SHA snapshots retain their original AAD and restore semantics. The
  first new-profile snapshot registers `snapshot-record-auth-v1`, so an older
  MDBX2 reader rejects the unknown critical extension rather than silently
  applying legacy decryption rules.
- Tiga mutations atomically update commits, rows, heads, and object versions.
- Tiga2 policy state, scoped overrides, exact exceptions, and typed audit events are synchronized. Concurrent policy conflicts merge toward the stricter value.
- Authorized Tiga mutations record the exact Commit2 `operation_id` and `commit_id` in the same transaction. Rejected decisions and non-mutating disclosures have no commit association.
- New audit events record the Tiga policy version and a SHA-256 fingerprint of the resolved policy used for the decision. The evidence is captured before a policy mutation changes the active policy.
- Audit synchronization authenticates the new fields, verifies that the operation and commit identify the same `commit_operations` row, and rejects immutable-event rewrites. MDBX1 and early MDBX2 audit rows retain null correlation and evidence fields.
- Commit2 adds idempotent operation IDs, typed change summaries, stable branch identity, merged vector clocks, and atomic device sequence allocation without rewriting historical commits.
- Offline sync bundle version 3 adds an explicit payload length and bounded decoding. MDBX2 readers continue to convert version 1 bundles without operation metadata and read version 2 bundles with operation metadata.
- Offline sync bundle version 4 adds paired incremental inventories, authenticated base validation, bounded resumable segments, and atomic commit-plus-auxiliary application while preserving the version 1-3 readers.
- Offline sync bundle versions 5 and 6 add optional bounded zstd representations for complete v3 and incremental v4 logical payloads. Their trailers hash the uncompressed bincode payload, both declared lengths are independently bounded, and feature-trimmed builds retain v1-v4 while explicitly rejecting v5/v6.
- Offline sync bundle versions 7 and 8 add keyed HMAC-SHA-256 envelopes for complete and incremental payloads; versions 9 and 10 combine the same authentication contract with zstd. The authentication trailer binds the versioned bounded header and logical payload digest, while the digest remains stable for incremental resume. Readers retain v1-v6, and authenticated versions fail closed without the matching vault integrity key.
- CLI bundle application delegates to `mdbx-storage::SyncApplyRepo`; the duplicate CLI SQL apply engine was removed.
- Storage accepts bounded authenticated state-delta payloads atomically, persists received batches for forwarding, preserves sparse local tombstones, and merges device revocation monotonically. Complete-state payloads remain supported and cannot be mixed with a delta on one commit.
- Unknown complete-state extensions survive decode, transactional apply, storage, collection, and re-encoding. Present keys update atomically; absent keys preserve the local value.
- Portable backup uses SQLite online backup so committed WAL pages are included, verifies SQLite and MDBX metadata plus `vault_id`, converts the result to a sidecar-independent file, and refuses to replace any destination artifact.

## Client/Core Boundary

Clients own upgrade prompts, backup placement, progress UI, platform capability evidence, and remediation interactions. The storage core owns format detection, deterministic conversion, transactions, rollback, idempotence, and validation. Clients must not reimplement the MDBX1-to-MDBX2 field mapping.

### Portable Backup API

Clients use `BackupService::create_portable_copy_path` through Rust or top-level UniFFI `create_portable_backup` before writable open. The result reports vault identity, preserved format, preserved schema, and file size. The reference CLI exposes this read-only path as `mdbx backup <output>` without requiring unlock credentials.

`MdbxVault.create_backup` remains the operational backup API for an already opened vault. The path API is the pre-migration archive seam: it accepts supported MDBX1, MDBX1 draft, and MDBX2 files, includes committed WAL pages, and publishes a single file with source format metadata unchanged.

A portable backup is a complete encrypted vault file and retains the source unlock methods. It does not decrypt records. A vault-internal snapshot remains a logical recovery point, while a sync bundle remains an incremental transport artifact. Direct copying of the SQLite main file is invalid while WAL may contain committed frames.

The destination path, `-wal`, and `-shm` names are reserved as one publication set. Existing artifacts are never replaced. Storage verifies integrity, source-equivalent MDBX metadata, and vault identity before publishing the single-file result.

### Epoch-Tagged Field Ciphertext

New field ciphertext written by an officially unlocked connection uses this outer format:

```text
MDBXFE2\0 || epoch_id_len_u16_le || epoch_id_utf8 || MDBXAE1 committed AEAD
```

The inner AEAD uses the record, attachment, metadata, or history subkey for the identified epoch. Length-prefixed AAD authenticates the domain, epoch ID, object type, object ID, and field name. Changing the outer epoch ID, moving ciphertext to another field, or modifying the inner ciphertext fails authentication.

Readers continue to accept existing `MDBXAE1` committed envelopes and earlier nonce envelopes. Before publishing the first `MDBXFE2` field, storage records the critical extension `field-key-epochs-v1` in the same database transaction. Current readers recognize it. Older MDBX2 writers treat it as an unknown critical extension and reject writable open, preventing writes that apply legacy key-selection rules to the new field format.

### Stable Branch Identity

`branch_id` is the immutable internal identity of a branch. `branch_name` is a mutable display attribute and a compatibility selector for interfaces created before schema 6. Multiple branches may have the same display name.

New operation metadata authenticates both the stable ID and the display name recorded at commit time. ID-based requests select exactly one branch and remain retryable after a display-name change. A name-only request is accepted only when the name identifies exactly one branch. Existing operation rows with a null ID continue to use the V1 request-hash and integrity algorithms; migration does not infer or write IDs into those rows.

Synchronization compares branch IDs when both peers provide them. If either peer omits the ID, comparison falls back to the legacy name. The same ID with different names represents one branch, while the same name with different IDs represents separate branches. Serialized branch heads and operation metadata accept a missing `branch_id` for older peers.

### Client-Controlled Migration APIs

The compatibility path `VaultConnection::open` continues to upgrade automatically so simple callers remain generation-compatible. A client that needs consent, backup, and progress orchestration first calls the read-only `mdbx_storage::migration::inspect_migration_path` or UniFFI `inspect_vault_migration`. When upgrade is required, it next calls `BackupService::create_portable_copy_path` or UniFFI `create_portable_backup`. Only after backup publication and consent does it call explicit upgrade. The inspection result reports the current format/schema, minimum reader/writer generations, whether an upgrade is required, and whether critical extensions are unknown.

After the client has obtained consent and completed its backup workflow, it can call `mdbx_storage::migration::upgrade_path` (or UniFFI `upgrade_vault`). The same storage-core transactional migrator performs the conversion. Clients own prompts and progress, never a second MDBX1 field-mapping implementation. Open and explicit upgrade repeat the read-only identity preflight before acquiring a writable handle; missing paths, uninitialized SQLite databases, and unknown critical extensions are rejected without modification.

### Client Operation Write API

Mobile and desktop clients should call `MdbxVault::list_branches` to obtain stable IDs and submit branch-specific multi-step edits through `execute_write_operation_on_branch`. The original `execute_write_operation` method remains available as the main-branch compatibility entry point. The boundary accepts a finite typed command set for project creation and entry create, update, delete, restore, and move operations; it never exposes SQL.

Every create command carries a client-generated stable UUID. The client reuses the same `operation_id` and complete command list for the initial call and retries. Storage executes the command list as one transaction and one commit. A completed operation retry returns the commit ID and the object IDs from the request without running mutations again. Reusing an operation ID with different command content is rejected, and failure of any command rolls back the entire batch.

The existing single-mutation FFI methods remain available as the MDBX1-compatible projection and simple-call entry points. A client action that must appear as one history node should use the operation API.

### Commit History Read API

The original `MdbxCommitHistoryItem`, `list_commit_history`, and `get_commit_history` interfaces remain unchanged for generated clients from the previous interface generation. MDBX2 clients use `MdbxCommitHistoryItemV2`, `list_commit_history_v2`, and `get_commit_history_v2` to read the optional stable branch ID. Results include operation metadata, branch, parents, typed change summaries, and a compatibility flag; MDBX1 commits without operation metadata remain visible through a compatibility summary. Clients must treat the storage-returned keyset cursor as opaque and must not recreate pagination with offsets.

Operation summaries use `create`, `update`, `delete`, `restore`, `move`, or the compatibility `change` action, with stable domain field names. Repository-generated generic `change` records are placeholders and never overwrite a more specific client-provided summary.

### Tiga Audit Read API

The existing UniFFI `MdbxSecurityAuditEvent` record and `list_security_audit_events` method remain unchanged for generated clients from the previous interface generation. MDBX2 clients use `MdbxSecurityAuditEventV2` and `list_security_audit_events_v2` to read optional operation ID, commit ID, policy version, and policy fingerprint fields.

A present `commit_id` always requires a matching `operation_id`. Storage validates the pair against `commit_operations` on local reads and synchronization. A null pair means that the event predates schema 5 or represents a decision that produced no database commit.

### Key Epoch Rotation API

MDBX2 clients request rotation through Rust `KeyEpochService::rotate_authorized` or UniFFI `MdbxVault.rotate_key_epoch`. The returned `previous_epoch_id`, `active_epoch_id`, `commit_id`, and `rotated_at` are the stable result of one rotation. This is an additive interface and does not change any MDBX1-compatible method signature.

Rotation does not use ordinary operation-idempotency retries. When a response is unknown, inspect commit history or `MdbxSecurityAuditEventV2` commit correlation before calling again; another call creates another epoch and commit. The key epoch field in sync payloads remains optional, so older payloads continue to deserialize and preserve local epoch state.

### Exact Vault Content Manifest

Clients that need an exact content checkpoint, rather than only an append-only
watermark, can use `VaultContentManifestService::issue/verify`, the CLI
`mdbx content-manifest create/verify` commands, or the UniFFI
`MdbxVault.create_content_manifest` and `verify_content_manifest` methods. The
bounded opaque token covers non-internal schema objects, column definitions,
and typed values from every main table, including unknown extension tables and
additive columns.

New tokens use manifest profile v2. V2 includes generated and hidden columns
through SQLite `table_xinfo`, adds canonical typed ordering for nullable or
collation-tied rows, and reads authenticated header metadata, vault identity,
and content from one snapshot. Verification remains profile-aware and accepts
previously issued v1 tokens with the original v1 algorithm. The token stays
opaque at the CLI and UniFFI boundaries, so clients do not need a signature or
storage-format migration.

This is an explicit O(vault-size) checkpoint for backup publication, migration
completion, device handoff, or suspected direct rewriting; it is not part of
the routine small-mutation commit path. Any legitimate write invalidates the
old token and requires client-side reissuance. External Blob Provider bodies,
OS state, and availability remain outside the manifest, and the operation does
not change MDBX1/MDBX1-DRAFT reading or migration semantics.
