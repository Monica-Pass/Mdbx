# MDBX Storage And Sync Specification

Version: `MDBX-1-DRAFT`

This document defines the single-file container strategy, internal persistence rules, incremental update behavior, sync model, and attachment storage behavior.

## 1. Container Strategy

MDBX SHOULD use a single portable `.mdbx` file as the user-visible vault artifact.

Inside the `.mdbx` file, the preferred engine is:

- `SQLite + custom encryption layer`

`LMDB` MAY be explored later, but SQLite is the preferred baseline because of tooling maturity, portability, recovery tooling, and schema evolution support.

### Vault Creation Lifecycle

Vault creation MUST atomically reserve a path that does not exist. An existing regular file, SQLite database, MDBX vault, or same-name SQLite WAL/SHM sidecar MUST be rejected without changing its contents. A client-side existence check may improve the error message, but the storage reservation remains authoritative.

Creation remains pending until schema creation, vault metadata, the genesis commit, the initial branch, the device head, the initial key epoch, and the first unlock method have all succeeded. Failure before that point MUST close the SQLite connection and remove the main database plus any WAL and SHM sidecars created by the same attempt. Opening or upgrading an established vault uses the open and migration interfaces, never the create interface.

### Existing Vault Open Lifecycle

Open and explicit upgrade MUST first inspect the file through a read-only SQLite handle. The preflight must confirm an initialized `vault_meta` row, a supported MDBX format generation, and the absence of unknown critical extensions before any writable handle, WAL mode change, migration, or compatibility cleanup is allowed.

The writable handle MUST use read-write flags without SQLite create permission. A missing path or an uninitialized SQLite database is an error and must remain unchanged. Connection-only settings such as foreign-key enforcement and busy timeout may be applied before migration; persistent WAL and secure-delete settings plus legacy plaintext-index cleanup are applied only after identity validation and a successful transactional migration.

### Portable Backup Lifecycle

A portable backup is a transactionally consistent, self-contained `.mdbx` file produced from a live vault. The storage layer MUST use SQLite's online backup API or an equivalent database snapshot mechanism so committed pages still present only in the source WAL are included. Copying the source main file while WAL is active is not a complete backup operation.

The backup MUST be built in a temporary file in the destination directory, converted to a non-WAL journal mode, checked with SQLite integrity verification, and inspected as a supported initialized MDBX vault. The copied format and schema metadata plus `vault_id` MUST equal the source. The temporary file MUST be synchronized before publication, and publication MUST use no-clobber semantics.

The destination main file and its same-name `-wal` and `-shm` sidecars MUST all be absent. Any existing destination artifact is preserved and causes the operation to fail. A successful portable backup has no required sidecars and can be opened independently with the source vault's existing unlock methods.

The storage facade is authoritative for these guarantees. An already opened Rust vault uses `BackupService::create_portable_copy`, while a client-controlled migration uses the read-only `BackupService::create_portable_copy_path` before writable open. UniFFI exposes the same distinction through `MdbxVault.create_backup` and top-level `create_portable_backup`. The reference CLI uses the read-only path operation for `mdbx backup <output>`, so backup neither requires unlock credentials nor triggers automatic migration.

Read-only path backup MUST preserve a supported MDBX1, MDBX1 draft, or MDBX2 generation in the result. It MUST leave persistent source database and WAL bytes unchanged. SQLite MAY update transient read marks in an existing SHM coordination file while reading a live WAL source; SHM is rebuildable and is not part of the portable result.

## 2. Internal Storage Goals

The internal layout MUST support all of the following:

- append-friendly writes
- partial updates
- crash recovery
- attachment metadata storage
- attachment binary storage indirection
- version history
- conflict detection metadata
- future migration hooks

## 3. Minimum Internal Logical Tables

The minimum logical schema MUST reserve space for at least these record classes:

- `projects`
- `entries`
- `attachments`
- `attachment_chunks`
- `commits`
- `commit_parents`
- `device_heads`
- `branches`
- `tombstones`
- `snapshots`
- `key_epochs`
- `conflicts`
- `unlock_methods`
- `object_versions`
- `project_tags`

An MVP MAY omit some secondary indexes or optional tables, but MUST NOT omit `projects` or `attachments`.

## 4. Project-Oriented Schema Rules

The `projects` table is mandatory.
The `entries` table MUST reference `project_id`.

This means:

- every password-like secret belongs to a project
- queries MUST be able to fetch a project and then its child entries
- sync and merge logic MUST preserve project membership

## 5. Attachment Schema Rules

The `attachments` table is mandatory from version 1.
The `attachment_chunks` table SHOULD be present from version 1 even if chunked storage is only partially used in MVP.

The schema MUST support:

- attachment owned by project
- attachment optionally owned by a specific entry
- content hash
- chunked binary data or external content reference
- soft delete via tombstone or delete marker
- integrity verification

## 6. Write Path Requirements

Routine small edits MUST avoid full logical rewrite of the entire vault contents.

A compliant write path SHOULD:

1. update changed project or entry rows only
2. append a commit or oplog record
3. update lightweight head metadata
4. avoid touching unrelated attachment rows
5. avoid touching unrelated large binary pages

## 7. WAL And Append Strategy

The preferred implementation SHOULD use SQLite WAL mode or an equivalent append-friendly strategy.

Design goals:

- small edits generate small write deltas
- cloud sync tools can propagate small changed regions where supported
- periodic compaction is explicit and infrequent

The implementation MUST document how it preserves durability during power loss or crash.

## 8. Commit And History Model

MDBX MUST maintain a Git-like logical history.

Minimum requirements:

- each local mutation produces a commit-like history record
- commits reference one or more parent commits
- device-local order is monotonic
- concurrent histories remain representable until merged

A commit record SHOULD include:

- commit ID
- device ID
- local sequence number
- parent commit IDs
- changed object references
- timestamp
- optional merge metadata
- integrity data

## 9. Conflict Detection

MDBX MUST detect concurrent edits using causal metadata, not timestamp alone.

Minimum acceptable mechanisms:

- version vectors
- device sequence graph
- per-record revision lineage
- field-level conflict markers where necessary

Different-field concurrent changes within the same project MAY auto-merge when safe.
Same-field concurrent secret changes MUST create an explicit conflict.

### 9.1 Key Epoch State

The key epoch field in sync state MUST remain optional so MDBX1 and early MDBX2 payloads continue to deserialize. When present, it carries the active epoch ID, every active and retired row in canonical ID order, and a state integrity tag.

A fast-forward rotation selects the incoming active epoch. Concurrent rotations compare candidate activation time and epoch ID deterministically, retain the union of valid wrappers, and retire candidates that are not selected. Rewriting wrapper bytes, profile, creation time, or activation time under an existing epoch ID is rejected.

Changing epoch state requires a verified-unlocked mutable connection. The apply transaction verifies the state tag and wrappers before writing object ciphertext that depends on the new epoch, then refreshes active and historical epoch keyrings after commit. Older payloads without this field do not clear or roll back local epoch state.

### 9.2 Transactional State Deltas

After the bootstrap floor, an outer write transaction SHOULD materialize one bounded immutable state-delta batch. A batch with associated commits is attached to the final associated commit; a transaction without a commit produces an auxiliary batch and MUST NOT add a user-visible history record.

The receiver MUST authenticate vault and batch identity, payload digest, row count, commit ownership, and resource limits before accepting state. Every associated commit MUST be available. A recognized delta cannot be mixed with complete sync state or a second delta on the same serialized commit. Commit insertion, sparse state application, attachment chunk replacement, device-head merge, authorized deletion, received-batch persistence, and incoming capture cleanup MUST commit or roll back together.

Delta tombstone rows are sparse and MUST NOT replace unrelated local tombstones. Device revocation merges monotonically. Physical object or tombstone deletion requires a matching authenticated permanent-purge receipt. Key epoch changes require the mutable verified-unlocked apply path; the immutable compatibility path rejects them atomically.

Complete sync state remains the bootstrap and old-peer fallback. Bundle v1-v3 retain their existing formats; a client MUST NOT claim incremental convergence until it exchanges both commit-inventory and auxiliary-delta checkpoints.

## 10. Merge Model

MDBX SHOULD support:

- fast-forward merge
- three-way merge for non-secret text fields
- conflict record creation for unsafe merges
- user-visible merge resolution later

The merge system MUST preserve both sides when automatic resolution is unsafe.

## 11. Snapshot And Recovery

MDBX MUST support recovery from logical corruption or interrupted sync.

Minimum requirements:

- historical commits remain replayable
- snapshots can be produced periodically
- snapshots can rebuild projects, entries, attachment metadata, and embedded attachment chunks when present
- partially damaged vaults SHOULD still allow partial recovery

A snapshot is a logical recovery point stored inside a vault. It is distinct from a portable backup, which creates an independently openable complete vault file, and from a sync bundle, which carries incremental commit state between replicas. None of these artifacts can be replaced by copying only the SQLite main file while WAL is active.

Offline sync bundle readers MUST enforce a payload limit before allocation and deserialization. Bundle v3 stores the payload length in the header and rejects non-zero reserved bytes or data after the payload hash. Bundle v1 and v2 compatibility readers MUST cap the underlying reader rather than call an unbounded read. Resource profiles may choose a lower limit; the protocol hard ceiling remains mandatory.

## 12. Attachment Storage Modes

MDBX MUST define these storage modes even if not all are enabled in MVP:

- `embedded-inline`
  - small binary stored directly in attachment payload

- `embedded-chunked`
  - attachment stored in encrypted chunks inside the database

- `external-hash-ref`
  - database stores metadata plus verified external blob reference

Default recommendation:

- small attachments MAY be embedded
- large attachments SHOULD be chunked or externally referenced by content hash

## 13. Attachment Update Rules

Editing project metadata MUST NOT require rewriting large attachment content.
Editing entry fields MUST NOT require rewriting unrelated attachment content.
Renaming an attachment MUST update metadata only.

## 14. Cloud-Drive Optimization

MDBX is designed for sync through tools such as Syncthing, Git, Nextcloud, WebDAV-backed sync layers, Dropbox, and OneDrive.

The implementation SHOULD:

- minimize rewritten regions for small edits
- prefer append-heavy patterns over random rewrite where practical
- compact only when thresholds are met
- keep attachment bodies isolated from routine metadata edits

## 15. Performance Targets

Target goals for a healthy implementation:

- common metadata save under `100 ms`
- project open fast enough for interactive UI
- search clearly faster than large KDBX libraries
- cloud-drive delta for small edit remains in `KB` scale in normal cases

These are product goals and must be tracked with benchmarks.

## 16. Required Indexing

The storage engine SHOULD maintain indexes for at least:

- project title
- project tag membership
- project group membership
- entry type by project
- recent modification time
- attachment ownership
- tombstone lookup
- commit lineage lookup

Full-text search MAY use temporary indexes for decrypted titles during an unlocked session. Persistent FTS tables MUST NOT store decrypted project titles or other secret-bearing text.

Temporary search indexes are not user-visible history and MUST NOT create commits. User-visible project tags are metadata, not temporary search state: tracked tag mutations SHOULD create a project-scoped commit, and sync state SHOULD carry the complete tag set for each project so tag deletion, including deleting the final tag, can be replayed safely. Readers that receive an older sync payload without a tag field MUST preserve local tags instead of treating the missing field as an empty set.

## 17. Compaction Rules

Compaction MAY rewrite larger portions of the vault, but it MUST be:

- explicit or policy-driven
- recoverable if interrupted
- unnecessary for routine edits
- safe for attachment integrity

## 18. Minimum Export Requirements

The storage layer MUST support export paths for:

- full vault export
- project export
- attachment extraction with integrity check
- KDBX export bridge

## 19. Rejection Rules

A storage design is non-compliant if it:

- lacks a first-class `projects` structure
- lacks first-class `attachments` structure
- rewrites the whole vault on ordinary small field edits by design
- cannot represent concurrent histories
- cannot explain recovery after interruption
