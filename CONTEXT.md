# MDBX Domain Context

## Purpose

MDBX is a local-first advanced encrypted database core for authenticated, versioned objects and binary content. Password management is one domain adapter, alongside bookmarks, mail, Steam `mafile`, and future application domains. The core keeps encryption, collections, object records, attachments, commits, synchronization, conflicts, snapshots, and policy independent from product-specific payload meaning.

The database core accepts opaque application payloads and provides durable security properties around them: authenticated encryption at rest, stable object identity, atomic commit operations, causal synchronization, recovery, audit, key epoch rotation, and MDBX1 compatibility. Application meaning and presentation stay in optional adapters.

## Domain Vocabulary

### Vault

A `Vault` is one encrypted MDBX database with a stable vault identity, unlock methods, Tiga policy, key epochs, commit history, and synchronization state.

### Collection

A `Collection` is a stable container for object records. Password projects, bookmark folders, mailboxes, and Steam account groups are domain presentations of this concept. MDBX1 stores collections in the physical `projects` table; the generic Module hides that compatibility implementation from new callers.

### ObjectRecord

An `ObjectRecord` is one encrypted, versioned item inside a collection. Password entries, bookmarks, mail messages, mail contacts, and `mafile` documents are ObjectRecords. MDBX1 stores ObjectRecords in the physical `entries` table.

### ObjectTypeId

An `ObjectTypeId` is the exact stable identifier for an ObjectRecord payload contract. MDBX legacy identifiers such as `login`, `note`, and `totp` remain valid. Extension identifiers use a namespaced form such as `com.monica.bookmark`, `com.monica.mail.message`, or `com.monica.steam.mafile`.

The core preserves every valid ObjectTypeId exactly. An unknown identifier remains unknown and must never be converted to a password type or another fallback. Interpretation belongs to a domain adapter.

### PayloadSchemaVersion

`PayloadSchemaVersion` is the unsigned version of the payload contract owned by an ObjectTypeId. It is independent from the MDBX database schema version. A domain adapter migrates its own plaintext payload after authenticated decryption; the core stores and synchronizes the declared version.

### ObjectRelation

An `ObjectRelation` is a typed directed edge between stable objects. It represents mail thread membership, reply relationships, bookmark aliases, label membership, contact links, Steam account ownership, or future cross-domain references. Relation kinds use stable namespaced identifiers and participate in commit, tombstone, snapshot, and synchronization rules.

### ObjectLabel

An `ObjectLabel` is a stable searchable classification attached to an ObjectRecord. Labels support mail labels, bookmark tags, and domain-neutral organization. They are user-visible metadata and therefore participate in commits and synchronization.

### Attachment

An `Attachment` is authenticated binary content or an external content reference owned by a Collection and optionally by an ObjectRecord. Mail attachments and `mafile` source documents use the same attachment integrity rules as password-vault files.

### ExtensionProfile

An `ExtensionProfile` declares the ObjectTypeIds, relation kinds, optional indexes, import/export adapters, and client presentation hints supplied by one domain extension. It never receives raw SQL authority over core history or key tables.

### CapabilitySet

A `CapabilitySet` is the compile-time and runtime set of optional adapters present in a build. Core readers, MDBX1 compatibility, encryption, commits, and synchronization are mandatory. KDBX import/export, benchmarks, mail indexes, bookmark indexes, and Steam adapters can be excluded when unused.

### CommitOperation

A `CommitOperation` is one finite user intent executed atomically and represented by one commit whenever practical. Importing one `mafile`, moving a bookmark group, or applying one mail synchronization batch can contain multiple row mutations without producing a commit per internal row.

### ConflictResolutionOperation

A `ConflictResolutionOperation` selects local state, incoming state, or a validated custom state for one conflicted object. It atomically writes the selected state, creates a two-parent merge commit, advances the object clock and heads, records a new ObjectVersion, reconciles tombstones, and marks the conflict resolved.

### TombstoneState

`TombstoneState` is the complete current deletion-marker collection projected into synchronization state. Per-commit tombstones remain compatible delete-event records. A present complete collection, including an empty collection, is authoritative only during conflict-free fast-forward application and therefore communicates both deletion and revival without discarding divergent local deletion state.

### HealthReport

A `HealthReport` is a read-only structured diagnosis of vault integrity. Each issue has a stable severity, category, and description suitable for CLI output and native client presentation. Tombstone diagnostics compare exact typed markers with the current deletion state of every synchronized object family while recognizing unresolved delete-versus-modify conflicts as a temporary valid state.

## Core Invariants

1. MDBX2 always reads MDBX1 data and preserves legacy public interfaces.
2. Physical `projects` and `entries` remain compatibility storage; new code uses Collection and ObjectRecord interfaces.
3. Unknown ObjectTypeIds round-trip exactly and remain opaque to adapters that do not support them.
4. The core authenticates storage context and ciphertext without needing to understand domain payload fields.
5. Domain-specific indexes are derived data. They can be rebuilt from authenticated ObjectRecords and must not become the only copy of user data.
6. ObjectRelations and ObjectLabels are first-class synchronized metadata with stable IDs and tombstones.
7. Optional capabilities may be removed from a build only when doing so preserves safe reading or produces an explicit unsupported-extension error.
8. One user intent should create one CommitOperation, avoiding histories filled with internal implementation commits.
9. Every stored payload is opaque to the core and remains protected by authenticated encryption, integrity context, version metadata, and atomic history rules.
10. Optional domain capabilities may add interpretation and rebuildable indexes, but they cannot weaken encryption, history, synchronization, recovery, or compatibility guarantees.
11. Conflict resolution is a tracked object mutation. Marking a conflict row resolved without applying and versioning the selected object state is invalid.
12. Custom conflict state preserves stable object identity and structural ownership. Plaintext custom metadata is authenticated and encrypted by the core inside the resolution transaction.
13. After successful conflict resolution or conflict-free fast-forward synchronization, every deleted object has an exact typed tombstone and every active object has no current typed tombstone. An unresolved delete-versus-modify conflict may temporarily preserve both the active local row and the incoming delete marker until resolution.
14. Health diagnostics must cover generic objects and legacy compatibility objects through the same severity and category model. A healthy report contains no Error or Critical issue.

## Module Architecture

### Generic Object Module

The Generic Object Module is the primary Interface for Collection, ObjectRecord, ObjectRelation, ObjectLabel, and Attachment behavior. Its Implementation owns compatibility mapping to existing tables, encryption, commit updates, causal metadata, and sync-state projection. This is a deep Module: callers supply stable domain values and receive complete invariant-preserving behavior.

### Legacy Password Adapter

The Legacy Password Adapter maps existing EntryType values and MDBX1 methods onto the Generic Object Module. It remains available for old clients and KDBX interoperability. The adapter does not define the generic core vocabulary.

### Domain Adapters

Bookmark, mail, and Steam adapters interpret namespaced ObjectTypeIds and payload schemas. They may add rebuildable indexes through explicit seams. One adapter alone does not justify a core interface; shared behavior moves into the core only after at least two adapters need the same seam.

### Conflict Resolution Module

The Conflict Resolution Module loads authenticated local and incoming ObjectVersions, validates identity and ownership constraints, and applies LocalWins, IncomingWins, or Custom state through one transaction. ObjectRelations, ObjectLabels, and ObjectLabelAssignments use the same merge-commit and tombstone rules as legacy projects, entries, and attachments. Duplicate assignment UUIDs for the same logical object-label membership are mapped to the local logical identity before resolution.

The synchronization state carries an optional complete TombstoneState. New producers always emit it. Legacy payloads omit it and retain their existing per-commit delete-event behavior. Receivers replace the complete collection only for conflict-free fast-forward commits; divergent commits continue to preserve local markers until a merge resolution becomes authoritative.

### Recovery and Health Module

The Recovery and Health Module performs read-only checks for SQLite integrity, authenticated commit history, snapshots, attachment chunks, references, device heads, and typed tombstones. It reports missing markers for deleted rows, unexplained markers for active rows, and duplicate markers as errors. Unknown extension tombstone types remain preserved. Branch tombstones remain event records because branches have no deleted-row state. The CLI and UniFFI expose the same underlying structured report.

### Capability Features

Cargo features select optional adapters and tools. Default builds retain current behavior. Minimal builds may remove imports, benchmarks, or domain indexes while keeping the same file reader, compatibility migrator, encryption, and generic object interfaces.

The supported storage profiles are:

| Profile | Cargo selection | Included behavior |
|---|---|---|
| Full | default features | Mandatory database core, KDBX JSON import and export, benchmark harness, and the MDBX1 derived search adapter |
| Core | `--no-default-features --features core` | Mandatory database core only |

Optional storage features are additive:

| Feature | Capability |
|---|---|
| `kdbx-import` | KDBX JSON import adapter |
| `kdbx-export` | KDBX JSON export adapter |
| `derived-search-index` | Legacy password-project search and temporary FTS index |
| `benchmarks` | Local benchmark harness; enables `derived-search-index` |

`CapabilitySet::current()` exposes the compiled capability set to Rust clients. Mandatory fields always report true in a supported build. Optional fields reflect Cargo feature selection.

When a domain adapter is absent, the Generic Object Module continues to read, authenticate, preserve, snapshot, synchronize, and recover its namespaced ObjectTypeIds as opaque records. Adapter-specific Rust modules and CLI commands are absent from that build. An absent adapter never authorizes plaintext interpretation, rewrites the type identity, or removes stored data. Unknown critical storage extensions continue to fail before writable open.
