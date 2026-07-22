# MDBX Security Specification

Version: `MDBX-1-DRAFT`

This document defines the Tiga model, required cryptography, key hierarchy, and memory handling rules.

## 1. Security Objectives

MDBX MUST protect against:

- offline file theft
- untrusted cloud storage
- tampering of encrypted records
- accidental long-lived plaintext exposure in normal workflows
- weak default KDF settings

MDBX cannot fully hide file size, access timing, or overall sync activity from the storage provider.

## 2. Required Algorithms

Baseline recommendations:

- password KDF: `Argon2id`
- authenticated encryption: `XChaCha20-Poly1305` or `AES-256-GCM`
- key derivation: `HKDF-SHA-256`
- hashing: `SHA-256`
- filename or identifier MAC where needed: `HMAC-SHA-256`

The preferred default stack is:

- `Argon2id + HKDF-SHA-256 + XChaCha20-Poly1305`

Current committed AEAD envelope:

- new ciphertext values MUST use `MDBXAE1\0 || commitment || nonce || ciphertext`
- `commitment` is an HMAC-SHA-256 commitment over the envelope context, associated data, nonce, and encrypted payload
- decryptors MUST continue to accept legacy `nonce || ciphertext` values written before the committed envelope existed
- encryptors MUST NOT write new legacy envelopes

Random key or nonce generation failure MUST fail the operation. Implementations MUST NOT fall back to an all-zero key, deterministic nonce, or other placeholder secret.

## 3. Tiga Modes

MDBX MUST expose three user-selectable security modes.

Stored values and API names:

- `power`
  - strongest-protection mode

- `multi`
  - balanced default mode

- `sky`
  - flexible and portable mode that remains secure

Compatibility display names MAY use `Power Type`, `Multi Type`, and `Sky Type`, but storage and API values SHOULD use `power`, `multi`, and `sky`.

### 3.1 Power

Purpose:

- maximum resistance against offline attack and local leakage

Typical effects:

- highest Argon2id cost
- shorter in-memory secret lifetime
- less plaintext caching
- stronger warnings before export or copy
- stricter attachment handling defaults
- password + security-key combined unlock SHOULD be configured for full Power policy satisfaction
- standalone portable unlock SHOULD NOT satisfy the full Power policy unless explicitly accepted as a downgrade by the user

### 3.2 Multi

Purpose:

- recommended default balance
- cloud-drive portability with strong recovery semantics

Typical effects:

- strong Argon2id cost
- moderate caching allowed
- usability features enabled when low risk
- security key SHOULD be recommended
- a portable recovery path such as a strong password MUST remain available unless the user explicitly chooses otherwise

### 3.3 Sky

Purpose:

- flexible, portable, and recovery-first use, including cloud-drive workflows
- Sky is not an unsafe mode

Typical effects:

- lower but still acceptable KDF cost floor
- more permissive caching
- faster unlock and routine operations
- password, PIN wrapper, platform credential wrapper, or security-key unlock MAY be offered
- all unlock paths MUST still use MDBX KDF, AEAD, keyring, and logging rules

## 4. Tiga Mode Scope

Tiga mode MUST support:

- global default mode
- optional project-level override
- optional entry-level override for especially sensitive secrets

A narrower scope override MUST take precedence over a broader one.

## 5. Required User Warnings

When switching to a weaker mode, the UI MUST:

- clearly state the new risk profile
- require explicit confirmation
- show which protections become weaker

## 6. Key Hierarchy

A compliant implementation SHOULD use a layered hierarchy:

- user secret inputs
- master unlock key
- vault key
- purpose keys
- record or object keys

A recommended derivation chain is:

- unlock key from `Argon2id`
- vault key from `HKDF`
- subkeys for metadata, records, attachments, and history

## 7. Record Authentication

MDBX MUST authenticate:

- vault header metadata that affects decryption
- project records
- entry records
- attachment metadata
- attachment content or chunk content
- history records
- snapshot records

Moving ciphertext into the wrong context MUST fail authentication.

MDBX2 schema 16 authenticates the vault header with
`mdbx-vault-header-hmac-sha256-v1` under the vault integrity subkey. The
length-delimited HMAC covers the vault identity, format and schema versions,
minimum reader/writer versions, creation/update timestamps, default Tiga mode,
active key epoch, compatibility and critical-extension flags, Tiga policy
version, and compliance status. A database trigger invalidates an established
tag whenever any covered column changes; a legal storage-core mutation MUST
refresh the tag in the same transaction. An established header MUST NOT be
downgraded to the migration-only `pending` state.

MDBX1 and earlier MDBX2 vaults enter `pending` during the additive migration
because no verified vault key is available at open time. The first successful
unlock establishes the tag. Subsequent unlocks MUST verify it before attaching
the keyring, and health checks MUST report invalidated or mismatched tags as an
error. A locked health check can validate tag shape but can only report keyed
verification as pending. This mechanism is complemented by an external
rollback anchor. After a successful unlock and durable mutation or sync, the
storage core can issue a bounded opaque HMAC token through the CLI and UniFFI.
The client MUST persist that token outside the vault, verify the previous token
after reopening and before trusting the state, and replace the persisted token
only after verification and a new issuance succeed. Equal or advanced
append-only commit and sync-delta inventory heads are accepted; missing or
rewritten anchored rows are rejected as rollback. The client owns token
retention, backup, and replacement policy. A lost token cannot be detected by
the database, and the anchor is not a trusted clock, an availability guarantee,
or a whole-vault authentication root.

## 8. Attachment Security Rules

Attachments are first-class sensitive data.

Therefore MDBX MUST:

- authenticate attachment metadata
- authenticate attachment content
- prevent metadata-only rename from invalidating unrelated content
- verify content hash before trusting attachment reconstruction

If external referenced attachments are supported, the external content MUST still be integrity-bound to the database metadata.

## 9. Memory Safety Rules

MDBX2 MUST keep long-lived keyring fields in automatically zeroizing buffers.
Argon2id and HKDF outputs, unwrapped vault keys, and unwrapped data-epoch keys
MUST enter such a buffer at the point they are produced. Cloning a keyring key
MUST preserve zeroizing ownership. This protects the normal Rust-owned lifetime;
it does not claim to erase copies made by callers, operating-system crash dumps,
hardware or cryptographic library internals, or allocator copies that are outside
the storage core's ownership.

Implementations SHOULD:

- minimize plaintext lifetime in memory
- zero sensitive buffers when practical
- avoid logging secrets
- avoid crash dumps with raw secret payloads where possible
- isolate attachment streaming so large files do not remain fully decrypted in memory unnecessarily

## 10. Unlock Factors

MDBX SHOULD clearly distinguish between user-visible unlock methods and the underlying cryptographic secret model.

User-visible unlock methods MAY include:

- `PIN`
- `password`
- `security key`
- biometric unlock wrapper where supported by platform

The actual vault protection boundary SHOULD still be enforced by the master unlock key, vault key, and their derivation chain.

MDBX SHOULD support combinations of:

- master password
- key file
- security key or hardware-backed key material
- biometric unlock wrapper where supported by platform
- combined password + security-key unlock, represented as `password_security_key`

### 10.1 PIN Unlock

`PIN` MAY be offered as a user-visible fast unlock method.

However, `PIN` SHOULD NOT be treated as the true vault master secret by itself.
A better model is:

- `PIN` unlocks a locally protected wrapping key
- the wrapping key then unlocks the real vault key material

This avoids making a short PIN the only real security boundary.

### 10.2 Password Unlock

`password` is a core unlock method that MDBX SHOULD support strongly.

Password input MUST support Unicode.
This means:

- Chinese passwords MUST be supported
- implementations MUST NOT assume passwords are ASCII-only
- the spec and implementation SHOULD define a stable encoding and normalization strategy

Recommended requirement:

- before entering the KDF, the password should go through a stable Unicode string handling pipeline
- implementations MUST avoid cross-platform differences that make the same Chinese password fail on another device

### 10.3 Security Key Unlock

`security key` SHOULD be supported as one of the unlock methods.

It may be used to:

- provide a hardware-protected unlock factor
- wrap or release locally stored key material
- combine with password or PIN for stronger unlock flows

It SHOULD NOT be described as a mandatory cloud-dependent unlock mechanism.
MDBX MUST remain local-first.

Hardware-key support does not make cloud-drive storage unsafe or unusable. Portability depends on the configured unlock methods:

- `password` and properly designed portable recovery methods can open a cloud-synced vault on a new device.
- `security_key`-only configurations require the same hardware key or equivalent platform credential on the new device.
- `password_security_key` provides stronger offline-attack resistance but intentionally reduces standalone portability.

Clients MUST explain these recovery consequences before disabling all portable unlock paths.

Biometric unlock SHOULD wrap a stronger underlying secret and SHOULD NOT replace the actual cryptographic vault secret model.

## 10.4 Minimum Unlock Capability

A user-facing MDBX implementation SHOULD support at least two of the following three unlock methods, and a full implementation SHOULD support all three:

- `PIN`
- `password`
- `security key`
- `password_security_key`

If an implementation claims password support, that password support MUST include Chinese input.

## 11. Minimum Parameter Philosophy

MDBX MUST define minimum supported security floors.
Even `sky` MUST remain meaningfully secure and MUST NOT degrade into a toy configuration.

The exact parameter table SHOULD be published separately and versioned.

## 12. Audit And Logging Rules

Logs MUST NOT contain:

- plaintext passwords
- TOTP seeds
- passkey private material
- decrypted attachment names unless the user explicitly exports diagnostic data

## 13. Recovery And Rotation

MDBX SHOULD support:

- key rotation
- backup verification
- snapshot verification
- attachment integrity scan

Rotation MUST preserve readability of records until migration is complete.

Data-key epoch rotation MUST be authorized as the `RotateKeyEpoch` Tiga administration operation. A successful rotation atomically generates an independent random epoch key, wraps it under the vault root key with AAD bound to vault and epoch identity, retires the previous active epoch, activates the new epoch, updates `vault_meta`, creates a `key-rotation` / `key-epoch` commit, and correlates the security audit event with that commit. Denial and failure preserve the previous active epoch, wrapper set, and commit state.

Sync state MUST carry the active identity, every active and retired wrapper, and a state tag authenticated by the vault integrity subkey. A receiver MUST verify the tag and wrappers before changing epoch state. Concurrent rotations retain both key materials and deterministically choose one active epoch. Senders distribute the rotation commit and key epoch state before fields encrypted under the new epoch.

## 14. Rejection Rules

A security design is non-compliant if it:

- lacks authenticated encryption
- leaves attachment integrity undefined
- writes new ciphertext without the committed AEAD envelope
- intentionally removes the ability to read legacy valid ciphertext or vaults without a documented critical-security migration
- falls back to an all-zero key, deterministic nonce, or placeholder secret after RNG failure
- allows weaker mode switching without explicit user acknowledgement
- stores long-lived plaintext secrets by default without strong justification
- treats biometric unlock as the only real secret
