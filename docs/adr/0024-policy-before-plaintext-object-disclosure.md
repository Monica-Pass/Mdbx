# ADR-0024: Policy before plaintext object disclosure

## Status

Accepted

## Context

MDBX1 complete-entry reads decrypt title and payload together. Keeping those APIs is necessary for compatibility, but using them for policy resolution or default details means plaintext can be produced before the caller knows whether Tiga allows disclosure. It also makes a corrupt payload mask an authorization denial with an earlier crypto error.

MDBX2 already has payload-free paginated object summaries, but it lacked a by-ID summary read and a single storage service that owned the sequence of policy evaluation, auditing, and payload decryption. Entry policy resolution also loaded complete entries, while parent project policy resolution decrypted project title and summary fields.

## Decision

MDBX2 separates object selection from object disclosure.

`EntryRepo` and `ProjectRepo` provide crate-internal policy-context projections containing only hierarchy, Tiga override, deletion, and clock fields required by policy work. Stored override strings are parsed strictly and unknown values fail closed. Tiga policy resolution and policy-change tracking use these projections instead of complete decrypted records.

`ObjectSummaryRepo::get` returns one `ObjectSummary`, including a deleted object, without selecting `payload_ct`. It remains a presentation metadata API and may decrypt the optional title.

`ObjectDisclosureService` is the generic plaintext boundary. It evaluates `TigaOperation::RevealSecret` for `TigaScope::Entry`, rejects non-allow decisions as `StorageError::Authorization`, rejects deleted objects, and only then calls the compatible complete-entry read. The allowed evaluation, object read, and success audit share one immediate transaction. A denial commits its audit event without executing the plaintext action. An active-session entry point renews idle activity only after successful disclosure.

The reference CLI uses metadata-only get by default and requires `entry get --reveal` to enter the disclosure service.

## Compatibility

Existing `EntryRepo::get_by_id`, list APIs, MDBX1 data, and callers keep their complete-record behavior. This ADR does not silently place authorization inside those low-level compatibility methods because many internal migrations, exports, and legacy clients already control their own authorization boundary.

New client and FFI surfaces should expose summary reads and authorized disclosure rather than presenting the compatible complete-record APIs as safe defaults.

UniFFI implements this decision additively through `get_object_summary`, `reveal_object`, `reveal_object_with_device_context`, and `MdbxObjectDisclosureResult`. Existing `get_object`, `list_objects`, and `list_entries` remain complete-record compatibility methods.

## Consequences

Tiga denials are decided before payload decryption, policy resolution survives unrelated ciphertext corruption, and default details no longer extend secret lifetime. Clients receive the authorization decision together with plaintext and remain responsible for enforcing constraints such as screen-capture protection.

Titles are still decrypted for metadata presentation. A title-free locked view remains a separate encrypted-index problem. Compatibility APIs can still reveal plaintext when called directly, so code review and future public bindings must preserve the disclosure boundary.
