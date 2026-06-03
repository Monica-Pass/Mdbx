# MDBX Documentation Index

Language: [简体中文](README.zh-CN.md) | [English](README.md)

This directory is the canonical documentation center for MDBX. MDBX is a
local-first encrypted password database format and reference architecture.

The documentation is organized by responsibility. Canonical documents live in
the category directories below. The old numbered files at `docs/*.md` are kept
only as compatibility entry points so old links keep working.

## Non-Negotiable Principles

Every implementation and every design choice MUST preserve these rules:

- Local-first operation
- Long-term readability and migration friendliness
- Forward and backward compatibility
- 4ever And 4ever: new versions read older vaults; older implementations should preserve unknown non-critical data where possible
- Data safety before convenience
- No mandatory central server
- Project-oriented password storage
- Native attachment capability
- Safer sync and conflict behavior than KDBX
- Better cloud-drive performance than KDBX

## Categories

### Governance

- [Agent execution rules](governance/00-agent-rules.md)
- [Agent execution rules zh-CN](governance/00-agent-rules.zh-CN.md)
- [RFC structure and documentation rules zh-CN](governance/05-rfc-structure.zh-CN.md)

### Product Model

- [Product specification](product/01-product-spec.md)
- [Product specification zh-CN](product/01-product-spec.zh-CN.md)

### Storage And Sync

- [Storage and sync specification](storage/02-storage-sync-spec.md)
- [Storage and sync specification zh-CN](storage/02-storage-sync-spec.zh-CN.md)
- [SQLite schema v1 zh-CN](storage/06-sqlite-schema-v1.zh-CN.md)

### Security

- [Security specification](security/03-security-spec.md)
- [Security specification zh-CN](security/03-security-spec.zh-CN.md)

### Delivery And Acceptance

- [Roadmap and acceptance](delivery/04-roadmap-acceptance.md)
- [Roadmap and acceptance zh-CN](delivery/04-roadmap-acceptance.zh-CN.md)
- [Low-end model task breakdown zh-CN](delivery/07-low-end-model-task-breakdown.zh-CN.md)
- [Implementation completion plan zh-CN](delivery/08-implementation-completion-plan.zh-CN.md)

### Integration

- [Monica Pass CLI development zh-CN](integration/11-monica-pass-cli-development.zh-CN.md)
- [Client integration guide](../CLIENT_INTEGRATION_GUIDE.md)
- [Client integration guide zh-CN](../CLIENT_INTEGRATION_GUIDE.zh-CN.md)
- [MDBX FFI guide](../crates/mdbx-ffi/README.md)
- [MDBX FFI guide zh-CN](../crates/mdbx-ffi/README.zh-CN.md)

## Recommended Reading Order

Implementation agents SHOULD read in this order:

1. [Agent execution rules](governance/00-agent-rules.md)
2. [Product specification](product/01-product-spec.md)
3. [Storage and sync specification](storage/02-storage-sync-spec.md)
4. [Security specification](security/03-security-spec.md)
5. [Roadmap and acceptance](delivery/04-roadmap-acceptance.md)
6. [RFC structure and documentation rules zh-CN](governance/05-rfc-structure.zh-CN.md)

Chinese-speaking reviewers SHOULD read in this order:

1. [MDBX 执行模型规则](governance/00-agent-rules.zh-CN.md)
2. [MDBX 产品规范](product/01-product-spec.zh-CN.md)
3. [MDBX 存储与同步规范](storage/02-storage-sync-spec.zh-CN.md)
4. [MDBX 安全规范](security/03-security-spec.zh-CN.md)
5. [MDBX 路线图与验收规范](delivery/04-roadmap-acceptance.zh-CN.md)
6. [MDBX RFC 结构与文档约定](governance/05-rfc-structure.zh-CN.md)
7. [MDBX SQLite 初版 Schema 规范](storage/06-sqlite-schema-v1.zh-CN.md)
8. [MDBX 低端模型任务拆分清单](delivery/07-low-end-model-task-breakdown.zh-CN.md)
9. [MDBX 实现补完计划](delivery/08-implementation-completion-plan.zh-CN.md)
10. [Monica Pass CLI 开发文档](integration/11-monica-pass-cli-development.zh-CN.md)
11. [MDBX FFI 指南](../crates/mdbx-ffi/README.zh-CN.md)

## Core Vocabulary

- `vault`: one MDBX database file.
- `project`: the top-level logical container for a real-world account, service, website, app, organization, identity set, or working set of secrets.
- `entry`: a concrete secret-bearing record inside a project, such as login, note, card, identity fragment, key, or token.
- `attachment`: a file or binary payload referenced by a project or entry.
- `tiga mode`: one of `power`, `multi`, or `sky` in stored values and APIs. `power` is strongest protection, `multi` is the balanced default, and `sky` is flexible and portable while still secure.
- `oplog`: append-only change history used for sync and recovery.
- `snapshot`: a compact recoverable state image.

## Writing Rules

When adding or updating docs:

- Use RFC-style requirement words: `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, `MAY`.
- Make core requirements testable.
- Separate normative requirements from advice.
- Put rules before examples.
- Do not leave ambiguity in the core data model.
- Keep compatibility links working when canonical files move.

## Scope Boundary

This directory defines the spec and implementation guidance. Production code
must follow these documents rather than redefining the format rules.
