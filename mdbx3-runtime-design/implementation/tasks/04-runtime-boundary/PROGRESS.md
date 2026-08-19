# Vault runtime boundary and read/write model 进度

任务：把连接、reader generation 与 single writer 收口到 storage-owned Vault Runtime。

形态：`single-full`

进度：3/6

当前：将兼容 FFI 迁移到 Runtime 且冻结 ABI。

验证：storage core 681+4 项通过；runtime 3 项和 clippy 通过。

文件：`mdbx3-runtime-design/implementation/tasks/04-runtime-boundary/TODO.csv`

下一步：把 `MdbxVault.conn` 类型替换为 `VaultRuntime`，保持 facade 调用和 UniFFI 签名不变。

## Context Recovery

- 当前里程碑：4 — 将兼容 FFI 迁移到 Runtime 且冻结 ABI
- 当前状态：IN_PROGRESS
- 上一项：3 — storage-owned VaultRuntime 与 single writer
- 当前事实文件：`TODO.csv`
- 关键上下文：新增 `mdbx_storage::runtime::VaultRuntime`，兼容后端先保持一个串行连接；generation 合约独立于后续 read snapshot 实现。
- 已知问题：生产 FFI 仍有 142 个 `.lock()` 访问点，raw SQL 仍有 6 处。
- 下一动作：用兼容 guard 迁移内部字段和构造路径，再移除 raw SQL。

## 已确认基线

1. `MdbxVault` 当前直接拥有 `Mutex<VaultConnection>`。
2. production FFI 有 142 个锁访问点、3 个 `inner()` 访问点、6 个 SQL 调用点。
3. `VaultConnection` 同时拥有 SQLite、keyring、active session、epoch keyrings 和 extension registry，不能无验证地拆成多个连接。
4. 第一兼容后端保留串行连接，以 storage-owned `read/write/reader generation` 接口隐藏实现。

## 约束

1. TDD 每次只推进一个可观察行为。
2. 测试使用真实临时 vault，不 mock 内部 storage 模块。
3. `.codex-tasks/` 不修改、不提交。
