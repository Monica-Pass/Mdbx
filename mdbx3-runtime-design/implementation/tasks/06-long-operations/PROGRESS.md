# Long operations and structured diagnostics 进度

进度：3/4

已完成：

- FFI 的 bootstrap/export/check/restore/benchmark 入口按 read/write 语义
  经过 `VaultRuntime`。
- 既有 segment durable ack、resume、tamper、replay 和取消行为保持不变。
- diagnostics 已由 storage-owned typed aggregate counts 提供，避免 FFI raw SQL
  与 payload disclosure。

当前：提交并推送本阶段事实文件。
