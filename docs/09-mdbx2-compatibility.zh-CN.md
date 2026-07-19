# MDBX2 兼容与迁移规范

版本：`MDBX-2`

本文定义第二代 MDBX（产品名 `MDBX2`）对上一代 vault 的兼容、自动升级和写入安全规则。

## 1. 兼容承诺

- MDBX2 实现 MUST 读取并升级 `MDBX-1`。
- MDBX2 实现 MUST 读取并升级历史测试格式 `MDBX-1-DRAFT`。
- 升级 MUST 保留稳定 ID、密文、commit DAG、object version、tombstone、snapshot、key epoch 和附件内容。
- 升级失败 MUST 保持原 vault 的 `format_version` 和数据不变。
- schema 迁移 MUST NOT 隐式执行 key rotation 或全库重新加密。

这里的“兼容上一代”首先保证新实现读取旧数据。已经发布的旧二进制无法理解未来关键语义，因此不能承诺它们可以安全写入任意 MDBX2 vault。

## 2. 版本字段

MDBX2 在 `vault_meta` 中增加：

- `schema_version`
  - 当前内部 schema 序号；Commit2 与完整 Tiga2 策略使用 `4`。
- `min_reader_version`
  - 可以读取当前 vault 的最低格式代际。
- `min_writer_version`
  - 可以安全写入当前 vault 的最低格式代际。

MDBX-1 自动升级后使用：

```text
format_version    = MDBX-2
schema_version    = 4
min_reader_version = MDBX-1
min_writer_version = MDBX-2
tiga_policy_version = 2
```

这表示 MDBX2 仍保持 MDBX-1 的可读结构，但只有理解 MDBX2 写入不变量的实现才能继续写入。

## 3. 自动升级流程

可写打开 MDBX-1 vault 时，MDBX2 MUST：

1. 读取 `format_version` 和 `critical_extensions`。
2. 遇到未知格式或未知关键扩展时拒绝可写打开。
3. 开始 `BEGIN IMMEDIATE` 事务。
4. 以 additive migration 增加新字段和 `schema_migrations`。
5. 将 Tiga1 模式映射为 Tiga2 策略；旧弱覆盖生成确定性的整改例外。
6. 评估旧解锁配置；不满足新策略时标记 `remediation-required`，不得拒绝用户打开。
7. 记录唯一 migration ID。
8. 完成全部结构和数据验证。
9. 最后更新 `format_version = MDBX-2`。
10. 提交事务。

升级器 MUST 幂等。重复打开已经升级的 vault 不得重复迁移或改变用户数据。

未来 MDBX3 打开 MDBX-1 时 MUST 顺序执行 `MDBX-1 -> MDBX-2 -> MDBX-3`，不得跳过中间代际迁移。

早期 schema 2 或 schema 3 的 MDBX2 vault 会原地升级到 schema 4，不改变 `MDBX-2`
格式标记。schema 4 增加 operation-level commit 元数据和设备原子序列状态，同时继续保留旧
`commits` 表与 DAG 作为 MDBX1 兼容投影。

## 4. Schema 演进规则

- 新字段 SHOULD 可空或带安全默认值。
- 新表和新索引 SHOULD 使用 additive migration。
- 已发布字段不得改变既有语义。
- 删除旧字段前 MUST 至少经过一个完整兼容代际。
- 未知非关键字段 SHOULD 被保留。
- 未知关键扩展 MUST 阻止写入。
- 格式版本标记 MUST 是迁移事务的最后一个数据变更。

## 5. MDBX2 首批一致性修复

MDBX2 同时收紧以下实现边界：

- snapshot 创建和恢复进入原子事务。
- snapshot 恢复重建精确 active set；快照后新增对象保留历史行，但通过 tombstone 离开 active set。
- snapshot 恢复为所有受影响对象写入统一 causal head 和 object version。
- Commit2 增加幂等 operation ID、结构化变更摘要、分支感知 head、合并后的 vector clock 和
  原子设备序列分配，不重写任何历史 commit。
- 同步协议与离线 bundle 使用 v2 传输 operation 元数据；MDBX2 仍可转换读取没有 operation
  元数据的 v1 bundle。
- 新 snapshot 明确携带 project tags 和 attachment chunks；旧快照缺少这些字段时不清空现有兼容数据。
- Tiga global/project/entry mutation 的 commit、对象更新、head 和 object version 原子提交。
- Tiga2 增加版本化策略、精确例外和类型化安全审计；策略状态、覆盖、例外和审计进入同步状态。
- 早期 `MDBX-2/schema 2` 自动执行 `schema 2 -> schema 3`，不改变格式代际。
- 迁移不得修改现有 KDF 参数或 wrapped vault key；凭据相关升级只能在用户成功认证后执行。
- CLI bundle apply 统一使用 `mdbx-storage::SyncApplyRepo`，不再维护独立 SQL 同步实现。

## 6. 验收要求

每次新增代际迁移至少必须测试：

- 上一代真实磁盘 vault 自动升级。
- draft/历史兼容格式升级。
- 重复升级幂等。
- 未知格式和关键扩展拒绝写入。
- 迁移失败不改变原格式标记。
- 升级前后对象数量、稳定 ID、commit 和附件内容一致。
- 新建 vault 直接使用当前代际。

## 7. 客户端与核心职责

- 客户端负责升级提示、备份位置、进度、平台能力证据和整改交互。
- `mdbx-storage` 负责格式识别、确定性映射、事务、回滚、幂等、策略例外和结果校验。
- 客户端不得自行复制 MDBX1 到 MDBX2 的字段转换逻辑。
- “兼容上一代”表示新代可以读取并升级上一代；不承诺旧二进制理解 MDBX2 新策略并安全写入。

### 7.1 客户端可控迁移 API

兼容默认路径仍然支持 `VaultConnection::open` 自动升级，保证旧客户端或简单调用方不会因为代际差异无法打开 vault。需要在 UI 中先提示、备份并取得用户同意的客户端，应先调用：

- `mdbx_storage::migration::inspect_migration_path`
- UniFFI：`inspect_vault_migration`

检查结果是只读的，包含当前 format/schema、最低读写代际、是否需要升级以及未知 critical extension 标志。用户确认后调用：

- `mdbx_storage::migration::upgrade_path`
- UniFFI：`upgrade_vault`

转换仍由 storage core 的同一事务迁移器执行；客户端只负责备份、提示、进度和整改 UI。未知 critical extension 可以被检查并展示，但显式升级必须拒绝写入。

### 7.2 客户端 operation 写入 API

移动端和桌面端的多步编辑应通过 UniFFI `MdbxVault::execute_write_operation` 提交。接口只接受有限的类型化命令：创建项目、创建/更新/删除/恢复/移动条目；接口不暴露 SQL。

每个创建命令必须携带客户端生成的稳定 UUID。客户端在首次调用和重试时复用同一 `operation_id` 与完整命令列表。storage 会将命令作为一个事务和一个 commit 执行；已完成 operation 的重试只返回 commit ID 与请求中的对象 ID，不再次执行写入。相同 operation ID 搭配不同命令内容会被拒绝，任一命令失败会回滚整个批次。

原有单项 FFI 方法继续保留，作为 MDBX1 兼容投影和简单调用入口；需要把一个用户动作合并为单一历史节点时，应使用 operation API。

### 7.3 Commit 历史读取 API

客户端通过 `MdbxVault::list_commit_history` 使用稳定游标分页读取历史，通过 `get_commit_history` 读取单条详情。返回内容包含 operation 信息、分支、parent、类型化变更摘要和兼容标志；没有 operation 元数据的 MDBX1 commit 仍以兼容摘要显示。游标只能由 storage 返回值继续使用，客户端不得按 offset 重建分页。

operation 摘要中的 action 使用 `create`、`update`、`delete`、`restore`、`move` 或兼容用的 `change`；fields 使用稳定的领域字段名。repository 产生的泛化 `change` 只作为占位，不会覆盖客户端已经提供的具体摘要。
