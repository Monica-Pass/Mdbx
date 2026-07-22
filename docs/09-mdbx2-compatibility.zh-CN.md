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
  - 当前内部 schema 序号；vault header HMAC 使用 `16`。
- `min_reader_version`
  - 可以读取当前 vault 的最低格式代际。
- `min_writer_version`
  - 可以安全写入当前 vault 的最低格式代际。

MDBX-1 自动升级后使用：

```text
format_version    = MDBX-2
schema_version    = 16
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
`commits` 表与 DAG 作为 MDBX1 兼容投影。schema 4 随后以增量迁移升级到 schema 5，增加可空的
Tiga 审计关联与策略证据字段；旧审计记录继续以空值读取。

schema 5 随后以增量迁移升级到 schema 6，增加可空的 `commit_operations.branch_id` 与查询索引。旧 operation 行继续保留空的分支 ID，因为其 V1 请求哈希与完整性标签只认证 `branch_name`，迁移过程不得推断并回填该字段。

schema 6 到 schema 11 继续采用顺序附加迁移：schema 7 增加通用关系、标签和标签分配；schema 8 增加 tombstone 删除证明与设备确认；schema 9 增加永久清理凭证；schema 10 将 Attachment 纳入 Tiga scope；schema 11 增加一对一 `collection_profiles`。这些迁移均保留 `projects`、`entries` 和旧公开接口。

schema 10 重建 Tiga 策略表时，也会保留当前 reader 不认识但属于附加性质的有界字段；字段必须可空或带安全字面量默认值。无法安全重建的字段会在替换旧表前让事务失败，绝不会静默丢弃非关键字段。

schema 12 增加本地稳定 commit 库存，迁移过程保持 commit 身份不变，并按照 parent-before-child 顺序回填。schema 13 增加状态 delta 批次库存、规范化 commit 关联、有界版本化信封规则，以及固定在迁移 commit 水位的 bootstrap floor。schema 14 为所有参与同步的核心状态族增加事务级逻辑变更采集；每个外层写事务提交前，MDBX 会对逻辑键去重，物化有界状态体，并将 commit 关联批次或 auxiliary 批次与业务行原子保存。创建或升级 vault 时产生的 bootstrap 变更会在同一事务中清除，因为这些状态已经由 floor 覆盖。迁移过程不会虚构历史 delta；早于 floor 的 checkpoint 继续使用有界完整状态完成首次同步。

schema 15 增加 `sync_state_extensions`，用于保存 complete-state 顶层的有界未知字段。apply 只 upsert incoming state 实际携带的键，并与 commit 和业务行处于同一个事务；缺少某个键不表示删除，因此旧 peer 仅仅省略未来字段时不能擦除本地扩展。collect 按键顺序恢复值。迁移和 current-schema 验证共同执行 256 个字段、128-byte 键、64 KiB 聚合预算及既有嵌套深度限制。

schema 16 为 `vault_meta` 增加 `header_integrity_profile` 和
`header_integrity_tag`，并增加受保护字段变更触发器。MDBX1/较早 MDBX2 升级时保持
原密文、unlock wrapper 与身份不变，header 先进入 `pending`；使用原凭据首次成功
解锁后，以 vault integrity subkey 建立 HMAC。此后受保护字段的合法 mutation 必须在
同一事务重新封签，直接篡改会进入 `invalidated` 或产生 tag mismatch。该 additive
字段不把 MDBX1 reader 变成 MDBX2 writer，`min_writer_version = MDBX-2` 边界不变。

storage core 将扩展值视为 opaque JSON：只验证、保存和转发，不解释也不解密。opaque 不等于自动加密。非敏感的能力或版本元数据可以使用普通 JSON；密码、邮件正文、token 或其他敏感材料在进入未知扩展前，MUST 由扩展生产者封装为认证密文。这样旧 reader 才能在锁定状态保存未来敏感状态，同时不会自行产生明文。

storage apply 现在识别经过认证的 `mdbx-storage/state-delta-v1` object payload。commit 关联信封必须附着在最后一个关联 commit 上，所有引用 commit 必须已经可用；commit、稀疏状态行、device head、经过授权的删除、接收批次和 capture 清理必须全部成功，否则整体回滚。fast-forward、divergent 和已有 commit 的延迟 payload 修复使用同一边界。bundle v4 及其压缩表示 v6 会在同一个外层事务中应用 commit 关联批次与 auxiliary 批次；尾部批次失败时整段回滚，也不会创建用户可见 commit。这些新增能力不会改变 `projects`、`entries`、commit DAG、sync-state v1-v2 或 bundle v1-v4 格式。

CLI 首次同步继续使用有界完整状态；取得 commit/delta 双 checkpoint 后改用 bundle v4 语义。未完成的 v4/v6 传输会在 checkpoint 文件中保存 transfer ID、下一段序号和上一段逻辑 payload 摘要，后续导出与应用必须匹配同一条恢复链。没有 resume 字段的旧 checkpoint JSON 仍可读取。transport-neutral 同步客户端只有在双方同时声明 commit paging、delta paging、bundle v4 与 resume 四项能力时才选择增量语义；支持 paging 的 Hello 不再携带旧的完整 commit ID 向量。zstd 通过独立的 `bundle-zstd-v1` 协商，不会放宽四项增量契约。旧 peer 或能力不完整的 peer 使用有界完整状态回退。CLI 导出默认写未压缩 v3/v4，只有显式 `--compression zstd` 才写 v5/v6。

### 3.1 真实发布 Golden Vault 与旧 Reader 边界

仓库同时冻结 `crates/mdbx-storage/test-data/mdbx1-release-1.0.mdbx` 与 `mdbx1-draft-golden.mdbx`。release fixture 由历史 `MDBX1.0` tag（commit `1a43fa9e8e87eebf6d0e1b84543c3291d0b25142`）真实生成；DRAFT fixture 由同一个历史 reader 只修改 `vault_meta.format_version` 后 checkpoint 得到。两份 manifest 都记录不可变 SHA-256、测试专用解锁凭据，以及 project、entry、attachment 和 snapshot 的稳定 ID。

共享迁移回归会分别复制两组原始字节，确认 inspection 不修改文件，再执行 schema 1 到当前 schema 的升级；随后使用原 MDBX1 凭据解锁，逐项验证 project metadata、entry payload、project tag、内联附件内容、snapshot 身份，并比较升级前后的 commit 与 object-version 身份，最后验证重复升级幂等。

另外，实测 `MDBX1.0` CLI 可以从已由当前 reader 升级的副本中列出该 project 和 entry。这只证明 MDBX1 物理兼容投影仍可读取，不表示旧 binary 是安全的 MDBX2 writer：旧代码不会执行 `min_writer_version` 门禁，也无法保存未来语义。vault 声明 `min_writer_version = MDBX-2` 后，旧 binary MUST NOT 再执行写入。

## 4. Schema 演进规则

- 新字段 SHOULD 可空或带安全默认值。
- 新表和新索引 SHOULD 使用 additive migration。
- 已发布字段不得改变既有语义。
- 删除旧字段前 MUST 至少经过一个完整兼容代际。
- 未知非关键字段 SHOULD 被保留。
- 未知关键扩展 MUST 阻止写入。
- 格式版本标记 MUST 是迁移事务的最后一个数据变更。

### 4.1 Epoch 标记字段密文

经过正式解锁的新字段密文使用以下外层格式：

```text
MDBXFE2\0 || epoch_id_len_u16_le || epoch_id_utf8 || MDBXAE1 committed AEAD
```

内层 AEAD 使用对应 epoch 的 record、attachment、metadata 或 history 子密钥。AAD 以长度前缀认证 domain、epoch ID、对象类型、对象 ID 和字段名，修改外层 epoch ID、移动密文到其他字段或修改内层密文都会导致认证失败。

reader MUST 继续读取旧的 `MDBXAE1` committed envelope 和更早的 nonce envelope。首次产生 `MDBXFE2` 密文时，storage core MUST 在同一数据库事务中登记关键扩展 `field-key-epochs-v1`。支持该扩展的 reader 可以继续打开；较早的 MDBX2 writer 会把该标识视为未知关键扩展并拒绝可写打开，从而避免使用旧密钥规则覆盖新字段。

## 5. MDBX2 首批一致性修复

MDBX2 同时收紧以下实现边界：

- snapshot 创建和恢复进入原子事务。
- snapshot 恢复重建精确 active set；快照后新增对象保留历史行，但通过 tombstone 离开 active set。
- snapshot 恢复为所有受影响对象写入统一 causal head 和 object version。
- Commit2 增加幂等 operation ID、结构化变更摘要、稳定分支身份、合并后的 vector clock 和
  原子设备序列分配，不重写任何历史 commit。
- 离线 bundle v3 增加显式 payload 长度和有界解码；MDBX2 继续转换读取没有 operation
  元数据的 v1 bundle，并继续读取携带 operation 元数据的 v2 bundle。
- 离线 bundle v4 增加成对增量 inventory、经过认证的 base 校验、有界可恢复 segment，以及 commit 与 auxiliary 的原子应用，同时保留 v1-v3 reader。
- 离线 bundle v5/v6 分别为 complete v3 和 incremental v4 逻辑 payload 增加可选、有界的 zstd 表示；trailer 认证未压缩 bincode payload，压缩与未压缩声明长度分别受限，裁剪构建继续支持 v1-v4 并明确拒绝 v5/v6。
- 新 snapshot 明确携带 project tags 和 attachment chunks；旧快照缺少这些字段时不清空现有兼容数据。
- Tiga global/project/entry mutation 的 commit、对象更新、head 和 object version 原子提交。
- Tiga2 增加版本化策略、精确例外和类型化安全审计；策略状态、覆盖、例外和审计进入同步状态。
- 产生数据变更的 Tiga 授权在同一事务中记录 Commit2 `operation_id` 与 `commit_id`；拒绝决定和不产生数据库变更的敏感操作没有 commit 关联。
- 新审计记录保存作出决定时的 Tiga 策略版本，以及生效策略序列化内容的 SHA-256 指纹。策略修改前先固定该证据，因此审计记录描述的是授权所采用的策略。
- 审计同步认证新增字段，验证 operation 与 commit 指向同一条 `commit_operations` 记录，并拒绝改写已有事件。MDBX1 与早期 MDBX2 审计记录保留空的关联和证据字段。
- 早期 `MDBX-2/schema 2` 自动执行 `schema 2 -> schema 3`，不改变格式代际。
- 迁移不得修改现有 KDF 参数或 wrapped vault key；凭据相关升级只能在用户成功认证后执行。
- CLI bundle apply 统一使用 `mdbx-storage::SyncApplyRepo`，不再维护独立 SQL 同步实现。
- storage 可以原子接收有界、认证的状态 delta，保存收到的批次以便继续转发，保留稀疏 delta 未涉及的本地 tombstone，并单调合并 device revocation。同一个 commit 不得混用完整状态与 delta，既有完整状态仍保持兼容。
- complete-state 未知扩展可经过 decode、事务 apply、数据库保存、collect 和重新编码而不丢失；incoming 中存在的键原子更新，缺失键保留本地值。
- 可移植备份使用 SQLite online backup，完整包含已提交的 WAL 页面；发布前校验 SQLite 完整性、MDBX metadata 与 `vault_id`，转换为无需旁路文件的单文件，并拒绝替换任何已有目标文件。

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

### 7.1 稳定分支身份

`branch_id` 是分支的不可变内部身份。`branch_name` 是可修改的显示属性，同时作为 schema 6 之前接口的兼容选择条件。多个分支可以使用相同显示名称。

新 operation 元数据同时认证稳定 ID 与提交时的显示名称。基于 ID 的请求只选择一个分支，显示名称修改后仍可按原 operation ID 重试。仅提供名称的请求只在该名称唯一时生效。旧 operation 行的 ID 为空，继续使用 V1 请求哈希与完整性算法；迁移过程不得为这些行补写 ID。

同步双方均提供 ID 时按 ID 比较分支；任一方缺少 ID 时按旧名称比较。相同 ID 与不同名称表示同一分支，相同名称与不同 ID 表示不同分支。旧同步消息缺少 `branch_id` 时仍可反序列化。

### 7.2 客户端可控迁移 API

兼容默认路径仍然支持 `VaultConnection::open` 自动升级，保证旧客户端或简单调用方不会因为代际差异无法打开 vault。需要在 UI 中先提示、备份并取得用户同意的客户端，应先调用：

- `mdbx_storage::migration::inspect_migration_path`
- UniFFI：`inspect_vault_migration`

检查结果是只读的，包含当前 format/schema、最低读写代际、是否需要升级以及未知 critical extension 标志。需要升级时，先调用：

- `mdbx_storage::backup::BackupService::create_portable_copy_path`
- UniFFI：`create_portable_backup`

备份发布且取得用户确认后调用：

- `mdbx_storage::migration::upgrade_path`
- UniFFI：`upgrade_vault`

转换仍由 storage core 的同一事务迁移器执行；客户端只负责备份、提示、进度和整改 UI。open 与显式升级会在建立可写连接前重复执行只读身份预检；路径缺失、未初始化的 SQLite 数据库与未知 critical extension 均会被拒绝，文件内容保持不变。

### 7.3 可移植备份 API

客户端在建立可写连接前，通过 Rust `BackupService::create_portable_copy_path` 或 UniFFI 顶层函数 `create_portable_backup` 创建备份。返回信息包含 vault 身份、保留的格式、保留的 schema 与文件大小。参考 CLI 的 `mdbx backup <output>` 使用同一只读接口，无需解锁凭据。

`MdbxVault.create_backup` 继续作为已经打开 vault 的日常备份接口。文件路径接口承担迁移前归档：它接受受支持的 MDBX1、MDBX1 draft 与 MDBX2 文件，包含已经提交的 WAL 页面，并在结果中保留源格式 metadata。

可移植备份是完整的加密 vault 文件，保留源 vault 的解锁方式，不解密业务记录。vault 内部 snapshot 仍是逻辑恢复点，sync bundle 仍是增量传输文件。源库采用 WAL 时，仅复制 SQLite 主文件会遗漏仍位于 WAL 的已提交页面。

目标主文件、`-wal` 与 `-shm` 名称共同构成发布目标集合，任一文件已经存在时均保留原内容并返回错误。storage 在发布单文件结果前执行完整性、与源一致的 MDBX metadata 和 vault 身份校验。

### 7.4 客户端 operation 写入 API

移动端和桌面端应先通过 UniFFI `MdbxVault::list_branches` 获取稳定 ID，再通过 `execute_write_operation_on_branch` 提交指定分支的多步编辑。原有 `execute_write_operation` 继续作为 main 分支兼容入口。接口只接受有限的类型化命令：创建项目、创建、更新、删除、恢复、移动条目；创建和更新同时接受 MDBX1 类型与 namespaced ObjectTypeId，接口不暴露 SQL。

每个创建命令必须携带客户端生成的稳定 UUID。客户端在首次调用和重试时复用同一 `operation_id` 与完整命令列表。storage 会将命令作为一个事务和一个 commit 执行；已完成 operation 的重试只返回 commit ID 与请求中的对象 ID，不再次执行写入。相同 operation ID 搭配不同命令内容会被拒绝，任一命令失败会回滚整个批次。

原有单项 FFI 方法继续保留，作为 MDBX1 兼容投影和简单调用入口；需要把一个用户动作合并为单一历史节点时，应使用 operation API。

原有 operation 方法现在施加默认资源契约：256 条命令、单条 JSON payload 1 MiB、全部 JSON payload 8 MiB、序列化 intent 16 MiB。新增 `default_write_operation_limits` 和 `*_with_limits` 接口允许新客户端选择更小或受控的更大限制，但不能超过 4,096 条命令、单条 16 MiB、总 payload 64 MiB 与 intent 128 MiB 的硬上限。限制检查和流式 intent 哈希发生在 vault 写锁及事务之前；超限不会创建对象、commit 或推进 branch head。旧客户端方法签名和默认 main 分支行为不变。

### 7.5 Commit 历史读取 API

原有 `MdbxCommitHistoryItem`、`list_commit_history` 与 `get_commit_history` 保持字段布局和方法语义，供上一版生成的客户端继续使用。MDBX2 客户端通过 `MdbxCommitHistoryItemV2`、`list_commit_history_v2` 与 `get_commit_history_v2` 读取可空的稳定分支 ID。返回内容包含 operation 信息、分支、parent、类型化变更摘要和兼容标志；没有 operation 元数据的 MDBX1 commit 仍以兼容摘要显示。游标只能由 storage 返回值继续使用，客户端不得按 offset 重建分页。

operation 摘要中的 action 使用 `create`、`update`、`delete`、`restore`、`move` 或兼容用的 `change`；fields 使用稳定的领域字段名。repository 产生的泛化 `change` 只作为占位，不会覆盖客户端已经提供的具体摘要。

### 7.6 Tiga 审计读取 API

原有 UniFFI `MdbxSecurityAuditEvent` 记录与 `list_security_audit_events` 方法保持不变，供上一版生成的客户端继续使用。MDBX2 客户端通过 `MdbxSecurityAuditEventV2` 与 `list_security_audit_events_v2` 读取可空的 operation ID、commit ID、策略版本和策略指纹。

只要 `commit_id` 存在，`operation_id` 就必须存在且两者必须匹配同一条 `commit_operations` 记录。storage 在本地读取和同步导入时执行该验证。两者均为空表示该记录来自 schema 5 之前，或者本次授权没有产生数据库 commit。

### 7.7 密钥 epoch 轮换 API

MDBX2 客户端通过 Rust `KeyEpochService::rotate_authorized` 或 UniFFI `MdbxVault.rotate_key_epoch` 请求轮换。返回的 `previous_epoch_id`、`active_epoch_id`、`commit_id` 与 `rotated_at` 是一次轮换的稳定结果。该调用新增接口，不改变任何 MDBX1 兼容方法的签名。

轮换不属于普通 operation 幂等重试。客户端遇到响应未知时，应先查询 commit history 或 `MdbxSecurityAuditEventV2` 的 commit 关联；再次调用会创建新的 epoch 和 commit。同步 payload 的 key epoch 字段保持可选，旧 payload 继续读取并保留本地 epoch 状态。

### 7.8 同步状态资源限制

完整 `SyncStatePayload` 具有独立的资源契约。默认 Rust API 接受不超过 96 MiB 的编码状态和 250,000 行；桌面调用方可以通过 `SyncStateLimits` 提高限制，但硬上限为 512 MiB 和 2,000,000 行。输出端在读取数据库行后使用有界序列化器，输入端在 JSON 解码前检查字节数，结构解析后再检查逻辑行数。

`mdbx-storage/state-v1` 和旧 `mdbx-cli/state-v1` 必须同时使用 object ID `state` 与匹配的 associated data。错误身份、超限状态或超限 apply 会使完整同步事务回滚；既有 state-v1、state-v2 和旧 CLI 字段保持兼容读取。未知 ObjectPayload 类型继续由普通 opaque payload 处理。

### 7.9 外部 rollback anchor

内部 header HMAC 只能认证当前打开的数据库，不能发现整个文件被替换成较旧但内部自洽的
副本。MDBX2 storage core 因此提供 `RollbackAnchorService::issue/verify`，CLI 提供
`mdbx anchor create/verify`，UniFFI 提供 `MdbxVault.create_rollback_anchor` 与
`verify_rollback_anchor`。token 是有界不透明字节，客户端不得解析、拼接或自行生成。

客户端必须把 token 持久化在 vault 之外，并遵守以下顺序：成功解锁并确认 mutation 或同步
已经持久化后签发 token；下次打开时先验证上一个 token，再信任数据库状态；验证成功后才用
新签发的 token 原子替换客户端保存的 token。相同或更高的 commit/delta append-only
inventory 水位通过，锚定行缺失、被改写、跨 vault、截断、超限或认证失败均拒绝。锚点不
改变 MDBX1/MDBX1-DRAFT 迁移语义，也不提供可信外部时钟、可用性保证或整个 vault 的统一
authentication root。客户端丢失 token 时，storage 无法推断此前状态；未来若要裁剪 delta
inventory，必须先版本化 anchor 语义，不能静默删除锚定行。
