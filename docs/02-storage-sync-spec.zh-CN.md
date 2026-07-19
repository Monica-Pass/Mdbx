# MDBX 存储与同步规范

版本：`MDBX-1-DRAFT`

本文定义 MDBX 的单文件容器策略、内部持久化规则、增量更新行为、同步模型、附件存储行为。

## 1. 容器策略

MDBX 应优先采用单一便携的 `.mdbx` 文件作为用户可见的 vault 载体。

在 `.mdbx` 文件内部，首选引擎为：

- `SQLite + 自定义加密层`

`LMDB` 可以在后续探索，但当前推荐以 SQLite 为基线，因为它在工具生态、可移植性、恢复工具、schema 演进支持方面更成熟。

### Vault 创建生命周期

vault 创建必须以原子方式占用一个尚不存在的文件路径。已有普通文件、SQLite 数据库、MDBX vault 或同名 SQLite WAL 与 SHM 文件必须被拒绝，且原内容保持不变。客户端可以先检查文件是否存在以提供清晰提示，最终判断仍由 storage 的排他占用操作完成。

在 schema、vault metadata、genesis commit、初始 branch、device head、初始 key epoch 与首个解锁方法全部成功前，创建状态保持为 pending。上述任一步骤失败时，必须先关闭 SQLite 连接，再删除本次创建产生的主数据库、WAL 与 SHM 文件。已有 vault 的读取与升级必须使用 open 和 migration 接口，禁止通过 create 接口处理。

### 已有 Vault 打开生命周期

open 与显式升级必须先通过只读 SQLite 连接检查文件。只读预检需要确认 `vault_meta` 已初始化、MDBX 格式代际受支持、critical extension 均可识别，随后才允许建立可写连接、切换 WAL、执行迁移或兼容清理。

可写连接必须使用不带 SQLite 创建权限的读写标志。路径缺失或 SQLite 数据库尚未初始化时返回错误，原文件状态保持不变。foreign key 与 busy timeout 等连接级设置可以在迁移前应用；持久 WAL、secure delete 与旧明文索引清理只能在身份验证和事务迁移成功后应用。

### 可移植备份生命周期

可移植备份是从活动 vault 生成的、事务一致且可以独立打开的单个 `.mdbx` 文件。storage 必须使用 SQLite online backup API 或等价的数据库快照机制，使仍然只存在于源 WAL 中的已提交页面进入备份。WAL 活跃时仅复制源主文件无法构成完整备份。

备份必须先写入目标目录内的临时文件，再转换为非 WAL 日志模式，执行 SQLite 完整性检查，并确认其属于受支持且已经初始化的 MDBX vault。目标 format、schema metadata 与 `vault_id` 必须和源文件一致。临时文件在发布前必须执行文件同步，发布操作必须禁止覆盖已有文件。

目标主文件及其同名 `-wal`、`-shm` 文件必须全部尚未存在。任一目标文件已经存在时，操作返回错误并保留其内容。成功生成的可移植备份没有必需的旁路文件，可以继续使用源 vault 的现有解锁方式独立打开。

上述保证由 storage facade 统一提供。已经打开的 Rust vault 调用 `BackupService::create_portable_copy`；客户端可控迁移在建立可写连接前调用只读的 `BackupService::create_portable_copy_path`。UniFFI 分别提供 `MdbxVault.create_backup` 与顶层 `create_portable_backup`。参考 CLI 的 `mdbx backup <output>` 使用只读文件路径接口，因此无需解锁凭据，也不会触发自动迁移。

只读文件路径备份必须在结果中保留受支持的 MDBX1、MDBX1 draft 或 MDBX2 代际。源主数据库与 WAL 的持久字节必须保持不变。读取活动 WAL 源时，SQLite 可以更新现有 SHM 协调文件中的临时 read mark；SHM 可以重建，也不会进入可移植结果。

## 2. 内部存储目标

内部布局必须支持以下能力：

- 追加友好写入
- 局部更新
- 崩溃恢复
- 附件元数据存储
- 附件二进制内容的间接存储
- 版本历史
- 冲突检测元数据
- 后续迁移钩子

## 3. 最小逻辑表集合

最小逻辑 schema 必须预留至少以下记录类：

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

MVP 可以暂时不实现某些辅助索引或次级表，但绝不能省略 `projects` 或 `attachments`。

## 4. Project 导向的 schema 规则

`projects` 表是强制存在的。
`entries` 表必须带有 `project_id` 外键或等效引用。

这意味着：

- 每个密码类秘密都必须归属于某个 project
- 查询必须能够先取 project，再取其子 entry
- 同步和合并逻辑必须保持 project 归属不丢失

## 5. Attachment schema 规则

`attachments` 表从版本 1 起就是强制的。
即使 MVP 只部分启用分块存储，`attachment_chunks` 表也应从版本 1 起预留。

schema 必须支持：

- 附件归属于 project
- 附件可选归属于某个具体 entry
- 内容 hash
- 分块二进制数据或外部内容引用
- 软删除或 tombstone 机制
- 完整性校验

## 6. 写入路径要求

日常小修改绝不能在逻辑层面导致整个 vault 内容被全量重写。

符合规范的写入路径应尽量做到：

1. 只更新发生变化的 project 或 entry 行
2. 追加一条 commit 或 oplog 记录
3. 更新轻量级 head 元数据
4. 不触碰无关附件行
5. 不触碰无关的大型二进制页面

## 7. WAL 与追加策略

首选实现应使用 SQLite WAL 模式或等价的追加友好策略。

设计目标：

- 小修改产生小写入增量
- 支持区域同步的云盘工具可以只传播较小差异
- 压缩/整理是明确且低频的动作

实现必须清楚说明在断电或崩溃场景下如何保证耐久性。

## 8. Commit 与历史模型

MDBX 必须维护类 Git 的逻辑历史。

最低要求：

- 每次本地变更都产生一个 commit 式历史记录
- commit 记录一个或多个父 commit
- 设备本地顺序单调递增
- 并发历史在合并前也必须可表达

一个 commit 记录最好包含：

- commit ID
- device ID
- 本地序列号
- 父 commit ID 列表
- 变更对象引用
- 时间戳
- 可选的 merge 元数据
- 完整性数据

## 9. 冲突检测

MDBX 必须基于因果元数据检测并发修改，不能只靠时间戳。

最低可接受机制包括：

- 版本向量
- 设备序列图
- 记录级修订血缘
- 必要时的字段级冲突标记

同一 project 内不同字段的并发修改，在安全时可以自动合并。
同一秘密字段的并发修改必须产生显式冲突。

## 10. 合并模型

MDBX 最好支持：

- fast-forward merge
- 针对非秘密文本字段的三方合并
- 对不安全合并生成 conflict 记录
- 后续由用户可视化解决合并冲突

当自动合并不安全时，系统必须保留双方结果。

## 11. 快照与恢复

MDBX 必须支持从逻辑损坏或同步中断中恢复。

最低要求：

- 历史 commit 可回放
- 可以周期性生成 snapshot
- snapshot 可以重建 project、entry、attachment 元数据，以及存在于数据库内的附件 chunk
- 局部损坏时最好仍能恢复剩余大部分数据

snapshot 是保存在 vault 内部的逻辑恢复点。可移植备份生成可独立打开的完整 vault 文件；sync bundle 在副本之间传输增量 commit 状态。三者用途不同，WAL 活跃时仅复制 SQLite 主文件也不能替代其中任何一种机制。

## 12. 附件存储模式

即使 MVP 还未全部实现，MDBX 也必须先定义以下存储模式：

- `embedded-inline`
  - 小型二进制直接内嵌在附件载荷中

- `embedded-chunked`
  - 附件在数据库内按加密分块存储

- `external-hash-ref`
  - 数据库保存元数据，并以内容 hash 绑定外部 blob

默认建议：

- 小附件可以内嵌
- 大附件最好采用分块或内容寻址的外部引用

## 13. 附件更新规则

修改 project 元数据时，不能因此重写大附件内容。
修改 entry 字段时，不能因此重写无关附件内容。
附件改名必须只改元数据。

## 14. 网盘优化

MDBX 的目标是通过 Syncthing、Git、Nextcloud、WebDAV 包装层、Dropbox、OneDrive 等方式同步。

实现应尽量做到：

- 小修改只改很小区域
- 能追加写就尽量追加写，少做随机重写
- 整理操作只在阈值满足时触发
- 将附件主体与普通元数据编辑隔离

## 15. 性能目标

一个健康实现应追踪以下目标：

- 常见元数据保存低于 `100 ms`
- 打开 project 足够快，可用于交互式 UI
- 大型库搜索明显快于 KDBX
- 小修改在云盘上的 delta 通常保持在 `KB` 级别

这些是产品目标，必须有基准测试来跟踪。

## 16. 必需索引

存储引擎最好至少维护以下索引：

- project 标题
- project 标签归属
- project 分组归属
- project 下 entry 类型
- 最近修改时间
- attachment 归属
- tombstone 查找
- commit 血缘查找

全文搜索可以在已解锁会话中使用临时索引。持久 FTS 表不得保存解密后的 project 标题或其他带秘密语义的文本。

临时搜索索引不是用户可见历史，不应产生 commit。用户可见的 project tag 属于元数据，不是临时搜索状态：tracked tag mutation 应产生 project 级 commit，sync state 应携带每个 project 的完整 tag 集合，这样删除 tag、包括删除最后一个 tag，才能被安全重放。收到旧版不含 tag 字段的 sync payload 时，读取端必须保留本地 tag，不能把缺失字段解释为“清空所有 tag”。

## 17. 整理与压缩规则

compaction 可以重写较大部分内容，但必须满足：

- 显式触发或策略触发
- 中断后仍可恢复
- 日常小修改不依赖 compaction
- 不破坏附件完整性

## 18. 最小导出要求

存储层必须支持以下导出路径：

- 整库导出
- project 导出
- 带完整性校验的附件提取
- KDBX 导出桥接

## 19. 拒收规则

以下存储设计不符合规范：

- 没有一等 `projects` 结构
- 没有一等 `attachments` 结构
- 设计上普通小修改就必须重写整个 vault
- 不能表达并发历史
- 不能说明中断后如何恢复
