# MDBX 文档总目录

语言：[简体中文](README.zh-CN.md) | [English](README.md)

这个目录是 MDBX 项目的文档中心。MDBX 是一种本地优先的加密密码数据库格式与参考架构。

文档现在按职责分类。规范正文放在下面的分类目录中，`docs/*.md` 旧编号路径只作为兼容入口保留，避免旧链接失效。

## 不可妥协原则

所有实现和所有设计决策都必须保留以下性质：

- 本地优先
- 长期可读、可迁移
- 前向兼容与后向兼容
- 4ever And 4ever：新版本必须能读旧 vault；旧实现应尽量保留未知但非关键的数据
- 数据安全优先于便利性
- 不依赖中心服务器
- 以 `project` 为中心组织密码
- 原生附件能力
- 比 KDBX 更安全的同步与冲突处理
- 比 KDBX 更好的网盘同步性能

## 分类目录

### 治理与文档规则

- [Agent execution rules](governance/00-agent-rules.md)
- [MDBX 执行模型规则](governance/00-agent-rules.zh-CN.md)
- [MDBX RFC 结构与文档约定](governance/05-rfc-structure.zh-CN.md)

### 产品模型

- [Product specification](product/01-product-spec.md)
- [MDBX 产品规范](product/01-product-spec.zh-CN.md)

### 存储与同步

- [Storage and sync specification](storage/02-storage-sync-spec.md)
- [MDBX 存储与同步规范](storage/02-storage-sync-spec.zh-CN.md)
- [MDBX SQLite 初版 Schema 规范](storage/06-sqlite-schema-v1.zh-CN.md)

### 安全

- [Security specification](security/03-security-spec.md)
- [MDBX 安全规范](security/03-security-spec.zh-CN.md)

### 交付、验收与任务拆分

- [Roadmap and acceptance](delivery/04-roadmap-acceptance.md)
- [MDBX 路线图与验收规范](delivery/04-roadmap-acceptance.zh-CN.md)
- [MDBX 低端模型任务拆分清单](delivery/07-low-end-model-task-breakdown.zh-CN.md)
- [MDBX 实现补完计划](delivery/08-implementation-completion-plan.zh-CN.md)

### 接入与工具链

- [Monica Pass CLI 开发文档](integration/11-monica-pass-cli-development.zh-CN.md)
- [Client integration guide](../CLIENT_INTEGRATION_GUIDE.md)
- [客户端接入指南](../CLIENT_INTEGRATION_GUIDE.zh-CN.md)
- [MDBX FFI guide](../crates/mdbx-ffi/README.md)
- [MDBX FFI 指南](../crates/mdbx-ffi/README.zh-CN.md)

## 推荐阅读顺序

实现模型建议按下面顺序阅读：

1. [Agent execution rules](governance/00-agent-rules.md)
2. [Product specification](product/01-product-spec.md)
3. [Storage and sync specification](storage/02-storage-sync-spec.md)
4. [Security specification](security/03-security-spec.md)
5. [Roadmap and acceptance](delivery/04-roadmap-acceptance.md)
6. [MDBX RFC 结构与文档约定](governance/05-rfc-structure.zh-CN.md)

中文阅读者建议按下面顺序阅读：

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

## 核心词汇

- `vault`：一个 MDBX 数据库文件。
- `project`：一个现实世界中的账号、网站、应用、组织、身份集合、工作环境、服务集合的主容器。
- `entry`：`project` 内部的具体记录，例如登录项、笔记、卡片、令牌、密钥等。
- `attachment`：归属于 `project` 或 `entry` 的文件或二进制内容。
- `tiga mode`：存储值和 API 使用三档之一：`power`、`multi`、`sky`。`power` 是最高防护，`multi` 是平衡默认，`sky` 是灵活便携但仍然安全。
- `oplog`：追加式变更历史，用于同步与恢复。
- `snapshot`：可用于恢复的压缩状态快照。

## 后续新增文档的写法要求

以后如果继续补规范，必须遵守：

- 使用 `MUST`、`MUST NOT`、`SHOULD`、`SHOULD NOT`、`MAY` 这种 RFC 风格词汇。
- 每条核心要求都要可测试。
- 规范性要求和建议性说明要分开。
- 先写规则，再写示例。
- 核心数据模型不能留下歧义。
- 正文移动时保留旧路径兼容入口。

## 范围边界

这个目录定义的是规范和实现指导。生产代码必须遵循这里的规则，而不是重新定义格式规则。
