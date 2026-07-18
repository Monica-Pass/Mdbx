# MDBX FFI

语言：[简体中文](README.zh-CN.md) | [English](README.md)

`mdbx-ffi` 是面向非 Rust MDBX 客户端的通用 UniFFI 边界。它把 vault 创建、解锁、project 和 generic entry 操作暴露在安全的 storage/repository facade 上，同时把具体产品 payload 语义留给各客户端。

这个 crate 不是低层 SQLite API。如果客户端需要通过 FFI 使用 tag、attachment、sync、conflict、snapshot 或 diagnostics，应该在这里新增明确的 facade 方法并补测试，而不是让客户端直接写 MDBX 底层表。

## 当前范围

当前导出的边界覆盖：

- 使用密码创建 vault，默认 Tiga 模式为 `Multi`
- 使用显式 `Sky`、`Multi` 或 `Power` Tiga 模式创建 vault
- 使用密码打开 vault
- 在已解锁 vault 上配置本地 security-key-material 解锁
- 使用本地 security-key material 打开 vault
- 在已解锁 vault 上重设主密码
- 按 vault、project 或 entry scope 读取完整的 Tiga2 有效运行时策略
- 使用类型化结果、原因码和客户端约束授权敏感操作
- 提交真实设备保证和平台保护能力
- 读取当前会话活动、解锁策略合规状态和安全审计事件
- 明确降低 vault profile 时创建精确且可审计的例外
- 配置并打开“密码 + 安全密钥”组合解锁方式
- 通过已授权 storage API 列出和删除解锁方式
- 创建 project
- 创建、列出、更新、软删除、恢复、移动 generic entry

当前还没有暴露：

- project 列表、更新、删除流程
- 除 project container 之外的嵌套文件夹专用操作
- tag
- attachment 与 attachment content
- sync bundle/apply 操作
- snapshot
- conflict 与 conflict resolution
- diagnostics / maintenance 数据

这些能力应该视为“缺少 facade 方法”，不能因此绕过 storage 层直接写表。

## 数据模型

### Records

`VaultInfo` 包含：

- `vault_id`：从 `vault_meta` 读取的稳定 vault 标识
- `device_id`：调用方传入的设备标识，用于 commit context

`ProjectRecord` 包含：

- `project_id`
- `title`

`EntryRecord` 包含：

- `entry_id`
- `project_id`
- `entry_type`
- `title`
- `payload_json`
- `deleted`

### Tiga2 运行时边界

`MdbxDeviceContext` 承载每次授权使用的真实设备证据。客户端只有在对应保护对本次操作实际生效时，才能报告 `TrustedHardware`、安全剪贴板、防截屏或安全临时文件能力，不得伪造能力来通过 Power 策略。

客户端应调用 `resolve_tiga_policy` 获取 vault、project 或 entry 的完整有效策略，并在执行客户端拥有的敏感动作前立即调用 `authorize_tiga_operation`。只有 `Allow` 和 `AllowWithConstraints` 可以继续；客户端必须执行返回的每一条约束。确认框不能绕过 `RequireFreshAuthentication`、`RequireAdditionalFactor` 或 `Deny`。

连接级授权成功后只会刷新 session 的 idle activity，不会改变最初认证时间或延长绝对寿命。`active_session_info`、`assess_tiga_unlock_policy` 和 `list_security_audit_events` 为安全 UI 提供所需状态，但不会暴露凭据或密钥材料。

`set_tiga_profile` 在降低当前基线时要求非空原因，并由 storage core 创建和持久化绑定精确 scope 的策略例外。加强 profile 时会清除当前 vault 级降级覆盖。

Power 整改通过 `setup_password_security_key_unlock`、`list_unlock_methods` 和 `remove_unlock_method` 完成。删除较弱的独立回退后，应使用 `open_vault_with_password_security_key` 重新打开，使活动 session 同时携带两个认证因素。

### Entry Type

`entry_type` 是由 `mdbx-core::model::EntryType` 解析的字符串。当前可用值：

- `login`
- `note`
- `totp`
- `card`
- `identity`

未知值会返回 `MdbxFfiError::InvalidEntryType`。

### Payload JSON

`payload_json` 必须是合法 JSON 字符串。FFI 层会校验它能被解析为 JSON，然后通过 storage repository API 写入解析后的值。

MDBX 有意让 FFI entry payload 保持 generic。具体产品 payload schema 由客户端负责；需要稳定解释时，客户端应该在 payload 内使用显式 version/kind 字段。典型 login payload 可以是：

```json
{
  "kind": "password",
  "schemaVersion": 1,
  "username": "alice@example.com",
  "password": "secret",
  "url": "https://example.com",
  "favorite": false
}
```

entry 返回时，`payload_json` 会从已存 JSON 值重新序列化。不要依赖输入时的空白或 object key 顺序被保留。

## 错误行为

所有导出函数都返回 `Result<_, MdbxFfiError>`。

- `Storage { message }`：storage、unlock、constraint 或 repository 失败
- `Serialization { message }`：输入 JSON 非法，或已存 JSON 无法解析
- `InvalidEntryType { entry_type }`：未知 entry type 字符串
- `LockPoisoned`：内部 vault mutex 被 poison

常见 constraint error 包括：更新已删除 entry、删除已删除 entry、恢复未删除 entry、移动已删除 entry，或传入的 entry ID 不属于给定 project ID。

## Rust 使用示例

Rust tests 使用的就是 UniFFI 导出的同一层 facade：

```rust
use mdbx_ffi::{create_vault, open_vault, MdbxFfiError};

fn main() -> Result<(), MdbxFfiError> {
    let path = "/tmp/example.mdbx".to_string();
    let password = "correct horse battery staple".to_string();
    let device_id = "desktop-1".to_string();

    let vault = create_vault(path.clone(), password.clone(), device_id.clone())?;
    let project = vault.create_project("Personal".to_string())?;

    let entry = vault.create_entry(
        project.project_id.clone(),
        "login".to_string(),
        "Example".to_string(),
        r#"{"kind":"password","schemaVersion":1,"username":"alice"}"#.to_string(),
    )?;

    let entries = vault.list_entries(project.project_id.clone(), Some("login".to_string()))?;
    assert_eq!(entries[0].entry_id, entry.entry_id);

    drop(vault);
    let reopened = open_vault(path, password, device_id)?;
    assert!(!reopened.info().vault_id.is_empty());
    Ok(())
}
```

## 生成绑定

安装与 crate 依赖版本匹配的 UniFFI CLI：

```sh
cargo install uniffi --version 0.31.1 --locked --features cli
```

构建动态库：

```sh
cargo build -p mdbx-ffi
```

从动态库生成 Swift bindings：

```sh
uniffi-bindgen-swift --swift-sources target/debug/libmdbx_ffi.dylib ./generated
uniffi-bindgen-swift --headers target/debug/libmdbx_ffi.dylib ./generated
```

Linux 动态库路径是 `target/debug/libmdbx_ffi.so`；Windows 是 `target/debug/mdbx_ffi.dll`。平台打包时仍然需要把对应 static/dynamic library 和生成的 bindings 一起交付。

## iOS 注意事项

Monica iOS workspace 的辅助脚本不放在本仓库内。预期打包流程是：

- 分别为 device 和 simulator target 构建 `mdbx-ffi`
- 使用 `uniffi-bindgen-swift` 生成 Swift、header 和 modulemap
- 把 static libraries 和生成的 header 打包为 XCFramework
- 在 Swift package 或 app target 中引入生成的 Swift source 与 XCFramework

生成的 bindings 应视为构建产物。需要变更时应从本 crate 重新生成，不要手动编辑生成的 Swift 或 headers。

## 扩展 FFI 边界

新增跨语言能力时：

1. 添加符合客户端需求的 typed UniFFI records/enums，但不要泄漏 raw storage rows。
2. 方法实现应调用 `mdbx-storage` repository/service APIs。
3. 保持 commit、object-version、tombstone、branch-head、device-head、key-epoch、conflict、snapshot、sync-state 等不变量。
4. 新增或更新 `crates/mdbx-ffi/tests/ffi_smoke.rs`，覆盖导出行为。
5. 至少运行 `cargo test -p mdbx-ffi`；如果改到共享 storage 行为，运行完整 `cargo test`。

不要暴露允许客户端直接写 `commits`、`commit_parents`、`object_versions`、`tombstones`、`snapshots`、`key_epochs`、`conflicts`、`device_heads`、`branches` 或 `project_tags` 的方法。

## 验证

从仓库根目录运行 FFI 测试：

```sh
cargo test -p mdbx-ffi
```

smoke tests 会验证 vault create/open、entry round trip、update/delete/restore/move、安全密钥材料解锁、主密码重设、完整 Tiga2 策略与授权映射、精确例外，以及 Power 组合因素整改。
