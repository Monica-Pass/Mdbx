# MDBX3 Runtime 实施进度

任务：实现 MDBX3 Runtime，并保持 MDBX2 文件、同步和既有 FFI 兼容。

形态：`epic`

进度：1/7 子任务完成

当前：子任务 2，建立 ABI 快照和兼容测试。

事实文件：`mdbx3-runtime-design/implementation/SUBTASKS.csv`

下一步：冻结当前 UniFFI 公开表面，并建立机器可读的兼容检查。

## 实施证据

1. 当前 `mdbx-ffi` library name 为 `mdbx_ffi`，crate type 包含 `cdylib`。
2. 当前 Android 应用内文件名为 `libmdbx_ffi.so`。
3. 当前 FFI build manifest 已经提供 storage 与 sync capability inventory。
4. 当前存储格式为 `MDBX-2`，schema 版本由 vault header 维护。
5. 子任务 1 提交 `d6076b0` 已推送，完整 `mdbx-ffi` 测试通过。
