# MDBX3 Runtime 实施进度

任务：实现 MDBX3 Runtime，并保持 MDBX2 文件、同步和既有 FFI 兼容。

形态：`epic`

进度：0/7 子任务完成

当前：子任务 1，加入 runtime identity 和 manifest。

事实文件：`mdbx3-runtime-design/implementation/SUBTASKS.csv`

下一步：读取子任务 1 状态，完成附加 manifest API、测试和第一段提交。

## 实施证据

1. 当前 `mdbx-ffi` library name 为 `mdbx_ffi`，crate type 包含 `cdylib`。
2. 当前 Android 应用内文件名为 `libmdbx_ffi.so`。
3. 当前 FFI build manifest 已经提供 storage 与 sync capability inventory。
4. 当前存储格式为 `MDBX-2`，schema 版本由 vault header 维护。
