# Release packaging and replacement gate 进度

进度：4/4

已完成：

- 新增 `scripts/verify-mdbx3-release.py`，对 staging 目录执行可重复的替换
  门禁。
- 构建脚本在 artifact report 后自动调用 gate，失败即终止发布。
- 三 ABI、basename、ELF 架构、manifest、SHA-256、535 symbols、237 checksums、
  contract 30 和体积比较均已验证。

当前：已完成实现与验证，等待本阶段提交推送记录。
