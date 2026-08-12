# P13 Hardening / Production Readiness

依据 V4.0，P13 不是“代码能编译”即可关闭，而是生产化硬化阶段。

当前状态：**未完成（约 10%）**。已有 systemd hardening、release checksum/signature 与 install/rollback 测试，但尚未形成完整验收证据。

必须补齐：

- Ubuntu/Debian/RHEL 系/Arch/openSUSE 固定版本 VM/镜像矩阵。
- Agent capability/collector 降级、SELinux/AppArmor、权限与升级/卸载验证。
- Rust fuzz、Web/API DAST、request smuggling/TLS/H2 差异测试。
- Agent/Ingest/Detection/Web Guard/API 的压力、背压、长稳和资源上限测试。
- PostgreSQL/Object Store/streaming 落地后的备份恢复、RPO/RTO 与灾难演练。
- cargo-audit、CodeQL、SBOM、release provenance/signature 门禁形成可审计产物。

退出条件：兼容、安全、性能、备份恢复和灾难演练全部有可复现报告，Critical/High release blocker 清零或有正式风险接受。
