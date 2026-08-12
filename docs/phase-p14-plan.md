# P14 Pilot / Go-No-Go

依据 V4.0，P14 是真实流量试点与发布决策阶段。

当前状态：**未完成（约 5%）**。仓库已有 monitor/shadow/canary/enforce 机制与部署文档，但没有真实业务试点证据。

必须补齐：

- 选定隔离测试业务和 tenant，先 monitor/shadow 收集基线。
- 通过固定 replay/attack simulation 校验事件、Incident、Evidence、AI Review、Response 全链路。
- 按 route 逐步 canary，记录阻断率、误报率、P95/P99 延迟、AI 调用占比与故障降级。
- 验证 R2/R3 审批、TTL、rollback、post-verification 与审计链。
- 演练模型不可用、Ingest 背压、Agent 离线、证书轮换、存储故障与回滚。
- 形成运维手册、告警责任、值班流程、已知风险/风险接受和 Go/No-Go 会议记录。

退出条件：满足 V4.0 的 Go criteria，特别是生产 Rust 主链路无 Python runtime dependency，性能/安全/证据/回滚门禁均有可审计证据。
